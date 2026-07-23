// avif/decode.rs
// AV1 frame decode via the `rav1d` crate (C API, hand-written ARM NEON asm).
// Output goes directly into a raw allocation — no Vec zero-fill overhead.

// Relax these clippy lints:
// - too_many_arguments: some things just need a lot of state, wrapping it
//   doesn't necessarily make it easier to follow what's going on
#![allow(clippy::too_many_arguments)]

use crate::decode::DecodeBuf;
use std::alloc::{Layout, alloc, dealloc};
use std::ptr::NonNull;

use rav1d::include::dav1d::data::Dav1dData;
use rav1d::include::dav1d::dav1d::{Dav1dContext, Dav1dSettings};
use rav1d::include::dav1d::headers::{
	DAV1D_MC_IDENTITY, DAV1D_PIXEL_LAYOUT_I400, DAV1D_PIXEL_LAYOUT_I420, DAV1D_PIXEL_LAYOUT_I422,
	Dav1dPixelLayout,
};
use rav1d::include::dav1d::picture::Dav1dPicture;
use rav1d::send_sync_non_null::SendSyncNonNull;
use rav1d::{
	dav1d_close, dav1d_data_wrap, dav1d_default_settings, dav1d_get_picture, dav1d_open,
	dav1d_picture_unref, dav1d_send_data,
};

// ── no-op free callback ───────────────────────────────────────────

unsafe extern "C" fn noop_free(
	_ptr: *const u8,
	_cookie: Option<SendSyncNonNull<std::ffi::c_void>>,
) {
}

// ── raw output buffer (no Vec, direct alloc) ──────────────────────

fn make_buf(data: *mut u8, len: usize, w: u32, h: u32) -> Box<DecodeBuf> {
	Box::new(DecodeBuf {
		width: w,
		height: h,
		channels: 4,
		data_len: len,
		data,
	})
}

fn alloc_buf(bytes: usize) -> *mut u8 {
	unsafe { alloc(Layout::array::<u8>(bytes).unwrap()) }
}

fn free_buf(data: *mut u8, len: usize) {
	unsafe { dealloc(data, Layout::array::<u8>(len).unwrap()) };
}

// ── public entry ──────────────────────────────────────────────────

pub fn decode_frame(obu: &[u8], target_width: u32) -> Option<Box<DecodeBuf>> {
	let ctx = open()?;
	send(&ctx, obu)?;
	let pic = recv(&ctx)?;
	let rgba = planes_to_rgba(&pic, target_width);
	unref(pic);
	close(ctx);
	rgba
}

// ── decoder lifecycle ─────────────────────────────────────────────

fn open() -> Option<Dav1dContext> {
	unsafe {
		let mut settings: Dav1dSettings = std::mem::zeroed();
		dav1d_default_settings(NonNull::new(&mut settings)?);
		settings.n_threads = 1;
		settings.max_frame_delay = 1;
		settings.frame_size_limit = 0;

		let mut ctx: Option<Dav1dContext> = None;
		let ret = dav1d_open(NonNull::new(&mut ctx), NonNull::new(&mut settings));
		if ret.0 != 0 {
			return None;
		}
		ctx
	}
}

fn send(ctx: &Dav1dContext, obu: &[u8]) -> Option<()> {
	unsafe {
		let mut data: Dav1dData = std::mem::zeroed();
		dav1d_data_wrap(
			NonNull::new(&mut data),
			NonNull::new(obu.as_ptr() as *mut u8),
			obu.len(),
			Some(noop_free),
			None,
		);
		let ret = dav1d_send_data(Some(*ctx), NonNull::new(&mut data));
		if ret.0 != 0 {
			return None;
		}
		Some(())
	}
}

fn recv(ctx: &Dav1dContext) -> Option<Dav1dPicture> {
	unsafe {
		let mut pic: Dav1dPicture = std::mem::zeroed();
		let ret = dav1d_get_picture(Some(*ctx), NonNull::new(&mut pic));
		if ret.0 != 0 {
			return None;
		}
		Some(pic)
	}
}

fn unref(mut pic: Dav1dPicture) {
	unsafe { dav1d_picture_unref(NonNull::new(&mut pic)) };
}

fn close(ctx: Dav1dContext) {
	unsafe { dav1d_close(NonNull::new(&mut Some(ctx))) };
}

// ── plane access ──────────────────────────────────────────────────

fn plane_ptr(pic: &Dav1dPicture, idx: usize) -> Option<NonNull<u8>> {
	pic.data[idx].map(|p| p.cast())
}
fn layout(pic: &Dav1dPicture) -> Dav1dPixelLayout {
	pic.p.layout
}
fn dims(pic: &Dav1dPicture) -> (u32, u32) {
	(pic.p.w as u32, pic.p.h as u32)
}
fn bpc(pic: &Dav1dPicture) -> u32 {
	pic.p.bpc as u32
}
fn strides(pic: &Dav1dPicture) -> (usize, usize) {
	(pic.stride[0] as usize, pic.stride[1] as usize)
}

// ── planes → RGBA (no Vec, writes directly into raw alloc) ────────

fn planes_to_rgba(pic: &Dav1dPicture, target_width: u32) -> Option<Box<DecodeBuf>> {
	let (sw, sh) = dims(pic);
	let dw = if target_width > 0 && target_width < sw {
		target_width
	} else {
		sw
	};
	let dh = if dw != sw {
		(sh as f64 * dw as f64 / sw as f64) as u32
	} else {
		sh
	};
	let n = (dw * dh) as usize * 4;
	let data = alloc_buf(n);

	let (is_gbrp, limited) = color_meta(pic);
	let ok = unsafe {
		let y = plane_ptr(pic, 0)?;
		let u = plane_ptr(pic, 1)?;
		let v = plane_ptr(pic, 2)?;
		if is_gbrp {
			interleave(
				data,
				y.as_ptr(),
				u.as_ptr(),
				v.as_ptr(),
				sw,
				sh,
				dw,
				dh,
				strides(pic).0,
				limited,
				bpc(pic),
			);
		} else {
			let l = layout(pic);
			let (xs, ys) = subsampling(l);
			let hc = has_chroma(l);
			let (y_str, uv_str) = strides(pic);
			convert(
				data,
				y.as_ptr(),
				u.as_ptr(),
				v.as_ptr(),
				sw,
				sh,
				dw,
				dh,
				y_str,
				uv_str,
				xs,
				ys,
				hc,
				limited,
				bpc(pic),
			);
		}
		true
	};
	if ok {
		Some(make_buf(data, n, dw, dh))
	} else {
		free_buf(data, n);
		None
	}
}

// ── GBRP interleave ───────────────────────────────────────────────

unsafe fn interleave(
	out: *mut u8,
	g: *const u8,
	b: *const u8,
	r: *const u8,
	sw: u32,
	sh: u32,
	dw: u32,
	dh: u32,
	stride: usize,
	limited: bool,
	bd: u32,
) {
	unsafe {
		let shift = bd.saturating_sub(8);
		let is16 = bd > 8;
		let dwu = dw as usize;
		let xr = sw as f64 / dw as f64;
		let yr = sh as f64 / dh as f64;
		let ss = if is16 { stride / 2 } else { stride };

		for dy in 0..dh as usize {
			let sy = if dw != sw {
				((dy as f64 + 0.5) * yr) as usize
			} else {
				dy
			};
			let dr = dy * dwu * 4;

			if dw == sw {
				for dx in 0..dwu {
					let (mut rv, mut gv, mut bv) = rgb(g, b, r, sy * ss + dx, is16, shift);
					if limited {
						limited3(&mut rv, &mut gv, &mut bv);
					}
					let di = dr + dx * 4;
					*out.add(di) = rv as u8;
					*out.add(di + 1) = gv as u8;
					*out.add(di + 2) = bv as u8;
					*out.add(di + 3) = 255;
				}
			} else {
				for dx in 0..dwu {
					let sx = ((dx as f64 + 0.5) * xr) as usize;
					let (mut rv, mut gv, mut bv) = rgb(g, b, r, sy * ss + sx, is16, shift);
					if limited {
						limited3(&mut rv, &mut gv, &mut bv);
					}
					let di = dr + dx * 4;
					*out.add(di) = rv as u8;
					*out.add(di + 1) = gv as u8;
					*out.add(di + 2) = bv as u8;
					*out.add(di + 3) = 255;
				}
			}
		}
	}
}

#[inline(always)]
unsafe fn rgb(
	g: *const u8,
	b: *const u8,
	r: *const u8,
	i: usize,
	is16: bool,
	shift: u32,
) -> (u32, u32, u32) {
	unsafe {
		if is16 {
			let (gp, bp, rp) = (g as *const u16, b as *const u16, r as *const u16);
			(
				(*rp.add(i) >> shift) as u32,
				(*gp.add(i) >> shift) as u32,
				(*bp.add(i) >> shift) as u32,
			)
		} else {
			((*r.add(i) as u32), (*g.add(i) as u32), (*b.add(i) as u32))
		}
	}
}

fn limited3(r: &mut u32, g: &mut u32, b: &mut u32) {
	let lim = |v: &mut u32| *v = ((v.saturating_sub(16)) * 255 / 219).min(255);
	lim(r);
	lim(g);
	lim(b);
}

// ── YUV → RGBA ────────────────────────────────────────────────────

unsafe fn convert(
	out: *mut u8,
	y: *const u8,
	u: *const u8,
	v: *const u8,
	sw: u32,
	sh: u32,
	dw: u32,
	dh: u32,
	y_str: usize,
	uv_str: usize,
	xs: usize,
	ys: usize,
	hc: bool,
	limited: bool,
	bd: u32,
) {
	unsafe {
		let shift = bd.saturating_sub(8);
		let is16 = bd > 8;
		let dwu = dw as usize;
		let xr = sw as f64 / dw as f64;
		let yr = sh as f64 / dh as f64;
		let ye = y_str / if is16 { 2 } else { 1 };
		let ue = uv_str / if is16 { 2 } else { 1 };

		for dy in 0..dh as usize {
			let sy = if dw != sw {
				((dy as f64 + 0.5) * yr) as usize
			} else {
				dy
			};
			let uvy = if hc { sy / ys } else { 0 };
			let dr = dy * dwu * 4;

			if dw == sw {
				for dx in 0..dwu {
					let yv = val(y, sy * ye + dx, is16, shift) as i32;
					let yb = if limited {
						(yv.saturating_sub(16)) * 298
					} else {
						yv * 256
					};
					let ux = if hc { dx / xs } else { dx };
					let cb = val(u, uvy * ue + ux, is16, shift) as i32 - 128;
					let cr = val(v, uvy * ue + ux, is16, shift) as i32 - 128;
					let di = dr + dx * 4;
					*out.add(di) = ((yb + 359 * cr + 128) >> 8).clamp(0, 255) as u8;
					*out.add(di + 1) = ((yb - 88 * cb - 183 * cr + 128) >> 8).clamp(0, 255) as u8;
					*out.add(di + 2) = ((yb + 454 * cb + 128) >> 8).clamp(0, 255) as u8;
					*out.add(di + 3) = 255;
				}
			} else {
				for dx in 0..dwu {
					let sx = ((dx as f64 + 0.5) * xr) as usize;
					let yv = val(y, sy * ye + sx, is16, shift) as i32;
					let yb = if limited {
						(yv.saturating_sub(16)) * 298
					} else {
						yv * 256
					};
					let ux = if hc { sx / xs } else { sx };
					let cb = val(u, uvy * ue + ux, is16, shift) as i32 - 128;
					let cr = val(v, uvy * ue + ux, is16, shift) as i32 - 128;
					let di = dr + dx * 4;
					*out.add(di) = ((yb + 359 * cr + 128) >> 8).clamp(0, 255) as u8;
					*out.add(di + 1) = ((yb - 88 * cb - 183 * cr + 128) >> 8).clamp(0, 255) as u8;
					*out.add(di + 2) = ((yb + 454 * cb + 128) >> 8).clamp(0, 255) as u8;
					*out.add(di + 3) = 255;
				}
			}
		}
	}
}

#[inline(always)]
unsafe fn val(ptr: *const u8, i: usize, is16: bool, shift: u32) -> u32 {
	unsafe {
		if is16 {
			(*((ptr as *const u16).add(i)) >> shift) as u32
		} else {
			*ptr.add(i) as u32
		}
	}
}

// ── helpers ───────────────────────────────────────────────────────

fn color_meta(pic: &Dav1dPicture) -> (bool, bool) {
	unsafe {
		if let Some(h) = pic.seq_hdr {
			let sh = h.as_ref();
			let is_gbrp = sh.mtrx == DAV1D_MC_IDENTITY;
			let has_color = sh.color_description_present != 0;
			let limited = has_color && sh.color_range == 0;
			(is_gbrp, limited)
		} else {
			(false, false)
		}
	}
}

fn subsampling(l: Dav1dPixelLayout) -> (usize, usize) {
	match l {
		DAV1D_PIXEL_LAYOUT_I420 => (2, 2),
		DAV1D_PIXEL_LAYOUT_I422 => (2, 1),
		DAV1D_PIXEL_LAYOUT_I400 => (0, 0),
		_ => (1, 1),
	}
}

fn has_chroma(l: Dav1dPixelLayout) -> bool {
	!matches!(l, DAV1D_PIXEL_LAYOUT_I400)
}
