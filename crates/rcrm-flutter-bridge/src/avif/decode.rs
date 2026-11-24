// avif/decode.rs
// AV1 frame decode via the `rav1d` crate (C API, hand-written ARM NEON asm).
// Output goes directly into a raw allocation — no Vec zero-fill overhead.

// Relax these clippy lints:
// - too_many_arguments: some things just need a lot of state, wrapping it
//   doesn't necessarily make it easier to follow what's going on
#![allow(clippy::too_many_arguments)]

use crate::decode::{DecodeBuf, Limit};
use std::alloc::{Layout, alloc, dealloc};
use std::ptr::NonNull;

use rav1d::include::dav1d::data::Dav1dData;
use rav1d::include::dav1d::dav1d::{Dav1dContext, Dav1dSettings};
use rav1d::include::dav1d::headers::{
	DAV1D_MC_BT470BG, DAV1D_MC_BT601, DAV1D_MC_BT709, DAV1D_MC_BT2020_CL, DAV1D_MC_BT2020_NCL,
	DAV1D_MC_FCC, DAV1D_MC_IDENTITY, DAV1D_MC_SMPTE240, DAV1D_MC_UNKNOWN, DAV1D_PIXEL_LAYOUT_I400,
	DAV1D_PIXEL_LAYOUT_I420, DAV1D_PIXEL_LAYOUT_I422, Dav1dMatrixCoefficients, Dav1dPixelLayout,
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
		// Allocated exactly by `alloc_buf`, so capacity == length.
		cap: len,
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

fn decode_with_ctx(ctx: &Dav1dContext, obu: &[u8], target_width: u32) -> Option<Box<DecodeBuf>> {
	let pic = send(ctx, obu).and_then(|()| recv(ctx))?;
	let rgba = planes_to_rgba(&pic, target_width);
	unref(pic);
	rgba
}

pub fn decode_frame(obu: &[u8], target_width: u32, limit: Limit) -> Option<Box<DecodeBuf>> {
	let ctx = open(limit)?;
	// The handle is a rav1d `RawArc` -- `Copy`, with no `Drop` -- so *dropping it
	// frees nothing*: the decoder context (its thread pool and frame buffers)
	// only goes away through `close`. Malformed or truncated bytes, and any
	// non-AVIF ISOBMFF file that still carries mdat+ispe, return early here, so
	// the close has to happen on every path rather than only on success.
	let result = decode_with_ctx(&ctx, obu, target_width);
	close(ctx);
	result
}

/// A rav1d context kept alive across several items. libavif decodes all tiles
/// of a `grid` with one decoder instance (its `read.c` documents this); some
/// tiles rely on reference frames set up by earlier tiles and decode black in
/// a fresh context.
pub struct TileDecoder {
	ctx: Dav1dContext,
}

impl TileDecoder {
	pub fn new(limit: Limit) -> Option<Self> {
		Some(Self { ctx: open(limit)? })
	}

	pub fn frame(&self, obu: &[u8], target_width: u32) -> Option<Box<DecodeBuf>> {
		decode_with_ctx(&self.ctx, obu, target_width)
	}

	/// Decode an alpha item to its native monochrome plane. Grid cells place the
	/// tile at native size and clip at the canvas, so the source dims travel with it.
	pub fn alpha_native(&self, obu: &[u8]) -> Option<(Vec<u8>, u32, u32)> {
		let pic = send(&self.ctx, obu).and_then(|()| recv(&self.ctx))?;
		let (w, h) = dims(&pic);
		// Same extraction as the resampled path with dw==sw, dh==sh. `unref` runs
		// on every path, including a picture with no luma plane.
		let out = unsafe { alpha_plane(&pic, w, h) };
		unref(pic);
		Some((out?, w, h))
	}
}

impl Drop for TileDecoder {
	fn drop(&mut self) {
		close(self.ctx);
	}
}

/// Map one display-pixel coordinate `(fx, fy)` in the final image back to the
/// source coordinate inside the `cw`×`ch` aperture. Pure so the direction can be
/// pinned by a unit test without mounting a decoder.
pub(crate) fn display_to_source(
	t: &crate::avif::parse::Transform,
	fx: u32,
	fy: u32,
	cw: u32,
	ch: u32,
) -> (u32, u32) {
	// Mirror lives in display space: for quarter turns the displayed axes are
	// swapped, so fx spans the cropped HEIGHT and fy the cropped WIDTH. Using
	// cw/ch here would underflow (u32 wrap) and read out of bounds.
	let (mw, mh) = if t.rotate & 1 == 1 {
		(ch, cw)
	} else {
		(cw, ch)
	};
	let (mx, my) = match t.mirror {
		1 => (mw - 1 - fx, fy),
		2 => (fx, mh - 1 - fy),
		_ => (fx, fy),
	};
	match t.rotate & 3 {
		1 => (cw - 1 - my, mx),
		2 => (cw - 1 - mx, ch - 1 - my),
		3 => (my, ch - 1 - mx),
		_ => (mx, my),
	}
}

/// Bake the container's clean-aperture crop, rotation and mirror into the RGBA
/// pixels. Called after alpha compositing so the alpha travels with the image.
pub fn apply_transform(
	src: Box<DecodeBuf>,
	t: &crate::avif::parse::Transform,
) -> Option<Box<DecodeBuf>> {
	if t.is_identity() {
		return Some(src);
	}
	let (sw, sh) = (src.width, src.height);
	let sp = unsafe { std::slice::from_raw_parts(src.data, src.data_len) };

	// ISO clap / libavif avifCropRectFromCleanApertureBox: the crop origin is
	//   crop = center(size) + offset - clap/2
	// computed over EXACT fractions. Integer truncation loses cases like
	// W=5, clapW=2, offset=1/2 -> crop 2 (verified against avifdec).
	// The fraction is (numerator, denominator); libavif rejects a non-integer
	// crop origin, so we do the same rather than silently rounding.
	// ISO/IEC 23000-22: cleanApertureWidth/Height must be integers, with a
	// strictly positive denominator (libavif rejects otherwise). A fractional
	// or zero-length aperture is not silently truncated to a smaller crop.
	let aperture = |num: u32, den: u32| -> Option<u32> {
		if den == 0 || !num.is_multiple_of(den) {
			return None;
		}
		Some(num / den)
	};
	let crop_origin = |size: u32, clap: u32, off_num: u32, off_den: u32| -> Option<i64> {
		if off_den == 0 {
			return None;
		}
		// center(size): size/2, but for odd size libavif uses size/2 as a
		// fraction (size, 2).
		let (cn, cd): (i64, i64) = if size.is_multiple_of(2) {
			((size / 2) as i64, 1)
		} else {
			(size as i64, 2)
		};
		let (on, od) = (off_num as i32 as i64, off_den as i64);
		let (hn, hd) = (clap as i64, 2i64);
		// crop = cn/cd + on/od - hn/hd over common denominator cd*od*hd.
		let den = cd * od * hd;
		let num = cn * od * hd + on * cd * hd - hn * cd * od;
		if num % den != 0 {
			return None;
		}
		Some(num / den)
	};
	let (x0, y0, cw, ch) = match t.crop {
		Some(c) => {
			let (cw, ch) = match (aperture(c[0], c[1]), aperture(c[2], c[3])) {
				(Some(w), Some(h)) => (w, h),
				_ => {
					drop(src);
					return None;
				}
			};
			if cw == 0 || ch == 0 || cw > sw || ch > sh {
				drop(src);
				return None;
			}
			let (ox, oy) = match (
				crop_origin(sw, cw, c[4], c[5]),
				crop_origin(sh, ch, c[6], c[7]),
			) {
				(Some(x), Some(y)) => (x, y),
				_ => {
					drop(src);
					return None;
				}
			};
			if ox < 0
				|| oy < 0
				|| ox as u64 + cw as u64 > sw as u64
				|| oy as u64 + ch as u64 > sh as u64
			{
				drop(src);
				return None;
			}
			(ox as u32, oy as u32, cw, ch)
		}
		None => (0, 0, sw, sh),
	};
	let (fw, fh) = if t.rotate & 1 == 1 {
		(ch, cw)
	} else {
		(cw, ch)
	};
	let n = fw as usize * fh as usize * 4;
	let mut out = Vec::new();
	out.try_reserve_exact(n).ok()?;
	out.resize(n, 0);

	for fy in 0..fh {
		for fx in 0..fw {
			// Inverse of the display pipeline: mirror, then rotate, then crop.
			let (cx, cy) = display_to_source(t, fx, fy, cw, ch);
			let src_i = ((y0 + cy) as usize * sw as usize + (x0 + cx) as usize) * 4;
			let dst_i = (fy as usize * fw as usize + fx as usize) * 4;
			out[dst_i..dst_i + 4].copy_from_slice(&sp[src_i..src_i + 4]);
		}
	}
	drop(src);
	Some(DecodeBuf::from_vec(out, fw, fh))
}

/// Decode an AVIF alpha auxiliary item (a monochrome AV1 frame) into one byte
/// per pixel, resampled to the primary image's dimensions.
pub fn decode_alpha(obu: &[u8], dw: u32, dh: u32, limit: Limit) -> Option<Vec<u8>> {
	if dw == 0 || dh == 0 {
		return None;
	}
	let ctx = open(limit)?;
	let result = send(&ctx, obu).and_then(|()| recv(&ctx)).and_then(|pic| {
		let out = unsafe { alpha_plane(&pic, dw, dh) };
		unref(pic);
		out
	});
	close(ctx);
	result
}

unsafe fn alpha_plane(pic: &Dav1dPicture, dw: u32, dh: u32) -> Option<Vec<u8>> {
	let (sw, sh) = dims(pic);
	let y = plane_ptr(pic, 0)?;
	let bpc = bpc(pic);
	let (is16, shift) = (bpc > 8, bpc.saturating_sub(8));
	let ye = strides(pic).0 / if is16 { 2 } else { 1 };
	let n = dw as usize * dh as usize;
	let mut out = Vec::new();
	out.try_reserve_exact(n).ok()?;
	out.resize(n, 0);
	// sx depends only on dx — precompute once (measured 2.68x). Build entries
	// with the EXACT original expression so f64 results stay bit-identical.
	let sx_index: Vec<usize> = if dw == sw {
		(0..dw as usize).collect()
	} else {
		(0..dw)
			.map(|dx| ((dx as f64 + 0.5) * sw as f64 / dw as f64) as usize)
			.collect()
	};
	for dy in 0..dh as usize {
		let sy = if dh == sh {
			dy
		} else {
			((dy as f64 + 0.5) * sh as f64 / dh as f64) as usize
		};
		let base = sy * ye;
		for (dx, &sx) in sx_index.iter().enumerate() {
			out[dy * dw as usize + dx] = unsafe { val(y.as_ptr(), base + sx, is16, shift) } as u8;
		}
	}
	Some(out)
}

// ── decoder lifecycle ─────────────────────────────────────────────

fn open(limit: Limit) -> Option<Dav1dContext> {
	unsafe {
		let mut settings: Dav1dSettings = std::mem::zeroed();
		dav1d_default_settings(NonNull::new(&mut settings)?);
		settings.n_threads = 1;
		settings.max_frame_delay = 1;
		// Fed to rav1d in PIXELS (the same thing the `heic` crate does), so a file
		// whose container `ispe` lies about its size is still rejected while its
		// OBUs are parsed instead of being decoded into a multi-GB allocation.
		// `frame_size_limit` is a u32, hence the saturating conversion.
		settings.frame_size_limit = limit.as_u32_saturating();

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

/// Fill RGBA from a monochrome Y plane via a caller-supplied Y→gray converter.
/// Generic so each converter (LUT / arithmetic) is monomorphized — no virtual
/// call in the pixel loop. `sx` is precomputed only when downscaling; row bases
/// are hoisted; output is written sequentially with a packed store.
fn fill_mono_gray(
	y16: &[u16],
	ys: usize,
	out: &mut [u8],
	sw: u32,
	sh: u32,
	dw: u32,
	dh: u32,
	to_gray: impl Fn(u16) -> u8,
) {
	let dwu = dw as usize;
	if dw == sw {
		for dy in 0..dh as usize {
			let row = dy * ys;
			let mut o = dy * dwu * 4;
			for dx in 0..dwu {
				let v = to_gray(y16[row + dx]);
				out[o..o + 4].copy_from_slice(&[v, v, v, 255]);
				o += 4;
			}
		}
	} else {
		let xr = sw as f64 / dw as f64;
		let yr = sh as f64 / dh as f64;
		let sx_index: Vec<usize> = (0..dw)
			.map(|dx| ((dx as f64 + 0.5) * xr) as usize)
			.collect();
		for dy in 0..dh as usize {
			let sy = ((dy as f64 + 0.5) * yr) as usize;
			let row = sy * ys;
			let mut o = dy * dwu * 4;
			for &sx in &sx_index {
				let v = to_gray(y16[row + sx]);
				out[o..o + 4].copy_from_slice(&[v, v, v, 255]);
				o += 4;
			}
		}
	}
}

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
	// A wide-but-tiny frame downscaled to a small width can round `dh` to 0
	// (e.g. 1000x1 with target_width=64). alloc(Layout::array::<u8>(0)) is UB,
	// and a zero-height DecodeBuf is meaningless to Dart. Reject before any
	// allocation — mirrors downscale_rgba_bilinear's existing dh==0 guard.
	if dw == 0 || dh == 0 {
		return None;
	}
	let n = (dw * dh) as usize * 4;
	let data = alloc_buf(n);
	if data.is_null() {
		// `alloc` returns null instead of aborting; without this the pixel loops
		// below would write dw*dh*4 bytes through a null pointer, and the size is
		// attacker-influenced whenever the declared dimensions lie.
		return None;
	}

	let (is_gbrp, limited, matrix) = color_meta(pic);
	let pix_layout = layout(pic);
	// Y is always required. Chroma planes exist only for non-monochrome frames;
	// fetching them unconditionally would reject valid I400 images.
	let Some(y) = plane_ptr(pic, 0) else {
		free_buf(data, n);
		return None;
	};
	// Monochrome (I400): rav1d supplies only the Y plane (u/v are null), so the
	// scalar convert below cannot be used — it reads u/v and would deref null.
	// Use yuv's SIMD gray->RGBA converter straight into the target `data`.
	// For a thumbnail (dw<sw) the Y plane is first bilinear-downscaled to a small
	// dw*dh byte buffer (1/4 of a full RGBA frame and 1/4 of the output bytes)
	// instead of converting a full-size RGBA frame then downscaling that — no
	// full-size intermediate allocation, and `data` is always the final output.
	if pix_layout == DAV1D_PIXEL_LAYOUT_I400 && bpc(pic) <= 8 {
		let range = if limited {
			yuv::YuvRange::Limited
		} else {
			yuv::YuvRange::Full
		};
		let (y_str, _) = strides(pic);
		// SAFETY: `y` is a non-null pointer to the frame's Y plane, backed by
		// y_str*sh bytes of frame memory valid until unref(pic) after this call.
		let frame_y = || unsafe { std::slice::from_raw_parts(y.as_ptr(), y_str * sh as usize) };
		// Owned downscale temp, kept alive across the conversion. Empty in the
		// full-size case (the frame's Y plane is borrowed directly instead).
		// Mono is one byte per pixel, so the shared bilinear core runs with C=1
		// and writes into a dw*dh buffer — identical geometry to the RGBA path.
		let scaled_y: Vec<u8> = if dw == sw {
			Vec::new()
		} else {
			let mut y = Vec::new();
			if crate::decode::bilinear_resample::<1>(frame_y(), y_str, &mut y, sw, sh, dw, dh)
				.is_none()
			{
				free_buf(data, n);
				return None;
			}
			y
		};
		let (y_plane, y_width, y_height, y_stride) = if dw == sw {
			(frame_y(), sw, sh, y_str)
		} else {
			(scaled_y.as_slice(), dw, dh, dw as usize)
		};
		let Ok(y_stride) = y_stride.try_into() else {
			free_buf(data, n);
			return None;
		};
		// SAFETY: `data` is a non-null alloc_buf(n) with n = dw*dh*4, alive until
		// make_buf takes ownership; a dw*4-stride, dh-row RGBA write fills it
		// exactly. `y_plane` borrows either the frame or `scaled_y`, both alive
		// across the conversion below.
		let out = unsafe { std::slice::from_raw_parts_mut(data, n) };
		let gray = yuv::YuvGrayImage {
			y_plane,
			y_stride,
			width: y_width,
			height: y_height,
		};
		if yuv::yuv400_to_rgba(&gray, out, dw * 4, range, yuv_matrix(&matrix)).is_err() {
			free_buf(data, n);
			return None;
		}
		return Some(make_buf(data, n, dw, dh));
	}
	// 10/12-bit monochrome (I400): rav1d supplies only a u16 Y plane, and yuv
	// has no u16 gray converter. Read Y directly, applying the same round-half-
	// up range conversion libavif uses (verified byte-exact vs avifdec for
	// 10/12-bit full and limited range). Nearest-neighbour sampling matches
	// alpha_plane.
	if pix_layout == DAV1D_PIXEL_LAYOUT_I400 && bpc(pic) > 8 {
		let (y_str, _) = strides(pic);
		let ys = y_str / 2; // rav1d stride is bytes; u16 plane
		let shift = bpc(pic).saturating_sub(8);
		// SAFETY: `y` is non-null, backed by y_str*sh bytes of frame memory
		// valid until unref(pic); u16 alignment is guaranteed by rav1d's
		// plane allocation. `data` is alloc_buf(n), n=dw*dh*4, filled exactly.
		let y16 = unsafe { std::slice::from_raw_parts(y.as_ptr().cast::<u16>(), ys * sh as usize) };
		let out = unsafe { std::slice::from_raw_parts_mut(data, n) };
		let (lo, span) = (16u32 << shift, 219u32 << shift);
		// Limited-range conversion has a per-pixel integer divide, so a small
		// LUT (1 KB / 4 KB, L1-resident) pays for itself (measured ~2x). Full
		// range is only an add+shift — no divide to eliminate — and a LUT was
		// measured ~0.54x there, so keep the plain arithmetic for full range.
		// Both use the exact original formula, so results are byte-identical.
		// The LUT index is clamped so hostile out-of-range samples cannot panic.
		// Monomorphized per branch (no virtual call in the pixel loop): limited
		// uses a small LUT, full range uses plain add+shift. Both formulas are
		// byte-identical to libavif. sx is precomputed only when downscaling.
		if limited {
			let lut_len = 1usize << (8 + shift);
			let mut lut = vec![0u8; lut_len];
			for (i, slot) in lut.iter_mut().enumerate() {
				let val = i as u32;
				// libavif scales by 256 and rounds half-up (byte-exact vs avifdec).
				let v = val.saturating_sub(lo) * 256 + span / 2;
				*slot = (v / span).min(255) as u8;
			}
			let to_gray = |val: u16| lut[(val as usize).min(lut_len - 1)];
			fill_mono_gray(y16, ys, out, sw, sh, dw, dh, to_gray);
		} else {
			let half = 1u32 << shift.saturating_sub(1);
			let to_gray = |val: u16| (((val as u32) + half) >> shift).min(255) as u8;
			fill_mono_gray(y16, ys, out, sw, sh, dw, dh, to_gray);
		}
		return Some(make_buf(data, n, dw, dh));
	}
	// Non-monochrome: chroma planes are required.
	let (Some(u), Some(v)) = (plane_ptr(pic, 1), plane_ptr(pic, 2)) else {
		free_buf(data, n);
		return None;
	};
	// 10/12-bit full-size: yuv's i010/i012 read u16 planes directly and write
	// 8-bit RGBA, ~9x faster than the scalar is16 loop. rav1d strides are in
	// BYTES; yuv expects components, so divide by 2 for u16 planes.
	if dw == sw && dh == sh && bpc(pic) > 8 && pix_layout == DAV1D_PIXEL_LAYOUT_I420 {
		let bd = bpc(pic);
		let (y_str_b, uv_str_b) = strides(pic);
		let (ys, us) = (y_str_b / 2, uv_str_b / 2);
		let ch = sh.div_ceil(2);
		let range = if limited {
			yuv::YuvRange::Limited
		} else {
			yuv::YuvRange::Full
		};
		#[expect(
			clippy::cast_possible_truncation,
			reason = "rav1d plane strides fit in u32"
		)]
		let (ys32, us32) = (ys as u32, us as u32);
		// SAFETY: data is alloc_buf(n), n=dw*dh*4; u/v/u16 planes are non-null,
		// backed by stride*height u16 values valid until unref(pic); lengths =
		// stride(components) * plane height (Y: sh rows, UV: ch rows).
		let out = unsafe { std::slice::from_raw_parts_mut(data, n) };
		let img = yuv::YuvPlanarImage {
			y_plane: unsafe {
				std::slice::from_raw_parts(y.as_ptr().cast::<u16>(), ys * sh as usize)
			},
			y_stride: ys32,
			u_plane: unsafe {
				std::slice::from_raw_parts(u.as_ptr().cast::<u16>(), us * ch as usize)
			},
			u_stride: us32,
			v_plane: unsafe {
				std::slice::from_raw_parts(v.as_ptr().cast::<u16>(), us * ch as usize)
			},
			v_stride: us32,
			width: sw,
			height: sh,
		};
		let m = yuv_matrix(&matrix);
		let conv = if bd == 10 {
			yuv::i010_to_rgba(&img, out, dw * 4, range, m)
		} else {
			yuv::i012_to_rgba(&img, out, dw * 4, range, m)
		};
		if conv.is_ok() {
			return Some(make_buf(data, n, dw, dh));
		}
		free_buf(data, n);
		return None;
	}
	if dw == sw && dh == sh && bpc(pic) <= 8 {
		let range = if limited {
			yuv::YuvRange::Limited
		} else {
			yuv::YuvRange::Full
		};
		let (y_str, uv_str) = strides(pic);
		// A chroma plane row is uv_stride bytes; it owns only chroma_height rows.
		let ch = match pix_layout {
			DAV1D_PIXEL_LAYOUT_I420 => sh.div_ceil(2),
			_ => sh, // 422 / 444 / GBRP: chroma height equals luma height
		};
		#[expect(
			clippy::cast_possible_truncation,
			reason = "rav1d plane strides fit in u32"
		)]
		let (yw, yh, s0, s1) = (sw, sh, y_str as u32, uv_str as u32);
		// SAFETY: `data` is a non-null `alloc_buf(n)` with n = dw*dh*4 bytes,
		// alive until make_buf takes ownership here; dw==sw && dh==sh so yuv
		// writes exactly n bytes. Plane pointers from `plane_ptr` are non-null
		// and backed by stride*height bytes of frame memory valid until
		// unref(pic) after the call; UV planes own only `ch` rows.
		let out = unsafe { std::slice::from_raw_parts_mut(data, n) };
		// SAFETY: same backing allocations as above; lengths = stride * plane
		// height (Y: sh rows; UV: ch rows), all within the frame buffers.
		let img = yuv::YuvPlanarImage {
			y_plane: unsafe { std::slice::from_raw_parts(y.as_ptr(), y_str * sh as usize) },
			y_stride: s0,
			u_plane: unsafe { std::slice::from_raw_parts(u.as_ptr(), uv_str * ch as usize) },
			u_stride: s1,
			v_plane: unsafe { std::slice::from_raw_parts(v.as_ptr(), uv_str * ch as usize) },
			v_stride: s1,
			width: yw,
			height: yh,
		};
		let m = yuv_matrix(&matrix);
		let conv = if is_gbrp {
			yuv::gbr_to_rgba(&img, out, dw * 4, range)
		} else {
			match pix_layout {
				DAV1D_PIXEL_LAYOUT_I420 => yuv::yuv420_to_rgba(&img, out, dw * 4, range, m),
				DAV1D_PIXEL_LAYOUT_I422 => yuv::yuv422_to_rgba(&img, out, dw * 4, range, m),
				_ => yuv::yuv444_to_rgba(&img, out, dw * 4, range, m),
			}
		};
		if conv.is_ok() {
			return Some(make_buf(data, n, dw, dh));
		}
		free_buf(data, n);
		return None;
	}
	let ok = unsafe {
		let (y, u, v) = (y.as_ptr(), u.as_ptr(), v.as_ptr());
		if is_gbrp {
			interleave(
				data,
				y,
				u,
				v,
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
				y,
				u,
				v,
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
				matrix,
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
		// sx depends only on dx — precompute once (see convert() for rationale).
		let sx_index: Vec<usize> = if dw == sw {
			Vec::new()
		} else {
			(0..dwu)
				.map(|dx| ((dx as f64 + 0.5) * xr) as usize)
				.collect()
		};

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
				for (dx, &sx) in sx_index.iter().enumerate() {
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
	matrix: YuvMatrix,
) {
	unsafe {
		let shift = bd.saturating_sub(8);
		let is16 = bd > 8;
		let dwu = dw as usize;
		let xr = sw as f64 / dw as f64;
		let yr = sh as f64 / dh as f64;
		let ye = y_str / if is16 { 2 } else { 1 };
		let ue = uv_str / if is16 { 2 } else { 1 };
		// sx and ux depend only on dx (image-level invariants), not on dy.
		// Build one table for the whole image instead of recomputing per pixel
		// (measured 1.4-1.7x on the thumbnail path). Table entries use the
		// IDENTICAL expression as before, so results are byte-for-byte equal.
		let x_index: Vec<(usize, usize)> = if dw == sw {
			Vec::new() // full-size branch computes ux inline
		} else {
			(0..dwu)
				.map(|dx| {
					let sx = ((dx as f64 + 0.5) * xr) as usize;
					(sx, if hc { sx / xs } else { sx })
				})
				.collect()
		};

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
					*out.add(di) = ((yb + matrix.cr * cr + 128) >> 8).clamp(0, 255) as u8;
					*out.add(di + 1) =
						((yb - matrix.cb_g * cb - matrix.cr_g * cr + 128) >> 8).clamp(0, 255) as u8;
					*out.add(di + 2) = ((yb + matrix.cb * cb + 128) >> 8).clamp(0, 255) as u8;
					*out.add(di + 3) = 255;
				}
			} else {
				for (dx, &(sx, ux)) in x_index.iter().enumerate() {
					let yv = val(y, sy * ye + sx, is16, shift) as i32;
					let yb = if limited {
						(yv.saturating_sub(16)) * 298
					} else {
						yv * 256
					};
					let cb = val(u, uvy * ue + ux, is16, shift) as i32 - 128;
					let cr = val(v, uvy * ue + ux, is16, shift) as i32 - 128;
					let di = dr + dx * 4;
					*out.add(di) = ((yb + matrix.cr * cr + 128) >> 8).clamp(0, 255) as u8;
					*out.add(di + 1) =
						((yb - matrix.cb_g * cb - matrix.cr_g * cr + 128) >> 8).clamp(0, 255) as u8;
					*out.add(di + 2) = ((yb + matrix.cb * cb + 128) >> 8).clamp(0, 255) as u8;
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

/// YUV→R'G'B' coefficients, scaled by 256 so the pixel loop stays in integers.
/// The fields are the multipliers of (Cr, Cb, Cr, Cb) for (R, G, G, B).
#[derive(Clone, Copy)]
struct YuvMatrix {
	cr: i32,
	cb_g: i32,
	cr_g: i32,
	cb: i32,
}

const BT601: YuvMatrix = YuvMatrix {
	cr: 359,
	cb_g: 88,
	cr_g: 183,
	cb: 454,
};
const BT709: YuvMatrix = YuvMatrix {
	cr: 403,
	cb_g: 48,
	cr_g: 120,
	cb: 475,
};
const BT2020: YuvMatrix = YuvMatrix {
	cr: 377,
	cb_g: 42,
	cr_g: 146,
	cb: 482,
};

/// Map our integer matrix to yuv's enum. `YuvMatrix` is selected by `matrix_for`
/// from the same AV1 sequence-header code, so the identity is exact.
fn yuv_matrix(m: &YuvMatrix) -> yuv::YuvStandardMatrix {
	if m.cr == BT709.cr {
		yuv::YuvStandardMatrix::Bt709
	} else if m.cr == BT2020.cr {
		yuv::YuvStandardMatrix::Bt2020
	} else {
		yuv::YuvStandardMatrix::Bt601
	}
}

/// Select the matrix from the AV1 sequence header. ISO/IEC 23091-2 leaves
/// `UNKNOWN` unspecified; libavif's convention is BT.709 for HD and BT.601
/// for SD, which matches what encoders actually signal in that case.
fn matrix_for(mtrx: Dav1dMatrixCoefficients, width: u32) -> YuvMatrix {
	match mtrx {
		DAV1D_MC_BT709 => BT709,
		DAV1D_MC_BT2020_NCL | DAV1D_MC_BT2020_CL => BT2020,
		DAV1D_MC_UNKNOWN if width >= 1280 => BT709,
		DAV1D_MC_UNKNOWN | DAV1D_MC_BT601 | DAV1D_MC_BT470BG | DAV1D_MC_FCC | DAV1D_MC_SMPTE240 => {
			BT601
		}
		// Other matrices (ICtCp, YCgCo, chroma-derived) need a different
		// transfer than this simple YUV pipeline; BT.601 is the safe fallback.
		_ => BT601,
	}
}

fn color_meta(pic: &Dav1dPicture) -> (bool, bool, YuvMatrix) {
	unsafe {
		if let Some(h) = pic.seq_hdr {
			let sh = h.as_ref();
			let is_gbrp = sh.mtrx == DAV1D_MC_IDENTITY;
			let has_color = sh.color_description_present != 0;
			let limited = has_color && sh.color_range == 0;
			(is_gbrp, limited, matrix_for(sh.mtrx, pic.p.w as u32))
		} else {
			(false, false, BT601)
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
#[cfg(test)]
mod tests {
	use super::*;
	use crate::avif::parse::Transform;

	#[test]
	fn matrix_coefficients_follow_the_signal() {
		assert_eq!(matrix_for(DAV1D_MC_BT709, 64).cr, 403);
		assert_eq!(matrix_for(DAV1D_MC_BT709, 64).cb_g, 48);
		assert_eq!(matrix_for(DAV1D_MC_BT709, 64).cr_g, 120);
		assert_eq!(matrix_for(DAV1D_MC_BT709, 64).cb, 475);
		assert_eq!(matrix_for(DAV1D_MC_BT2020_NCL, 64).cr, 377);
		assert_eq!(matrix_for(DAV1D_MC_BT2020_NCL, 64).cb, 482);
		assert_eq!(matrix_for(DAV1D_MC_BT601, 64).cr, 359);
		assert_eq!(matrix_for(DAV1D_MC_UNKNOWN, 1920).cr, 403);
		assert_eq!(matrix_for(DAV1D_MC_UNKNOWN, 64).cr, 359);
	}

	#[test]
	fn irot_direction_matches_libavif() {
		// Measured against avifdec on libavif's abc_color_irot_alpha_*.avif:
		// the old mapping produced a picture exactly 180 degrees away from the
		// reference. irot=1 is a quarter turn the opposite way from our old
		// mapping, irot=3 the mirror of it.
		let t = |rotate, mirror| crate::avif::parse::Transform {
			rotate,
			mirror,
			crop: None,
		};
		// Combined rotate + mirror: on a 2x3 aperture rotated 90 degrees the
		// display is 3x2, so fx reaches 2 while cw is only 2. Mirroring in the
		// pre-rotation space (`cw-1-fx`) would underflow; it must use ch.
		assert_eq!(display_to_source(&t(1, 1), 2, 0, 2, 3), (1, 0));
		assert_eq!(display_to_source(&t(1, 1), 0, 0, 2, 3), (1, 2));
		assert_eq!(display_to_source(&t(0, 0), 0, 0, 2, 3), (0, 0));
		assert_eq!(display_to_source(&t(1, 0), 0, 0, 2, 3), (1, 0));
		assert_eq!(display_to_source(&t(1, 0), 2, 0, 2, 3), (1, 2));
		assert_eq!(display_to_source(&t(3, 0), 0, 0, 2, 3), (0, 2));
		assert_eq!(display_to_source(&t(2, 0), 0, 0, 2, 3), (1, 2));
	}

	fn fixture(name: &str) -> Vec<u8> {
		std::fs::read(format!("tests/testdata/avif/{name}")).expect("read AVIF fixture")
	}

	fn first_pixel(name: &str) -> [u8; 4] {
		let data = fixture(name);
		let buf = crate::avif::decode(&data, 0).expect("decode AVIF fixture");
		let px = unsafe { std::slice::from_raw_parts(buf.data, buf.data_len) };
		let p = [px[0], px[1], px[2], px[3]];
		unsafe { crate::decode::free_decode_buf(Box::into_raw(buf)) };
		p
	}

	#[test]
	fn alpha_avif_is_composited() {
		let data = fixture("alpha.avif");
		let buf = crate::avif::decode(&data, 0).expect("alpha AVIF must decode");
		assert_eq!((buf.width, buf.height), (64, 64));
		let px = unsafe { std::slice::from_raw_parts(buf.data, buf.data_len) };
		let alpha: Vec<u8> = px
			.as_chunks::<4>()
			.0
			.iter()
			.take(4096)
			.map(|p| p[3])
			.collect();
		assert!(
			alpha.iter().all(|&a| (120..=136).contains(&a)),
			"alpha {alpha:?}"
		);
		unsafe { crate::decode::free_decode_buf(Box::into_raw(buf)) };
	}

	#[test]
	fn bt709_and_bt2020_matrices_are_applied() {
		let rgb = first_pixel("rgb.avif");
		let bt709 = first_pixel("bt709.avif");
		let bt2020 = first_pixel("bt2020.avif");
		// With the old BT.601-only converter these were 232 and 244; ffmpeg
		// reports 254 and 253 for the same files.
		assert!(bt709[0] >= 248, "BT.709 red {} (rgb {rgb:?})", bt709[0]);
		assert!(bt2020[0] >= 248, "BT.2020 red {} (rgb {rgb:?})", bt2020[0]);
	}

	fn pixels(name: &str) -> (u32, u32, Vec<u8>) {
		let data = fixture(name);
		let buf = crate::avif::decode(&data, 0).expect("decode AVIF fixture");
		let out = unsafe { std::slice::from_raw_parts(buf.data, buf.data_len) }.to_vec();
		let (w, h) = (buf.width, buf.height);
		unsafe { crate::decode::free_decode_buf(Box::into_raw(buf)) };
		(w, h, out)
	}

	fn near(actual: u8, expected: u8) -> bool {
		actual.abs_diff(expected) <= 3
	}

	#[test]
	fn irot_is_baked_into_the_pixels() {
		let (w, h, px) = pixels("orient_rot.avif");
		assert_eq!((w, h), (2, 4));
		// Independent reference: avifdec -r on this fixture produces exactly
		// these pixels. The previous array was this one reversed (a 180-degree
		// error) because it had been copied from our own inverted transform.
		let expect = [
			(255, 255, 0),
			(0, 0, 0),
			(0, 0, 255),
			(255, 255, 255),
			(0, 255, 0),
			(255, 0, 255),
			(255, 0, 0),
			(0, 255, 255),
		];
		for (i, (r, g, b)) in expect.iter().enumerate() {
			let p = &px[i * 4..i * 4 + 4];
			assert!(
				near(p[0], *r) && near(p[1], *g) && near(p[2], *b),
				"pixel {i}: {p:?}"
			);
		}
	}

	#[test]
	fn imir_is_baked_into_the_pixels() {
		let (w, h, px) = pixels("orient_mir.avif");
		assert_eq!((w, h), (4, 2));
		let expect = [
			(255, 255, 0),
			(0, 0, 255),
			(0, 255, 0),
			(255, 0, 0),
			(0, 0, 0),
			(255, 255, 255),
			(255, 0, 255),
			(0, 255, 255),
		];
		for (i, (r, g, b)) in expect.iter().enumerate() {
			let p = &px[i * 4..i * 4 + 4];
			assert!(
				near(p[0], *r) && near(p[1], *g) && near(p[2], *b),
				"pixel {i}: {p:?}"
			);
		}
	}

	#[test]
	fn clap_fractional_offset_uses_exact_arithmetic() {
		// libavif avifCropRectFromCleanApertureBox uses exact fractions:
		// W=5, clapW=2, horizOff=1/2 -> cropX = 5/2 + 1/2 - 1 = 2 (integer).
		// Integer truncation gives (5-2)/2 + 0 = 1, one pixel too far left.
		// Verified against avifenc --clap 2,1,2,1,1,2,0,1 on a 5x2 image.
		let mut data = vec![0u8; 5 * 2 * 4];
		for y in 0..2 {
			for x in 0..5 {
				let i = (y * 5 + x) * 4;
				data[i] = x as u8;
				data[i + 1] = y as u8;
			}
		}
		let src = DecodeBuf::from_vec(data, 5, 2);
		let t = Transform {
			crop: Some([2, 1, 2, 1, 1, 2, 0, 1]),
			..Transform::default()
		};
		let out = apply_transform(src, &t).expect("crop");
		assert_eq!((out.width, out.height), (2, 2));
		let px = unsafe { std::slice::from_raw_parts(out.data, out.data_len) };
		// cropX=2 -> first output column is source column 2, not 1.
		assert_eq!((px[0], px[4]), (2, 3), "fractional clap offset: {px:?}");
		unsafe { crate::decode::free_decode_buf(Box::into_raw(out)) };
	}

	#[test]
	fn clap_illegal_values_are_rejected_not_silently_defaulted() {
		// libavif v1.4.2 avifCropRectFromCleanApertureBox (strict mode):
		//   - clap width/height must be an integer (num % den == 0), den > 0;
		//   - the calculated crop origin must be an integer (else BMFF parse
		//     failure), and must be inside the image, never clamped.
		// The old code truncated fractional dimensions and `unwrap_or(0)`-ed a
		// non-integer origin into a silent crop at column 0 — neither matches
		// libavif strict nor its --no-strict (which ignores clap entirely).
		let src = || {
			let mut data = vec![0u8; 5 * 2 * 4];
			for (i, b) in data.iter_mut().enumerate() {
				*b = (i / 4) as u8;
			}
			DecodeBuf::from_vec(data, 5, 2)
		};
		// clap width 3/2 is fractional -> libavif rejects.
		let out = apply_transform(
			src(),
			&Transform {
				crop: Some([3, 2, 1, 1, 0, 1, 0, 1]),
				..Transform::default()
			},
		);
		assert!(out.is_none(), "fractional clap width must be rejected");
		// W=5, clapW=2, horizOff=1/3 -> cropX = 5/2 + 1/3 - 1 = 11/6, not integer.
		let out = apply_transform(
			src(),
			&Transform {
				crop: Some([2, 1, 1, 1, 1, 3, 0, 1]),
				..Transform::default()
			},
		);
		assert!(out.is_none(), "non-integer crop origin must be rejected");
		// zero denominator must be rejected outright.
		let out = apply_transform(
			src(),
			&Transform {
				crop: Some([2, 1, 1, 1, 1, 0, 0, 1]),
				..Transform::default()
			},
		);
		assert!(out.is_none(), "zero offset denominator must be rejected");
		// clapW larger than the image must be rejected, not clamped.
		let out = apply_transform(
			src(),
			&Transform {
				crop: Some([9, 1, 1, 1, 0, 1, 0, 1]),
				..Transform::default()
			},
		);
		assert!(out.is_none(), "clap wider than image must be rejected");
	}

	#[test]
	fn clap_crops_to_the_clean_aperture() {
		let (w, h, px) = pixels("orient_clap.avif");
		assert_eq!((w, h), (2, 1));
		for (i, (r, g, b)) in [(0, 255, 0), (0, 0, 255)].iter().enumerate() {
			let p = &px[i * 4..i * 4 + 4];
			assert!(
				near(p[0], *r) && near(p[1], *g) && near(p[2], *b),
				"pixel {i}: {p:?}"
			);
		}
	}

	/// Synthetic clap with a NON-ZERO horizontal offset, pinned against libavif's
	/// `avifCropRectFromCleanApertureBox`: cropX = (W - clapW)/2 + horizOff.
	/// The fixture above has horizOff=0, so both the correct and inverted signs
	/// produce the same pixels; this one distinguishes them.
	#[test]
	fn clap_positive_horiz_offset_shifts_right() {
		// 4x2 source, each pixel's R channel encodes its column index (0..3),
		// G encodes its row (0..1).
		let mut src_data = vec![0u8; 4 * 2 * 4];
		for y in 0..2 {
			for x in 0..4 {
				let i = (y * 4 + x) * 4;
				src_data[i] = x as u8;
				src_data[i + 1] = y as u8;
			}
		}
		let src = DecodeBuf::from_vec(src_data, 4, 2);
		// clap: w=2/1, h=2/1, horizOff=+1/1, vertOff=0/1. h=2 (not 1) keeps
		// cropY an integer for an even-height image, as libavif strict requires;
		// the horizontal sign is what this test pins.
		let crop = [2, 1, 2, 1, 1, 1, 0, 1];
		let t = Transform {
			crop: Some(crop),
			..Transform::default()
		};
		let out = apply_transform(src, &t).expect("crop");
		assert_eq!((out.width, out.height), (2, 2));
		let px = unsafe { std::slice::from_raw_parts(out.data, out.data_len) };
		// libavif: cropX = (4-2)/2 + 1 = 2 -> columns 2,3. With the inverted
		// sign it would be (4-2)/2 - 1 = 0 -> columns 0,1.
		assert_eq!((px[0], px[4]), (2, 3), "clap horizOff sign: {px:?}");
		unsafe { crate::decode::free_decode_buf(Box::into_raw(out)) };
	}
}
