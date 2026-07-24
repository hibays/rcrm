// jxl/decode.rs
// JXL frame decode via jxl-oxide.
// Reads directly from planar colour channels — no interleaved float allocation.

#![allow(clippy::too_many_arguments)]

use crate::decode::DecodeBuf;
use jxl_oxide::JxlImage;
use jxl_oxide::image::BitDepth;
use jxl_render::ImageBuffer;

pub fn decode_frame(data: &[u8], target_width: u32) -> Option<Box<DecodeBuf>> {
	let reader = std::io::Cursor::new(data);
	let image = JxlImage::builder().read(reader).ok()?;
	let (full_w, full_h) = (image.width(), image.height());
	let bit_depth = image.image_header().metadata.bit_depth;
	let render = image.render_frame(0).ok()?;
	let orientation = render.orientation();
	let channels = render.color_channels();
	let is_gray = channels.len() < 3;

	// Source grid dimensions (before orientation).
	let (grid_w, grid_h) = match orientation {
		1..=4 => (full_w, full_h),
		_ => (full_h, full_w),
	};

	let (dw, dh, rgba) = if target_width > 0 && target_width < full_w {
		let dh = (full_h as f64 * target_width as f64 / full_w as f64) as u32;
		if dh > 0 {
			let rgba = planar_sample_downscale(
				channels,
				grid_w,
				grid_h,
				orientation,
				bit_depth,
				is_gray,
				target_width,
				dh,
			);
			(target_width, dh, rgba)
		} else {
			let rgba = planar_sample(channels, grid_w, grid_h, orientation, bit_depth, is_gray);
			(full_w, full_h, rgba)
		}
	} else {
		let rgba = planar_sample(channels, grid_w, grid_h, orientation, bit_depth, is_gray);
		(full_w, full_h, rgba)
	};

	let n = rgba.len();
	let (p, _, _) = rgba.into_raw_parts();
	Some(Box::new(DecodeBuf {
		width: dw,
		height: dh,
		channels: 4,
		data_len: n,
		data: p,
	}))
}

/// Read a float sample from a planar ImageBuffer at grid coordinates (x, y).
#[inline]
fn sample_planar(ch: &ImageBuffer, x: usize, y: usize, bd: BitDepth) -> f32 {
	match ch {
		ImageBuffer::F32(g) => g.try_get_ref(x, y).copied().unwrap_or(0.0),
		ImageBuffer::I32(g) => bd.parse_integer_sample(g.try_get_ref(x, y).copied().unwrap_or(0)),
		ImageBuffer::I16(g) => {
			bd.parse_integer_sample(g.try_get_ref(x, y).copied().unwrap_or(0) as i32)
		}
	}
}

/// Map oriented output coords (dx, dy) → source grid coords (gx, gy).
#[inline]
fn orient_src(dx: u32, dy: u32, gw: u32, gh: u32, o: u32) -> (u32, u32) {
	match o {
		2 => (gw - 1 - dx, dy),
		3 => (gw - 1 - dx, gh - 1 - dy),
		4 => (dx, gh - 1 - dy),
		5 => (dy, dx),
		6 => (gw - 1 - dy, dx),
		7 => (gh - 1 - dy, gw - 1 - dx),
		8 => (dy, gh - 1 - dx),
		_ => (dx, dy),
	}
}

/// Bilinear sample from planar channels, write RGBA to output.
fn sample_bilin(
	channels: &[ImageBuffer],
	fx: f64,
	fy: f64,
	gw: u32,
	gh: u32,
	bd: BitDepth,
	gray: bool,
	out: &mut Vec<u8>,
) {
	let x0 = fx as usize;
	let y0 = fy as usize;
	let x1 = (x0 + 1).min(gw as usize - 1);
	let y1 = (y0 + 1).min(gh as usize - 1);
	let frac_x = (fx - fx.floor()) as f32;
	let frac_y = (fy - fy.floor()) as f32;

	if gray {
		let s = |x, y| sample_planar(&channels[0], x, y, bd);
		let t = s(x0, y0) + (s(x1, y0) - s(x0, y0)) * frac_x;
		let b = s(x0, y1) + (s(x1, y1) - s(x0, y1)) * frac_x;
		let v = ((t + (b - t) * frac_y).clamp(0.0, 1.0) * 255.0 + 0.5) as u8;
		out.extend_from_slice(&[v, v, v, 255]);
	} else {
		let s = |c, x, y| sample_planar(&channels[c], x, y, bd);
		for c in 0..3 {
			let t = s(c, x0, y0) + (s(c, x1, y0) - s(c, x0, y0)) * frac_x;
			let b = s(c, x0, y1) + (s(c, x1, y1) - s(c, x0, y1)) * frac_x;
			let v = ((t + (b - t) * frac_y).clamp(0.0, 1.0) * 255.0 + 0.5) as u8;
			out.push(v);
		}
		out.push(255);
	}
}

/// Planar → RGBA at full resolution.
fn planar_sample(
	channels: &[ImageBuffer],
	gw: u32,
	gh: u32,
	orientation: u32,
	bd: BitDepth,
	gray: bool,
) -> Vec<u8> {
	let (ow, oh) = match orientation {
		1..=4 => (gw, gh),
		_ => (gh, gw),
	};
	let n = (ow * oh) as usize;
	let mut out = Vec::with_capacity(n * 4);
	if gray {
		for dy in 0..oh {
			for dx in 0..ow {
				let (sx, sy) = orient_src(dx, dy, gw, gh, orientation);
				let v = sample_planar(&channels[0], sx as usize, sy as usize, bd);
				let v = (v.clamp(0.0, 1.0) * 255.0 + 0.5) as u8;
				out.extend_from_slice(&[v, v, v, 255]);
			}
		}
	} else {
		for dy in 0..oh {
			for dx in 0..ow {
				let (sx, sy) = orient_src(dx, dy, gw, gh, orientation);
				let sx = sx as usize;
				let sy = sy as usize;
				for c in 0..3 {
					let v = sample_planar(&channels[c], sx, sy, bd);
					out.push((v.clamp(0.0, 1.0) * 255.0 + 0.5) as u8);
				}
				out.push(255);
			}
		}
	}
	out
}

/// Map oriented float coord → source grid float coord.
#[inline]
fn orient_src_f(fx: f64, fy: f64, gw: f64, gh: f64, o: u32) -> (f64, f64) {
	let w = gw - 1.0;
	let h = gh - 1.0;
	match o {
		2 => (w - fx, fy),
		3 => (w - fx, h - fy),
		4 => (fx, h - fy),
		5 => (fy, fx),
		6 => (w - fy, fx),
		7 => (h - fy, w - fx),
		8 => (fy, h - fx),
		_ => (fx, fy),
	}
}

/// Planar → RGBA at target width (bilinear downscale during conversion).
fn planar_sample_downscale(
	channels: &[ImageBuffer],
	gw: u32,
	gh: u32,
	orientation: u32,
	bd: BitDepth,
	gray: bool,
	dw: u32,
	dh: u32,
) -> Vec<u8> {
	let n = (dw * dh) as usize;
	let mut out = Vec::with_capacity(n * 4);
	// Oriented full-res dimensions.
	let fw = match orientation {
		1..=4 => gw,
		_ => gh,
	} as f64;
	let fh = match orientation {
		1..=4 => gh,
		_ => gw,
	} as f64;
	let gwf = gw as f64;
	let ghf = gh as f64;
	for dy in 0..dh {
		for dx in 0..dw {
			let ofx = ((dx as f64 + 0.5) * fw / dw as f64 - 0.5).clamp(0.0, fw - 1.0);
			let ofy = ((dy as f64 + 0.5) * fh / dh as f64 - 0.5).clamp(0.0, fh - 1.0);
			let (gfx, gfy) = orient_src_f(ofx, ofy, gwf, ghf, orientation);
			sample_bilin(
				channels,
				gfx.clamp(0.0, gwf - 1.0),
				gfy.clamp(0.0, ghf - 1.0),
				gw,
				gh,
				bd,
				gray,
				&mut out,
			);
		}
	}
	out
}

#[cfg(test)]
mod tests {
	use super::*;

	fn test_read(p: &str) -> Vec<u8> {
		std::fs::read(format!("tests/testdata/{p}")).expect("read test file")
	}

	#[test]
	fn decode_jxl_small() {
		let data = test_read(
			"jxl/Chungking.Express.1994.CHINESE.2160p.UHD.BluRay.x265.10bit.HDR.DDP5.1-RARBG.mkv_snapshot_00.41.05_[2023.11.19_14.06.32].jxl",
		);
		let buf = decode_frame(&data, 0).expect("decode jxl");
		assert!(buf.width > 0);
		unsafe { crate::decode::free_decode_buf(Box::into_raw(buf)) };
	}

	#[test]
	fn decode_jxl_downscale() {
		let data = test_read("jxl/4x-IMG_20250716_002259_095.jxl");
		let buf = decode_frame(&data, 400).expect("jxl downscale");
		assert_eq!(buf.width, 400);
		unsafe { crate::decode::free_decode_buf(Box::into_raw(buf)) };
	}
}
