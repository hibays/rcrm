// src/decode.rs
// Shared decode types and utilities. AVIF → avif.rs, JXL → jxl-oxide.
// Output is raw RGBA pixels (width × height × 4 bytes) — Dart feeds them
// directly to ui.ImageDescriptor.raw without any BMP encoding overhead.

#[repr(C)]
pub struct DecodeBuf {
	pub width: u32,
	pub height: u32,
	pub channels: u8, // 4 = RGBA
	pub data_len: usize,
	pub data: *mut u8, // raw RGBA pixels (w × h × 4)
}

unsafe impl Send for DecodeBuf {}

pub unsafe fn free_decode_buf(ptr: *mut DecodeBuf) {
	if ptr.is_null() {
		return;
	}
	let buf = unsafe { Box::from_raw(ptr) };
	if !buf.data.is_null() && buf.data_len > 0 {
		let _ = unsafe { Vec::from_raw_parts(buf.data, buf.data_len, buf.data_len) };
	}
}

pub fn decode_avif(data: &[u8], target_width: u32) -> Option<Box<DecodeBuf>> {
	crate::avif::decode(data, target_width)
}

pub fn decode_jxl(data: &[u8], target_width: u32) -> Option<Box<DecodeBuf>> {
	use jxl_oxide::JxlImage;
	let reader = std::io::Cursor::new(data);
	let image = JxlImage::builder().read(reader).ok()?;
	let render = image.render_frame(0).ok()?;
	let fb = render.image_all_channels();
	let w = fb.width() as u32;
	let h = fb.height() as u32;
	let rgba = floats_to_rgba8(fb.buf(), w, h, fb.channels());
	finish_decode(rgba, w, h, target_width)
}

pub fn finish_decode(rgba: Vec<u8>, mut w: u32, mut h: u32, tw: u32) -> Option<Box<DecodeBuf>> {
	let mut rgba = rgba;
	if tw > 0 && tw < w {
		let s = tw as f64 / w as f64;
		let nh = (h as f64 * s) as u32;
		if nh > 0 {
			rgba = bilinear_downscale(&rgba, w, h, tw, nh);
			w = tw;
			h = nh;
		}
	}
	let n = rgba.len();
	let (p, _, _) = rgba.into_raw_parts();
	Some(Box::new(DecodeBuf {
		width: w,
		height: h,
		channels: 4, // RGBA
		data_len: n,
		data: p,
	}))
}

pub fn bilinear_downscale(src: &[u8], sw: u32, sh: u32, dw: u32, dh: u32) -> Vec<u8> {
	let ss = sw as usize * 4;
	let ds = dw as usize * 4;
	let mut dst = vec![0u8; ds * dh as usize];
	let sx = sw as f64 / dw as f64;
	let sy = sh as f64 / dh as f64;
	for dy in 0..dh {
		let fy_ = ((dy as f64 + 0.5) * sy - 0.5).clamp(0.0, (sh - 1) as f64);
		let fy = (fy_ - fy_.floor()) as f32;
		let y0 = fy_ as u32;
		let y1 = (y0 + 1).min(sh - 1);
		let r0 = y0 as usize * ss;
		let r1 = y1 as usize * ss;
		for dx in 0..dw {
			let fx_ = ((dx as f64 + 0.5) * sx - 0.5).clamp(0.0, (sw - 1) as f64);
			let fx = (fx_ - fx_.floor()) as f32;
			let x0 = fx_ as u32;
			let x1 = (x0 + 1).min(sw - 1);
			let x0o = x0 as usize * 4;
			let x1o = x1 as usize * 4;
			let di = dy as usize * ds + dx as usize * 4;
			for c in 0..4 {
				let t = src[r0 + x0o + c] as f32
					+ (src[r0 + x1o + c] as f32 - src[r0 + x0o + c] as f32) * fx;
				let b = src[r1 + x0o + c] as f32
					+ (src[r1 + x1o + c] as f32 - src[r1 + x0o + c] as f32) * fx;
				dst[di + c] = (t + (b - t) * fy) as u8;
			}
		}
	}
	dst
}

fn floats_to_rgba8(f: &[f32], w: u32, h: u32, ch: usize) -> Vec<u8> {
	let n = (w as usize) * (h as usize);
	let mut o = Vec::with_capacity(n * 4);
	let u = |v: f32| (v.clamp(0.0, 1.0) * 255.0 + 0.5) as u8;
	match ch {
		1 => {
			for &g in f {
				let v = u(g);
				o.extend_from_slice(&[v, v, v, 255]);
			}
		}
		2 => {
			for p in f.chunks_exact(2) {
				let v = u(p[0]);
				o.extend_from_slice(&[v, v, v, u(p[1])]);
			}
		}
		3 => {
			for t in f.chunks_exact(3) {
				o.extend_from_slice(&[u(t[0]), u(t[1]), u(t[2]), 255]);
			}
		}
		4 => {
			for q in f.chunks_exact(4) {
				o.extend_from_slice(&[u(q[0]), u(q[1]), u(q[2]), u(q[3])]);
			}
		}
		_ => o.resize(n * 4, 0),
	}
	o
}

#[cfg(test)]
mod tests {
	use super::*;

	fn test_read(p: &str) -> Vec<u8> {
		std::fs::read(format!("tests/testdata/{p}")).expect("read test file")
	}

	#[test]
	fn decode_jqis5_valid() {
		let data = test_read("avif/jqis5.avif");
		let buf = decode_avif(&data, 0).expect("decode");
		assert_eq!(buf.width, 1503);
		assert_eq!(buf.height, 2140);
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	#[test]
	fn decode_test1_valid() {
		let data = test_read("avif/test1.avif");
		let buf = decode_avif(&data, 0).expect("decode");
		assert_eq!(buf.width, 3072);
		assert_eq!(buf.height, 4096);
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	#[test]
	fn decode_test1_downscale() {
		let data = test_read("avif/test1.avif");
		let buf = decode_avif(&data, 400).expect("downscale");
		assert_eq!(buf.width, 400);
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	#[test]
	fn decode_pureblack_valid() {
		let data = test_read("avif/pureblack2_35.avif");
		let buf = decode_avif(&data, 0).expect("decode");
		assert_eq!(buf.width, 2858);
		assert_eq!(buf.height, 4288);
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	#[test]
	fn decode_jqis5_downscale() {
		let data = test_read("avif/jqis5.avif");
		let buf = decode_avif(&data, 400).expect("downscale");
		assert_eq!(buf.width, 400);
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	#[test]
	fn decode_adonis_valid() {
		let data = test_read("avif/adonis.avif");
		let buf = decode_avif(&data, 0).expect("decode");
		assert_eq!(buf.width, 1242);
		assert_eq!(buf.height, 1865);
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	#[test]
	fn decode_adonis_downscale() {
		let data = test_read("avif/adonis.avif");
		let buf = decode_avif(&data, 400).expect("downscale");
		assert_eq!(buf.width, 400);
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	#[test]
	fn compare_adonis_vs_ffmpeg() {
		cmp_ffmpeg("avif/adonis.avif", "Adonis GBRP");
	}
	#[test]
	fn decode_big_gbrp_valid() {
		let data = test_read("avif/big_gbrp.avif");
		let buf = decode_avif(&data, 0).expect("decode");
		assert_eq!(buf.width, 7450);
		assert_eq!(buf.height, 5294);
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	#[test]
	fn decode_big_gbrp_downscale() {
		let data = test_read("avif/big_gbrp.avif");
		let buf = decode_avif(&data, 400).expect("downscale");
		assert_eq!(buf.width, 400);
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	#[test]
	fn compare_gbrp_vs_ffmpeg() {
		cmp_ffmpeg("avif/jqis5.avif", "GBRP");
	}

	#[test]
	fn compare_yuv_vs_ffmpeg() {
		cmp_ffmpeg("avif/test_yuv.avif", "YUV");
	}

	fn cmp_ffmpeg(path: &str, label: &str) {
		let data = test_read(path);
		let buf = decode_avif(&data, 0).expect("decode");
		let rgba = unsafe { std::slice::from_raw_parts(buf.data, buf.data_len) };
		let (w, h) = (buf.width as usize, buf.height as usize);
		assert_eq!(buf.channels, 4, "{label}: not RGBA");

		let ff = std::process::Command::new("ffmpeg")
			.args([
				"-y",
				"-i",
				&format!("tests/testdata/{path}"),
				"-f",
				"rawvideo",
				"-pix_fmt",
				"rgb24",
				"-vframes",
				"1",
				"pipe:1",
			])
			.output()
			.expect("ffmpeg")
			.stdout;
		assert!(ff.len() >= w * h * 3, "{label}: ffmpeg output short");

		let mut sum = [0u64; 3];
		for y in 0..h {
			for x in 0..w {
				let ff_i = (y * w + x) * 3;
				let ri = (y * w + x) * 4;
				// RGBA vs ffmpeg rgb24
				sum[0] += (rgba[ri] as i16 - ff[ff_i] as i16).unsigned_abs() as u64;
				sum[1] += (rgba[ri + 1] as i16 - ff[ff_i + 1] as i16).unsigned_abs() as u64;
				sum[2] += (rgba[ri + 2] as i16 - ff[ff_i + 2] as i16).unsigned_abs() as u64;
			}
		}
		let avg: Vec<_> = sum.iter().map(|s| *s as f64 / (w * h) as f64).collect();
		let ta = avg.iter().sum::<f64>() / 3.0;
		println!(
			"{label} ffmpeg: R={:.2} G={:.2} B={:.2} avg={ta:.2}",
			avg[0], avg[1], avg[2]
		);
		assert!(ta < 2.0, "{label} diff {ta:.2}");
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	#[test]
	fn decode_jxl_small() {
		let data = test_read(
			"jxl/Chungking.Express.1994.CHINESE.2160p.UHD.BluRay.x265.10bit.HDR.DDP5.1-RARBG.mkv_snapshot_00.41.05_[2023.11.19_14.06.32].jxl",
		);
		let buf = decode_jxl(&data, 0).expect("decode jxl");
		assert!(buf.width > 0);
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	#[test]
	fn decode_jxl_downscale() {
		let data = test_read("jxl/4x-IMG_20250716_002259_095.jxl");
		let buf = decode_jxl(&data, 400).expect("jxl downscale");
		assert_eq!(buf.width, 400);
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}
}
