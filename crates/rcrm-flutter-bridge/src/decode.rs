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
	crate::jxl::decode(data, target_width)
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
		cmp_ffmpeg_avif("avif/adonis.avif", "Adonis GBRP");
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
		cmp_ffmpeg_avif("avif/jqis5.avif", "GBRP");
	}

	#[test]
	fn compare_yuv_vs_ffmpeg() {
		cmp_ffmpeg_avif("avif/test_yuv.avif", "YUV");
	}

	#[test]
	fn compare_jxl_vs_ffmpeg() {
		cmp_ffmpeg_jxl("jxl/4x-IMG_20250716_002259_095.jxl", "JXL");
	}

	#[test]
	fn thumb_webp_from_image_is_a_scaled_thumbnail_in_one_call() {
		let data = test_read("avif/test1.avif");
		let buf = unsafe {
			crate::rcrm_generate_thumb_webp_from_image(data.as_ptr(), data.len(), 400, 82, 1)
		};
		assert!(!buf.is_null(), "decode + encode must succeed");
		let webp = unsafe { &*buf };
		let bytes = unsafe { std::slice::from_raw_parts(webp.data, webp.data_len) };
		// A real WebP container, not a partial buffer.
		assert_eq!(&bytes[0..4], b"RIFF");
		assert_eq!(&bytes[8..12], b"WEBP");
		// And it is the SCALED one: 400 wide, aspect preserved — the pixels
		// never passed through Dart to get there.
		let (rgba, w, h) = zenwebp::oneshot::decode_rgba(bytes).expect("decode back");
		// test1.avif is 3072x4096, so 400 wide scales to 533 tall — the scale
		// happened inside Rust, on pixels Dart never saw.
		assert_eq!(w, 400);
		assert_eq!(h, 533);
		assert_eq!(rgba.len(), (w * h * 4) as usize);
		// The input was borrowed: the caller's buffer is untouched and still
		// its own to free (this is what lets a failure fall back safely).
		assert_eq!(&data[4..8], b"ftyp", "input buffer must still be intact");
		unsafe { crate::webp::free_webp_buf(buf) };
	}

	#[test]
	fn thumb_webp_from_image_rejects_unparsable_bytes() {
		let junk = vec![0u8; 4096];
		let buf = unsafe {
			crate::rcrm_generate_thumb_webp_from_image(junk.as_ptr(), junk.len(), 400, 82, 0)
		};
		assert!(buf.is_null(), "garbage must not produce a buffer");
		let empty: Vec<u8> = Vec::new();
		let buf = unsafe {
			crate::rcrm_generate_thumb_webp_from_image(empty.as_ptr(), 0, 400, 82, 0)
		};
		assert!(buf.is_null(), "an empty input must be refused");
	}

	fn cmp_ffmpeg_avif(path: &str, label: &str) {
		let data = test_read(path);
		let buf = decode_avif(&data, 0).expect("decode");
		check_vs_ffmpeg(path, label, &buf);
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	fn cmp_ffmpeg_jxl(path: &str, label: &str) {
		let data = test_read(path);
		let buf = decode_jxl(&data, 0).expect("decode jxl");
		check_vs_ffmpeg(path, label, &buf);
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	fn check_vs_ffmpeg(path: &str, label: &str, buf: &DecodeBuf) {
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
	}
}
