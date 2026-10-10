// src/decode.rs
// Shared decode support for every software image decoder in this crate — the one
// place the three of them (AVIF → avif.rs, JXL → jxl/, HEIC/HEIF → heic/) take
// their common pieces from:
//
//   * `DecodeBuf` — the `#[repr(C)]` hand-off struct plus its ownership/free rules
//   * `MAX_DECODE_MP` / `Limit` — the single pixel ceiling all three enforce, as
//     the one place the number is written and as the value they pass around
//   * `bilinear_tap` / `bilinear_taps_at` / `downscale_rgba_bilinear` — resampling
//
// Decoders own their format work (parsing, limits, colour); anything two of them
// would otherwise write twice belongs here. Output is raw RGBA pixels
// (width × height × 4 bytes) — Dart reads them straight out of `DecodeBuf` and
// hands them to ui.ImageDescriptor.raw without any BMP encoding overhead, so the
// return path copies nothing.

/// The ONE pixel ceiling for every software image decoder in this crate (AVIF via
/// rav1d, JXL, HEIC). Defined here and referenced everywhere else because three
/// copies of the same number is how the AVIF path ended up rejecting every real
/// 12 MP phone photo while HEIC accepted 48 MP ones.
///
/// It is a memory bound, not a quality policy: these decoders allocate a full-frame
/// RGBA buffer, so 64 MP ~= 256 MB is the most this app attempts on the <=4 GB
/// devices it ships to. rav1d also receives it as its own frame limit, so a
/// container that lies about its size cannot smuggle a larger frame through.
pub const MAX_DECODE_MP: u64 = 64_000_000;

/// The invariant that matters: a normal phone still (48 MP at the top end) must
/// always fit. It lives next to the number, so the ceiling cannot be lowered back
/// into "rejects real photos" territory without the build failing.
const _: () = assert!(MAX_DECODE_MP >= 48_000_000);

/// That ceiling as a value, handed to a decoder instead of a bare
/// `max_pixels: u64` threaded through every function.
///
/// The pixels, the saturating u32 rav1d's settings want and the test-only door
/// all live on the type, so a caller cannot pass a number whose unit and origin
/// have to be reconstructed from the call site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limit(u64);

impl Limit {
	/// The ceiling every production path uses — [`MAX_DECODE_MP`] above, which
	/// stays the one place the number is written.
	pub const PRODUCTION: Limit = Limit(MAX_DECODE_MP);

	/// A ceiling of exactly `pixels`, for tests that must exercise the limit
	/// itself: a fixture larger than any real photo, or one deliberately below it
	/// so the file gets refused.
	///
	/// It is a *value* rather than a `#[cfg(test)]` relaxation of the check
	/// inside a decoder, because that mistake shipped once: relaxed under
	/// `cfg(test)`, the AVIF path accepted every file in the suite while the app
	/// refused real 16 MP photos, and no test could tell. A limit that travels in
	/// from the call site stays visible in the test that chose it, and the type
	/// those tests exercise is the one production uses.
	///
	/// Only `#[cfg(test)]` callers exist, hence the conditional allow: the
	/// constructor is deliberately not `cfg(test)`-gated, a plain build simply
	/// has nobody to call it.
	#[cfg_attr(not(test), allow(dead_code))]
	pub const fn synthetic(pixels: u64) -> Limit {
		Limit(pixels)
	}

	/// The ceiling in pixels, for comparing against a container's declared size.
	pub const fn pixels(self) -> u64 {
		self.0
	}

	/// The ceiling as rav1d's `frame_size_limit` field needs it. Saturating, like
	/// the `.min(u32::MAX as u64) as u32` it replaces: the field is a u32, and a
	/// ceiling too large to express in one must clamp rather than wrap into a
	/// tiny one.
	pub const fn as_u32_saturating(self) -> u32 {
		if self.0 > u32::MAX as u64 {
			u32::MAX
		} else {
			self.0 as u32
		}
	}
}

#[repr(C)]
pub struct DecodeBuf {
	pub width: u32,
	pub height: u32,
	pub channels: u8, // 4 = RGBA
	/// Bytes of pixel data actually used.
	pub data_len: usize,
	/// Bytes **allocated** at `data`. Usually equal to `data_len`, but a
	/// decoder that hands back a `Vec` is free to have spare capacity, and
	/// freeing has to rebuild the allocation exactly — so the real capacity
	/// travels with the buffer instead of being assumed.
	pub cap: usize,
	pub data: *mut u8, // raw RGBA pixels (w × h × 4)
}

unsafe impl Send for DecodeBuf {}

impl DecodeBuf {
	/// Wraps a decoder's `Vec<u8>` without copying: the allocation travels with
	/// the buffer and [_free_decode_buf] below frees it with the same capacity.
	pub fn from_vec(mut data: Vec<u8>, width: u32, height: u32) -> Box<DecodeBuf> {
		let data_len = data.len();
		let cap = data.capacity();
		let ptr = data.as_mut_ptr();
		std::mem::forget(data);
		Box::new(DecodeBuf {
			width,
			height,
			channels: 4,
			data_len,
			cap,
			data: ptr,
		})
	}
}

impl Drop for DecodeBuf {
	/// Frees the pixel allocation with the capacity that travelled with it. Both
	/// origins — a decoder's `Vec` through [DecodeBuf::from_vec], and the AVIF
	/// path's raw `alloc`/`dealloc` — go through the global allocator, so
	/// rebuilding a `Vec` is the exact inverse of either.
	///
	/// This lives here, not only in [free_decode_buf], because the thumbnail path
	/// can panic *after* the decode (the WebP encoder) inside a `catch_unwind`:
	/// with no `Drop` the unwind dropped the `Box` and leaked the whole frame —
	/// up to ~256 MiB at the HEIC ceiling.
	fn drop(&mut self) {
		if self.data.is_null() || self.data_len == 0 {
			return;
		}
		// Take the pointer first so a panic inside the deallocation cannot leave
		// this struct pointing at freed memory, and so a double free is
		// impossible even if something calls `free_decode_buf` after a drop.
		let data = std::mem::replace(&mut self.data, std::ptr::null_mut());
		let len = self.data_len;
		let cap = self.cap;
		drop(unsafe { Vec::from_raw_parts(data, len, cap) });
	}
}

pub unsafe fn free_decode_buf(ptr: *mut DecodeBuf) {
	if ptr.is_null() {
		return;
	}
	// `Drop` frees the pixels; this is only the ownership hand-back.
	drop(unsafe { Box::from_raw(ptr) });
}

/// How a destination axis maps onto a source axis, for resampling.
///
/// The pixel **centre** of destination index `d` is mapped back into the source
/// (`(d + 0.5) * src / dst - 0.5`), clamped at both edges, then split into the
/// two source taps and the blend weight between them:
/// `.0` = lower tap, `.1` = upper tap (equal to `.0` at the edge), `.2` = weight
/// of the upper tap.
///
/// This is the one place the mapping lives. `downscale_rgba_bilinear` below and
/// the JXL path's `sample_bilin` both use it, so a scaled thumbnail has the same
/// geometry whichever decoder produced it.
#[inline]
pub fn bilinear_tap(d: u32, dst_len: u32, src_len: u32) -> (usize, usize, f64) {
	let (src, dst) = (src_len as f64, dst_len as f64);
	let s = ((d as f64 + 0.5) * src / dst - 0.5).clamp(0.0, src - 1.0);
	bilinear_taps_at(s, src_len)
}

/// The tap half of [`bilinear_tap`], for callers that computed the source
/// coordinate themselves (JXL maps it through the container's orientation
/// first). `s` must already be inside `0 ..= src_len - 1`.
#[inline]
pub fn bilinear_taps_at(s: f64, src_len: u32) -> (usize, usize, f64) {
	let i0 = s.floor();
	let i1 = (i0 + 1.0).min(src_len as f64 - 1.0);
	(i0 as usize, i1 as usize, s - i0)
}

/// Bilinear downscale of an already-decoded, already-oriented RGBA8 image.
///
/// Same sampling maths as the JXL path (`planar_sample_downscale`), through the
/// shared [`bilinear_tap`]: the target pixel centre is mapped back into the
/// source and the four neighbours are blended. Used by the HEIC decoder, which
/// returns a finished RGBA frame and has no scaler of its own; the result is
/// allocated *exactly* so it can be freed as a plain `Vec` like every other
/// decode buffer.
pub fn downscale_rgba_bilinear(
	src: &[u8],
	sw: u32,
	sh: u32,
	dw: u32,
	dh: u32,
) -> Option<Box<DecodeBuf>> {
	if sw == 0 || sh == 0 || dw == 0 || dh == 0 {
		return None;
	}
	let needed = (sw as usize) * (sh as usize) * 4;
	if src.len() < needed {
		return None;
	}
	let mut out = Vec::new();
	out.try_reserve_exact((dw as usize) * (dh as usize) * 4)
		.ok()?;
	for dy in 0..dh {
		let (y0, y1, wy) = bilinear_tap(dy, dh, sh);
		for dx in 0..dw {
			let (x0, x1, wx) = bilinear_tap(dx, dw, sw);
			let i00 = (y0 * sw as usize + x0) * 4;
			let i10 = (y0 * sw as usize + x1) * 4;
			let i01 = (y1 * sw as usize + x0) * 4;
			let i11 = (y1 * sw as usize + x1) * 4;
			for c in 0..4 {
				let top = src[i00 + c] as f64 * (1.0 - wx) + src[i10 + c] as f64 * wx;
				let bot = src[i01 + c] as f64 * (1.0 - wx) + src[i11 + c] as f64 * wx;
				out.push((top * (1.0 - wy) + bot * wy).round() as u8);
			}
		}
	}
	Some(DecodeBuf::from_vec(out, dw, dh))
}

pub fn decode_avif(data: &[u8], target_width: u32) -> Option<Box<DecodeBuf>> {
	crate::avif::decode(data, target_width)
}

pub fn decode_jxl(data: &[u8], target_width: u32) -> Option<Box<DecodeBuf>> {
	crate::jxl::decode(data, target_width)
}

#[cfg(feature = "mobile-decode")]
pub fn decode_heic(data: &[u8], target_width: u32) -> Option<Box<DecodeBuf>> {
	crate::heic::decode(data, target_width)
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

	/// 3072x4096 is 12.6 MP — inside the shared 64 MP ceiling, and it still goes
	/// through the parameterised door (see [`decode_avif_unlimited`]) so these
	/// pixel assertions stay about the decoder rather than about the policy.
	#[test]
	fn decode_test1_valid() {
		let data = test_read("avif/test1.avif");
		let buf = decode_avif_unlimited(&data, 0).expect("decode");
		assert_eq!(buf.width, 3072);
		assert_eq!(buf.height, 4096);
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	#[test]
	fn decode_test1_downscale() {
		let data = test_read("avif/test1.avif");
		let buf = decode_avif_unlimited(&data, 400).expect("downscale");
		assert_eq!(buf.width, 400);
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	/// Test-only door with the ceiling lifted above every fixture, for the files
	/// here that are larger than any real phone photo (big_gbrp is 39 MP). The
	/// production entry point [`decode_avif`] deliberately has no such escape: a
	/// test-only relaxed limit inside it once kept the suite green while the app
	/// refused real 16 MP files.
	fn decode_avif_unlimited(data: &[u8], target_width: u32) -> Option<Box<DecodeBuf>> {
		crate::avif::decode_with_limit(data, target_width, Limit::synthetic(u64::MAX))
	}

	#[test]
	fn decode_pureblack_valid() {
		let data = test_read("avif/pureblack2_35.avif");
		let buf = decode_avif_unlimited(&data, 0).expect("decode");
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
		let buf = decode_avif_unlimited(&data, 0).expect("decode");
		assert_eq!(buf.width, 7450);
		assert_eq!(buf.height, 5294);
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	#[test]
	fn decode_big_gbrp_downscale() {
		let data = test_read("avif/big_gbrp.avif");
		let buf = decode_avif_unlimited(&data, 400).expect("downscale");
		assert_eq!(buf.width, 400);
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	/// The three software decoders share one ceiling now (64 MP), so the 39 MP
	/// fixture is *inside* it: the production entry point must decode it. What
	/// must still be refused is anything over the ceiling, which is checked
	/// through the parameterised door because the tree keeps no >64 MP fixture.
	#[test]
	fn the_production_ceiling_admits_the_39mp_fixture() {
		let data = test_read("avif/big_gbrp.avif");
		let buf = decode_avif(&data, 0).expect("39 MP is inside the shared 64 MP ceiling");
		assert_eq!(buf.width, 7450);
		assert_eq!(buf.height, 5294);
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	/// The same door, used the other way round: a ceiling below the file's size
	/// refuses it. 1 MP is below adonis (1242x1865 = 2.3 MP).
	///
	/// The refusal that lands here is rav1d's `frame_size_limit` (it logs "Frame
	/// size 1242x1865 exceeds limit 1000000"), not the container check: this
	/// parser takes the first `ispe` it finds in the file, which for adonis is a
	/// smaller item than the primary frame. That is why the ceiling has to reach
	/// both doors — a limit that only guards the parsed `ispe` would let this file
	/// through.
	#[test]
	fn a_ceiling_below_the_file_size_refuses_it() {
		let data = test_read("avif/adonis.avif");
		assert!(
			crate::avif::decode_with_limit(&data, 0, Limit::synthetic(1_000_000)).is_none(),
			"a 1 MP ceiling must refuse a 2.3 MP file"
		);
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
		// jqis5 rather than test1: both are inside the production ceiling, but the
		// smaller frame keeps this end-to-end test cheap, and the assertions below
		// are written against jqis5's 1503x2140 geometry.
		let data = test_read("avif/jqis5.avif");
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
		// jqis5.avif is 1503x2140, so 400 wide scales to 569 tall (truncating, as
		// the shared downscaler does) — the scale happened inside Rust, on pixels
		// Dart never saw.
		assert_eq!(w, 400);
		assert_eq!(h, 569);
		assert_eq!(rgba.len(), (w * h * 4) as usize);
		// The input was borrowed: the caller's buffer is untouched and still
		// its own to free (this is what lets a failure fall back safely).
		assert_eq!(&data[4..8], b"ftyp", "input buffer must still be intact");
		unsafe { crate::webp::free_webp_buf(buf) };
	}

	/// The HEIC half of the same chain, end to end, with the `kind_hint` the app
	/// sends (3). Skips when the gitignored fixture is absent. This is the test
	/// that mirrors what the desktop/mobile app actually calls for a `.heic`
	/// thumbnail, so a rejected decode shows up here rather than in the UI.
	#[test]
	fn thumb_webp_from_heic_image_in_one_call() {
		let Ok(data) = std::fs::read("tests/testdata/heic/IMG_20240322_182430.HEIC") else {
			eprintln!("skipping: no HEIC fixture");
			return;
		};
		let buf = unsafe {
			crate::rcrm_generate_thumb_webp_from_image(data.as_ptr(), data.len(), 400, 82, 3)
		};
		assert!(!buf.is_null(), "HEIC decode + encode must succeed");
		let webp = unsafe { &*buf };
		let bytes = unsafe { std::slice::from_raw_parts(webp.data, webp.data_len) };
		assert_eq!(&bytes[0..4], b"RIFF");
		assert_eq!(&bytes[8..12], b"WEBP");
		let (_rgba, w, h) = zenwebp::oneshot::decode_rgba(bytes).expect("decode back");
		assert_eq!(w, 400);
		// 4624x3472 → 400 wide keeps the aspect ratio; which side is "width"
		// depends on the container orientation the decoder applied.
		assert!(h == 300 || h == 533, "unexpected thumbnail height {h}");
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
		let buf =
			unsafe { crate::rcrm_generate_thumb_webp_from_image(empty.as_ptr(), 0, 400, 82, 0) };
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
