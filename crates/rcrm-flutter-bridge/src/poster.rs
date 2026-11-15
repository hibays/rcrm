// src/poster.rs
// Poster encoding from an mpv frame, all in Rust.
//
// Two poster backends exist, and this module is where they meet:
//
//   media_kit screenshot (iOS): a tightly packed BGRA frame at the video's own
//     size, which is blank-tested, bilinearly downscaled and encoded —
//     `encode_poster`.
//   libmpv direct (every other platform): libmpv already rendered straight into
//     a target-sized BGR0 surface, so there is nothing to resample — one
//     in-place pass makes the frame opaque and measures its luma, then the
//     encoder reads that same buffer — `encode_poster_frame`.
//
// The blank band and the WebP encoder are the same code for both, and neither
// path lets a pixel enter Dart.

use crate::webp::{self, WebpBuf};

#[cfg(feature = "mpv-poster")]
use crate::decode::downscale_bgra_opaque_bilinear;

/// Blank-frame band, the same 20..235 the JPEG blank detector uses
/// (`rcrm_is_blank_frame`). A frame outside it is a black/white leader, not a
/// poster.
pub const BLANK_LOW: f64 = 20.0;
pub const BLANK_HIGH: f64 = 235.0;

/// What one poster attempt produced.
pub enum PosterResult {
	/// A blank leader/fade; no WebP was encoded.
	Blank,
	/// A finished WebP buffer (free with `rcrm_free_webp_buf`).
	Encoded(Box<WebpBuf>),
	/// The input was not a frame of the stated size, or the encoder refused it.
	Invalid,
}

/// Mean BT.601 luma of a tightly packed BGRA8 buffer.
///
/// The read-only half of the pair below, used where the frame is only measured
/// (the media_kit screenshot path, whose next step resamples into a new
/// buffer). Every pixel is counted, like `rcrm_is_blank_frame` does for a decoded JPEG;
/// sampling was the Dart version's shortcut, and a blank test is exactly the
/// kind of predicate that must not be approximated.
// Compiled for the screenshot encoder and for the tests; a libmpv-only build
// measures luma inside the same pass that makes the frame opaque.
#[cfg(any(feature = "mpv-poster", test))]
pub fn mean_luma_bgra(bytes: &[u8]) -> f64 {
	let mut sum = 0.0;
	let mut n = 0usize;
	for pixel in bytes.as_chunks::<4>().0 {
		let blue = f64::from(pixel[0]);
		let green = f64::from(pixel[1]);
		let red = f64::from(pixel[2]);
		sum += 0.299 * red + 0.587 * green + 0.114 * blue;
		n += 1;
	}
	if n == 0 { 0.0 } else { sum / n as f64 }
}

/// Whether `mean` is outside the poster band.
pub fn is_blank_luma(mean: f64) -> bool {
	!(BLANK_LOW..=BLANK_HIGH).contains(&mean)
}

/// Make a BGR0 frame opaque and return its mean BT.601 luma.
///
/// mpv's `bgr0` surface leaves the fourth byte at 0 — render.h says its content
/// is "uninitialized garbage (often the value 0)" — and a WebP reads that as
/// fully transparent. Every alpha byte is therefore set to 255 in the same pass
/// that measures the luma, so a rendered frame is read once, not twice.
///
/// A trailing partial pixel is ignored; every caller passes a frame of exactly
/// `width * height * 4` bytes.
// The libmpv surface is where this runs; the tests pin it for every feature
// shape, and a screenshot-only build does not need it.
#[cfg(any(feature = "libmpv-poster", test))]
pub fn make_opaque_and_mean_luma_bgra(bytes: &mut [u8]) -> f64 {
	let mut sum = 0.0;
	let mut n = 0usize;
	for pixel in bytes.as_chunks_mut::<4>().0 {
		pixel[3] = 255;
		sum +=
			0.299 * f64::from(pixel[2]) + 0.587 * f64::from(pixel[1]) + 0.114 * f64::from(pixel[0]);
		n += 1;
	}
	if n == 0 { 0.0 } else { sum / n as f64 }
}

/// Blank test + bilinear downscale + WebP encode for one raw BGRA frame.
///
/// This is the media_kit screenshot path (iOS): the frame arrives at the
/// video's own resolution, so it is resampled here before encoding.
/// [target_width] is a maximum: 0 or a value at least as wide as the source
/// means "keep the source size". The output is always RGBA with opaque alpha.
#[cfg(feature = "mpv-poster")]
pub fn encode_poster(
	bgra: &[u8],
	width: u32,
	height: u32,
	target_width: u32,
	quality: u8,
) -> PosterResult {
	let expected = (width as usize)
		.checked_mul(height as usize)
		.and_then(|pixels| pixels.checked_mul(4));
	if width == 0 || height == 0 || expected != Some(bgra.len()) {
		return PosterResult::Invalid;
	}
	if is_blank_luma(mean_luma_bgra(bgra)) {
		return PosterResult::Blank;
	}
	let target = if target_width == 0 || target_width >= width {
		width
	} else {
		target_width
	};
	let target_height = if target == width {
		height
	} else {
		let rounded =
			(u64::from(height) * u64::from(target) + u64::from(width) / 2) / u64::from(width);
		rounded.max(1).min(u64::from(height)) as u32
	};
	let scaled = match downscale_bgra_opaque_bilinear(bgra, width, height, target, target_height) {
		Some(buffer) => buffer,
		None => return PosterResult::Invalid,
	};
	let encoded = unsafe {
		webp::encode_rgba_webp(
			scaled.data,
			scaled.data_len,
			scaled.width,
			scaled.height,
			quality,
		)
	};
	match encoded {
		Some(buffer) => PosterResult::Encoded(buffer),
		None => PosterResult::Invalid,
	}
}

/// Blank test + in-place WebP encode for a frame that is ALREADY at the poster
/// size.
///
/// This is the libmpv direct path: mpv rendered into the target surface
/// itself, so there is nothing to resample and no second buffer — the alpha fix,
/// the luma test and the encoder all read [bgra] where libmpv wrote it.
#[cfg(feature = "libmpv-poster")]
pub fn encode_poster_frame(bgra: &mut [u8], width: u32, height: u32, quality: u8) -> PosterResult {
	let expected = (width as usize)
		.checked_mul(height as usize)
		.and_then(|pixels| pixels.checked_mul(4));
	if width == 0 || height == 0 || expected != Some(bgra.len()) {
		return PosterResult::Invalid;
	}
	if is_blank_luma(make_opaque_and_mean_luma_bgra(bgra)) {
		return PosterResult::Blank;
	}
	match webp::encode_bgra(bgra, width, height, quality) {
		Some(buffer) => PosterResult::Encoded(buffer),
		None => PosterResult::Invalid,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn bgra_solid(red: u8, green: u8, blue: u8, width: usize, height: usize) -> Vec<u8> {
		let mut pixels = vec![0u8; width * height * 4];
		for pixel in pixels.as_chunks_mut::<4>().0 {
			pixel[0] = blue;
			pixel[1] = green;
			pixel[2] = red;
			pixel[3] = 0;
		}
		pixels
	}

	#[test]
	fn mean_luma_counts_every_pixel() {
		assert!(mean_luma_bgra(&bgra_solid(0, 0, 0, 2, 2)) < 0.01);
		assert!((mean_luma_bgra(&bgra_solid(255, 255, 255, 2, 2)) - 255.0).abs() < 0.01);
		assert!((mean_luma_bgra(&bgra_solid(120, 120, 120, 2, 2)) - 120.0).abs() < 0.01);
	}

	#[test]
	fn black_and_white_are_blank_grey_is_not() {
		assert!(is_blank_luma(19.9));
		assert!(!is_blank_luma(20.0));
		assert!(!is_blank_luma(235.0));
		assert!(is_blank_luma(235.1));
	}

	/// The alpha byte mpv leaves at 0 must become opaque, and the luma the same
	/// pass reports must match the frame it wrote.
	#[test]
	fn making_a_frame_opaque_keeps_its_luma() {
		let mut frame = bgra_solid(120, 120, 120, 4, 4);
		let mean = make_opaque_and_mean_luma_bgra(&mut frame);
		assert!((mean - 120.0).abs() < 0.01);
		assert!(frame.as_chunks::<4>().0.iter().all(|pixel| pixel[3] == 255));
		assert!(
			frame.as_chunks::<4>().0.iter().all(|pixel| pixel[0] == 120),
			"colours are untouched"
		);
	}

	#[cfg(feature = "mpv-poster")]
	mod media_kit_screenshot {
		use super::*;

		#[test]
		fn a_blank_frame_is_rejected_without_encoding() {
			assert!(matches!(
				encode_poster(&bgra_solid(0, 0, 0, 2, 2), 2, 2, 640, 82),
				PosterResult::Blank
			));
			assert!(matches!(
				encode_poster(&bgra_solid(255, 255, 255, 2, 2), 2, 2, 640, 82),
				PosterResult::Blank
			));
		}

		#[test]
		fn a_real_frame_is_encoded_at_the_target_size() {
			// A solid grey is inside the band, so it must be encoded. Colour is
			// lossy at this size; dimensions and opaque alpha are the contracts.
			let frame = encode_poster(&bgra_solid(120, 120, 120, 32, 32), 32, 32, 8, 82);
			let PosterResult::Encoded(buffer) = frame else {
				panic!("a real frame must encode");
			};
			let webp = &*buffer;
			let bytes = unsafe { std::slice::from_raw_parts(webp.data, webp.data_len) };
			assert_eq!(&bytes[0..4], b"RIFF");
			assert_eq!(&bytes[8..12], b"WEBP");
			let (rgba, width, height) = zenwebp::oneshot::decode_rgba(bytes).expect("decode back");
			assert_eq!((width, height), (8, 8));
			assert_eq!(rgba.len(), (width * height * 4) as usize);
			assert!(
				rgba.as_chunks::<4>().0.iter().all(|pixel| pixel[3] == 255),
				"downscaled posters must be opaque"
			);
			unsafe { webp::free_webp_buf(Box::into_raw(buffer)) };
		}

		#[test]
		fn target_width_zero_keeps_the_source_size() {
			let frame = encode_poster(&bgra_solid(120, 120, 120, 4, 4), 4, 4, 0, 82);
			let PosterResult::Encoded(buffer) = frame else {
				panic!("a real frame must encode");
			};
			let webp = &*buffer;
			let bytes = unsafe { std::slice::from_raw_parts(webp.data, webp.data_len) };
			let (_, width, height) = zenwebp::oneshot::decode_rgba(bytes).expect("decode back");
			assert_eq!((width, height), (4, 4));
			unsafe { webp::free_webp_buf(Box::into_raw(buffer)) };
		}

		#[test]
		fn a_wrong_length_is_invalid() {
			assert!(matches!(
				encode_poster(&[0u8; 3], 4, 4, 640, 82),
				PosterResult::Invalid
			));
			assert!(matches!(
				encode_poster(&[], 0, 0, 640, 82),
				PosterResult::Invalid
			));
		}

		/// The FFI contract: a blank frame returns null AND sets out_blank, so
		/// the Dart caller can tell "blank" from "encode failed".
		#[test]
		fn ffi_marks_blank_and_returns_null() {
			let frame = [0u8; 4 * 4 * 4];
			let mut blank = 0i32;
			let out = unsafe {
				crate::rcrm_encode_poster_webp(frame.as_ptr(), frame.len(), 4, 4, 2, 82, &mut blank)
			};
			assert!(out.is_null());
			assert_eq!(blank, 1);
		}

		/// A non-blank BGRA frame encodes, and out_blank stays 0. This is the ABI
		/// the Dart worker binds (target width in, WebpBuf out).
		#[test]
		fn ffi_encodes_a_non_blank_frame() {
			let mut frame = vec![0u8; 16 * 16 * 4];
			for pixel in frame.as_chunks_mut::<4>().0 {
				pixel[2] = 120; // red-ish, luma ~35.9
				pixel[3] = 0;
			}
			let mut blank = 0i32;
			let out = unsafe {
				crate::rcrm_encode_poster_webp(
					frame.as_ptr(),
					frame.len(),
					16,
					16,
					8,
					82,
					&mut blank,
				)
			};
			assert!(!out.is_null());
			assert_eq!(blank, 0);
			unsafe { webp::free_webp_buf(out) };
		}
	}

	#[cfg(feature = "libmpv-poster")]
	mod libmpv_surface {
		use super::*;

		#[test]
		fn an_opaque_rendered_frame_is_encoded_in_place() {
			let mut frame = bgra_solid(120, 120, 120, 32, 32);
			let frame = encode_poster_frame(&mut frame, 32, 32, 82);
			let PosterResult::Encoded(buffer) = frame else {
				panic!("a real frame must encode");
			};
			let webp = &*buffer;
			let bytes = unsafe { std::slice::from_raw_parts(webp.data, webp.data_len) };
			let (rgba, width, height) = zenwebp::oneshot::decode_rgba(bytes).expect("decode back");
			assert_eq!((width, height), (32, 32), "no resampling happens here");
			assert!(rgba.as_chunks::<4>().0.iter().all(|pixel| pixel[3] == 255));
			// Lossy at this size, but the colour is still grey.
			assert!(rgba[0].abs_diff(120) < 12, "pixel was {}", rgba[0]);
			unsafe { webp::free_webp_buf(Box::into_raw(buffer)) };
		}

		#[test]
		fn a_blank_surface_is_rejected_before_encoding() {
			let mut black = bgra_solid(0, 0, 0, 8, 8);
			assert!(matches!(
				encode_poster_frame(&mut black, 8, 8, 82),
				PosterResult::Blank
			));
			let mut white = bgra_solid(255, 255, 255, 8, 8);
			assert!(matches!(
				encode_poster_frame(&mut white, 8, 8, 82),
				PosterResult::Blank
			));
			// The alpha fix still ran, so a rejected frame is not left
			// transparent if a caller ever encodes it by hand.
			assert!(black.as_chunks::<4>().0.iter().all(|pixel| pixel[3] == 255));
		}

		#[test]
		fn a_wrong_length_is_invalid() {
			assert!(matches!(
				encode_poster_frame(&mut [0u8; 3], 4, 4, 82),
				PosterResult::Invalid
			));
		}
	}
}
