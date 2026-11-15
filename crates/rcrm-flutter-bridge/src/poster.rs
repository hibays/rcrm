// src/poster.rs
// Poster encoding from a raw mpv screenshot, all in Rust.
//
// The mobile poster path receives a paused-seek screenshot as tightly packed
// BGRA (mpv's `screenshot-raw`). Three jobs used to happen in Dart — swap the
// channels, count every 16th pixel for the blank test, and box-filter the
// frame down to 640 wide — before the pixels were copied to the WebP worker.
// That is exactly the work Rust already does for decoded thumbnails, so this
// module composes the same pieces:
//
//   mean_luma_bgra  →  downscale_bgra_opaque_bilinear  →  encode_rgba_webp
//
// The result is one call, one full-frame copy (Dart must move the screenshot
// into native memory either way), and no pixel loop on the UI isolate.

use crate::decode::downscale_bgra_opaque_bilinear;
use crate::webp::{self, WebpBuf};

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
	/// The input was not a tight BGRA frame, or the encoder refused it.
	Invalid,
}

/// Mean BT.601 luma of a tightly packed BGRA8 buffer.
///
/// Every pixel is counted, like `rcrm_is_blank_frame` does for a decoded JPEG;
/// sampling was the Dart version's shortcut, and a blank test is exactly the
/// kind of predicate that must not be approximated.
pub fn mean_luma_bgra(bytes: &[u8]) -> f64 {
	let mut sum = 0.0;
	let mut n = 0usize;
	for p in bytes.as_chunks::<4>().0 {
		let b = p[0] as f64;
		let g = p[1] as f64;
		let r = p[2] as f64;
		sum += 0.299 * r + 0.587 * g + 0.114 * b;
		n += 1;
	}
	if n == 0 { 0.0 } else { sum / n as f64 }
}

/// Whether [mean] is outside the poster band.
pub fn is_blank_luma(mean: f64) -> bool {
	!(BLANK_LOW..=BLANK_HIGH).contains(&mean)
}

/// Blank test + bilinear downscale + WebP encode for one raw BGRA frame.
///
/// [target_width] is a maximum: 0 or a value at least as wide as the source
/// means "keep the source size". The output is always RGBA with opaque alpha.
pub fn encode_poster(
	bgra: &[u8],
	width: u32,
	height: u32,
	target_width: u32,
	quality: u8,
) -> PosterResult {
	let expected = (width as usize)
		.checked_mul(height as usize)
		.and_then(|p| p.checked_mul(4));
	if width == 0 || height == 0 || expected != Some(bgra.len()) {
		return PosterResult::Invalid;
	}
	if is_blank_luma(mean_luma_bgra(bgra)) {
		return PosterResult::Blank;
	}
	let tw = if target_width == 0 || target_width >= width {
		width
	} else {
		target_width
	};
	let th = if tw == width {
		height
	} else {
		let rounded = (height as u64 * tw as u64 + width as u64 / 2) / width as u64;
		rounded.max(1).min(height as u64) as u32
	};
	let scaled = match downscale_bgra_opaque_bilinear(bgra, width, height, tw, th) {
		Some(buf) => buf,
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
		Some(buf) => PosterResult::Encoded(buf),
		None => PosterResult::Invalid,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn bgra_solid(r: u8, g: u8, b: u8, w: usize, h: usize) -> Vec<u8> {
		let mut src = vec![0u8; w * h * 4];
		for p in src.as_chunks_mut::<4>().0 {
			p[0] = b;
			p[1] = g;
			p[2] = r;
			p[3] = 0;
		}
		src
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
		let PosterResult::Encoded(buf) = frame else {
			panic!("a real frame must encode");
		};
		let webp = &*buf;
		let bytes = unsafe { std::slice::from_raw_parts(webp.data, webp.data_len) };
		assert_eq!(&bytes[0..4], b"RIFF");
		assert_eq!(&bytes[8..12], b"WEBP");
		let (rgba, w, h) = zenwebp::oneshot::decode_rgba(bytes).expect("decode back");
		assert_eq!((w, h), (8, 8));
		assert_eq!(rgba.len(), (w * h * 4) as usize);
		assert!(
			rgba.as_chunks::<4>().0.iter().all(|p| p[3] == 255),
			"downscaled posters must be opaque"
		);
		unsafe { webp::free_webp_buf(Box::into_raw(buf)) };
	}

	#[test]
	fn target_width_zero_keeps_the_source_size() {
		let frame = encode_poster(&bgra_solid(120, 120, 120, 4, 4), 4, 4, 0, 82);
		let PosterResult::Encoded(buf) = frame else {
			panic!("a real frame must encode");
		};
		let webp = &*buf;
		let bytes = unsafe { std::slice::from_raw_parts(webp.data, webp.data_len) };
		let (_, w, h) = zenwebp::oneshot::decode_rgba(bytes).expect("decode back");
		assert_eq!((w, h), (4, 4));
		unsafe { webp::free_webp_buf(Box::into_raw(buf)) };
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

	/// The FFI contract: a blank frame returns null AND sets out_blank, so the
	/// Dart caller can tell "blank" from "encode failed".
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
		for p in frame.as_chunks_mut::<4>().0 {
			p[2] = 120; // red-ish, luma ~35.9
			p[3] = 0;
		}
		let mut blank = 0i32;
		let out = unsafe {
			crate::rcrm_encode_poster_webp(frame.as_ptr(), frame.len(), 16, 16, 8, 82, &mut blank)
		};
		assert!(!out.is_null());
		assert_eq!(blank, 0);
		unsafe { webp::free_webp_buf(out) };
	}
}
