// src/poster.rs
// Poster encoding from libmpv's software-rendered frame, all in Rust.
//
// libmpv rendered straight into a target-sized BGR0 surface, so there is
// nothing to resample: one in-place pass makes the frame opaque and measures
// its luma, then the encoder reads that same buffer. Neither pass lets a pixel
// enter Dart.

use crate::webp::{self, WebpBuf};

/// Blank-frame band, the same 20..235 the old JPEG blank detector used. A
/// frame outside it is a black/white leader, not a poster.
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

/// Blank test + in-place WebP encode for a frame that is ALREADY at the poster
/// size.
///
/// libmpv rendered into the target surface itself, so there is nothing to
/// resample and no second buffer — the alpha fix, the luma test and the encoder
/// all read [bgra] where libmpv wrote it.
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
		// The alpha fix still ran, so a rejected frame is not left transparent.
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
