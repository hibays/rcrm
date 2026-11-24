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

/// Rotate a tightly packed BGRA frame clockwise by `degrees`.
///
/// The caller only ever asks for a quarter turn, because that is the one libmpv's
/// software renderer refuses to draw (see `libmpv_poster::finalize_rotation`); a
/// frame the renderer turned itself (0° and 180°) never reaches this function.
/// All four right angles are implemented anyway — the DIRECTION is the part a
/// reader sees when it is wrong, so each one is pinned by a test.
///
/// `None` means the arguments do not describe a frame — the same contract
/// [encode_poster_frame] enforces, so a caller cannot rotate then encode a
/// buffer of the wrong length.
pub fn rotate_bgra_clockwise(src: &[u8], width: u32, height: u32, degrees: u32) -> Option<Vec<u8>> {
	let pixels = usize::try_from(width)
		.ok()?
		.checked_mul(usize::try_from(height).ok()?)?;
	if width == 0 || height == 0 || src.len() != pixels.checked_mul(4)? {
		return None;
	}
	let angle = degrees % 360;
	if !angle.is_multiple_of(90) {
		return None;
	}
	// A quarter turn swaps the axes; a half turn does not. Only the result's
	// WIDTH is needed to index it — its height follows from the same length.
	let dst_width = if angle % 180 == 90 { height } else { width } as usize;
	let mut dst = vec![0u8; src.len()];
	if angle == 0 {
		dst.copy_from_slice(src);
		return Some(dst);
	}
	let width = width as usize;
	let height = height as usize;
	// The per-pixel destination formula depends only on `angle` (an image-level
	// invariant). Resolve it once into a per-row mapping instead of re-matching
	// inside the 230k-pixel inner loop. Byte-identical; measured gain is ~1.24x
	// for 180deg, ~1.0x for 90/270deg (quarter turns are strided writes, so the
	// win is mostly cancelled by memory bandwidth — keep it for clarity).
	// CLOCKWISE: 90 -> (height-1-y, x), 180 -> (width-1-x, height-1-y),
	// 270 -> (y, width-1-x). Each direction is pinned by a test below.
	for y in 0..height {
		// For each x: (dx, dy) and thus `to` is affine in x for every angle.
		// Compute the row's starting `to` and its per-x stride once.
		let (to_x0, to_stride) = match angle {
			90 => ((height - 1 - y) * 4, dst_width as isize * 4), // dx=height-1-y, dy=x
			180 => (((height - 1 - y) * dst_width + (width - 1)) * 4, -4isize),
			_ => (((width - 1) * dst_width + y) * 4, -(dst_width as isize) * 4), // 270: dx=y, dy=width-1-x
		};
		for x in 0..width {
			let from = (y * width + x) * 4;
			let to = (to_x0 as isize + to_stride * x as isize) as usize;
			dst[to..to + 4].copy_from_slice(&src[from..from + 4]);
		}
	}
	Some(dst)
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

	fn tagged(width: usize, height: usize) -> Vec<u8> {
		let mut pixels = vec![0u8; width * height * 4];
		for (index, pixel) in pixels.as_chunks_mut::<4>().0.iter_mut().enumerate() {
			pixel[0] = index as u8 + 1;
			pixel[3] = 255;
		}
		pixels
	}

	fn tags(frame: &[u8], width: usize) -> Vec<Vec<u8>> {
		frame
			.as_chunks::<4>()
			.0
			.chunks(width)
			.map(|row| row.iter().map(|pixel| pixel[0]).collect())
			.collect()
	}

	/// The direction is the whole point: a poster rotated the wrong way is a
	/// defect a reader sees, so all four turns are pinned.
	#[test]
	fn rotation_turns_the_frame_clockwise() {
		let frame = tagged(3, 2);
		assert_eq!(
			tags(&rotate_bgra_clockwise(&frame, 3, 2, 90).unwrap(), 2),
			vec![vec![4, 1], vec![5, 2], vec![6, 3]]
		);
		assert_eq!(
			tags(&rotate_bgra_clockwise(&frame, 3, 2, 180).unwrap(), 3),
			vec![vec![6, 5, 4], vec![3, 2, 1]]
		);
		assert_eq!(
			tags(&rotate_bgra_clockwise(&frame, 3, 2, 270).unwrap(), 2),
			vec![vec![3, 6], vec![2, 5], vec![1, 4]]
		);
		assert_eq!(rotate_bgra_clockwise(&frame, 3, 2, 0).unwrap(), frame);
		assert_eq!(
			rotate_bgra_clockwise(&frame, 3, 2, 360).unwrap(),
			frame,
			"a full turn is no turn"
		);
	}

	/// The hoisted per-row affine mapping must be byte-identical to the literal
	/// per-pixel match for every size/angle — the tiny direction test above pins
	/// orientation but not every offset across a large frame.
	#[test]
	fn rotation_affine_matches_per_pixel_reference() {
		fn reference(src: &[u8], w: usize, h: usize, angle: u32) -> Vec<u8> {
			let dst_width = if angle % 180 == 90 { h } else { w };
			let mut dst = vec![0u8; src.len()];
			for y in 0..h {
				for x in 0..w {
					let (dx, dy) = match angle {
						90 => (h - 1 - y, x),
						180 => (w - 1 - x, h - 1 - y),
						_ => (y, w - 1 - x),
					};
					let from = (y * w + x) * 4;
					let to = (dy * dst_width + dx) * 4;
					dst[to..to + 4].copy_from_slice(&src[from..from + 4]);
				}
			}
			dst
		}
		for &(w, h) in &[(1usize, 1usize), (3, 2), (7, 5), (16, 9), (64, 48)] {
			let src: Vec<u8> = (0..w * h * 4).map(|i| (i * 31 + i / 7) as u8).collect();
			for angle in [90, 180, 270] {
				assert_eq!(
					rotate_bgra_clockwise(&src, w as u32, h as u32, angle).unwrap(),
					reference(&src, w, h, angle),
					"w={w} h={h} angle={angle}"
				);
			}
		}
	}

	/// A rotation that does not describe a frame is refused rather than
	/// producing a buffer the encoder would then refuse.
	#[test]
	fn rotation_refuses_what_it_cannot_rotate() {
		let frame = tagged(3, 2);
		assert!(rotate_bgra_clockwise(&frame, 3, 2, 45).is_none());
		assert!(rotate_bgra_clockwise(&frame, 3, 2, 91).is_none());
		assert!(rotate_bgra_clockwise(&frame[..23], 3, 2, 90).is_none());
		assert!(rotate_bgra_clockwise(&frame, 0, 2, 90).is_none());
	}

	#[test]
	fn a_wrong_length_is_invalid() {
		assert!(matches!(
			encode_poster_frame(&mut [0u8; 3], 4, 4, 82),
			PosterResult::Invalid
		));
	}
}
