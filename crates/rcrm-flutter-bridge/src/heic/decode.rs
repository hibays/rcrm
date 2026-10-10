// heic/decode.rs
// HEIC/HEIF stills via the `heic` crate (pure-Rust HEVC backend).
//
// The crate parses the ISOBMFF container itself, applies the container's
// orientation (irot/imir) and clean-aperture crop, and colour-converts to the
// layout we ask for — so this module only has to guard resources and scale.
// It has no scaler of its own, hence `downscale_rgba_bilinear` in the shared
// decode module (same sampling maths the JXL path uses).

use crate::decode::{DecodeBuf, Limit, downscale_rgba_bilinear};
use heic::{DecoderConfig, Limits, PixelLayout};

pub fn decode_frame(data: &[u8], target_width: u32) -> Option<Box<DecodeBuf>> {
	decode_with_limit(data, target_width, Limit::PRODUCTION)
}

/// The ceiling is a parameter so tests can exercise the limit itself rather than
/// a test-only escape hatch — a `#[cfg(test)] u64::MAX` in here once hid a limit
/// that rejected every real HEIC in the app. The `heic` crate enforces it
/// *before* it allocates (`LimitExceeded` → null → the caller falls back), which
/// is why the number has to reach its own `Limits` rather than a check of ours.
fn decode_with_limit(data: &[u8], target_width: u32, limit: Limit) -> Option<Box<DecodeBuf>> {
	let mut limits = Limits::default();
	limits.max_pixels = Some(limit.pixels());

	// `DecoderConfig::new()` resolves to the pure-Rust backend (it is the only
	// one compiled in), and orientation is applied by default — which is what a
	// viewer wants, since Dart paints these pixels without touching EXIF.
	let out = DecoderConfig::new()
		.decode_request(data)
		.with_output_layout(PixelLayout::Rgba8)
		.with_limits(&limits)
		.decode()
		.ok()?;

	let (w, h) = (out.width, out.height);
	if w == 0 || h == 0 || out.data.len() < (w as usize) * (h as usize) * 4 {
		return None;
	}

	if target_width > 0 && target_width < w {
		// Aspect-preserving, like the other two decoders.
		let dh = ((h as f64) * (target_width as f64) / (w as f64)).round() as u32;
		if dh > 0
			&& let Some(scaled) = downscale_rgba_bilinear(&out.data, w, h, target_width, dh)
		{
			return Some(scaled);
		}
	}
	// No scaling asked for (or it failed): hand the decoder's own buffer over
	// without a copy — `from_vec` carries the capacity so the free is exact.
	Some(DecodeBuf::from_vec(out.data, w, h))
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The HEIC fixtures are the user's own camera files and the testdata tree
	/// is gitignored, so a checkout without them skips instead of failing (the
	/// avif/jxl fixtures happen to be present on the dev machines).
	fn fixture(name: &str) -> Option<Vec<u8>> {
		let path = format!("tests/testdata/heic/{name}");
		match std::fs::read(&path) {
			Ok(bytes) => Some(bytes),
			Err(_) => {
				eprintln!("skipping: no fixture at {path}");
				None
			}
		}
	}

	#[test]
	fn decodes_a_phone_heic_at_full_size() {
		let Some(data) = fixture("IMG_20240322_182430.HEIC") else {
			return;
		};
		let buf = decode_frame(&data, 0).expect("decode");
		// 4624x3472 stored; the container's orientation is applied by the
		// decoder, so the long side may land on either axis.
		let (long, short) = (buf.width.max(buf.height), buf.width.min(buf.height));
		assert_eq!((long, short), (4624, 3472));
		assert_eq!(buf.channels, 4);
		assert_eq!(
			buf.data_len,
			(buf.width as usize) * (buf.height as usize) * 4
		);
		assert_eq!(buf.cap, buf.data_len, "capacity travels with the buffer");
		// Not a blank frame: a real photo has varied pixels.
		let px = unsafe { std::slice::from_raw_parts(buf.data, buf.data_len) };
		let pixels = px.as_chunks::<4>().0;
		assert!(
			pixels.iter().take(4096).any(|p| p != &pixels[0]),
			"decoded frame is a flat colour"
		);
		unsafe { crate::decode::free_decode_buf(Box::into_raw(buf)) };
	}

	#[test]
	fn downscales_to_the_requested_width() {
		let Some(data) = fixture("IMG_20240729_214837.HEIC") else {
			return;
		};
		let buf = decode_frame(&data, 400).expect("decode scaled");
		assert_eq!(buf.width, 400);
		assert!(buf.height > 0 && buf.height < 400, "height {}", buf.height);
		assert_eq!(buf.data_len, 400 * buf.height as usize * 4);
		unsafe { crate::decode::free_decode_buf(Box::into_raw(buf)) };
	}

	/// Both shapes of the call the app makes, on ONE fixture: the full-size decode
	/// (`AuthImage` with no `targetWidth`) and a thumbnail-width decode
	/// (`DiskThumbImage`/`PooledImage` ask for 400). The two must agree about the
	/// same picture, so a scale that silently returned nothing, the wrong geometry
	/// or a blank frame fails here rather than reaching the user as a grid cell
	/// that stays empty while the viewer shows the file.
	///
	/// The HEIC fixtures are the user's own camera files (gitignored), so this
	/// skips with a message instead of failing on a checkout without them.
	#[test]
	fn decodes_full_size_and_a_thumbnail_width_from_the_same_fixture() {
		let Some(data) = fixture("IMG_20240322_182430.HEIC") else {
			return;
		};
		const THUMB_W: u32 = 400;
		let full = decode_frame(&data, 0).expect("full-size decode");
		let thumb = decode_frame(&data, THUMB_W).expect("thumbnail-width decode");

		assert_eq!(thumb.width, THUMB_W, "not the width that was asked for");
		for (label, buf) in [("full", &full), ("thumb", &thumb)] {
			assert!(buf.width > 0 && buf.height > 0, "{label}: empty geometry");
			assert_eq!(buf.channels, 4, "{label}: not RGBA");
			assert_eq!(
				buf.data_len,
				(buf.width as usize) * (buf.height as usize) * 4,
				"{label}: buffer does not describe its frame"
			);
			assert_eq!(buf.cap, buf.data_len, "{label}: capacity travels with it");
		}

		// The scaled frame is the same picture: aspect-preserving in the
		// orientation the decoder applied, and not a flat colour.
		let (fw, fh) = (full.width as f64, full.height as f64);
		let (tw, th) = (thumb.width as f64, thumb.height as f64);
		assert!(
			((fw / fh) - (tw / th)).abs() < 0.02,
			"aspect ratio drifted: {}x{fh} vs {tw}x{th}",
			full.width
		);
		let px = unsafe { std::slice::from_raw_parts(thumb.data, thumb.data_len) };
		let pixels = px.as_chunks::<4>().0;
		assert!(
			pixels.iter().take(4096).any(|p| p != &pixels[0]),
			"the scaled frame is a flat colour"
		);
		assert_eq!(
			pixels[0][3], 255,
			"a scaled HEIC still must stay opaque — alpha 0 shows as nothing"
		);

		unsafe { crate::decode::free_decode_buf(Box::into_raw(full)) };
		unsafe { crate::decode::free_decode_buf(Box::into_raw(thumb)) };
	}

	#[test]
	fn rejects_bytes_that_are_not_heif() {
		let junk = vec![0u8; 4096];
		assert!(decode_frame(&junk, 0).is_none());
		assert!(decode_frame(&[], 0).is_none());
	}

	/// Regression: the first version of this module reused the AVIF path's old
	/// 8.3 MP ceiling (AVIF and HEIC now share the one crate-wide ceiling), which
	/// rejected every real phone still (16 MP here) — and a `#[cfg(test)] u64::MAX`
	/// escape kept the tests green while the app showed nothing. Both halves are
	/// pinned now.
	#[test]
	fn a_real_phone_still_fits_under_the_production_limit() {
		let Some(data) = fixture("IMG_20240322_182430.HEIC") else {
			return;
		};
		// The exact number that used to reject it.
		assert!(
			decode_with_limit(&data, 0, Limit::synthetic(8_300_000)).is_none(),
			"a ceiling below the file size must reject a 16 MP still"
		);
		assert!(
			decode_with_limit(&data, 0, Limit::PRODUCTION).is_some(),
			"the production limit must accept a normal phone photo"
		);
	}
}
