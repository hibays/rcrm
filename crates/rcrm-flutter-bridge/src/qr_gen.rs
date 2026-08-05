// src/qr_gen.rs
// rcrm-flutter-bridge — QR generation for the cast-pairing screen
//
// The TV receiver shows a pairing QR on screen. Generation runs here (rxing
// encoder → L8 luma → WebP via zenwebp) instead of in Flutter, so the
// qr_flutter package can be dropped and the 2048px (2K) code arrives as a
// small WebP.
//
// Encoding is LOSSLESS (VP8L). Measured on a 2048² two-tone image
// (cargo test bench, --release): lossy VP8 quality 80 / method 4 takes
// ~165ms and 16.6KB, while lossless VP8L quality 80 / method 4 takes ~9ms
// and 3.0KB. VP8's DCT/quantization machinery is wasted on a two-color
// image; on L8 input zenwebp's VP8L path falls back to a literal +
// run-length encoder, which compresses the constant runs almost instantly
// and smaller, with pixel-exact edges. Lossless is both faster AND smaller
// here.
//
// The C-ABI surface (rcrm_generate_qr_webp) lives in lib.rs; this module
// exposes only plain Rust functions.

use rxing::{BarcodeFormat, EncodeHints, MultiFormatWriter, Writer};
use zenwebp::{EncodeRequest, LosslessConfig, PixelLayout};

/// Nominal generated resolution: 2048×2048 (2K). The phone scans the QR from
/// a TV screen, so extra pixels keep it readable at distance; the WebP is
/// heavily compressible (two-tone) and stays a few KB.
pub const QR_SIZE: u32 = 2048;

/// Encode [payload] as a QR code and return lossless WebP bytes.
///
/// The output is a 2048×2048 white QR with black modules, quiet zone
/// included (rxing's writer pads by 4 modules). Returns `None` on any
/// encoding failure.
pub fn generate_qr_webp(payload: &str) -> Option<Vec<u8>> {
	if payload.is_empty() {
		return None;
	}
	let hints = EncodeHints {
		// "M" error correction — good density/safety balance for a
		// TV-displayed pairing code.
		ErrorCorrection: Some("M".to_string()),
		..EncodeHints::default()
	};
	let matrix = MultiFormatWriter
		.encode_with_hints(
			payload,
			&BarcodeFormat::QR_CODE,
			QR_SIZE as i32,
			QR_SIZE as i32,
			&hints,
		)
		.ok()?;

	// L8 (1 byte/pixel luma) instead of RGBA: the QR is monochrome, so this
	// cuts the intermediate buffer from 16 MiB to 4 MiB. 0 = black, 255 =
	// white; lossless keeps module edges pixel-exact.
	let mut luma = vec![0xffu8; (QR_SIZE as usize) * (QR_SIZE as usize)];
	// matrix.get(x, y) → true = black. The writer pads to exactly 2048², so
	// in-bounds reads are the norm; the check_in_bounds guard is
	// belt-and-suspenders: for rxing's BitMatrix, an x beyond the width
	// (but y within) reads the NEXT ROW's module, not "false" — silently
	// corrupting the quiet zone. Note rxing's check_in_bounds has INVERTED
	// semantics: it returns true when the coordinate is OUT of bounds.
	for y in 0..QR_SIZE {
		for x in 0..QR_SIZE {
			if !matrix.check_in_bounds(x, y) && matrix.get(x, y) {
				luma[(y * QR_SIZE + x) as usize] = 0;
			}
		}
	}

	// method 4 / quality 90: measured ~9ms on 2048² — instant for "New
	// code". (See the module doc for why lossless beats lossy here.)
	let cfg = LosslessConfig::new().with_quality(90.0).with_method(4);
	EncodeRequest::lossless(&cfg, &luma, PixelLayout::L8, QR_SIZE, QR_SIZE)
		.encode()
		.ok()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn generates_webp() {
		let bytes = generate_qr_webp("rcrmcast://v1?h=192.168.1.7&p=8901&t=abc&f=beef").unwrap();
		assert!(!bytes.is_empty());
		assert_eq!(&bytes[0..4], b"RIFF");
		assert_eq!(&bytes[8..12], b"WEBP");
		// Lossless VP8L chunk tag.
		assert!(
			bytes.windows(4).any(|w| w == b"VP8L"),
			"must be lossless VP8L, got {:02X?}",
			&bytes[..24]
		);
		// 2048² two-tone must stay tiny (a few KB).
		assert!(
			bytes.len() < 30_000,
			"2048 QR WebP should be small, got {} bytes",
			bytes.len()
		);
	}

	#[test]
	fn generates_lossless_roundtrip() {
		let payload = "rcrmcast://v1?h=10.0.0.9&p=8901&t=token&f=fp";
		let bytes = generate_qr_webp(payload).unwrap();
		// zenwebp's own decoder must see a 2048² image. L8 encodes as
		// gray → RGBA decode yields r == g == b.
		let (rgba, w, h) = zenwebp::oneshot::decode_rgba(&bytes).expect("decode");
		assert_eq!(w, QR_SIZE);
		assert_eq!(h, QR_SIZE);
		let px = |x: usize, y: usize| {
			let i = (y * QR_SIZE as usize + x) * 4;
			rgba[i]
		};
		// Four corners are quiet zone → pixel-exact white (255) in lossless.
		for (x, y) in [
			(0, 0),
			(QR_SIZE - 1, 0),
			(0, QR_SIZE - 1),
			(QR_SIZE - 1, QR_SIZE - 1),
		] {
			assert_eq!(px(x as usize, y as usize), 0xff, "corner ({x},{y}) white");
		}
		// Something must be dark (modules exist).
		let dark = rgba
			.chunks_exact(4)
			.filter(|p| p[0] < 0x40 && p[1] < 0x40 && p[2] < 0x40)
			.count();
		assert!(dark > 1000, "QR has dark modules: {dark}");
	}

	#[test]
	fn empty_payload_fails() {
		assert!(generate_qr_webp("").is_none());
	}

	/// Full circle: a QR generated here must be readable by the bridge's own
	/// scanner (qr_scan::decode_qr_rgb on the decoded WebP pixels). This
	/// proves the generated code actually works in the field.
	#[test]
	fn generated_qr_scans_back() {
		let payload = "rcrmcast://v1?h=192.168.1.7&p=8901&t=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef&f=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef&n=Living%20Room";
		let bytes = generate_qr_webp(payload).unwrap();
		let (rgba, w, h) = zenwebp::oneshot::decode_rgba(&bytes).expect("decode");
		// decode_qr_rgb wants tight RGB (3 bytes/px); RGBA → RGB.
		let mut rgb = Vec::with_capacity((w as usize) * (h as usize) * 3);
		for px in rgba.chunks_exact(4) {
			rgb.extend_from_slice(&px[..3]);
		}
		let out = crate::qr_scan::decode_qr_rgb(w as usize, h as usize, &rgb);
		assert_eq!(out.as_deref(), Some(payload));
	}
}
