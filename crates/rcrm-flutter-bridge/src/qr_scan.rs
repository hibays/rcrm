// src/qr_scan.rs
// rcrm-flutter-bridge — QR decoding for the cast-pairing scan screen
//
// Windows has no QR-capable native barcode API, and the mobile_scanner plugin
// ships no Windows implementation. Instead the bridge decodes QR codes itself
// (zune-jpeg → luma → rxing), so every platform shares one code path.
//
// rxing is a Rust port of the ZXing barcode library — unlike rqrr (a quirc
// port) it has a full detector that tolerates perspective distortion, blur,
// small module sizes and distance, so the phone no longer needs to fill most
// of the frame with the QR code. Cargo features are pinned to decoders +
// full_barcode_format_support + multi_barcode_readers (no image/client deps).
//
// The C-ABI surface (rcrm_decode_qr / _bgra / _luma) lives in lib.rs; this
// module exposes only plain Rust functions.

use std::collections::HashSet;

use rxing::common::HybridBinarizer;
use rxing::{
	BarcodeFormat, BinaryBitmap, DecodeHints, Luma8LuminanceSource, MultiFormatReader, Reader,
};

/// Decode the first QR code found in a JPEG frame.
///
/// Returns `Some(utf8)` on success. Barcode detection is embedded; failures
/// (no grid found, checksum error) return `None`.
pub fn decode_qr_jpeg(data: &[u8]) -> Option<String> {
	let mut dec = zune_jpeg::JpegDecoder::new(zune_jpeg::zune_core::bytestream::ZCursor::new(data));
	// info() only reports after the headers are parsed.
	dec.decode_headers().ok()?;
	let info = dec.info()?;
	let width = info.width as usize;
	let height = info.height as usize;
	let pixels = dec.decode().ok()?;
	// zune-jpeg emits 3 bytes per pixel (RGB) regardless of source colorspace;
	// verify the luma access stays in bounds for every row.
	decode_qr_rgb(width, height, &pixels)
}

/// Decode the first QR code from raw RGB pixels (3 bytes per pixel).
/// Returns `None` when no QR code can be read.
pub fn decode_qr_rgb(width: usize, height: usize, pixels: &[u8]) -> Option<String> {
	if width == 0 || height == 0 || pixels.len() < width * height * 3 {
		return None;
	}
	decode_luma(width, height, |x, y| {
		let i = (y * width + x) * 3;
		// ITU-R BT.601 luma — same weights the blank-frame check uses.
		(0.299 * pixels[i] as f64 + 0.587 * pixels[i + 1] as f64 + 0.114 * pixels[i + 2] as f64)
			.round() as u8
	})
}

/// Decode the first QR code from raw BGRA pixels (4 bytes per pixel, byte
/// order B,G,R,A) with a row stride. iOS' frame stream (camera_avfoundation)
/// exposes BGRA8888 whose CVPixelBuffer rows are 64-byte aligned — for odd
/// widths `bytesPerRow > width * 4`, so `row_stride` is the distance in
/// bytes between row starts (pass `bytesPerRow`). This mirror of
/// [`decode_qr_rgb`] lets the phone-side scanner consume streaming frames
/// without a YUV conversion path.
pub fn decode_qr_bgra(
	width: usize,
	height: usize,
	row_stride: usize,
	pixels: &[u8],
) -> Option<String> {
	if width == 0 || height == 0 || width > 8192 || height > 8192 {
		return None;
	}
	if row_stride < width * 4 {
		return None;
	}
	// Last row needs only `width * 4` bytes; rows before it need full strides.
	if pixels.len() < row_stride * (height - 1) + width * 4 {
		return None;
	}
	decode_luma(width, height, |x, y| {
		let i = y * row_stride + x * 4;
		// bytes are B,G,R,A — BT.601 weights apply to R,G,B.
		(0.299 * pixels[i + 2] as f64 + 0.587 * pixels[i + 1] as f64 + 0.114 * pixels[i] as f64)
			.round() as u8
	})
}

/// Decode a QR code from a greyscale (luma) buffer with a row stride.
///
/// Camera frame streams (CameraX / AVFoundation yuv420) expose the Y plane
/// with padding: `row_stride` is the distance in bytes between row starts.
/// This lets the mobile scanner feed frames straight to rxing without a
/// JPEG round-trip (the Luma8 source needs a tight buffer, so strided rows
/// are repacked here).
pub fn decode_qr_luma(
	width: usize,
	height: usize,
	row_stride: usize,
	data: &[u8],
) -> Option<String> {
	if width == 0 || height == 0 || row_stride < width {
		return None;
	}
	// Last row needs only `width` bytes; rows before it need full strides.
	if data.len() < row_stride * (height - 1) + width {
		return None;
	}
	let mut tight = Vec::with_capacity(width * height);
	for y in 0..height {
		tight.extend_from_slice(&data[y * row_stride..y * row_stride + width]);
	}
	rxing_decode(width, height, tight)
}

/// Convert arbitrary pixels to a tight luma buffer and decode a QR from it.
fn decode_luma(
	width: usize,
	height: usize,
	mut fill: impl FnMut(usize, usize) -> u8,
) -> Option<String> {
	if width == 0 || height == 0 || width > 8192 || height > 8192 {
		return None;
	}
	let mut luma = Vec::with_capacity(width * height);
	for y in 0..height {
		for x in 0..width {
			luma.push(fill(x, y));
		}
	}
	rxing_decode(width, height, luma)
}

/// Run the ZXing (rxing) QR detector/decoder on a tight greyscale buffer.
/// TryHarder is on: the scan screen wants maximum sensitivity (small, far,
/// blurry codes) over speed — decode is still a few ms at frame sizes.
fn rxing_decode(width: usize, height: usize, luma: Vec<u8>) -> Option<String> {
	if width == 0 || height == 0 || luma.len() != width * height {
		return None;
	}
	let source = Luma8LuminanceSource::new(luma, width as u32, height as u32).ok()?;
	let mut bitmap = BinaryBitmap::new(HybridBinarizer::new(source));
	let hints = DecodeHints {
		PossibleFormats: Some(HashSet::from([BarcodeFormat::QR_CODE])),
		TryHarder: Some(true),
		..DecodeHints::default()
	};
	let mut reader = MultiFormatReader::default();
	let result = reader.decode_with_hints(&mut bitmap, &hints).ok()?;
	Some(result.getText().to_string())
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Build a real QR bitmap (via the `qrcode` dev-dependency), scale it up
	/// (real camera frames are far larger than a QR's raw module grid), render
	/// it as greyscale pixels, and expect it to round-trip back to the payload.
	fn render_qr_greyscale(payload: &str, scale: usize) -> (usize, usize, Vec<u8>) {
		let code = qrcode::QrCode::new(payload.as_bytes()).expect("qr encodes");
		let n = code.width();
		let size = n * scale;
		let mut luma = vec![255u8; size * size];
		for y in 0..n {
			for x in 0..n {
				if code.to_colors()[y * n + x] == qrcode::Color::Dark {
					for dy in 0..scale {
						for dx in 0..scale {
							luma[(y * scale + dy) * size + (x * scale + dx)] = 0;
						}
					}
				}
			}
		}
		(size, size, luma)
	}

	/// rxing_decode from a greyscale buffer must recover a QR payload,
	/// including the mirrored variant (webcam previews can be mirrored).
	#[test]
	fn decodes_roundtrip_payload() {
		let payload = "rcrmcast://v1?h=192.168.1.7&p=8443&t=abcdef&f=beef0000";
		let (w, h, luma) = render_qr_greyscale(payload, 4);
		let out = decode_qr_luma(w, h, w, &luma);
		assert_eq!(out.as_deref(), Some(payload));
	}

	/// JPEG round-trip: render a QR to a JPEG (via the jpeg-encoder
	/// dev-dependency) and decode it through the public JPEG entry point.
	#[test]
	fn decodes_from_jpeg() {
		let payload = "rcrmcast://v1?h=10.0.0.5&p=443&t=xyz&f=aabbccdd";
		let (w, h, luma) = render_qr_greyscale(payload, 6);
		// Convert luma back to RGB (jpeg-encoder wants planar RGB).
		let mut rgb = vec![0u8; w * h * 3];
		for (i, v) in luma.iter().enumerate() {
			rgb[i * 3] = *v;
			rgb[i * 3 + 1] = *v;
			rgb[i * 3 + 2] = *v;
		}
		let mut jpeg = Vec::new();
		let encoder = jpeg_encoder::Encoder::new(&mut jpeg, 95);
		encoder
			.encode(&rgb, w as u16, h as u16, jpeg_encoder::ColorType::Rgb)
			.expect("jpeg encodes");
		assert!(!jpeg.is_empty());

		// Sanity: the bridge's own zune-jpeg decoder must parse this JPEG.
		let mut dec =
			zune_jpeg::JpegDecoder::new(zune_jpeg::zune_core::bytestream::ZCursor::new(&jpeg));
		dec.decode_headers().expect("jpeg headers parse");
		let info = dec.info().expect("jpeg headers parse");
		let pixels = dec.decode().expect("jpeg decodes");
		assert_eq!((info.width as usize, info.height as usize), (w, h));
		assert_eq!(pixels.len(), w * h * 3, "RGB 3 bytes/pixel");

		let out = decode_qr_jpeg(&jpeg);
		assert_eq!(out.as_deref(), Some(payload));
	}

	/// BGRA round-trip: exercises the path iOS uses for its frame stream
	/// (camera_avfoundation exposes BGRA8888, never JPEG).
	#[test]
	fn decodes_from_bgra() {
		let payload = "rcrmcast://v1?h=10.1.2.3&p=8443&t=abc&f=11223344";
		let (w, h, luma) = render_qr_greyscale(payload, 6);
		// luma → BGRA (B,G,R,A = v,v,v,255).
		let mut bgra = vec![0u8; w * h * 4];
		for (i, v) in luma.iter().enumerate() {
			bgra[i * 4] = *v; // B
			bgra[i * 4 + 1] = *v; // G
			bgra[i * 4 + 2] = *v; // R
			bgra[i * 4 + 3] = 255; // A
		}
		let out = decode_qr_bgra(w, h, w * 4, &bgra);
		assert_eq!(out.as_deref(), Some(payload));
	}

	/// Strided Y-plane input (CameraX pads rows) must decode like a tight one.
	#[test]
	fn decodes_strided_luma() {
		let payload = "rcrmcast://v1?h=192.168.0.9&p=8080&t=zzz&f=deadbeef";
		let (w, h, luma) = render_qr_greyscale(payload, 6);
		let stride = w + 64;
		let mut padded = vec![0u8; stride * h];
		for y in 0..h {
			padded[y * stride..y * stride + w].copy_from_slice(&luma[y * w..(y + 1) * w]);
		}
		let out = decode_qr_luma(w, h, stride, &padded);
		assert_eq!(out.as_deref(), Some(payload));
	}

	/// A nonsense frame must not panic and must return None.
	#[test]
	fn garbage_frame_returns_none() {
		let noise: Vec<u8> = (0..4096).map(|i| (i * 31) as u8).collect();
		assert!(decode_qr_jpeg(&noise).is_none());
	}

	/// Strided BGRA input (iOS CVPixelBuffer rows are 64-byte aligned, so
	/// bytesPerRow > width*4 for odd widths) must decode like a tight one.
	#[test]
	fn decodes_strided_bgra() {
		let payload = "rcrmcast://v1?h=10.0.0.5&p=8443&t=stride&f=abcdef12";
		let (w, h, luma) = render_qr_greyscale(payload, 6);
		// Odd width makes `width*4` misalign with a 64-byte row: pad to the
		// next multiple of 64 to emulate CVPixelBuffer's alignment.
		let tight_stride = w * 4;
		let row_stride = (tight_stride + 63) & !63;
		assert!(row_stride > tight_stride, "test needs real padding");
		let mut padded = vec![0u8; row_stride * h];
		for y in 0..h {
			let src = &luma[y * w..(y + 1) * w];
			for (x, v) in src.iter().enumerate() {
				let i = y * row_stride + x * 4;
				padded[i] = *v; // B
				padded[i + 1] = *v; // G
				padded[i + 2] = *v; // R
				padded[i + 3] = 255; // A
			}
		}
		let out = decode_qr_bgra(w, h, row_stride, &padded);
		assert_eq!(out.as_deref(), Some(payload));
	}
}
