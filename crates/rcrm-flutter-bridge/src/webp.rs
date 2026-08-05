// src/webp.rs
// Pure-Rust WebP thumbnail encoding (zenwebp, AGPL-3.0 — rcrm is
// open-source). Input is raw RGBA pixels; output is lossy WebP bytes.
// Only the ENCODER is used — decoding stays on Flutter's native codecs.

use zenwebp::{EncodeRequest, LossyConfig, PixelLayout};

/// Output buffer: a heap-allocated byte slice (WebP bytes).
/// Freed with `rcrm_free_webp_buf`.
#[repr(C)]
pub struct WebpBuf {
	pub data_len: usize,
	pub data: *mut u8,
}

/// Free a `WebpBuf` returned by `rcrm_encode_thumb_webp` /
/// `rcrm_generate_qr_webp`.
///
/// # Safety
/// `ptr` must be null or a pointer previously returned by those functions.
/// Must not be freed twice.
pub unsafe fn free_webp_buf(ptr: *mut WebpBuf) {
	if ptr.is_null() {
		return;
	}
	let buf = unsafe { Box::from_raw(ptr) };
	if !buf.data.is_null() && buf.data_len > 0 {
		// Reconstruct the exact `Box<[u8]>` the encoder created via
		// `vec_into_webp_buf`. A Box<[u8]>'s layout is determined by its
		// length alone, so this reconstruction is always sound — no
		// capacity mismatch, no wrong-Layout dealloc.
		let slice = std::ptr::slice_from_raw_parts_mut(buf.data, buf.data_len);
		let _ = unsafe { Box::from_raw(slice) };
	}
}

/// Transfer ownership of an encoded byte buffer into a [`WebpBuf`].
///
/// The buffer is first converted to a `Box<[u8]>`, whose layout is fixed by
/// its length. This makes the later `free_webp_buf` reconstruction exact:
/// transferring a `Vec` with spare capacity would make the free path
/// deallocate with the wrong layout (undefined behavior).
pub(crate) fn vec_into_webp_buf(encoded: Vec<u8>) -> Box<WebpBuf> {
	let boxed: Box<[u8]> = encoded.into_boxed_slice();
	let data_len = boxed.len();
	let data = Box::into_raw(boxed).cast::<u8>();
	Box::new(WebpBuf { data_len, data })
}

/// Encode RGBA8 pixels (`width * height * 4` bytes) as lossy WebP at
/// `quality` (0-100). Returns a `WebpBuf` holding the encoded bytes.
///
/// # Safety
/// `data` must be a valid pointer to at least `len` bytes. `len` must equal
/// `width * height * 4`.
pub unsafe fn encode_rgba_webp(
	data: *const u8,
	len: usize,
	width: u32,
	height: u32,
	quality: u8,
) -> Option<Box<WebpBuf>> {
	if data.is_null() || len == 0 || width == 0 || height == 0 {
		return None;
	}
	if len != (width as usize) * (height as usize) * 4 {
		return None;
	}
	let pixels = unsafe { std::slice::from_raw_parts(data, len) };

	let cfg = LossyConfig::new()
		.with_quality(quality.clamp(0, 100) as f32)
		.with_method(5); // speed/quality balance (0 = fast, 6 = best)
	let encoded =
		match EncodeRequest::lossy(&cfg, pixels, PixelLayout::Rgba8, width, height).encode() {
			Ok(b) => b,
			Err(_) => return None,
		};
	Some(vec_into_webp_buf(encoded))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn encodes_rgba_to_webp() {
		// 2x2 solid red RGBA.
		let pixels: Vec<u8> = vec![
			255, 0, 0, 255, 255, 0, 0, 255, //
			255, 0, 0, 255, 255, 0, 0, 255, //
		];
		let buf =
			unsafe { encode_rgba_webp(pixels.as_ptr(), pixels.len(), 2, 2, 82) }.expect("encode");
		assert!(buf.data_len > 0);
		assert!(!buf.data.is_null());
		let bytes = unsafe { std::slice::from_raw_parts(buf.data, buf.data_len) };
		eprintln!("encoded first16: {:02X?}", &bytes[..16.min(bytes.len())]);
		// WebP RIFF magic.
		assert_eq!(&bytes[0..4], b"RIFF");
		assert_eq!(&bytes[8..12], b"WEBP");
		// Round-trip through zenwebp's own decoder to verify pixels.
		let (rgba, w, h) = zenwebp::oneshot::decode_rgba(bytes).expect("decode roundtrip");
		assert_eq!(w, 2);
		assert_eq!(h, 2);
		eprintln!("decoded pixels: {:?}", &rgba[..16]);
		// Lossy WebP on a 2x2 image has tiny per-channel error (±2).
		assert!(
			rgba[0] > 250 && rgba[2] < 8 && rgba[3] == 255,
			"pixel 0 must be red-ish: {:?}",
			&rgba[..4]
		);
		assert!(
			rgba[4] > 250 && rgba[6] < 8 && rgba[7] == 255,
			"pixel 1 must be red-ish: {:?}",
			&rgba[4..8]
		);
		unsafe { free_webp_buf(Box::into_raw(buf)) };
	}

	#[test]
	fn rejects_bad_dimensions() {
		let pixels = [0u8; 16];
		let r = unsafe { encode_rgba_webp(pixels.as_ptr(), 16, 2, 2, 82) };
		assert!(r.is_some());
		let r = unsafe { encode_rgba_webp(pixels.as_ptr(), 15, 2, 2, 82) };
		assert!(r.is_none());
		let r = unsafe { encode_rgba_webp(pixels.as_ptr(), 16, 0, 2, 82) };
		assert!(r.is_none());
	}
}
