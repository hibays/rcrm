// heic/mod.rs
// Self-contained HEIC/HEIF still decoder — the `heic` crate (pure-Rust HEVC
// backend), one of the `mobile-decode` feature's dependencies.
//
// Same contract as `avif` and `jxl`: bytes in, RGBA8 out, `target_width` 0
// meaning full resolution.

mod decode;

use crate::decode::DecodeBuf;

/// Decode a HEIC/HEIF image. `target_width` 0 = full resolution.
pub fn decode(data: &[u8], target_width: u32) -> Option<Box<DecodeBuf>> {
	decode::decode_frame(data, target_width)
}
