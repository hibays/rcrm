// jxl/mod.rs
// Self-contained JXL decoder using jxl-rs (the `jxl` crate).
// The decoder writes straight into the final RGBA buffer — no planar float
// allocation on the way out.

mod decode;

use crate::decode::DecodeBuf;

/// Decode a JXL image. `target_width` 0 = full resolution.
pub fn decode(data: &[u8], target_width: u32) -> Option<Box<DecodeBuf>> {
	decode::decode_frame(data, target_width)
}
