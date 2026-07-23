// avif/mod.rs
// Self-contained AVIF decoder — ISOBMFF parse + AV1 decode via rav1d.
// No zenavif dependency. Colour info from the AV1 bitstream, not the container.

mod decode;
mod parse;

use crate::decode::DecodeBuf;

/// rav1d always decodes the full frame internally — even when target_width is
/// tiny. On ≤4 GB RAM devices, full-frame buffers for >12 MP images risk OOM.
const fn max_decode_mp() -> u64 {
	#[cfg(not(test))]
	{
		8_300_000
	}
	#[cfg(test)]
	{
		u64::MAX
	}
}

pub fn decode(data: &[u8], target_width: u32) -> Option<Box<DecodeBuf>> {
	let info = parse::AvifInfo::parse(data)?;
	if info.pixels() > max_decode_mp() {
		return None;
	}
	let obu = info.av1_obu(data);
	decode::decode_frame(obu, target_width)
}
