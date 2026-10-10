// avif/mod.rs
// Self-contained AVIF decoder — ISOBMFF parse + AV1 decode via rav1d.
// No zenavif dependency. Colour info from the AV1 bitstream, not the container.
//
// ORIENTATION: unlike the HEIC path (whose crate applies `irot`/`imir` and the
// clean-aperture crop by default), nothing here applies the container's
// `irot`/`imir` transform or EXIF orientation. The pixels come back in the
// frame's own orientation and the reported width/height are the container's, so
// a rotated AVIF displays sideways and its dimensions read transposed against
// what the user sees. Documented, not implemented: the honest fix is a
// rotation+mirror pass over the decoded RGBA, and until then callers must not
// treat AVIF dimensions as display-oriented (the info sheet's axis swap for EXIF
// orientations 5-8 assumes uprightness, which HEIC/JXL provide and AVIF does
// not).

mod decode;
mod parse;

use crate::decode::{DecodeBuf, Limit};

/// Production entry point — the shipped ceiling, exactly as users get it.
pub fn decode(data: &[u8], target_width: u32) -> Option<Box<DecodeBuf>> {
	decode_with_limit(data, target_width, Limit::PRODUCTION)
}

/// The ceiling is a parameter so a test can exercise the limit itself instead of
/// a relaxed copy of it (the HEIC decoder is shaped the same way). It is also fed
/// to rav1d's own frame limit, so a container whose `ispe` under-reports its size
/// cannot smuggle an oversized frame past the container-level check below.
pub fn decode_with_limit(data: &[u8], target_width: u32, limit: Limit) -> Option<Box<DecodeBuf>> {
	let info = parse::AvifInfo::parse(data)?;
	if info.pixels() > limit.pixels() {
		return None;
	}
	let obu = info.av1_obu(data);
	decode::decode_frame(obu, target_width, limit)
}
