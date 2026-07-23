// avif/parse.rs
// Minimal ISOBMFF parser — only what we need:
//   • mdat offset+size → AV1 bitstream for rav1d
//   • ispe dimensions → reject oversize images before decode

pub struct AvifInfo {
	pub width: u32,
	pub height: u32,
	offset: usize,
	len: usize,
}

impl AvifInfo {
	pub fn parse(data: &[u8]) -> Option<Self> {
		let (mdat_off, mdat_sz) = find_mdat(data)?;
		let (w, h) = scan_ispe(data)?;
		let payload_off = mdat_off + 8;
		let payload_len = mdat_sz.saturating_sub(8);
		if payload_off + payload_len > data.len() {
			return None;
		}
		Some(Self {
			width: w,
			height: h,
			offset: payload_off,
			len: payload_len,
		})
	}

	pub fn pixels(&self) -> u64 {
		self.width as u64 * self.height as u64
	}

	pub fn av1_obu<'a>(&self, data: &'a [u8]) -> &'a [u8] {
		&data[self.offset..self.offset + self.len]
	}
}

/// Flat top-level scan — mdat is always a direct child of root.
fn find_mdat(d: &[u8]) -> Option<(usize, usize)> {
	let mut p = 0;
	while p + 8 <= d.len() {
		let sz = u32::from_be_bytes([d[p], d[p + 1], d[p + 2], d[p + 3]]) as usize;
		if sz < 8 || p + sz > d.len() {
			return None;
		}
		if &d[p + 4..p + 8] == b"mdat" {
			return Some((p, sz));
		}
		p += sz;
	}
	None
}

/// Byte-window scan for the ispe fourcc — handles arbitrary nesting depth.
/// ispe full-box layout:
///   [size:4] "ispe" [version:1] [flags:3] [width:4] [height:4]   (20 bytes)
fn scan_ispe(d: &[u8]) -> Option<(u32, u32)> {
	if d.len() < 20 {
		return None;
	}
	let end = d.len() - 19;
	for p in 0..end {
		if &d[p..p + 4] != b"ispe" {
			continue;
		}
		let b = &d[p + 8..p + 20]; // version(1) + flags(3) + w(4) + h(4)
		let w = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
		let h = u32::from_be_bytes([b[8], b[9], b[10], b[11]]);
		if w > 0 && h > 0 {
			return Some((w, h));
		}
	}
	None
}
