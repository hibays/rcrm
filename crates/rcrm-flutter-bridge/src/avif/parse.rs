// avif/parse.rs
// ISOBMFF item-location parser for AVIF (ISO/IEC 14496-12 + ISO 23008-12):
//   • pitm → primary item, iloc → its byte extent (mdat or idat)
//   • iref/auxl + iinf → alpha auxiliary item
//   • ispe → declared canvas, used as the pre-decode ceiling check
// Feeding a whole mdat to the AV1 decoder breaks every file with auxiliary
// items (alpha, depth): the item payloads share one mdat and are not the
// primary item's OBU.

use std::collections::HashMap;

/// Transform properties (`irot` / `imir` / `clap`) associated with the primary
/// item through `ipco` + `ipma`. Cropping is applied first, then rotation,
/// then mirroring, matching the HEIF/AVIF display pipeline.
#[derive(Default, Debug)]
pub struct Transform {
	pub rotate: u8,
	/// 0 = none, 1 = left-to-right mirror, 2 = top-to-bottom mirror.
	/// `imir` axis 0 (top/bottom exchange) maps to 2, axis 1 (left/right) to 1;
	/// the AVIF spec's axis 0 must NOT be mistaken for "no transform".
	pub mirror: u8,
	/// clap: width, height, horizontal offset, vertical offset (num/den pairs).
	pub crop: Option<[u32; 8]>,
}

impl Transform {
	pub fn is_identity(&self) -> bool {
		self.rotate == 0 && self.mirror == 0 && self.crop.is_none()
	}
}

pub struct AvifInfo {
	pub width: u32,
	pub height: u32,
	primary: ItemData,
	alpha: Option<ItemData>,
	pub transform: Transform,
	/// Present when the primary item is a `grid` derived image; the tiles then
	/// replace `primary`/`alpha` as the sources of pixels.
	pub grid: Option<GridInfo>,
	/// Alpha item that is itself a grid, decoded into a grey alpha plane.
	pub alpha_grid: Option<GridInfo>,
}

#[derive(Debug)]
struct ItemLocation {
	id: u32,
	construction: u16,
	base: u64,
	/// All extents of the item, in order. A segmented item (extent_count > 1)
	/// must be concatenated; keeping only the first truncates a valid AV1 frame.
	extents: Vec<(u64, u64)>,
}

/// Item bytes as either a zero-copy window into the source file (the common
/// single-extent case) or a concatenated buffer for a segmented item.
#[derive(Debug, Default)]
pub struct ItemData {
	window: (usize, usize),
	merged: Vec<u8>,
}

impl ItemData {
	pub fn as_slice<'a>(&'a self, data: &'a [u8]) -> &'a [u8] {
		if self.merged.is_empty() {
			&data[self.window.0..self.window.0 + self.window.1]
		} else {
			&self.merged
		}
	}
}

/// One box: (fourcc, payload start, box end, payload is a full box).
fn box_at(d: &[u8], p: usize, end: usize) -> Option<(&[u8], usize, usize)> {
	if p + 8 > end {
		return None;
	}
	let mut size = u32::from_be_bytes([d[p], d[p + 1], d[p + 2], d[p + 3]]) as usize;
	let typ = &d[p + 4..p + 8];
	let mut header = 8;
	if size == 1 {
		if p + 16 > end {
			return None;
		}
		size = u64::from_be_bytes([
			d[p + 8],
			d[p + 9],
			d[p + 10],
			d[p + 11],
			d[p + 12],
			d[p + 13],
			d[p + 14],
			d[p + 15],
		]) as usize;
		header = 16;
	} else if size == 0 {
		size = end - p;
	}
	if size < header {
		return None;
	}
	// A malicious largesize can be u64::MAX; p + size would wrap and make the
	// bounds check pass, handing children() an end before p (walks backwards).
	let box_end = p.checked_add(size)?;
	if box_end > end {
		return None;
	}
	Some((typ, p + header, box_end))
}

fn children(d: &[u8], start: usize, end: usize) -> Vec<(&[u8], usize, usize)> {
	let mut out = Vec::new();
	let mut p = start;
	while let Some((typ, payload, box_end)) = box_at(d, p, end) {
		out.push((typ, payload, box_end));
		p = box_end;
	}
	out
}

fn find_box(d: &[u8], start: usize, end: usize, want: &[u8; 4]) -> Option<(usize, usize)> {
	children(d, start, end)
		.into_iter()
		.find(|(typ, _, _)| *typ == want.as_slice())
		.map(|(_, payload, box_end)| (payload, box_end))
}

fn u16at(d: &[u8], p: usize) -> Option<u16> {
	Some(u16::from_be_bytes(d.get(p..p + 2)?.try_into().ok()?))
}
fn u32at(d: &[u8], p: usize) -> Option<u32> {
	Some(u32::from_be_bytes(d.get(p..p + 4)?.try_into().ok()?))
}
fn uint_at(d: &[u8], p: usize, size: usize) -> Option<u64> {
	let bytes = d.get(p..p + size)?;
	let mut v = 0u64;
	for b in bytes {
		v = (v << 8) | *b as u64;
	}
	Some(v)
}

/// Map item IDs to the URN of their `auxC` property. alpha/depth/gain-map
/// auxiliary items all carry an `auxl` reference; the URN is the only honest
/// discriminator (ISO/IEC 23008-12 + AVIF spec).
/// Everything derived from `ipco` + `ipma`, collected in ONE walk. Previously
/// `parse_aux_urns`, `parse_transform` and `scan_ispe` each traversed the same
/// property tree (scan_ispe even byte-scanned the whole file); that is three
/// parses of identical bytes. The structural ispe on the primary item is also
/// strictly more correct than finding the first fourcc in mdat.
struct ItemProps<'a> {
	transform: Transform,
	ispe: Option<(u32, u32)>,
	aux_urns: Vec<(u32, &'a [u8])>,
}

fn parse_item_props<'a>(
	d: &'a [u8],
	items: &[(&[u8], usize, usize)],
	primary_id: u32,
) -> ItemProps<'a> {
	let mut out = ItemProps {
		transform: Transform::default(),
		ispe: None,
		aux_urns: Vec::new(),
	};
	let Some((iprp, iprp_end)) = find_child(items, b"iprp") else {
		return out;
	};
	let prop_items = children(d, iprp, iprp_end);
	let Some((ipco, ipco_end)) = find_child(&prop_items, b"ipco") else {
		return out;
	};
	let props = children(d, ipco, ipco_end);
	let Some((ipma, _)) = find_child(&prop_items, b"ipma") else {
		return out;
	};
	let version = *d.get(ipma).unwrap_or(&0);
	// libavif read.c:2993: ipma flags&1 => property_index is u15 (2-byte
	// association), otherwise u7 (1 byte). The old code always read 1 byte,
	// so a spec-legal flags=1 file lost irot/clap/imir associations.
	let flags = u32::from_be_bytes([
		0,
		*d.get(ipma + 1).unwrap_or(&0),
		*d.get(ipma + 2).unwrap_or(&0),
		*d.get(ipma + 3).unwrap_or(&0),
	]);
	let u15 = flags & 1 != 0;
	let count = u32at(d, ipma + 4).unwrap_or(0) as usize;
	let mut pos = ipma + 8;
	for _ in 0..count.min(4096) {
		let id = if version == 0 {
			let v = u16at(d, pos).unwrap_or(0) as u32;
			pos += 2;
			v
		} else {
			let v = u32at(d, pos).unwrap_or(0);
			pos += 4;
			v
		};
		let associations = *d.get(pos).unwrap_or(&0) as usize; // u8, 0..=255
		pos += 1;
		for _ in 0..associations {
			// bit(1) essential + u7/u15 property_index, big-endian. We don't
			// act on `essential` (this reader is deliberately lenient about
			// unknown essential properties), so only the index is read.
			let (_essential, index) = if u15 {
				let word = u16at(d, pos).unwrap_or(0);
				pos += 2;
				((word >> 15) != 0, (word & 0x7fff) as usize)
			} else {
				let byte = *d.get(pos).unwrap_or(&0);
				pos += 1;
				((byte & 0x80) != 0, (byte & 0x7f) as usize)
			};
			// ISO/IEC 14496-12 8.11.14.3: index 0 means "no property".
			if index == 0 {
				continue;
			}
			let Some((typ, payload, box_end)) = props.get(index.wrapping_sub(1)) else {
				continue;
			};
			let (payload, box_end) = (*payload, *box_end);
			if *typ == b"auxC" {
				// auxC FullBox (4 bytes) then a null-terminated URN, borrowed
				// from the file. Bound the URN by THIS box's end, not the file
				// end: a malformed unterminated URN must not swallow the bytes
				// of following boxes. Few aux items, so Vec beats HashMap+String.
				let tail = d.get(payload + 4..box_end).unwrap_or(&[]);
				let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
				let urn = &tail[..end];
				if let Some(slot) = out.aux_urns.iter_mut().find(|(i, _)| *i == id) {
					slot.1 = urn;
				} else {
					out.aux_urns.push((id, urn));
				}
				continue;
			}
			if id != primary_id {
				continue;
			}
			match *typ {
				// libavif writes these as plain property boxes (no FullBox
				// version/flags), so the fields start at the payload.
				b"irot" => out.transform.rotate = d.get(payload).copied().unwrap_or(0) & 3,
				b"imir" => {
					// ISO/IEC 23008-12 6.5.12: axis 0 exchanges top/bottom,
					// axis 1 exchanges left/right. Map to our mirror codes
					// (2 = vertical, 1 = horizontal); never leave 0 = "none".
					out.transform.mirror = if d.get(payload).copied().unwrap_or(0) & 1 == 0 {
						2
					} else {
						1
					};
				}
				b"clap" => {
					if let Some(bytes) = d.get(payload..payload + 32) {
						let mut crop = [0u32; 8];
						for (i, word) in crop.iter_mut().enumerate() {
							*word = u32::from_be_bytes([
								bytes[i * 4],
								bytes[i * 4 + 1],
								bytes[i * 4 + 2],
								bytes[i * 4 + 3],
							]);
						}
						out.transform.crop = Some(crop);
					}
				}
				b"ispe" => {
					// ispe is a FullBox: version+flags (4), width (4), height (4).
					if let (Some(w), Some(h)) = (u32at(d, payload + 4), u32at(d, payload + 8))
						&& w > 0
						&& h > 0
					{
						out.ispe = Some((w, h));
					}
				}
				_ => {}
			}
		}
	}
	out
}

impl AvifInfo {
	pub fn parse(data: &[u8]) -> Option<Self> {
		let (meta_payload, meta_end) = find_box(data, 0, data.len(), b"meta")?;
		let meta = meta_payload.checked_add(4)?; // skip the meta FullBox version+flags
		if meta > meta_end {
			return None;
		}
		let items = children(data, meta, meta_end);

		let primary_id = find_child(&items, b"pitm").and_then(|(p, _)| {
			let version = *data.get(p)?;
			if version == 0 {
				u16at(data, p + 4).map(u32::from)
			} else {
				u32at(data, p + 4)
			}
		})?;

		// construction_method 1 locates the item inside `idat`; its base offset
		// is relative to the idat box payload, not the file.
		let locations = parse_iloc(data, &items, primary_id)?;
		let item_types = parse_iinf(data, &items);
		let aux_refs = parse_iref_auxl(data, &items);

		let primary = locate(data, &locations, primary_id)?;
		// `auxl` links alpha, depth and gain-map items alike; only the `auxC`
		// property's URN says which is which. Without this check a depth map or
		// HDR gain map would be composited as alpha, making the image transparent.
		let props = parse_item_props(data, &items, primary_id);
		let alpha_id = aux_refs
			.iter()
			.find(|(from, to)| {
				*to == primary_id
					&& *from != primary_id
					&& item_types.contains_key(from)
					&& aux_is_alpha(&props.aux_urns, &aux_refs, *from)
			})
			.map(|(from, _)| *from);
		let alpha = alpha_id.and_then(|id| locate(data, &locations, id));
		let transform = props.transform;
		// Structural ispe from the primary item; fall back to the byte scan
		// only for unusual nesting where ipma does not associate an ispe.
		let (w, h) = props.ispe.or_else(|| scan_ispe(data))?;

		let is_grid = |id: u32| item_types.get(&id).is_some_and(|t| *t == *b"grid");
		let grid = if is_grid(primary_id) {
			Some(parse_grid(
				data,
				&items,
				&locations,
				&aux_refs,
				&props.aux_urns,
				primary_id,
				&primary,
			)?)
		} else {
			None
		};
		// An alpha item can itself be a grid (libavif's
		// color_grid_alpha_grid_gainmap_nogrid.avif). Feeding its config bytes to
		// the AV1 decoder would composite garbage as alpha.
		let alpha_grid = match (alpha_id, alpha.as_ref()) {
			(Some(id), Some(config)) if is_grid(id) => parse_grid(
				data,
				&items,
				&locations,
				&aux_refs,
				&props.aux_urns,
				id,
				config,
			),
			_ => None,
		};

		Some(Self {
			width: w,
			height: h,
			primary,
			alpha,
			transform,
			grid,
			alpha_grid,
		})
	}

	pub fn pixels(&self) -> u64 {
		self.width as u64 * self.height as u64
	}

	pub fn av1_obu<'a>(&'a self, data: &'a [u8]) -> &'a [u8] {
		self.primary.as_slice(data)
	}

	pub fn alpha_obu<'a>(&'a self, data: &'a [u8]) -> Option<&'a [u8]> {
		self.alpha.as_ref().map(|a| a.as_slice(data))
	}
}

fn find_child<'a>(items: &'a [(&'a [u8], usize, usize)], want: &[u8; 4]) -> Option<(usize, usize)> {
	items
		.iter()
		.find(|(typ, _, _)| *typ == want.as_slice())
		.map(|(_, payload, end)| (*payload, *end))
}

fn parse_iloc(
	d: &[u8],
	items: &[(&[u8], usize, usize)],
	primary_id: u32,
) -> Option<Vec<ItemLocation>> {
	let (p, _) = find_child(items, b"iloc")?;
	let version = *d.get(p)?;
	let sizes = *d.get(p + 4)?;
	let (offset_size, length_size) = ((sizes >> 4) as usize, (sizes & 0x0f) as usize);
	let advertised_base = ((*d.get(p + 5)? >> 4) & 0x0f) as usize;
	let index_size = if version >= 1 {
		(*d.get(p + 5)? & 0x0f) as usize
	} else {
		0
	};
	// ISO/IEC 14496-12: these widths are 0/4/8 only. libavif rejects other
	// values (read.c:2004-2005); without the check a crafted size can make a
	// tiny file drive huge with_capacity reservations in parse_iloc_layout.
	if !matches!(offset_size, 0 | 4 | 8)
		|| !matches!(length_size, 0 | 4 | 8)
		|| !matches!(advertised_base, 0 | 4 | 8)
		|| !matches!(index_size, 0 | 4 | 8)
	{
		return None;
	}
	// libavif writes a 2-byte base_offset here while advertising zero in some
	// versions; try the declared size first, then the common alternatives, and
	// keep the first layout whose extents all point inside the file.
	for base_size in [advertised_base, 0, 2, 4, 8] {
		if let Some(locations) = parse_iloc_layout(
			d,
			p,
			version,
			offset_size,
			length_size,
			base_size,
			index_size,
		) && locations.iter().any(|loc| loc.id == primary_id)
		{
			return Some(locations);
		}
	}
	None
}

fn parse_iloc_layout(
	d: &[u8],
	p: usize,
	version: u8,
	offset_size: usize,
	length_size: usize,
	base_size: usize,
	index_size: usize,
) -> Option<Vec<ItemLocation>> {
	// version+flags (4), offset/length sizes (1), base/index sizes (1).
	let mut pos = p + 6;
	let count = if version < 2 {
		u16at(d, pos)? as usize
	} else {
		u32at(d, pos)? as usize
	};
	if count == 0 {
		return None;
	}
	pos += if version < 2 { 2 } else { 4 };
	// Byte budget, not a hardcoded count: every item consumes at least its
	// mandatory fields, so `count` items cannot fit in fewer bytes than that.
	// This bounds Vec::with_capacity(count) by the file size (v2's count is a
	// u32 — a 4-byte field must not drive a multi-GB reservation). A large,
	// structurally legal file with >1024 items is accepted (libavif does too).
	let min_item = (if version < 2 { 2 } else { 4 }) // item_ID
		+ (if version >= 1 { 2 } else { 0 }) // construction_method
		+ 2 // data_reference_index
		+ base_size // base_offset
		+ 2; // extent_count
	if count
		.checked_mul(min_item)
		.is_none_or(|need| need > d.len().saturating_sub(pos))
	{
		return None;
	}
	let mut out = Vec::new();
	out.try_reserve_exact(count).ok()?;
	for _ in 0..count {
		let id = if version < 2 {
			u16at(d, pos)? as u32
		} else {
			u32at(d, pos)?
		};
		pos += if version < 2 { 2 } else { 4 };
		let construction = if version >= 1 {
			let c = u16at(d, pos)?;
			pos += 2; // construction_method
			// Only file(0) and idat(1) are defined; libavif rejects > 1.
			if c > 1 {
				return None;
			}
			c
		} else {
			0
		};
		// ISO/IEC 14496-12: data_reference_index is present in EVERY version,
		// right after construction_method (or item_ID for v0). The old v0 branch
		// skipped it, shifting base/extents by 2 bytes and rejecting files with
		// a nonzero base_offset that decode fine in libavif.
		pos += 2; // data_reference_index (unused: this reader has no external data refs)
		let base = uint_at(d, pos, base_size)?;
		pos += base_size;
		let extents = u16at(d, pos)? as usize;
		pos += 2;
		// Byte budget, not a hardcoded count: each extent consumes its
		// mandatory offset/length/index bytes, so the declared count must fit
		// in the file. This bounds Vec::with_capacity(extents) (a 1.1 KB file
		// declaring 65535 extents cannot reserve 2.1 MB). A structurally legal
		// file with many in-file extents is accepted, as libavif does.
		let per_extent = offset_size + length_size + index_size;
		if per_extent == 0 {
			return None;
		}
		let ext_bytes = extents.checked_mul(per_extent)?;
		if ext_bytes > d.len().saturating_sub(pos) {
			return None;
		}
		let mut ext = Vec::new();
		ext.try_reserve_exact(extents).ok()?;
		for _ in 0..extents {
			// ISO/IEC 14496-12 8.11.3.1 / libavif read.c:2062: for v1/v2 with
			// index_size>0, item_reference_index comes BEFORE extent_offset /
			// extent_length. Reading it last shifts every field (M1).
			pos += index_size;
			let off = uint_at(d, pos, offset_size)?;
			pos += offset_size;
			let len = uint_at(d, pos, length_size)?;
			pos += length_size;
			// A zero-length extent contributes no bytes. libavif accepts it
			// (read.c:2095-2104); skipping it keeps the real extents intact.
			if len == 0 {
				continue;
			}
			ext.push((off, len));
		}
		// Keep the bound check the base_size heuristic relies on to reject a
		// wrong candidate layout. construction_method=1 adds the idat payload
		// offset, so this is necessary but not sufficient; locate() rechecks
		// against the real absolute offset.
		for &(off, len) in &ext {
			if base.checked_add(off)?.checked_add(len)? > d.len() as u64 {
				return None;
			}
		}
		out.push(ItemLocation {
			id,
			construction,
			base,
			extents: ext,
		});
	}
	Some(out)
}

/// Offset of the `idat` box payload. ISO/IEC 23008-12 puts `idat` inside `meta`
/// (some writers place it at the top level), so a top-level-only search misses
/// the common case.
fn idat_payload_offset(d: &[u8]) -> Option<usize> {
	if let Some((p, _)) = find_box(d, 0, d.len(), b"idat") {
		return Some(p);
	}
	let (meta_payload, meta_end) = find_box(d, 0, d.len(), b"meta")?;
	let meta = meta_payload.checked_add(4)?;
	find_child(&children(d, meta, meta_end), b"idat").map(|(p, _)| p)
}

fn locate(d: &[u8], locations: &[ItemLocation], id: u32) -> Option<ItemData> {
	let loc = locations.iter().find(|l| l.id == id)?;
	if loc.extents.is_empty() {
		return None; // an item with no extents has no data
	}
	let base = if loc.construction == 1 {
		// idat-relative offsets are relative to the box payload.
		idat_payload_offset(d)? as u64
	} else {
		0
	};
	// A malicious iloc can carry u64 offsets that wrap; checked arithmetic keeps
	// the bounds check below honest instead of aliasing into arbitrary bytes.
	// Common single-extent case: validate in place and hand out a zero-copy
	// window into `d` before allocating anything (not even the `windows` Vec).
	let window_for = |off: u64, len: u64| -> Option<(usize, usize)> {
		let start = base.checked_add(loc.base)?.checked_add(off)?;
		let start = usize::try_from(start).ok()?;
		let len = usize::try_from(len).ok()?;
		if start > d.len() || len > d.len() - start || len == 0 {
			return None;
		}
		Some((start, len))
	};
	if loc.extents.len() == 1 {
		return Some(ItemData {
			window: window_for(loc.extents[0].0, loc.extents[0].1)?,
			merged: Vec::new(),
		});
	}
	// Segmented item: validate every extent, bounding the merged total by the
	// file size before any reservation.
	let mut windows = Vec::new();
	windows.try_reserve_exact(loc.extents.len()).ok()?;
	let mut total = 0u64;
	for &(off, len) in &loc.extents {
		let (start, len) = window_for(off, len)?;
		total = total.checked_add(len as u64)?;
		windows.push((start, len));
	}
	// The concatenated item can never legitimately exceed the source file.
	// Overlapping extents (each in-bounds) could otherwise make a 1 MB file
	// reserve gigabytes (measured 4.29 GB). This bound is checked BEFORE the
	// reservation, so a hostile iloc cannot trigger a huge allocation.
	if total > d.len() as u64 {
		return None;
	}
	// Segmented item: concatenate every extent into one owned buffer. This is
	// rare (libavif's own test corpus has a couple) and only here is a copy paid.
	let mut merged = Vec::new();
	merged
		.try_reserve_exact(usize::try_from(total).ok()?)
		.ok()?;
	for (start, len) in windows {
		merged.extend_from_slice(&d[start..start + len]);
	}
	Some(ItemData {
		window: (0, 0),
		merged,
	})
}

fn parse_iinf(d: &[u8], items: &[(&[u8], usize, usize)]) -> HashMap<u32, [u8; 4]> {
	let mut out = HashMap::new();
	let Some((p, _)) = find_child(items, b"iinf") else {
		return out;
	};
	let version = *d.get(p).unwrap_or(&0);
	// iinf FullBox: version+flags (4), entry_count (2 or 4), then infe boxes.
	let mut pos = p + 4;
	let count = if version < 2 {
		let c = u16at(d, pos).unwrap_or(0) as usize;
		pos += 2;
		c
	} else {
		let c = u32at(d, pos).unwrap_or(0) as usize;
		pos += 4;
		c
	};
	for _ in 0..count {
		let Some((typ, payload, end)) = box_at(d, pos, d.len()) else {
			break;
		};
		pos = end;
		if typ != b"infe" || payload + 4 > d.len() {
			continue;
		}
		let v = d[payload];
		let printable = |at: usize| {
			d.get(at..at + 4)
				.is_some_and(|t| t.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_'))
		};
		// libavif writes version-2 infe with a 16-bit item_ID followed by a
		// 16-bit protection index, despite the 32-bit ID in the spec. Pick the
		// layout whose item_type looks like a fourcc.
		let (id, item_type_at) = if printable(payload + 8) {
			(u16at(d, payload + 4).map(u32::from), payload + 8)
		} else if v >= 2 && printable(payload + 10) {
			(u32at(d, payload + 4), payload + 10)
		} else {
			(None, payload + 8)
		};
		if let (Some(id), Some(t)) = (id, d.get(item_type_at..item_type_at + 4)) {
			out.insert(id, t.try_into().unwrap_or(*b"    "));
		}
	}
	out
}

/// Every `iref` entry of one type, grouped by its `from_item_ID` and keeping
/// all `to_item_ID`s. `dimg` legitimately has many targets (one per tile);
/// `auxl` must have exactly one — that distinction is made by the caller.
fn iref_groups(d: &[u8], items: &[(&[u8], usize, usize)], want: &[u8; 4]) -> Vec<(u32, Vec<u32>)> {
	let mut out = Vec::new();
	let Some((p, end)) = find_child(items, b"iref") else {
		return out;
	};
	let version = *d.get(p).unwrap_or(&0);
	let width = if version == 0 { 2 } else { 4 };
	let mut pos = p + 4;
	while pos < end {
		let Some((typ, payload, box_end)) = box_at(d, pos, end) else {
			break;
		};
		pos = box_end;
		if typ != want {
			continue;
		}
		let Some(from) = uint_at(d, payload, width) else {
			continue;
		};
		let refs = uint_at(d, payload + width, width).unwrap_or(0) as usize;
		let mut targets = Vec::new();
		for i in 0..refs.min(4096) {
			if let Some(to) = uint_at(d, payload + width * (2 + i), width) {
				targets.push(to as u32);
			}
		}
		out.push((from as u32, targets));
	}
	out
}

fn parse_iref_auxl(d: &[u8], items: &[(&[u8], usize, usize)]) -> Vec<(u32, u32)> {
	iref_groups(d, items, b"auxl")
		.into_iter()
		// An auxiliary item must reference exactly one item. libavif ignores
		// ambiguous multi-target references (circle_auxl_two_targets.avif),
		// otherwise a depth/gain-map target could be composited as alpha.
		.filter(|(_, targets)| targets.len() == 1)
		.map(|(from, targets)| (from, targets[0]))
		.collect()
}

/// A `grid` derived image: `rows`×`cols` AV1 tiles stitched into `out_w`×`out_h`.
#[derive(Debug)]
pub struct GridInfo {
	pub rows: u32,
	pub cols: u32,
	pub out_w: u32,
	pub out_h: u32,
	/// Tile item data in row-major order.
	pub tiles: Vec<ItemData>,
	/// Alpha item data, parallel to `tiles`, when the tiles have alpha.
	pub alpha_tiles: Option<Vec<ItemData>>,
}

/// An auxiliary item referenced by more than one item is ambiguous; libavif
/// ignores it entirely (both avifdec and ffmpeg decode those files opaque).
fn aux_is_unambiguous(aux_refs: &[(u32, u32)], from: u32) -> bool {
	aux_refs.iter().filter(|(f, _)| *f == from).count() == 1
}

/// libavif internal.h:78-79 / read.c:1947 `isAlphaURN`: exactly these two
/// URNs mark an auxiliary item as alpha. `ends_with(b":alpha")` both missed
/// ALPHA1 and wrongly accepted arbitrary suffix URNs.
fn is_alpha_urn(urn: &[u8]) -> bool {
	urn == b"urn:mpeg:mpegB:cicp:systems:auxiliary:alpha" || urn == b"urn:mpeg:hevc:2015:auxid:1"
}

/// An `auxl` source item is alpha iff it is unambiguous and its `auxC` URN is
/// an alpha URN. An item with no recorded URN stays lenient (matches the
/// long-standing behaviour for files lacking `auxC`).
fn aux_is_alpha(aux_urns: &[(u32, &[u8])], aux_refs: &[(u32, u32)], from: u32) -> bool {
	aux_is_unambiguous(aux_refs, from)
		&& aux_urns
			.iter()
			.find(|(id, _)| *id == from)
			.is_none_or(|(_, urn)| is_alpha_urn(urn))
}

fn parse_grid(
	data: &[u8],
	items: &[(&[u8], usize, usize)],
	locations: &[ItemLocation],
	aux_refs: &[(u32, u32)],
	aux_urns: &[(u32, &[u8])],
	grid_id: u32,
	config: &ItemData,
) -> Option<GridInfo> {
	let (rows, cols, out_w, out_h) = parse_grid_config(config.as_slice(data))?;
	let tile_ids = iref_groups(data, items, b"dimg")
		.into_iter()
		.find(|(from, _)| *from == grid_id)
		.map(|(_, ids)| ids)?;
	let tiles: Vec<ItemData> = tile_ids
		.iter()
		.map(|id| locate(data, locations, *id))
		.collect::<Option<Vec<_>>>()?;
	let alpha_tiles = {
		let mut ats = Vec::new();
		ats.try_reserve_exact(tiles.len()).ok()?;
		for id in &tile_ids {
			// libavif read.c:5492 applies avifDecoderItemIsAlphaAux to each
			// grid tile's aux item: it must carry an alpha URN. Without this
			// check a depth/gain-map aux tile is composited as alpha, making a
			// large area transparent (verified with a depth-URN patch).
			let aid = aux_refs
				.iter()
				.find(|(_, to)| to == id)
				.map(|(from, _)| *from)
				.filter(|from| aux_is_alpha(aux_urns, aux_refs, *from));
			ats.push(aid.and_then(|a| locate(data, locations, a)));
		}
		if !ats.is_empty() && ats.iter().all(Option::is_some) {
			Some(ats.into_iter().flatten().collect())
		} else {
			None
		}
	};
	Some(GridInfo {
		rows,
		cols,
		out_w,
		out_h,
		tiles,
		alpha_tiles,
	})
}

fn parse_grid_config(data: &[u8]) -> Option<(u32, u32, u32, u32)> {
	let _version = *data.first()?;
	let flags = *data.get(1)?;
	let rows = *data.get(2)? as u32 + 1;
	let cols = *data.get(3)? as u32 + 1;
	let (w, h) = if flags & 1 != 0 && data.len() >= 12 {
		(u32at(data, 4)?, u32at(data, 8)?)
	} else if data.len() >= 8 {
		// libavif writes the output dimensions as 16-bit values.
		(u16at(data, 4)? as u32, u16at(data, 6)? as u32)
	} else {
		(0, 0)
	};
	Some((rows, cols, w, h))
}

/// Byte-window scan for the ispe fourcc — handles arbitrary nesting depth.
fn scan_ispe(d: &[u8]) -> Option<(u32, u32)> {
	if d.len() < 20 {
		return None;
	}
	let end = d.len() - 16;
	for p in 0..end {
		if &d[p..p + 4] != b"ispe" {
			continue;
		}
		// "ispe" fourcc at p..p+4; FullBox version+flags at p+4..p+8;
		// width at p+8..p+12; height at p+12..p+16.
		let b = &d[p + 4..p + 16];
		let w = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
		let h = u32::from_be_bytes([b[8], b[9], b[10], b[11]]);
		if w > 0 && h > 0 {
			return Some((w, h));
		}
	}
	None
}

#[cfg(test)]
mod tests {
	use super::*;

	const ALPHA: [u8; 3] = [0xA0, 0xA1, 0xA2];
	const PRIMARY: [u8; 4] = [0x0F, 0x10, 0x11, 0x12];

	/// In-process parse benchmark (no FFI/thread noise). Run with
	/// `cargo test --features mobile-decode --release parse_bench -- --ignored --nocapture`.
	#[test]
	#[ignore]
	fn parse_bench() {
		for name in [
			"white_1x1.avif",
			"jqis5.avif",
			"big_gbrp.avif",
			"sofa_grid1x5_420.avif",
		] {
			let path = format!("tests/testdata/avif/{name}");
			let alt = format!("tests/testdata/avif/libavif/{name}");
			let data = std::fs::read(&path).or_else(|_| std::fs::read(&alt));
			let Ok(data) = data else { continue };
			let n = 2000;
			let t = std::time::Instant::now();
			let mut sink = 0u64;
			for _ in 0..n {
				sink = sink.wrapping_add(AvifInfo::parse(&data).map(|i| i.pixels()).unwrap_or(0));
			}
			let ns = t.elapsed().as_nanos() / n as u128;
			eprintln!("{name}: {ns} ns/parse (sink {sink})");
		}
	}

	fn box_bytes(typ: &[u8; 4], payload: &[u8]) -> Vec<u8> {
		let mut out = Vec::new();
		out.extend_from_slice(&((8 + payload.len()) as u32).to_be_bytes());
		out.extend_from_slice(typ);
		out.extend_from_slice(payload);
		out
	}

	fn full_box(typ: &[u8; 4], version: u8, payload: &[u8]) -> Vec<u8> {
		let mut p = vec![version, 0, 0, 0];
		p.extend_from_slice(payload);
		box_bytes(typ, &p)
	}

	/// Minimal two-item AVIF: item 1 is the primary, item 2 is `auxl`-linked to
	/// it. `aux_urn` models the item's `auxC` property (real libavif files carry
	/// one); `None` models a file with no `auxC`, which must keep the lenient
	/// behaviour.
	fn two_item_avif(
		aux_urn: Option<&str>,
		extra_auxl_target: Option<u16>,
		shared_auxl_target: Option<u16>,
	) -> Vec<u8> {
		let pitm = full_box(b"pitm", 0, &1u16.to_be_bytes());
		let mut iinf_body = 2u16.to_be_bytes().to_vec();
		for (id, typ) in [(1u16, b"av01"), (2u16, b"auxv")] {
			let mut infe = Vec::new();
			infe.extend_from_slice(&id.to_be_bytes());
			infe.extend_from_slice(&0u16.to_be_bytes());
			infe.extend_from_slice(typ);
			infe.push(0);
			iinf_body.extend_from_slice(&full_box(b"infe", 0, &infe));
		}
		let iinf = full_box(b"iinf", 0, &iinf_body);
		let mut auxl = Vec::new();
		auxl.extend_from_slice(&2u16.to_be_bytes()); // from_item_ID
		auxl.extend_from_slice(&(1 + extra_auxl_target.is_some() as u16).to_be_bytes());
		auxl.extend_from_slice(&1u16.to_be_bytes()); // to_item_ID (primary)
		if let Some(extra) = extra_auxl_target {
			auxl.extend_from_slice(&extra.to_be_bytes());
		}
		let mut iref_body = box_bytes(b"auxl", &auxl);
		if let Some(extra) = shared_auxl_target {
			let mut shared = Vec::new();
			shared.extend_from_slice(&2u16.to_be_bytes()); // same from_item_ID
			shared.extend_from_slice(&1u16.to_be_bytes());
			shared.extend_from_slice(&extra.to_be_bytes());
			iref_body.extend_from_slice(&box_bytes(b"auxl", &shared));
		}
		let iref = full_box(b"iref", 0, &iref_body);
		let ispe = full_box(b"ispe", 0, &[0, 0, 0, 1, 0, 0, 0, 1]);

		let iprp = aux_urn.map(|urn| {
			let mut auxc_payload = vec![0u8, 0, 0, 0]; // FullBox version+flags
			auxc_payload.extend_from_slice(urn.as_bytes());
			auxc_payload.push(0);
			let auxc = box_bytes(b"auxC", &auxc_payload);
			let ipco = box_bytes(b"ipco", &auxc);
			let mut ipma_body = 1u32.to_be_bytes().to_vec(); // entry_count
			ipma_body.extend_from_slice(&2u16.to_be_bytes()); // item_ID 2
			ipma_body.push(1); // association_count
			ipma_body.push(0x01); // -> ipco property index 1
			let ipma = full_box(b"ipma", 0, &ipma_body);
			box_bytes(b"iprp", &[ipco, ipma].concat())
		});
		let iprp_len = iprp.as_ref().map_or(0, Vec::len);

		let ftyp = box_bytes(b"ftyp", b"avifmif1");
		// Per item: item_ID(2) + data_ref(2) + extent_count(2) + off(4) + len(4).
		let iloc_len = 8 + 4 + 4 + 2 * 14;
		let meta_len =
			8 + 4 + pitm.len() + iinf.len() + iref.len() + ispe.len() + iloc_len + iprp_len;
		let prefix_len = ftyp.len() + meta_len + 8;
		let alpha_off = prefix_len as u32;
		let primary_off = (prefix_len + ALPHA.len()) as u32;

		let mut iloc_body = vec![0x44, 0, 0, 2];
		for (id, off, len) in [
			(1u16, primary_off, PRIMARY.len() as u32),
			(2u16, alpha_off, ALPHA.len() as u32),
		] {
			iloc_body.extend_from_slice(&id.to_be_bytes());
			iloc_body.extend_from_slice(&0u16.to_be_bytes()); // data_reference_index
			iloc_body.extend_from_slice(&1u16.to_be_bytes()); // extent_count
			iloc_body.extend_from_slice(&off.to_be_bytes());
			iloc_body.extend_from_slice(&len.to_be_bytes());
		}
		let iloc = full_box(b"iloc", 0, &iloc_body);
		assert_eq!(iloc.len(), iloc_len);

		let mut meta_body = Vec::new();
		meta_body.extend_from_slice(&pitm);
		meta_body.extend_from_slice(&iinf);
		meta_body.extend_from_slice(&iref);
		meta_body.extend_from_slice(&ispe);
		if let Some(iprp) = iprp {
			meta_body.extend_from_slice(&iprp);
		}
		meta_body.extend_from_slice(&iloc);
		let meta = full_box(b"meta", 0, &meta_body);
		assert_eq!(meta.len(), meta_len);

		let mut file = ftyp;
		file.extend_from_slice(&meta);
		let mut mdat_payload = ALPHA.to_vec();
		mdat_payload.extend_from_slice(&PRIMARY);
		file.extend_from_slice(&box_bytes(b"mdat", &mdat_payload));
		file
	}

	#[test]
	fn box_at_rejects_overflowing_large_size() {
		// A child box with largesize == usize::MAX at p=8 makes p+size wrap to a
		// value below p. Without a checked add, box_at returns a bogus end and
		// children() walks backwards. Malicious input, so it must be rejected.
		let mut d = vec![0u8; 32];
		d[0..4].copy_from_slice(&8u32.to_be_bytes()); // first box, size 8
		d[4..8].copy_from_slice(b"free");
		d[8..12].copy_from_slice(&1u32.to_be_bytes()); // largesize marker
		d[12..16].copy_from_slice(b"free");
		d[16..24].copy_from_slice(&u64::MAX.to_be_bytes());
		assert!(box_at(&d, 8, d.len()).is_none());
	}

	#[test]
	fn idat_payload_is_found_inside_meta() {
		// ISO/IEC 23008-12 puts ItemDataBox inside MetaBox. libavif's
		// draw_points_idat.avif uses construction_method=1, so offsets are
		// relative to this payload; a top-level-only search must not miss it.
		let idat = box_bytes(b"idat", &[0xAA, 0xBB, 0xCC]);
		let meta = full_box(b"meta", 0, &idat);
		let mut file = box_bytes(b"ftyp", b"avif");
		file.extend_from_slice(&meta);
		let offset = idat_payload_offset(&file).expect("find nested idat");
		assert_eq!(&file[offset..offset + 3], &[0xAA, 0xBB, 0xCC]);
	}

	#[test]
	fn ipma_flags_bit0_selects_15bit_property_index() {
		// ISO/IEC 14496-12 8.11.14.1 / libavif read.c:2993: when ipma flags&1
		// is set, each association is 2 bytes with a 15-bit property_index;
		// otherwise 1 byte with 7 bits. Our parser ignored the flag and always
		// read 1 byte, so a spec-legal file lost its irot/clap association and
		// fell back to the raw ispe (verified: orient_rot.avif 2x4 -> 4x2).
		let irot = box_bytes(b"irot", &[1]); // rotation 90°, property index 1
		let ipco = box_bytes(b"ipco", &irot);
		let mut ipma_payload = vec![0, 0, 0, 1]; // version 0, flags = 0x000001 (U15)
		ipma_payload.extend_from_slice(&1u32.to_be_bytes()); // entry_count
		ipma_payload.extend_from_slice(&1u16.to_be_bytes()); // item_ID 1
		ipma_payload.push(1); // association_count
		ipma_payload.extend_from_slice(&1u16.to_be_bytes()); // assoc: essential=0, index=1
		let ipma = box_bytes(b"ipma", &ipma_payload);
		let iprp = box_bytes(b"iprp", &[ipco, ipma].concat());
		let items = [(&b"iprp"[..], 8usize, iprp.len())];
		let props = parse_item_props(&iprp, &items, 1);
		assert_eq!(
			props.transform.rotate, 1,
			"15-bit ipma index must associate irot"
		);
	}

	#[test]
	fn alpha_urn_set_matches_libavif() {
		// libavif internal.h:78-79 accepts exactly two alpha URNs. Our old
		// `ends_with(b":alpha")` accepted any such suffix and rejected the
		// legal ALPHA1 URN (urn:mpeg:hevc:2015:auxid:1).
		const ALPHA0: &[u8] = b"urn:mpeg:mpegB:cicp:systems:auxiliary:alpha";
		const ALPHA1: &[u8] = b"urn:mpeg:hevc:2015:auxid:1";
		assert!(is_alpha_urn(ALPHA0));
		assert!(is_alpha_urn(ALPHA1));
		assert!(!is_alpha_urn(
			b"urn:mpeg:mpegB:cicp:systems:auxiliary:depth"
		));
		assert!(!is_alpha_urn(b"urn:example:fake:alpha"));
	}

	#[test]
	fn iloc_v0_data_reference_index_is_read_before_base_offset() {
		// ISO/IEC 14496-12: data_reference_index (u16) follows item_ID for EVERY
		// iloc version; construction_method (u16) precedes it only for v1/v2.
		// The old v0 branch skipped it, so base_offset landed on the data_ref
		// bytes and a legitimate nonzero-base item failed to locate (libavif's
		// colors-animated-8bpc-audio.avif: baseline decoded 150x150, ours NULL).
		let mut body = vec![0x44, 0x40, 0, 1]; // off=4, len=4, base=4, idx=0, count=1
		body.extend_from_slice(&1u16.to_be_bytes()); // item_ID
		body.extend_from_slice(&0xBEEFu16.to_be_bytes()); // data_reference_index
		body.extend_from_slice(&100u32.to_be_bytes()); // base_offset
		body.extend_from_slice(&1u16.to_be_bytes()); // extent_count
		body.extend_from_slice(&7u32.to_be_bytes()); // extent_offset
		body.extend_from_slice(&9u32.to_be_bytes()); // extent_length
		let iloc = full_box(b"iloc", 0, &body);
		// Pad the buffer so base(100)+off(7)+len(9) is a valid in-file window.
		let mut d = iloc;
		d.resize(256, 0);
		let items = [(&b"iloc"[..], 8usize, 31)];
		let locs = parse_iloc(&d, &items, 1).expect("v0 iloc with nonzero base");
		assert_eq!(locs.len(), 1);
		assert_eq!(
			locs[0].base, 100,
			"base_offset must be read after the 2-byte data_reference_index"
		);
	}

	#[test]
	fn iloc_v1_index_size_precedes_extent_offset() {
		// ISO/IEC 14496-12 8.11.3.1 / libavif read.c:2062-2075: for v1/v2 with
		// index_size>0, each extent starts with an item_reference_index of
		// `index_size` bytes, THEN extent_offset, THEN extent_length. The old
		// code skipped index AFTER reading off/len, so a spec-valid v1 file
		// with index_size=4 decoded to garbage (libavif decodes it fine).
		let mut body = vec![0x44, 0x04, 0, 1]; // off=4, len=4, base=0, index=4, count=1
		body.extend_from_slice(&1u16.to_be_bytes()); // item_ID
		body.extend_from_slice(&0u16.to_be_bytes()); // construction_method (v1)
		body.extend_from_slice(&0u16.to_be_bytes()); // data_reference_index
		// base_offset: 0 bytes (base_offset_size = 0)
		body.extend_from_slice(&1u16.to_be_bytes()); // extent_count
		body.extend_from_slice(&7u32.to_be_bytes()); // item_reference_index (ignored)
		body.extend_from_slice(&100u32.to_be_bytes()); // extent_offset
		body.extend_from_slice(&9u32.to_be_bytes()); // extent_length
		let iloc = full_box(b"iloc", 1, &body);
		let mut d = iloc;
		d.resize(256, 0);
		let items = [(&b"iloc"[..], 8usize, 31)];
		let locs = parse_iloc(&d, &items, 1).expect("v1 iloc with index_size=4");
		assert_eq!(locs.len(), 1);
		assert_eq!(
			locs[0].extents,
			vec![(100, 9)],
			"extent_offset/length must be read after the index_size-byte reference index"
		);
	}

	#[test]
	fn locate_rejects_extents_whose_total_exceeds_file() {
		// Two extents each spanning the whole 64-byte buffer -> merged total
		// 128 > file size. A malicious iloc can declare 65535 overlapping
		// extents, turning a 1.11 MB file into a 4.29 GB allocation (measured).
		// The merged data can never legitimately exceed the source file.
		let d = vec![0u8; 64];
		let loc = ItemLocation {
			id: 1,
			construction: 0,
			base: 0,
			extents: vec![(0, 64), (0, 64)],
		};
		assert!(
			locate(&d, &[loc], 1).is_none(),
			"sum of extents must not exceed the source file size"
		);
	}

	#[test]
	fn iloc_zero_length_extent_and_zero_extent_item_are_tolerated() {
		// libavif accepts a zero-length extent (contributes 0 bytes) and an
		// item with extent_count=0 (parsed as empty); neither may reject the
		// whole iLoc layout. Verified: avifdec decodes such files, we didn't.
		let mk = |extents: &[(u32, u32)]| {
			let mut body = vec![0x44, 0, 0, 1]; // off=4, len=4, base=0, idx=0, count=1
			body.extend_from_slice(&1u16.to_be_bytes()); // item_ID
			body.extend_from_slice(&0u16.to_be_bytes()); // data_reference_index
			body.extend_from_slice(&(extents.len() as u16).to_be_bytes());
			for &(off, len) in extents {
				body.extend_from_slice(&off.to_be_bytes());
				body.extend_from_slice(&len.to_be_bytes());
			}
			let iloc = full_box(b"iloc", 0, &body);
			let mut d = iloc;
			d.resize(256, 0);
			let items = [(&b"iloc"[..], 8usize, 31)];
			parse_iloc(&d, &items, 1)
		};
		// A zero-length extent followed by the real data must keep the real one.
		let locs = mk(&[(0, 0), (100, 9)]).expect("zero-length extent tolerated");
		assert_eq!(locs[0].extents, vec![(100, 9)]);
		// An item with extent_count=0 is simply not emitted (locate returns None).
		let locs = mk(&[]).expect("zero-extent item tolerated");
		assert!(locs.is_empty() || locs[0].extents.is_empty());
	}

	#[test]
	fn iloc_high_item_and_extent_counts_accepted_when_file_is_large_enough() {
		// Byte-budget checks (not a hardcoded 1024) must bound reservations.
		// A large file declaring 1025 items / 1025 extents is structural but
		// libavif-legal; avifdec decodes it. Verified with count_cap_probe.py.
		let mut body = vec![0x44, 0]; // off=4, len=4, base=0, idx=0
		body.extend_from_slice(&1025u16.to_be_bytes()); // item_count
		for i in 1..=1025u16 {
			body.extend_from_slice(&i.to_be_bytes()); // item_ID
			body.extend_from_slice(&0u16.to_be_bytes()); // data_ref
			body.extend_from_slice(&1u16.to_be_bytes()); // extent_count
			body.extend_from_slice(&0u32.to_be_bytes()); // extent_offset
			body.extend_from_slice(&1u32.to_be_bytes()); // extent_length
		}
		let iloc = full_box(b"iloc", 0, &body);
		let items = [(&b"iloc"[..], 8usize, iloc.len())];
		let locs = parse_iloc(&iloc, &items, 1).expect("1025 items in a large-enough file");
		assert_eq!(locs.len(), 1025);

		// A single item with 1025 extents (all pointing into a big enough file).
		let mut body = vec![0x44, 0, 0, 1];
		body.extend_from_slice(&1u16.to_be_bytes());
		body.extend_from_slice(&0u16.to_be_bytes());
		body.extend_from_slice(&1025u16.to_be_bytes()); // extent_count
		for i in 0..1025u32 {
			body.extend_from_slice(&i.to_be_bytes());
			body.extend_from_slice(&1u32.to_be_bytes());
		}
		let iloc = full_box(b"iloc", 0, &body);
		let items = [(&b"iloc"[..], 8usize, iloc.len())];
		let locs = parse_iloc(&iloc, &items, 1).expect("1025 extents in a large-enough file");
		assert_eq!(locs[0].extents.len(), 1025);
	}

	#[test]
	fn iloc_multiple_extents_are_concatenated() {
		// A segmented item's extents must be concatenated, not silently reduced
		// to the first one. libavif's
		// arc_triomphe_extent1000_nullbyte_extent1310.avif has two extents; the
		// old parser fed only the first (incomplete) AV1 frame to rav1d -> NULL
		// while baseline decoded 64x64.
		const CHUNK1: [u8; 4] = [1, 2, 3, 4];
		const CHUNK2: [u8; 3] = [9, 8, 7];
		let pitm = full_box(b"pitm", 0, &1u16.to_be_bytes());
		let mut iinf_body = 1u16.to_be_bytes().to_vec();
		let mut infe = Vec::new();
		infe.extend_from_slice(&1u16.to_be_bytes());
		infe.extend_from_slice(&0u16.to_be_bytes());
		infe.extend_from_slice(b"av01");
		infe.push(0);
		iinf_body.extend_from_slice(&full_box(b"infe", 0, &infe));
		let iinf = full_box(b"iinf", 0, &iinf_body);
		let ispe = full_box(b"ispe", 0, &[0, 0, 0, 1, 0, 0, 0, 1]);
		let ipco = box_bytes(b"ipco", &ispe);
		let mut ipma_body = 1u32.to_be_bytes().to_vec();
		ipma_body.extend_from_slice(&1u16.to_be_bytes());
		ipma_body.push(1);
		ipma_body.push(0x01);
		let ipma = full_box(b"ipma", 0, &ipma_body);
		let iprp = box_bytes(b"iprp", &[ipco, ipma].concat());
		let ftyp = box_bytes(b"ftyp", b"avifmif1");
		// iloc v0: id(2) + data_ref(2) + extent_count(2) + 2*(off(4)+len(4)) = 22
		let iloc_len = 8 + 4 + 4 + 22;
		let meta_len = 8 + 4 + pitm.len() + iinf.len() + iprp.len() + iloc_len;
		let mdat_payload = (ftyp.len() + meta_len + 8) as u32;
		let (off1, off2) = (mdat_payload, mdat_payload + CHUNK1.len() as u32 + 1);
		let mut iloc_body = vec![0x44, 0, 0, 1]; // off=4, len=4, base=0, idx=0, count=1
		iloc_body.extend_from_slice(&1u16.to_be_bytes());
		iloc_body.extend_from_slice(&0u16.to_be_bytes()); // data_reference_index
		iloc_body.extend_from_slice(&2u16.to_be_bytes()); // extent_count
		iloc_body.extend_from_slice(&off1.to_be_bytes());
		iloc_body.extend_from_slice(&(CHUNK1.len() as u32).to_be_bytes());
		iloc_body.extend_from_slice(&off2.to_be_bytes());
		iloc_body.extend_from_slice(&(CHUNK2.len() as u32).to_be_bytes());
		let iloc = full_box(b"iloc", 0, &iloc_body);
		assert_eq!(iloc.len(), iloc_len);
		let mut meta_body = Vec::new();
		meta_body.extend_from_slice(&pitm);
		meta_body.extend_from_slice(&iinf);
		meta_body.extend_from_slice(&iprp);
		meta_body.extend_from_slice(&iloc);
		let meta = full_box(b"meta", 0, &meta_body);
		assert_eq!(meta.len(), meta_len);
		let mut file = ftyp;
		file.extend_from_slice(&meta);
		let mut payload = CHUNK1.to_vec();
		payload.push(0xEE); // gap between the two extents
		payload.extend_from_slice(&CHUNK2);
		file.extend_from_slice(&box_bytes(b"mdat", &payload));

		let info = AvifInfo::parse(&file).expect("parse synthetic multi-extent AVIF");
		let expect = [CHUNK1.as_slice(), CHUNK2.as_slice()].concat();
		assert_eq!(
			info.av1_obu(&file),
			expect.as_slice(),
			"all extents must be concatenated into the item data"
		);
	}

	#[test]
	fn primary_and_alpha_items_are_located_by_pitm_and_iloc() {
		let file = two_item_avif(None, None, None);
		let info = AvifInfo::parse(&file).expect("parse synthetic AVIF");
		assert_eq!((info.width, info.height), (1, 1));
		assert_eq!(info.av1_obu(&file), PRIMARY);
		assert_eq!(info.alpha_obu(&file), Some(ALPHA.as_slice()));
	}

	#[test]
	fn depth_aux_item_is_not_composited_as_alpha() {
		// Evidence: libavif tests/data/colors-animated-8bpc-depth-exif-xmp.avif
		// carries auxC = urn:mpeg:mpegB:cicp:systems:auxiliary:depth, and
		// `avifdec` decodes it fully opaque. A depth map must never become alpha.
		let file = two_item_avif(
			Some("urn:mpeg:mpegB:cicp:systems:auxiliary:depth"),
			None,
			None,
		);
		let info = AvifInfo::parse(&file).expect("parse synthetic AVIF");
		assert_eq!(info.av1_obu(&file), PRIMARY);
		assert_eq!(
			info.alpha_obu(&file),
			None,
			"depth map must not become alpha"
		);
	}

	#[test]
	fn shared_aux_item_is_not_alpha() {
		// Evidence: libavif color_grid_alpha_item_shared_in_auxl.avif uses one
		// alpha item as auxl for two colour items. Both avifdec and ffmpeg
		// ignore that ambiguous reference and decode fully opaque.
		let file = two_item_avif(
			Some("urn:mpeg:mpegB:cicp:systems:auxiliary:alpha"),
			None,
			Some(3),
		);
		let info = AvifInfo::parse(&file).expect("parse synthetic AVIF");
		assert_eq!(info.av1_obu(&file), PRIMARY);
		assert_eq!(
			info.alpha_obu(&file),
			None,
			"shared aux item must not become alpha"
		);
	}

	#[test]
	fn imir_axis_zero_maps_to_vertical_mirror() {
		// ISO/IEC 23008-12 6.5.12: imir axis 0 exchanges top/bottom, axis 1
		// exchanges left/right. A fixture with payload 01 (axis 1) exists, so
		// axis 0 was never covered and used to be dropped (mirror=0 = none).
		// Verified against avifdec: axis 0 on orient_mir.avif gives the
		// vertically mirrored image (MAE 159 vs our old output).
		let mirror_for = |axis: u8| {
			let imir = box_bytes(b"imir", &[axis, 0, 0, 0]);
			let ipco = box_bytes(b"ipco", &imir);
			let mut ipma_body = 1u32.to_be_bytes().to_vec(); // entry_count
			ipma_body.extend_from_slice(&1u16.to_be_bytes()); // item_ID 1
			ipma_body.push(1); // association_count
			ipma_body.push(0x01); // -> ipco property 1
			let ipma = full_box(b"ipma", 0, &ipma_body);
			let iprp = box_bytes(b"iprp", &[ipco, ipma].concat());
			// parse_item_props wants the buffer and a slice of (fourcc, payload,
			// end) items. Build both from the single iprp box.
			let mut data = Vec::new();
			let payload = 8usize; // iprp payload starts after its 8-byte header
			data.extend_from_slice(&iprp);
			let items = [(&b"iprp"[..], payload, data.len())];
			parse_item_props(&data, &items, 1).transform.mirror
		};
		assert_eq!(mirror_for(0), 2, "imir axis 0 must be top/bottom mirror");
		assert_eq!(mirror_for(1), 1, "imir axis 1 must be left/right mirror");
	}

	#[test]
	fn auxl_with_multiple_targets_is_not_alpha() {
		// Evidence: libavif tests/data/circle_auxl_two_targets.avif links its
		// alpha item to two targets (auxl count = 2). avifdec ignores that
		// ambiguous reference and decodes fully opaque; we must too, otherwise a
		// 65%-transparent image is shown where the reference is opaque.
		let file = two_item_avif(
			Some("urn:mpeg:mpegB:cicp:systems:auxiliary:alpha"),
			Some(3),
			None,
		);
		let info = AvifInfo::parse(&file).expect("parse synthetic AVIF");
		assert_eq!(info.av1_obu(&file), PRIMARY);
		assert_eq!(
			info.alpha_obu(&file),
			None,
			"multi-target auxl must not become alpha"
		);
	}
}
