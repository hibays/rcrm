// avif/mod.rs
// Self-contained AVIF decoder — ISOBMFF parse + AV1 decode via rav1d.
// No zenavif dependency. Colour info from the AV1 bitstream, not the container.
//
// ORIENTATION: the container's `irot`/`imir`/`clap` transforms ARE applied to
// the decoded RGBA (see decode::apply_transform), matching libavif's display
// pipeline; the reported width/height are the post-transform dimensions. EXIF
// orientation is not handled here (the info sheet's axis swap covers it).

mod decode;
mod parse;

use crate::decode::{DecodeBuf, Limit};

/// Grid canvas byte count with checked arithmetic. On 32-bit (Android
/// armeabi-v7a) `w*h*4` can wrap a usize, bypassing try_reserve_exact and
/// causing a panic in GridCanvas::place; the ispe ceiling doesn't cover a
/// malicious grid canvas. bpp is 1 (alpha plane) or 4 (RGBA).
fn canvas_bytes(w: u32, h: u32, bpp: usize, limit: Limit) -> Option<usize> {
	let px = (w as u64).checked_mul(h as u64)?;
	if px == 0 || px > limit.pixels() {
		return None;
	}
	let bytes = px.checked_mul(bpp as u64)?;
	usize::try_from(bytes).ok()
}

fn scaled_dims(w: u32, h: u32, target_width: u32) -> (u32, u32) {
	if target_width > 0 && target_width < w {
		(
			target_width,
			(h as f64 * target_width as f64 / w as f64) as u32,
		)
	} else {
		(w, h)
	}
}

/// Copy one tile into a grid canvas at `(x, y)`, clipped to the canvas. libavif
/// places every tile at its native dimensions in row-major order and clips only
/// at the final output bounds (read.c: `avifDecoderDataCopyTileToImage`); it
/// never rescales a tile to a `output/rows × output/cols` cell.
struct GridCanvas<'a> {
	pixels: &'a mut [u8],
	width: u32,
	height: u32,
	bpp: usize,
}

impl GridCanvas<'_> {
	fn place(&mut self, tile: &[u8], tile_w: u32, tile_h: u32, x: u32, y: u32) {
		// A malformed grid can place a tile outside the canvas. `saturating_sub`
		// would give cw==0 here but still run the loop with an out-of-bounds dst.
		if x >= self.width || y >= self.height {
			return;
		}
		let cw = tile_w.min(self.width - x);
		let ch = tile_h.min(self.height.saturating_sub(y));
		for dy in 0..ch as usize {
			let src = dy * tile_w as usize * self.bpp;
			let dst = ((y as usize + dy) * self.width as usize + x as usize) * self.bpp;
			self.pixels[dst..dst + cw as usize * self.bpp]
				.copy_from_slice(&tile[src..src + cw as usize * self.bpp]);
		}
	}
}

/// Decode a `grid` whose items are monochrome alpha tiles into one byte per
/// output pixel. Tiles are placed at native size and clipped to the canvas.
fn decode_alpha_grid(
	grid: &parse::GridInfo,
	data: &[u8],
	out_w: u32,
	out_h: u32,
	limit: Limit,
) -> Option<Vec<u8>> {
	if grid.tiles.len() != (grid.rows * grid.cols) as usize {
		return None;
	}
	let decoder = decode::TileDecoder::new(limit)?;
	let mut tiles = grid
		.tiles
		.iter()
		.map(|t| decoder.alpha_native(t.as_slice(data)));
	let first = tiles.next().flatten()?;
	let (tw, th) = (first.1, first.2);
	// Same libavif grid-coverage rule as the colour path, before decoding the
	// rest — an aliased alpha tile grid must not burn unbounded CPU.
	if !grid_tiles_cover_canvas(grid.rows, grid.cols, out_w, out_h, tw, th) {
		return None;
	}
	// Match the colour path: a hostile grid canvas must fail gracefully, not
	// abort the process on an OOM from vec![0; n].
	let n = canvas_bytes(out_w, out_h, 1, limit)?;
	let mut out = Vec::new();
	out.try_reserve_exact(n).ok()?;
	out.resize(n, 0);
	let mut canvas = GridCanvas {
		pixels: &mut out,
		width: out_w,
		height: out_h,
		bpp: 1,
	};
	for (i, plane) in std::iter::once(Some(first)).chain(tiles).enumerate() {
		let (plane, w, h) = plane?;
		let x = (i as u32 % grid.cols) * tw;
		let y = (i as u32 / grid.cols) * th;
		canvas.place(&plane, w, h, x, y);
	}
	Some(out)
}

/// libavif read.c:1745-1757 (HEIF 6.6.2.3.1 / MIAF 7.3.11.4.2): a grid's
/// tiles, at their native size, must completely cover the output canvas, and
/// the last row/column must actually overlap it (no fully redundant tile).
/// Checked with u64 math so huge declared counts/dimensions can't wrap.
fn grid_tiles_cover_canvas(rows: u32, cols: u32, out_w: u32, out_h: u32, tw: u32, th: u32) -> bool {
	if rows == 0 || cols == 0 || tw == 0 || th == 0 || out_w == 0 || out_h == 0 {
		return false;
	}
	let (r, c, w, h) = (rows as u64, cols as u64, out_w as u64, out_h as u64);
	let (twu, thu) = (tw as u64, th as u64);
	twu * c >= w && thu * r >= h && twu * (c - 1) < w && thu * (r - 1) < h
}

/// Decode every AV1 tile of a `grid` derived image and stitch it into one RGBA
/// buffer. Alpha tiles, when present, are composited into the tile before the copy.
fn decode_grid(
	grid: &parse::GridInfo,
	alpha_grid: Option<&parse::GridInfo>,
	data: &[u8],
	target_width: u32,
	limit: Limit,
) -> Option<Box<DecodeBuf>> {
	if grid.tiles.len() != (grid.rows * grid.cols) as usize {
		return None;
	}
	let (out_w, out_h) = (grid.out_w, grid.out_h);
	let n = canvas_bytes(out_w, out_h, 4, limit)?;
	let mut out = Vec::new();
	out.try_reserve_exact(n).ok()?;
	out.resize(n, 0);
	// One decoder for all colour tiles and one for all alpha tiles, matching
	// libavif. A tile may depend on reference frames set up by an earlier tile.
	let color_decoder = decode::TileDecoder::new(limit)?;
	let alpha_decoder = grid
		.alpha_tiles
		.as_ref()
		.and_then(|_| decode::TileDecoder::new(limit));
	// Decode, place and free one tile at a time: only the first tile's native
	// size is needed up front (all tiles in a grid share it), so N full-size
	// RGBA buffers never coexist.
	let mut tile_iter = grid
		.tiles
		.iter()
		.map(|t| color_decoder.frame(t.as_slice(data), 0));
	let first = tile_iter.next().flatten()?;
	let (tw, th) = (first.width, first.height);
	// Validate grid self-consistency BEFORE decoding the remaining tiles. An
	// aliased grid (thousands of tiles pointing at one large frame) would
	// otherwise burn minutes of CPU; libavif rejects it as Invalid image grid.
	if !grid_tiles_cover_canvas(grid.rows, grid.cols, out_w, out_h, tw, th) {
		drop(first);
		return None;
	}

	for (i, tile) in std::iter::once(Some(first)).chain(tile_iter).enumerate() {
		let tile = tile?;
		if let Some(ats) = &grid.alpha_tiles
			&& let Some(a) = ats.get(i)
			&& let Some(decoder) = &alpha_decoder
			&& let Some((native, aw, ah)) = decoder.alpha_native(a.as_slice(data))
		{
			let px = unsafe { std::slice::from_raw_parts_mut(tile.data, tile.data_len) };
			// Alpha is one byte per pixel: copy the plane channel by channel.
			for dy in 0..ah.min(tile.height) as usize {
				for dx in 0..aw.min(tile.width) as usize {
					let src = dy * aw as usize + dx;
					let dst = (dy * tile.width as usize + dx) * 4 + 3;
					px[dst] = native[src];
				}
			}
		}
		let px = unsafe { std::slice::from_raw_parts(tile.data, tile.data_len) };
		let x = (i as u32 % grid.cols) * tw;
		let y = (i as u32 / grid.cols) * th;
		GridCanvas {
			pixels: &mut out,
			width: out_w,
			height: out_h,
			bpp: 4,
		}
		.place(px, tile.width, tile.height, x, y);
		unsafe { crate::decode::free_decode_buf(Box::into_raw(tile)) };
	}

	if let Some(ag) = alpha_grid
		&& let Some(plane) = decode_alpha_grid(ag, data, out_w, out_h, limit)
	{
		for (pixel, a) in out.as_chunks_mut::<4>().0.iter_mut().zip(plane) {
			pixel[3] = a;
		}
	}
	let composed = DecodeBuf::from_vec(out, out_w, out_h);
	let (dw, dh) = scaled_dims(out_w, out_h, target_width);
	if (dw, dh) == (out_w, out_h) {
		return Some(composed);
	}
	let src = unsafe { std::slice::from_raw_parts(composed.data, composed.data_len) };
	let scaled = crate::decode::downscale_rgba_bilinear(src, out_w, out_h, dw, dh);
	unsafe { crate::decode::free_decode_buf(Box::into_raw(composed)) };
	scaled
}

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
	let primary = if let Some(grid) = &info.grid {
		decode_grid(grid, info.alpha_grid.as_ref(), data, target_width, limit)?
	} else {
		decode::decode_frame(info.av1_obu(data), target_width, limit)?
	};

	// AVIF alpha is a separate monochrome item in the same mdat. Grid alphas
	// were already composited inside decode_grid; their item data is a grid
	// config, not an AV1 frame, so feeding it to decode_alpha would be garbage.
	if info.grid.is_none()
		&& info.alpha_grid.is_none()
		&& let Some(alpha_obu) = info.alpha_obu(data)
	{
		let (w, h) = (primary.width, primary.height);
		if let Some(alpha) = decode::decode_alpha(alpha_obu, w, h, limit)
			&& alpha.len() >= w as usize * h as usize
		{
			// SAFETY: `primary.data` points to `data_len` bytes owned by the
			// DecodeBuf and is still live; we only write each pixel's alpha.
			let pixels = unsafe { std::slice::from_raw_parts_mut(primary.data, primary.data_len) };
			for (pixel, a) in pixels.as_chunks_mut::<4>().0.iter_mut().zip(alpha) {
				pixel[3] = a;
			}
		}
	}
	decode::apply_transform(primary, &info.transform)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn grid_tiles_must_cover_canvas_without_full_extra_row_or_col() {
		// libavif read.c:1745-1757 (HEIF 6.6.2.3.1 / MIAF 7.3.11.4.2):
		//   tw*cols >= out_w && th*rows >= out_h          (tiles cover canvas)
		//   tw*(cols-1) < out_w && th*(rows-1) < out_h   (last row/col overlaps)
		// A 33 KB grid aliasing one 3.2MP tile 4096× took 2.9 s to decode while
		// avifdec rejects it instantly as "Invalid image grid".
		let valid = |rows, cols, out_w, out_h, tw, th| {
			grid_tiles_cover_canvas(rows, cols, out_w, out_h, tw, th)
		};
		// sofa_grid1x5: 5 rows x 1 col (native tile 1024x154) -> 1024x770.
		assert!(valid(5, 1, 1024, 770, 1024, 154));
		// color_grid_alpha_nogrid: 2 rows x 1 col, tile 80x64 -> 80x80.
		assert!(valid(2, 1, 80, 80, 80, 64));
		// gainmap grid: 3 rows x 4 cols, tile 128x200 -> 512x600.
		assert!(valid(3, 4, 512, 600, 128, 200));
		assert!(valid(1, 1, 80, 80, 80, 80)); // single tile
		// Cropping the last tile is allowed: 2 cols, tile 80, output 120.
		assert!(valid(1, 2, 120, 80, 80, 80));
		// DoS: 64x64 grid of 1024x154 tiles, output only 1024x770 — a full
		// extra row/col would be needed, so it must be rejected.
		assert!(!valid(64, 64, 1024, 770, 1024, 154));
		// Tiles that don't cover the canvas at all.
		assert!(!valid(1, 2, 1000, 770, 1024, 154));
		// Overflow-safe on huge values.
		assert!(!valid(u32::MAX, u32::MAX, u32::MAX, u32::MAX, 1024, 1024));
	}

	#[test]
	fn grid_canvas_ignores_tiles_placed_outside_the_output() {
		// A malformed grid (tile wider than output, or too many columns) must not
		// index past the canvas. Without the guard this panics at out[dst..dst].
		let mut out = [0u8; 8]; // 2x2 RGBA
		let tile = [9u8; 16];
		GridCanvas {
			pixels: &mut out,
			width: 2,
			height: 2,
			bpp: 4,
		}
		.place(&tile, 2, 2, 5, 0); // x past the right edge
		GridCanvas {
			pixels: &mut out,
			width: 2,
			height: 2,
			bpp: 4,
		}
		.place(&tile, 2, 2, 0, 5); // y past the bottom edge
		assert_eq!(out, [0u8; 8]);
	}
}
