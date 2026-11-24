// src/decode.rs
// Shared decode support for every software image decoder in this crate — the one
// place the three of them (AVIF → avif.rs, JXL → jxl/, HEIC/HEIF → heic/) take
// their common pieces from:
//
//   * `DecodeBuf` — the `#[repr(C)]` hand-off struct plus its ownership/free rules
//   * `MAX_DECODE_MP` / `Limit` — the single pixel ceiling all three enforce, as
//     the one place the number is written and as the value they pass around
//   * `bilinear_tap` / `bilinear_taps_at` / `downscale_rgba_bilinear` — resampling
//
// Decoders own their format work (parsing, limits, colour); anything two of them
// would otherwise write twice belongs here. Output is raw RGBA pixels
// (width × height × 4 bytes) — Dart reads them straight out of `DecodeBuf` and
// hands them to ui.ImageDescriptor.raw without any BMP encoding overhead, so the
// return path copies nothing.

/// The ONE pixel ceiling for every software image decoder in this crate (AVIF via
/// rav1d, JXL, HEIC). Defined here and referenced everywhere else because three
/// copies of the same number is how the AVIF path ended up rejecting every real
/// 12 MP phone photo while HEIC accepted 48 MP ones.
///
/// It is a memory bound, not a quality policy: these decoders allocate a full-frame
/// RGBA buffer, so 64 MP ~= 256 MB is the most this app attempts on the <=4 GB
/// devices it ships to. rav1d also receives it as its own frame limit, so a
/// container that lies about its size cannot smuggle a larger frame through.
#[cfg(feature = "mobile-decode")]
pub const MAX_DECODE_MP: u64 = 64_000_000;

/// The invariant that matters: a normal phone still (48 MP at the top end) must
/// always fit. It lives next to the number, so the ceiling cannot be lowered back
/// into "rejects real photos" territory without the build failing.
#[cfg(feature = "mobile-decode")]
const _: () = assert!(MAX_DECODE_MP >= 48_000_000);

/// That ceiling as a value, handed to a decoder instead of a bare
/// `max_pixels: u64` threaded through every function.
///
/// The pixels, the saturating u32 rav1d's settings want and the test-only door
/// all live on the type, so a caller cannot pass a number whose unit and origin
/// have to be reconstructed from the call site.
#[cfg(feature = "mobile-decode")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limit(u64);

#[cfg(feature = "mobile-decode")]
impl Limit {
	/// The ceiling every production path uses — [`MAX_DECODE_MP`] above, which
	/// stays the one place the number is written.
	pub const PRODUCTION: Limit = Limit(MAX_DECODE_MP);

	/// A ceiling of exactly `pixels`, for tests that must exercise the limit
	/// itself: a fixture larger than any real photo, or one deliberately below it
	/// so the file gets refused.
	///
	/// It is a *value* rather than a `#[cfg(test)]` relaxation of the check
	/// inside a decoder, because that mistake shipped once: relaxed under
	/// `cfg(test)`, the AVIF path accepted every file in the suite while the app
	/// refused real 16 MP photos, and no test could tell. A limit that travels in
	/// from the call site stays visible in the test that chose it, and the type
	/// those tests exercise is the one production uses.
	///
	/// Only `#[cfg(test)]` callers exist, hence the conditional allow: the
	/// constructor is deliberately not `cfg(test)`-gated, a plain build simply
	/// has nobody to call it.
	#[cfg_attr(not(test), allow(dead_code))]
	pub const fn synthetic(pixels: u64) -> Limit {
		Limit(pixels)
	}

	/// The ceiling in pixels, for comparing against a container's declared size.
	pub const fn pixels(self) -> u64 {
		self.0
	}

	/// The ceiling as rav1d's `frame_size_limit` field needs it. Saturating, like
	/// the `.min(u32::MAX as u64) as u32` it replaces: the field is a u32, and a
	/// ceiling too large to express in one must clamp rather than wrap into a
	/// tiny one.
	pub const fn as_u32_saturating(self) -> u32 {
		if self.0 > u32::MAX as u64 {
			u32::MAX
		} else {
			self.0 as u32
		}
	}
}

#[repr(C)]
pub struct DecodeBuf {
	pub width: u32,
	pub height: u32,
	pub channels: u8, // 4 = RGBA
	/// Bytes of pixel data actually used.
	pub data_len: usize,
	/// Bytes **allocated** at `data`. Usually equal to `data_len`, but a
	/// decoder that hands back a `Vec` is free to have spare capacity, and
	/// freeing has to rebuild the allocation exactly — so the real capacity
	/// travels with the buffer instead of being assumed.
	pub cap: usize,
	pub data: *mut u8, // raw RGBA pixels (w × h × 4)
}

unsafe impl Send for DecodeBuf {}

impl DecodeBuf {
	/// Wraps a decoder's `Vec<u8>` without copying: the allocation travels with
	/// the buffer and [_free_decode_buf] below frees it with the same capacity.
	pub fn from_vec(mut data: Vec<u8>, width: u32, height: u32) -> Box<DecodeBuf> {
		let data_len = data.len();
		let cap = data.capacity();
		let ptr = data.as_mut_ptr();
		std::mem::forget(data);
		Box::new(DecodeBuf {
			width,
			height,
			channels: 4,
			data_len,
			cap,
			data: ptr,
		})
	}
}

impl Drop for DecodeBuf {
	/// Frees the pixel allocation with the capacity that travelled with it. Both
	/// origins — a decoder's `Vec` through [DecodeBuf::from_vec], and the AVIF
	/// path's raw `alloc`/`dealloc` — go through the global allocator, so
	/// rebuilding a `Vec` is the exact inverse of either.
	///
	/// This lives here, not only in [free_decode_buf], because the thumbnail path
	/// can panic *after* the decode (the WebP encoder) inside a `catch_unwind`:
	/// with no `Drop` the unwind dropped the `Box` and leaked the whole frame —
	/// up to ~256 MiB at the HEIC ceiling.
	fn drop(&mut self) {
		if self.data.is_null() || self.data_len == 0 {
			return;
		}
		// Take the pointer first so a panic inside the deallocation cannot leave
		// this struct pointing at freed memory, and so a double free is
		// impossible even if something calls `free_decode_buf` after a drop.
		let data = std::mem::replace(&mut self.data, std::ptr::null_mut());
		let len = self.data_len;
		let cap = self.cap;
		drop(unsafe { Vec::from_raw_parts(data, len, cap) });
	}
}

#[cfg(feature = "mobile-decode")]
pub unsafe fn free_decode_buf(ptr: *mut DecodeBuf) {
	if ptr.is_null() {
		return;
	}
	// `Drop` frees the pixels; this is only the ownership hand-back.
	drop(unsafe { Box::from_raw(ptr) });
}

/// How a destination axis maps onto a source axis, for resampling.
///
/// The pixel **centre** of destination index `d` is mapped back into the source
/// (`(d + 0.5) * src / dst - 0.5`), clamped at both edges, then split into the
/// two source taps and the blend weight between them:
/// `.0` = lower tap, `.1` = upper tap (equal to `.0` at the edge), `.2` = weight
/// of the upper tap.
///
/// This is the one place the mapping lives: `downscale_rgba_bilinear` uses it
/// for every decoder that returns a finished RGBA frame (HEIC and JXL now both
/// go through it), so a scaled thumbnail has the same geometry everywhere.
#[inline]
pub fn bilinear_tap(d: u32, dst_len: u32, src_len: u32) -> (usize, usize, f64) {
	let (src, dst) = (src_len as f64, dst_len as f64);
	let s = ((d as f64 + 0.5) * src / dst - 0.5).clamp(0.0, src - 1.0);
	bilinear_taps_at(s, src_len)
}

/// The tap half of [`bilinear_tap`], for callers that computed the source
/// coordinate themselves. `s` must already be inside `0 ..= src_len - 1`.
#[inline]
pub fn bilinear_taps_at(s: f64, src_len: u32) -> (usize, usize, f64) {
	let i0 = s.floor();
	let i1 = (i0 + 1.0).min(src_len as f64 - 1.0);
	(i0 as usize, i1 as usize, s - i0)
}

/// The one bilinear resampling core, shared by every decoder that scales a
/// finished plane. `C` is the bytes-per-pixel (1 for mono Y, 4 for RGBA);
/// `src_stride` is in bytes (may exceed `sw*C` for padded frame planes).
///
/// The target pixel centre is mapped back into the source with [`bilinear_tap`]
/// and the four neighbours are blended — identical geometry for every caller.
/// A const generic keeps `C` compile-time, so the channel loop unrolls with no
/// runtime cost and the mono path does not pay for RGBA's four channels.
///
/// `dst` must be empty on entry; after the call its length is exactly `dw*dh*C`,
/// every byte written once. Both callers pass a fresh `Vec`, so no caller data
/// is truncated; `DecodeBuf::from_vec` records the exact reserved capacity.
#[cfg(feature = "mobile-decode")]
pub(crate) fn bilinear_resample<const C: usize>(
	src: &[u8],
	src_stride: usize,
	dst: &mut Vec<u8>,
	sw: u32,
	sh: u32,
	dw: u32,
	dh: u32,
) -> Option<()> {
	let len = usize::try_from((dw as u64).checked_mul(dh as u64)?.checked_mul(C as u64)?).ok()?;
	dst.try_reserve_exact(len).ok()?;
	// x taps depend only on (dx, dw, sw) — compute each ONCE for the whole
	// image, not once per output pixel (measured 3.4x for mono, 1.35x RGBA).
	// Collect BEFORE publishing dst's length: this is the only allocation that
	// can fail/panic, so no uninitialised byte can ever become part of dst.
	let x_taps: Vec<(usize, usize, f64)> = (0..dw).map(|dx| bilinear_tap(dx, dw, sw)).collect();
	// SAFETY: dst is empty on entry (documented contract) and len <= spare
	// capacity from try_reserve_exact. `spare_capacity_mut` gives the uninit
	// tail; every byte is written through `out` below BEFORE set_len publishes
	// the length, so no uninitialised byte is ever part of dst — not even if
	// the loop unwinds via the safe `src[i00+c]` indexing. Raw writes avoid a
	// memset of len bytes and a bounds check per byte (measured 1.05-1.15x).
	let out = dst.spare_capacity_mut().as_mut_ptr().cast::<u8>();
	let mut o = 0usize;
	for dy in 0..dh {
		let (y0, y1, wy) = bilinear_tap(dy, dh, sh);
		let iwy = 1.0 - wy; // constant across the whole row
		let row0 = y0 * src_stride;
		let row1 = y1 * src_stride;
		for &(x0, x1, wx) in &x_taps {
			let iwx = 1.0 - wx; // constant across all channels of this pixel
			let i00 = row0 + x0 * C;
			let i10 = row0 + x1 * C;
			let i01 = row1 + x0 * C;
			let i11 = row1 + x1 * C;
			for c in 0..C {
				let top = src[i00 + c] as f64 * iwx + src[i10 + c] as f64 * wx;
				let bot = src[i01 + c] as f64 * iwx + src[i11 + c] as f64 * wx;
				// SAFETY: o+C <= dh*dw*C == len (o advances by C once per pixel,
				// dh*dw pixels total), and `out` is valid for len bytes in the
				// spare capacity from the reserve above. Each slot is written
				// once before set_len publishes the length.
				unsafe { *out.add(o + c) = (top * iwy + bot * wy).round() as u8 };
			}
			o += C;
		}
	}
	debug_assert_eq!(o, len);
	// SAFETY: all len bytes in 0..len were written through `out`; len <= capacity.
	unsafe { dst.set_len(len) };
	Some(())
}

/// Bilinear downscale of an already-decoded, already-oriented RGBA8 image.
///
/// Used by the HEIC and JXL decoders, which return finished RGBA frames and
/// have no scaler of their own; the result is allocated *exactly* so it can be
/// freed as a plain `Vec` like every other decode buffer.
#[cfg(feature = "mobile-decode")]
pub fn downscale_rgba_bilinear(
	src: &[u8],
	sw: u32,
	sh: u32,
	dw: u32,
	dh: u32,
) -> Option<Box<DecodeBuf>> {
	if sw == 0 || sh == 0 || dw == 0 || dh == 0 {
		return None;
	}
	let needed = (sw as usize) * (sh as usize) * 4;
	if src.len() < needed {
		return None;
	}
	let mut out = Vec::new();
	bilinear_resample::<4>(src, sw as usize * 4, &mut out, sw, sh, dw, dh)?;
	Some(DecodeBuf::from_vec(out, dw, dh))
}

#[cfg(feature = "mobile-decode")]
pub fn decode_avif(data: &[u8], target_width: u32) -> Option<Box<DecodeBuf>> {
	crate::avif::decode(data, target_width)
}

#[cfg(feature = "mobile-decode")]
pub fn decode_jxl(data: &[u8], target_width: u32) -> Option<Box<DecodeBuf>> {
	crate::jxl::decode(data, target_width)
}

#[cfg(feature = "mobile-decode")]
pub fn decode_heic(data: &[u8], target_width: u32) -> Option<Box<DecodeBuf>> {
	crate::heic::decode(data, target_width)
}

// The fixture tests exercise the AVIF/JXL/HEIC decoders, so they only exist
// with mobile-decode.
#[cfg(all(test, feature = "mobile-decode"))]
mod tests {
	use super::*;

	fn test_read(p: &str) -> Vec<u8> {
		std::fs::read(format!("tests/testdata/{p}")).expect("read test file")
	}

	/// libavif fixtures are per-machine (gitignored); skip rather than panic.
	fn libavif_fixture(name: &str) -> Option<Vec<u8>> {
		std::fs::read(format!("tests/testdata/avif/libavif/{name}")).ok()
	}

	/// Mean absolute error over one channel between our RGBA and a reference.
	fn channel_mae(ours: &[u8], reference: &[u8], pixels: usize, channel: usize) -> f64 {
		let n = pixels.min(ours.len() / 4).min(reference.len() / 4);
		if n == 0 {
			return f64::INFINITY;
		}
		let sum: u64 = (0..n)
			.map(|i| {
				(ours[i * 4 + channel] as i32 - reference[i * 4 + channel] as i32).unsigned_abs()
					as u64
			})
			.sum();
		sum as f64 / n as f64
	}

	/// Full-corpus reference comparison. `manifest.tsv` is generated by
	/// `tests/gen_avif_reference.py` from two independent references (avifdec /
	/// ffmpeg); only fixtures where they agree are listed. Missing fixtures or
	/// manifest skip the test, so a clean checkout stays green.
	#[test]
	fn avif_reference_corpus_matches_ffmpeg() {
		let manifest_path = "tests/testdata/avif/libavif/ref/manifest.tsv";
		let Ok(manifest) = std::fs::read_to_string(manifest_path) else {
			eprintln!("skipping: no AVIF reference manifest (run tests/gen_avif_reference.py)");
			return;
		};
		let mut checked = 0usize;
		for line in manifest.lines() {
			let cols: Vec<&str> = line.split('\t').collect();
			if cols.len() != 4 {
				continue;
			}
			let name = cols[0];
			let pixels: usize = cols[1].parse().expect("manifest pixels");
			let rgb_tol: f64 = cols[2].parse().expect("manifest rgb tolerance");
			let alpha_tol: f64 = cols[3].parse().expect("manifest alpha tolerance");
			let Some(data) = libavif_fixture(name) else {
				continue; // per-machine fixture absent
			};
			let Ok(reference) =
				std::fs::read(format!("tests/testdata/avif/libavif/ref/{name}.raw"))
			else {
				continue;
			};
			let buf = decode_avif(&data, 0).unwrap_or_else(|| panic!("{name}: ours returned NULL"));
			assert_eq!(
				buf.width as usize * buf.height as usize,
				pixels,
				"{name}: pixel count mismatch"
			);
			let ours = unsafe { std::slice::from_raw_parts(buf.data, buf.data_len) };
			// Average over RGB (the same metric used in the three-way audit):
			// a 12-bit fixture can have a consistent +/-3 rounding in one
			// channel, which the average absorbs but a per-channel max rejects.
			let rgb = (channel_mae(ours, &reference, pixels, 0)
				+ channel_mae(ours, &reference, pixels, 1)
				+ channel_mae(ours, &reference, pixels, 2))
				/ 3.0;
			let alpha = channel_mae(ours, &reference, pixels, 3);
			unsafe { free_decode_buf(Box::into_raw(buf)) };
			assert!(rgb <= rgb_tol, "{name}: RGB MAE {rgb:.2} > {rgb_tol}");
			assert!(
				alpha <= alpha_tol,
				"{name}: alpha MAE {alpha:.2} > {alpha_tol}"
			);
			checked += 1;
		}
		eprintln!("AVIF reference corpus: checked {checked} fixtures");
	}

	#[test]
	fn mono_and_high_bitdepth_avif_decode() {
		// I400 (monochrome) and 10-bit AV1 use different plane layouts from the
		// common 8-bit 420 path. Both must decode at full size with correct dims.
		let mono = std::fs::read("tests/testdata/avif/libavif/gradmono.avif");
		let hbd = std::fs::read("tests/testdata/avif/libavif/grad10.avif");
		if let Ok(data) = mono {
			let buf = decode_avif(&data, 0).expect("I400 AVIF must decode");
			assert_eq!((buf.width, buf.height), (256, 256));
			unsafe { free_decode_buf(Box::into_raw(buf)) };
			// A monochrome AVIF must also produce a thumbnail when scaled below
			// its native width (mobile thumbnail path). Previously the I400
			// fast path required dw==sw, so it fell through to the chroma path
			// (which derefs null u/v) and returned NULL.
			let small = decode_avif(&data, 64).expect("I400 AVIF must downscale");
			assert_eq!((small.width, small.height), (64, 64));
			unsafe { free_decode_buf(Box::into_raw(small)) };
		}
		if let Ok(data) = hbd {
			let buf = decode_avif(&data, 0).expect("10-bit AVIF must decode");
			assert_eq!((buf.width, buf.height), (256, 256));
			unsafe { free_decode_buf(Box::into_raw(buf)) };
		}
	}

	/// 10/12-bit monochrome (I400) AVIF: only the Y plane exists (u/v are null),
	/// so it fell through to the chroma path and returned NULL even though
	/// avifdec decodes it. Both full- and limited-range conversions must be
	/// byte-exact with libavif (full: round(val>>shift); limited: ×256 rounding).
	#[test]
	fn mono10_avif_matches_libavif() {
		let Some(data) = libavif_fixture("mono10_grad.avif") else {
			eprintln!("skipping: no 10-bit mono fixture");
			return;
		};
		let Some(reference) =
			std::fs::read("tests/testdata/avif/libavif/ref/mono10_grad.avif.raw").ok()
		else {
			eprintln!("skipping: no 10-bit mono reference");
			return;
		};
		let buf = decode_avif(&data, 0).expect("10-bit I400 AVIF must decode");
		assert_eq!((buf.width, buf.height), (128, 128));
		let ours = unsafe { std::slice::from_raw_parts(buf.data, buf.data_len) };
		assert_eq!(
			ours,
			&reference[..ours.len().min(reference.len())],
			"10-bit mono RGBA must match avifdec byte-for-byte"
		);
		// A 10-bit mono thumbnail must also be produced (downscale path).
		let small = decode_avif(&data, 64).expect("10-bit I400 must downscale");
		assert_eq!((small.width, small.height), (64, 64));
		unsafe {
			free_decode_buf(Box::into_raw(buf));
			free_decode_buf(Box::into_raw(small));
		}
	}

	/// Limited-range 10-bit mono: libavif scales Y by 256 with half-up rounding,
	/// not ×255 truncation (a 765/1024-value error in a full ramp). Verified
	/// byte-exact against avifdec over the complete 0..1023 limited Y ramp.
	#[test]
	fn mono10_limited_range_matches_libavif() {
		let Some(data) = libavif_fixture("mono10_limited_ramp.avif") else {
			eprintln!("skipping: no limited mono fixture");
			return;
		};
		let Some(reference) =
			std::fs::read("tests/testdata/avif/libavif/ref/mono10_limited_ramp.avif.raw").ok()
		else {
			eprintln!("skipping: no limited mono reference");
			return;
		};
		let buf = decode_avif(&data, 0).expect("limited 10-bit mono must decode");
		assert_eq!((buf.width, buf.height), (1024, 1));
		let ours = unsafe { std::slice::from_raw_parts(buf.data, buf.data_len) };
		assert_eq!(
			ours,
			&reference[..ours.len().min(reference.len())],
			"limited mono RGBA must match avifdec byte-for-byte"
		);
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	#[test]
	fn idat_items_decode() {
		let Some(data) = libavif_fixture("draw_points_idat.avif") else {
			eprintln!("skipping: no libavif idat fixture");
			return;
		};
		let buf = decode_avif(&data, 0).expect("idat construction_method=1 must decode");
		assert_eq!((buf.width, buf.height), (33, 11));
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	#[test]
	fn grid_items_decode() {
		let Some(data) = libavif_fixture("sofa_grid1x5_420.avif") else {
			eprintln!("skipping: no libavif grid fixture");
			return;
		};
		let buf = decode_avif(&data, 0).expect("grid-derived image must decode");
		assert_eq!((buf.width, buf.height), (1024, 770));
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	#[test]
	fn grid_with_alpha_decodes() {
		let Some(data) = libavif_fixture("color_grid_alpha_nogrid.avif") else {
			eprintln!("skipping: no libavif grid+alpha fixture");
			return;
		};
		let buf = decode_avif(&data, 0).expect("grid with alpha tiles must decode");
		assert_eq!((buf.width, buf.height), (80, 80));
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	#[test]
	fn grid_tiles_are_stacked_at_native_size_then_cropped() {
		let Some(data) = libavif_fixture("color_grid_alpha_nogrid.avif") else {
			eprintln!("skipping: no libavif grid+alpha fixture");
			return;
		};
		let buf = decode_avif(&data, 0).expect("decode");
		let px = unsafe { std::slice::from_raw_parts(buf.data, buf.data_len) };
		// Reference: avifdec -r and ffmpeg (libdav1d) agree to within 1 on all
		// of these. Cropping each 80x64 tile to its 80x40 cell instead of
		// stacking the two full tiles then cropping the canvas fails every
		// pixel below row 40.
		let expect = [
			(5, 40, 0, 0, 0),
			(20, 20, 162, 211, 120),
			(25, 40, 116, 201, 35),
			(39, 40, 254, 254, 254),
			(40, 20, 115, 197, 34),
			(50, 10, 109, 194, 31),
			(60, 60, 79, 155, 5),
			(70, 40, 53, 104, 3),
			(79, 40, 0, 0, 0),
		];
		for (y, x, r, g, b) in expect {
			let p = &px[(y * 80 + x) * 4..(y * 80 + x) * 4 + 4];
			assert!(
				p[0].abs_diff(r) <= 4 && p[1].abs_diff(g) <= 4 && p[2].abs_diff(b) <= 4,
				"pixel ({x},{y}): got {p:?}, want ({r},{g},{b})"
			);
		}
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	#[test]
	fn decode_jqis5_valid() {
		let data = test_read("avif/jqis5.avif");
		let buf = decode_avif(&data, 0).expect("decode");
		assert_eq!(buf.width, 1503);
		assert_eq!(buf.height, 2140);
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	/// 3072x4096 is 12.6 MP — inside the shared 64 MP ceiling, and it still goes
	/// through the parameterised door (see [`decode_avif_unlimited`]) so these
	/// pixel assertions stay about the decoder rather than about the policy.
	#[test]
	fn decode_test1_valid() {
		let data = test_read("avif/test1.avif");
		let buf = decode_avif_unlimited(&data, 0).expect("decode");
		assert_eq!(buf.width, 3072);
		assert_eq!(buf.height, 4096);
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	#[test]
	fn decode_test1_downscale() {
		let data = test_read("avif/test1.avif");
		let buf = decode_avif_unlimited(&data, 400).expect("downscale");
		assert_eq!(buf.width, 400);
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	/// Test-only door with the ceiling lifted above every fixture, for the files
	/// here that are larger than any real phone photo (big_gbrp is 39 MP). The
	/// production entry point [`decode_avif`] deliberately has no such escape: a
	/// test-only relaxed limit inside it once kept the suite green while the app
	/// refused real 16 MP files.
	fn decode_avif_unlimited(data: &[u8], target_width: u32) -> Option<Box<DecodeBuf>> {
		crate::avif::decode_with_limit(data, target_width, Limit::synthetic(u64::MAX))
	}

	#[test]
	fn decode_pureblack_valid() {
		let data = test_read("avif/pureblack2_35.avif");
		let buf = decode_avif_unlimited(&data, 0).expect("decode");
		assert_eq!(buf.width, 2858);
		assert_eq!(buf.height, 4288);
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	#[test]
	fn decode_jqis5_downscale() {
		let data = test_read("avif/jqis5.avif");
		let buf = decode_avif(&data, 400).expect("downscale");
		assert_eq!(buf.width, 400);
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	#[test]
	fn decode_adonis_valid() {
		let data = test_read("avif/adonis.avif");
		let buf = decode_avif(&data, 0).expect("decode");
		assert_eq!(buf.width, 1242);
		assert_eq!(buf.height, 1865);
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	#[test]
	fn decode_adonis_downscale() {
		let data = test_read("avif/adonis.avif");
		let buf = decode_avif(&data, 400).expect("downscale");
		assert_eq!(buf.width, 400);
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	#[test]
	fn compare_adonis_vs_ffmpeg() {
		cmp_ffmpeg_avif("avif/adonis.avif", "Adonis GBRP");
	}
	#[test]
	fn decode_big_gbrp_valid() {
		let data = test_read("avif/big_gbrp.avif");
		let buf = decode_avif_unlimited(&data, 0).expect("decode");
		assert_eq!(buf.width, 7450);
		assert_eq!(buf.height, 5294);
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	#[test]
	fn decode_big_gbrp_downscale() {
		let data = test_read("avif/big_gbrp.avif");
		let buf = decode_avif_unlimited(&data, 400).expect("downscale");
		assert_eq!(buf.width, 400);
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	/// The three software decoders share one ceiling now (64 MP), so the 39 MP
	/// fixture is *inside* it: the production entry point must decode it. What
	/// must still be refused is anything over the ceiling, which is checked
	/// through the parameterised door because the tree keeps no >64 MP fixture.
	#[test]
	fn the_production_ceiling_admits_the_39mp_fixture() {
		let data = test_read("avif/big_gbrp.avif");
		let buf = decode_avif(&data, 0).expect("39 MP is inside the shared 64 MP ceiling");
		assert_eq!(buf.width, 7450);
		assert_eq!(buf.height, 5294);
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	/// The same door, used the other way round: a ceiling below the file's size
	/// refuses it. 1 MP is below adonis (1242x1865 = 2.3 MP).
	///
	/// The refusal that lands here is rav1d's `frame_size_limit` (it logs "Frame
	/// size 1242x1865 exceeds limit 1000000"), not the container check: this
	/// parser takes the first `ispe` it finds in the file, which for adonis is a
	/// smaller item than the primary frame. That is why the ceiling has to reach
	/// both doors — a limit that only guards the parsed `ispe` would let this file
	/// through.
	#[test]
	fn a_ceiling_below_the_file_size_refuses_it() {
		let data = test_read("avif/adonis.avif");
		assert!(
			crate::avif::decode_with_limit(&data, 0, Limit::synthetic(1_000_000)).is_none(),
			"a 1 MP ceiling must refuse a 2.3 MP file"
		);
	}

	#[test]
	fn compare_gbrp_vs_ffmpeg() {
		cmp_ffmpeg_avif("avif/jqis5.avif", "GBRP");
	}

	#[test]
	fn compare_yuv_vs_ffmpeg() {
		cmp_ffmpeg_avif("avif/test_yuv.avif", "YUV");
	}

	#[test]
	fn compare_jxl_vs_ffmpeg() {
		cmp_ffmpeg_jxl("jxl/4x-IMG_20250716_002259_095.jxl", "JXL");
	}

	#[test]
	fn thumb_webp_from_image_is_a_scaled_thumbnail_in_one_call() {
		// jqis5 rather than test1: both are inside the production ceiling, but the
		// smaller frame keeps this end-to-end test cheap, and the assertions below
		// are written against jqis5's 1503x2140 geometry.
		let data = test_read("avif/jqis5.avif");
		let buf = unsafe {
			crate::rcrm_generate_thumb_webp_from_image(data.as_ptr(), data.len(), 400, 82, 1)
		};
		assert!(!buf.is_null(), "decode + encode must succeed");
		let webp = unsafe { &*buf };
		let bytes = unsafe { std::slice::from_raw_parts(webp.data, webp.data_len) };
		// A real WebP container, not a partial buffer.
		assert_eq!(&bytes[0..4], b"RIFF");
		assert_eq!(&bytes[8..12], b"WEBP");
		// And it is the SCALED one: 400 wide, aspect preserved — the pixels
		// never passed through Dart to get there.
		let (rgba, w, h) = zenwebp::oneshot::decode_rgba(bytes).expect("decode back");
		// jqis5.avif is 1503x2140, so 400 wide scales to 569 tall (truncating, as
		// the shared downscaler does) — the scale happened inside Rust, on pixels
		// Dart never saw.
		assert_eq!(w, 400);
		assert_eq!(h, 569);
		assert_eq!(rgba.len(), (w * h * 4) as usize);
		// The input was borrowed: the caller's buffer is untouched and still
		// its own to free (this is what lets a failure fall back safely).
		assert_eq!(&data[4..8], b"ftyp", "input buffer must still be intact");
		unsafe { crate::webp::free_webp_buf(buf) };
	}

	/// The HEIC half of the same chain, end to end, with the `kind_hint` the app
	/// sends (3). Skips when the gitignored fixture is absent. This is the test
	/// that mirrors what the desktop/mobile app actually calls for a `.heic`
	/// thumbnail, so a rejected decode shows up here rather than in the UI.
	#[test]
	fn thumb_webp_from_heic_image_in_one_call() {
		let Ok(data) = std::fs::read("tests/testdata/heic/IMG_20240322_182430.HEIC") else {
			eprintln!("skipping: no HEIC fixture");
			return;
		};
		let buf = unsafe {
			crate::rcrm_generate_thumb_webp_from_image(data.as_ptr(), data.len(), 400, 82, 3)
		};
		assert!(!buf.is_null(), "HEIC decode + encode must succeed");
		let webp = unsafe { &*buf };
		let bytes = unsafe { std::slice::from_raw_parts(webp.data, webp.data_len) };
		assert_eq!(&bytes[0..4], b"RIFF");
		assert_eq!(&bytes[8..12], b"WEBP");
		let (_rgba, w, h) = zenwebp::oneshot::decode_rgba(bytes).expect("decode back");
		assert_eq!(w, 400);
		// 4624x3472 → 400 wide keeps the aspect ratio; which side is "width"
		// depends on the container orientation the decoder applied.
		assert!(h == 300 || h == 533, "unexpected thumbnail height {h}");
		unsafe { crate::webp::free_webp_buf(buf) };
	}

	#[test]
	fn thumb_webp_from_image_rejects_unparsable_bytes() {
		let junk = vec![0u8; 4096];
		let buf = unsafe {
			crate::rcrm_generate_thumb_webp_from_image(junk.as_ptr(), junk.len(), 400, 82, 0)
		};
		assert!(buf.is_null(), "garbage must not produce a buffer");
		let empty: Vec<u8> = Vec::new();
		let buf =
			unsafe { crate::rcrm_generate_thumb_webp_from_image(empty.as_ptr(), 0, 400, 82, 0) };
		assert!(buf.is_null(), "an empty input must be refused");
	}

	fn cmp_ffmpeg_avif(path: &str, label: &str) {
		let data = test_read(path);
		let buf = decode_avif(&data, 0).expect("decode");
		check_vs_ffmpeg(path, label, &buf);
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	fn cmp_ffmpeg_jxl(path: &str, label: &str) {
		let data = test_read(path);
		let buf = decode_jxl(&data, 0).expect("decode jxl");
		check_vs_ffmpeg(path, label, &buf);
		unsafe { free_decode_buf(Box::into_raw(buf)) };
	}

	fn check_vs_ffmpeg(path: &str, label: &str, buf: &DecodeBuf) {
		let rgba = unsafe { std::slice::from_raw_parts(buf.data, buf.data_len) };
		let (w, h) = (buf.width as usize, buf.height as usize);
		assert_eq!(buf.channels, 4, "{label}: not RGBA");

		let ff = std::process::Command::new("ffmpeg")
			.args([
				"-y",
				"-i",
				&format!("tests/testdata/{path}"),
				"-f",
				"rawvideo",
				"-pix_fmt",
				"rgb24",
				"-vframes",
				"1",
				"pipe:1",
			])
			.output()
			.expect("ffmpeg")
			.stdout;
		assert!(ff.len() >= w * h * 3, "{label}: ffmpeg output short");

		let mut sum = [0u64; 3];
		for y in 0..h {
			for x in 0..w {
				let ff_i = (y * w + x) * 3;
				let ri = (y * w + x) * 4;
				sum[0] += (rgba[ri] as i16 - ff[ff_i] as i16).unsigned_abs() as u64;
				sum[1] += (rgba[ri + 1] as i16 - ff[ff_i + 1] as i16).unsigned_abs() as u64;
				sum[2] += (rgba[ri + 2] as i16 - ff[ff_i + 2] as i16).unsigned_abs() as u64;
			}
		}
		let avg: Vec<_> = sum.iter().map(|s| *s as f64 / (w * h) as f64).collect();
		let ta = avg.iter().sum::<f64>() / 3.0;
		println!(
			"{label} ffmpeg: R={:.2} G={:.2} B={:.2} avg={ta:.2}",
			avg[0], avg[1], avg[2]
		);
		assert!(ta < 2.0, "{label} diff {ta:.2}");
	}
}
