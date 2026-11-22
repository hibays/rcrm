// jxl/decode.rs
// JXL frame decode via jxl-rs (the `jxl` crate).
// The decoder renders straight into the RGBA8 buffer we hand back to Dart —
// no planar float grid, no interleaved intermediate, no copy on the way out.

use std::sync::LazyLock;

use jxl::api::{
	Event, JxlDecoder, JxlDecoderOptions, JxlOutputBuffer, JxlParallelRunner, JxlParallelRunnerFun,
	JxlPixelFormat, ProfileLevel,
};
use jxl::error::Result as JxlResult;
use rayon::prelude::*;

use crate::decode::{DecodeBuf, Limit, downscale_rgba_bilinear};

/// jxl-rs is sequential unless a runner is supplied; measured on the local
/// fixtures that is 2–5x slower than the old decoder and loses the speed win.
/// Cap the count like the poster renderer: min(cores, 8), 4 on Android. Sharing
/// one pool also stops several concurrent decodes from multiplying threads.
fn decoder_threads() -> usize {
	let available = std::thread::available_parallelism()
		.map(|n| n.get())
		.unwrap_or(2);
	#[cfg(target_os = "android")]
	{
		available.min(4)
	}
	#[cfg(not(target_os = "android"))]
	{
		available.min(8)
	}
}

static JXL_POOL: LazyLock<rayon::ThreadPool> = LazyLock::new(|| {
	rayon::ThreadPoolBuilder::new()
		.num_threads(decoder_threads())
		.thread_name(|i| format!("jxl-decode-{i}"))
		.build()
		.expect("bounded jxl thread pool")
});

struct JxlRunner;

impl JxlParallelRunner for JxlRunner {
	fn run(&mut self, num: usize, fun: &JxlParallelRunnerFun<'_>) -> JxlResult<()> {
		if decoder_threads() <= 1 {
			for i in 0..num {
				fun(i)?;
			}
			return Ok(());
		}
		// One pool for the whole process: jxl-rs calls `run` many times per
		// frame, and building a pool per call would cost more than the decode.
		JXL_POOL.install(|| (0..num).into_par_iter().try_for_each(fun))
	}

	fn num_threads(&self) -> usize {
		decoder_threads()
	}
}

pub fn decode_frame(data: &[u8], target_width: u32) -> Option<Box<DecodeBuf>> {
	let mut input = data;
	let mut options = JxlDecoderOptions::default();
	// `sample_limit` counts samples as pixels * (3 + extra channels) and rejects
	// when the count is >= the limit, so it needs headroom over the shared
	// ceiling. It is an early, pre-allocation guard for hostile headers; the
	// exact pixel policy is checked against `basic_info()` below.
	options.sample_limit = Some(
		Limit::PRODUCTION
			.pixels()
			.saturating_mul(8)
			.try_into()
			.unwrap_or(usize::MAX),
	);
	// The old decoder enforced no ISO complexity limits. jxl-rs defaults to
	// Main5, which enforces them; Main10 lifts them only when the container
	// declares Level 10 (a `jxll` box). Our sample_limit and pixel ceiling
	// still bound memory, so accept those files rather than reject files the
	// old path took.
	options.max_profile_level = ProfileLevel::Main10;
	let mut decoder = JxlDecoder::new(options);
	let mut runner = JxlRunner;

	// A hostile stream can ask for bytes forever. The input is a complete
	// in-memory slice, so there is nothing more to give: cap the event count
	// and turn that into "no image" instead of a hung ImageLoadGate slot.
	const MAX_EVENTS: usize = 4096;
	let mut events = 0usize;

	// Output buffers are refused before BasicInfo, and with `adjust_orientation`
	// on (the default) the reported size is already the display-oriented one —
	// the old path's manual `orient_src` mapping is no longer needed.
	let (w, h, extra_channels) = loop {
		events += 1;
		if events > MAX_EVENTS {
			return None;
		}
		match decoder.process(&mut input, None, Some(&mut runner)).ok()? {
			Event::BasicInfo => {
				let info = decoder.basic_info()?;
				break (info.size.0, info.size.1, info.extra_channels.len());
			}
			Event::NeedMoreInput { .. } => continue,
			_ => {}
		}
	};

	if w == 0 || h == 0 || (w as u64) * (h as u64) > Limit::PRODUCTION.pixels() {
		return None;
	}
	// jxl-rs requires one entry in `extra_channel_format` per extra channel in
	// the frame header (it asserts equality). A file with an alpha/depth channel
	// would otherwise panic inside the decoder; `None` discards that channel
	// because RGBA already carries colour + alpha. The old decoder never looked
	// at extra channels, so this is required for behaviour parity.
	decoder
		.set_pixel_format(JxlPixelFormat::rgba8(extra_channels))
		.ok()?;

	// Direct output: the decoder fills this exact allocation, which is then
	// moved into `DecodeBuf` without a copy. The size derives from a
	// header-declared canvas, so allocation must be fallible like the AVIF path's
	// `alloc_buf` and the shared `downscale_rgba_bilinear`: `vec!`/`with_capacity`
	// would abort the whole process under Android memory pressure.
	// `JxlOutputBuffer::new` requires initialized bytes, so fill with zeros after
	// the reservation (which does not allocate again). rgba8 is byte-aligned, so
	// there is no row-alignment constraint.
	let len = w * h * 4;
	let mut rgba = Vec::new();
	rgba.try_reserve_exact(len).ok()?;
	rgba.resize(len, 0);
	let mut buffers = [JxlOutputBuffer::new(&mut rgba, h, w * 4)];
	let mut saw_frame = false;
	loop {
		events += 1;
		if events > MAX_EVENTS {
			return None;
		}
		match decoder
			.process(&mut input, Some(&mut buffers), Some(&mut runner))
			.ok()?
		{
			// The first visible frame is all the app ever shows, matching the
			// old `render_frame(0)`. Pixels are complete at FrameComplete; the
			// decoder's scratch memory is released when it drops here.
			Event::FrameComplete { .. } => {
				saw_frame = true;
				break;
			}
			// Internal/reference-only frames are not reported by jxl-rs; without
			// a visible frame the zeroed buffer is not an image, so refuse it
			// instead of handing Dart a fabricated transparent picture.
			Event::Complete => break,
			Event::NeedMoreInput { .. } => {}
			_ => {}
		}
	}
	if !saw_frame {
		return None;
	}

	let (w32, h32) = (w as u32, h as u32);
	if target_width > 0 && target_width < w32 {
		// Truncating aspect maths, without a float round-trip. The shared
		// downscaler works on the already-oriented RGBA8 pixels.
		let dh = (h as u64 * target_width as u64 / w as u64) as u32;
		if dh > 0
			&& let Some(scaled) = downscale_rgba_bilinear(&rgba, w32, h32, target_width, dh)
		{
			return Some(scaled);
		}
	}
	Some(DecodeBuf::from_vec(rgba, w32, h32))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn test_read(p: &str) -> Vec<u8> {
		std::fs::read(format!("tests/testdata/{p}")).expect("read test file")
	}

	#[test]
	fn decode_jxl_small() {
		let data = test_read(
			"jxl/Chungking.Express.1994.CHINESE.2160p.UHD.BluRay.x265.10bit.HDR.DDP5.1-RARBG.mkv_snapshot_00.41.05_[2023.11.19_14.06.32].jxl",
		);
		let buf = decode_frame(&data, 0).expect("decode jxl");
		assert_eq!((buf.width, buf.height), (3596, 2160));
		assert_eq!(buf.channels, 4);
		assert_eq!(buf.data_len, buf.width as usize * buf.height as usize * 4);
		assert_eq!(buf.cap, buf.data_len, "capacity travels with the buffer");
		// Not a blank frame: the alpha channel alone is 255 for an opaque still.
		let px = unsafe { std::slice::from_raw_parts(buf.data, buf.data_len) };
		assert!(
			px.as_chunks::<4>()
				.0
				.iter()
				.take(4096)
				.any(|p| p[0] != 0 || p[1] != 0 || p[2] != 0)
		);
		unsafe { crate::decode::free_decode_buf(Box::into_raw(buf)) };
	}

	#[test]
	fn decode_jxl_downscale() {
		let data = test_read("jxl/4x-IMG_20250716_002259_095.jxl");
		let buf = decode_frame(&data, 400).expect("jxl downscale");
		assert_eq!(buf.width, 400);
		assert_eq!(buf.height, 500);
		assert_eq!(buf.data_len, 400 * buf.height as usize * 4);
		unsafe { crate::decode::free_decode_buf(Box::into_raw(buf)) };
	}

	#[test]
	fn garbage_is_refused() {
		let junk = vec![0u8; 4096];
		assert!(decode_frame(&junk, 0).is_none());
	}

	/// The synchronous thumbnail generator takes JXL bytes by hint 2. Pins the
	/// whole decoded → downscaled → WebP-encoded chain with no Dart pixel loop.
	#[test]
	fn thumb_webp_from_jxl_image_in_one_call() {
		let data = test_read("jxl/4x-IMG_20250716_002259_095.jxl");
		let prefix = data[..8].to_vec();
		let buf = unsafe {
			crate::rcrm_generate_thumb_webp_from_image(data.as_ptr(), data.len(), 400, 82, 2)
		};
		assert!(!buf.is_null(), "decode + encode must succeed");
		let webp = unsafe { &*buf };
		let bytes = unsafe { std::slice::from_raw_parts(webp.data, webp.data_len) };
		assert_eq!(&bytes[0..4], b"RIFF");
		assert_eq!(&bytes[8..12], b"WEBP");
		let (rgba, w, h) = zenwebp::oneshot::decode_rgba(bytes).expect("decode back");
		assert_eq!(w, 400);
		assert_eq!(rgba.len(), (w * h * 4) as usize);
		assert_eq!(&data[..8], prefix.as_slice(), "input must stay borrowed");
		unsafe { crate::webp::free_webp_buf(buf) };
	}
}
