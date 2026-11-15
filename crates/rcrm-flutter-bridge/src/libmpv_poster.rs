// src/libmpv_poster.rs
//! Video posters rendered by libmpv itself.
//!
//! The frame never enters Dart: libmpv draws into a [Surface] this module
//! allocates, the opaque-alpha pass and the luma blank test run over that same
//! buffer, and the WebP encoder reads it in place. A whole job — one client,
//! one render context, one seek per candidate position — runs on the thread the
//! FFI export spawns, because render.h requires a context to be created, used
//! and freed on one thread.
//!
//! Two facts about the protocol are load-bearing, and both were measured
//! (`docs/MPV_POSTER_EVAL.md`): the frame the render context still holds from
//! before a seek must be consumed BEFORE seeking, and the frame that arrives
//! after it is only this position's poster once `time-pos` says the clock has
//! arrived. Without the first, a poster for 60 s shows the frame at 3 s.

use std::time::{Duration, Instant};

use crate::libmpv::{Event, LibMpvError, Mpv, RenderContext, Surface};
use crate::poster::{self, PosterResult};
use crate::webp::WebpBuf;

/// The most one poster job may take, all stages together. A poster that needs
/// longer is a poster the library grid is better off without.
const JOB_TIMEOUT: Duration = Duration::from_secs(40);
/// Opening the file: a WebDAV round trip for a multi-gigabyte film over a slow
/// link is still over well before this, because mpv loads the header only.
const LOAD_TIMEOUT: Duration = Duration::from_secs(25);
/// The first frame after a seek.
const SEEK_TIMEOUT: Duration = Duration::from_secs(5);
/// The frame whose timestamp matches the seek target.
const FRAME_TIMEOUT: Duration = Duration::from_secs(3);
/// How far `time-pos` may sit from the target before the frame in hand is not
/// accepted as the one that was asked for. `absolute+exact` lands on a frame
/// boundary, so this only absorbs timestamp rounding — and it is wide enough
/// that a 24 fps clip's own frame duration never trips it.
const POSITION_TOLERANCE: f64 = 0.5;
/// How long to sleep between frame polls. Checking for a frame is a read of a
/// flag libmpv keeps in memory; the sleep is what stops a pool of workers from
/// spinning a core each while a seek decodes.
const FRAME_POLL: Duration = Duration::from_millis(2);
/// The tallest surface a poster may ask for. A 640-wide portrait frame is 1138
/// pixels tall; this cap only stops absurd source metadata from asking for a
/// 1 GB allocation.
const MAX_HEIGHT: u32 = 8_192;
/// How many stale frames one drain may consume. Bounded because a libmpv build
/// that reported FRAME without ever clearing it would otherwise spin here.
const MAX_DRAINED_FRAMES: usize = 8;

/// What one libmpv job produced.
pub(crate) enum PosterFrame {
	/// A finished WebP, freed by the caller with `rcrm_free_webp_buf`.
	Encoded(Box<WebpBuf>),
	/// The file loaded and every candidate position was tried, but none
	/// produced a usable frame (all blank, or the seek never got there).
	NoFrame,
}

/// Render a poster for `url`.
///
/// `positions` are candidate timestamps in seconds, most promising first — the
/// order the Dart side's `posterSeekPlan` produces, so both poster backends look
/// where the same rule says to look. `header_fields` is the CRLF-separated
/// header block the Dart side already builds for HTTP fetches (empty for none);
/// it becomes libmpv's `http-header-fields`. `target_width` is a maximum: a
/// smaller video keeps its own size.
///
/// # Errors
///
/// [LibMpvError::Unavailable] when this process has no usable libmpv. Every
/// other variant is per-file, and a caller may still get a poster for another
/// file.
pub(crate) fn generate(
	url: &str,
	header_fields: &str,
	positions: &[f64],
	target_width: u32,
	quality: u8,
) -> Result<PosterFrame, LibMpvError> {
	let started = Instant::now();
	let mpv = Mpv::create(&options(header_fields))?;
	let deadline = Instant::now() + JOB_TIMEOUT;
	// BEFORE the file loads: render.h says mpv reverts to a video output that
	// creates its own window when no render context exists yet.
	let render = RenderContext::new(&mpv)?;
	mpv.command(&["loadfile", url])?;
	wait_for_load(&mpv, stage_deadline(deadline, LOAD_TIMEOUT))?;

	let (source_width, source_height) = display_size(&mpv);
	let (width, height) = target_size(source_width, source_height, target_width)?;
	let mut surface = Surface::new(width, height);
	let duration = mpv.get_f64("duration").filter(|seconds| *seconds > 0.0);
	rcrm_core::log_debug!(
		"[poster] libmpv source={source_width}x{source_height} surface={width}x{height} duration={duration:?} loaded_ms={}",
		started.elapsed().as_millis()
	);

	for &position in positions {
		if let Some(duration) = duration
			&& position >= duration
		{
			// A seek at or past the end returns the last frame or nothing. The
			// Dart plan already avoids this when it knows the length; this is
			// the same rule against the length mpv read itself.
			rcrm_core::log_debug!("[poster] skip {position}s: duration is {duration}s");
			continue;
		}
		if Instant::now() >= deadline {
			return Err(LibMpvError::Timeout {
				stage: "job",
				timeout: JOB_TIMEOUT,
			});
		}
		match attempt(&mpv, &render, &mut surface, position, quality, deadline) {
			Ok(Some(buffer)) => return Ok(PosterFrame::Encoded(buffer)),
			Ok(None) => rcrm_core::log_debug!("[poster] no usable frame at {position}s"),
			Err(error) => rcrm_core::log_debug!("[poster] position {position}s failed: {error}"),
		}
	}
	Ok(PosterFrame::NoFrame)
}

/// One candidate position: seek, wait for the frame, and encode it.
///
/// `Ok(None)` means nothing usable came back at this position (the frame was
/// blank, or the seek never produced one) and the caller should try the next;
/// only a real libmpv failure is an `Err`, and it is per-position too.
fn attempt(
	mpv: &Mpv,
	render: &RenderContext<'_>,
	surface: &mut Surface,
	position: f64,
	quality: u8,
	job_deadline: Instant,
) -> Result<Option<Box<WebpBuf>>, LibMpvError> {
	drain(render, surface)?;
	let target = format!("{position:.3}");
	let seek_started = Instant::now();
	mpv.command(&["seek", &target, "absolute+exact"])?;
	wait_for_seek(mpv, stage_deadline(job_deadline, SEEK_TIMEOUT))?;
	let seek_ms = seek_started.elapsed().as_millis();
	let frame_started = Instant::now();
	render_frame_at(
		mpv,
		render,
		surface,
		position,
		stage_deadline(job_deadline, FRAME_TIMEOUT),
	)?;
	let frame_ms = frame_started.elapsed().as_millis();
	let (width, height) = surface.size();
	let encode_started = Instant::now();
	let encoded = poster::encode_poster_frame(surface.pixels_mut(), width, height, quality);
	rcrm_core::log_debug!(
		"[poster] libmpv pos={position}s seek_ms={} frame_ms={} encode_ms={}",
		seek_ms,
		frame_ms,
		encode_started.elapsed().as_millis()
	);
	match encoded {
		PosterResult::Encoded(buffer) => Ok(Some(buffer)),
		PosterResult::Blank => Ok(None),
		PosterResult::Invalid => Err(LibMpvError::Encode),
	}
}

/// Render and discard every frame the context is still holding.
fn drain(render: &RenderContext<'_>, surface: &mut Surface) -> Result<(), LibMpvError> {
	for _ in 0..MAX_DRAINED_FRAMES {
		if !render.has_frame() {
			return Ok(());
		}
		render.render(surface)?;
		render.report_swap();
	}
	Ok(())
}

/// Render until the frame in hand belongs to `target`.
///
/// The SEEK event only says the seek STARTED. The first frame the context
/// reports afterwards can still be the one that was already on screen while mpv
/// decodes towards the target, and `time-pos` is the only honest answer to "is
/// this the frame that was asked for" — so a frame is accepted only once the
/// clock has arrived, and the next update is rendered otherwise.
fn render_frame_at(
	mpv: &Mpv,
	render: &RenderContext<'_>,
	surface: &mut Surface,
	target: f64,
	deadline: Instant,
) -> Result<(), LibMpvError> {
	loop {
		if render.has_frame() {
			render.render(surface)?;
			render.report_swap();
			match mpv.get_f64("time-pos") {
				Some(at) if (at - target).abs() <= POSITION_TOLERANCE => return Ok(()),
				// Keep waiting: mpv is still decoding towards the target and
				// will report the frame it lands on.
				Some(at) => rcrm_core::log_debug!("[poster] frame at {at}s is not {target}s yet"),
				// No clock to check against (should not happen for a loaded
				// video): the frame is the best answer available.
				None => return Ok(()),
			}
		}
		let left = remaining(deadline, "frame", FRAME_TIMEOUT)?;
		std::thread::sleep(left.min(FRAME_POLL));
	}
}

/// Wait for the file to finish loading.
fn wait_for_load(mpv: &Mpv, deadline: Instant) -> Result<(), LibMpvError> {
	loop {
		let left = remaining(deadline, "load", LOAD_TIMEOUT)?;
		match mpv.wait_event(left) {
			Event::FileLoaded => return Ok(()),
			Event::EndFile { error } => {
				return Err(LibMpvError::Load {
					message: error.unwrap_or_else(|| "playback ended while loading".to_string()),
				});
			}
			Event::Shutdown => {
				return Err(LibMpvError::Load {
					message: "mpv shut down while loading".to_string(),
				});
			}
			Event::Timeout => {
				return Err(LibMpvError::Timeout {
					stage: "load",
					timeout: LOAD_TIMEOUT,
				});
			}
			Event::Seek | Event::Other => {}
		}
	}
}

/// Wait for the seek to reach libmpv's core.
fn wait_for_seek(mpv: &Mpv, deadline: Instant) -> Result<(), LibMpvError> {
	loop {
		let left = remaining(deadline, "seek", SEEK_TIMEOUT)?;
		match mpv.wait_event(left) {
			Event::Seek => return Ok(()),
			Event::EndFile { error } => {
				return Err(LibMpvError::Load {
					message: error.unwrap_or_else(|| "playback ended during the seek".to_string()),
				});
			}
			Event::Shutdown => {
				return Err(LibMpvError::Load {
					message: "mpv shut down during the seek".to_string(),
				});
			}
			Event::Timeout => {
				return Err(LibMpvError::Timeout {
					stage: "seek",
					timeout: SEEK_TIMEOUT,
				});
			}
			Event::FileLoaded | Event::Other => {}
		}
	}
}

/// The deadline a stage must finish by: its own budget, or the job's, whichever
/// comes first.
fn stage_deadline(job_deadline: Instant, budget: Duration) -> Instant {
	let own = Instant::now() + budget;
	own.min(job_deadline)
}

/// The time left before `deadline`, or the timeout that deadline represents.
fn remaining(
	deadline: Instant,
	stage: &'static str,
	timeout: Duration,
) -> Result<Duration, LibMpvError> {
	let left = deadline.saturating_duration_since(Instant::now());
	if left.is_zero() {
		Err(LibMpvError::Timeout { stage, timeout })
	} else {
		Ok(left)
	}
}

/// The client options every poster job runs with.
fn options(header_fields: &str) -> Vec<(&'static str, String)> {
	let mut options: Vec<(&'static str, String)> = vec![
		// The render context drives the video output; nothing else may.
		("vo", "libmpv".to_string()),
		// CPU decode. hwdec would want a GPU context the software renderer does
		// not have, and one frame is not worth building one for.
		("hwdec", "no".to_string()),
		// Only the picture is wanted, so no audio or subtitle track is selected
		// at all (aid/sid, not merely muted).
		("aid", "no".to_string()),
		("sid", "no".to_string()),
		// Load, seek, draw — never play. keep-open keeps the picture instead of
		// ending the file at its last frame.
		("pause", "yes".to_string()),
		("keep-open", "yes".to_string()),
		// No user configuration, terminal, OSD or key bindings: a poster must
		// render the same on a user's machine as in a test.
		("config", "no".to_string()),
		("terminal", "no".to_string()),
		("input-default-bindings", "no".to_string()),
		("input-vo-keyboard", "no".to_string()),
		("osd-level", "0".to_string()),
		// RCrm's own server presents a self-signed certificate and the Dart
		// client pins it; libmpv cannot know about that pin, so its own
		// verification is off for this one fetch path — the same scoped
		// relaxation the old ffmpeg poster command made (ffmpeg's
		// -tls_verify 0). The pin itself still governs every request the app
		// makes, and the player keeps its own TLS settings.
		("tls-verify", "no".to_string()),
	];
	if let Some(fields) = http_header_fields(header_fields) {
		options.push(("http-header-fields", fields));
	}
	options
}

/// Convert a CRLF-separated header block into libmpv's `http-header-fields`
/// value.
///
/// mpv separates fields with commas, so a header whose VALUE contains one
/// cannot be expressed. That is acceptable here because the only header this
/// path sends is `Authorization: Basic <base64>`, whose alphabet excludes
/// commas — and a wrong header costs a poster, never a leak.
fn http_header_fields(headers: &str) -> Option<String> {
	let fields: Vec<&str> = headers
		.split(['\r', '\n'])
		.map(str::trim)
		.filter(|line| !line.is_empty())
		.collect();
	if fields.is_empty() {
		None
	} else {
		Some(fields.join(","))
	}
}

/// The video's display size in pixels.
///
/// `dwidth`/`dheight` fold in the container's aspect and rotation, which is what
/// decides the picture's shape; `width`/`height` are the coded size and are only
/// the fallback.
fn display_size(mpv: &Mpv) -> (i64, i64) {
	let width = mpv
		.get_i64("dwidth")
		.filter(|width| *width > 0)
		.or_else(|| mpv.get_i64("width"));
	let height = mpv
		.get_i64("dheight")
		.filter(|height| *height > 0)
		.or_else(|| mpv.get_i64("height"));
	(width.unwrap_or(0), height.unwrap_or(0))
}

/// The surface size for a `source_width` x `source_height` video, at most
/// `max_width` pixels wide.
///
/// The height follows from the source's own aspect because mpv letterboxes a
/// frame whose shape does not match the surface (render.h) — a portrait poster
/// would arrive with black bars down both sides. The width is a maximum, never
/// a target: like the encoder's, it does not upscale.
fn target_size(
	source_width: i64,
	source_height: i64,
	max_width: u32,
) -> Result<(u32, u32), LibMpvError> {
	let width = u32::try_from(source_width).ok().filter(|width| *width > 0);
	let height = u32::try_from(source_height)
		.ok()
		.filter(|height| *height > 0);
	let (source_width, source_height) = match (width, height) {
		(Some(width), Some(height)) => (width, height),
		_ => {
			return Err(LibMpvError::Load {
				message: "no video track, or no size reported for one".to_string(),
			});
		}
	};
	let width = max_width.max(1).min(source_width);
	let scaled = u64::from(source_height) * u64::from(width);
	let height = (scaled + u64::from(source_width) / 2) / u64::from(source_width);
	Ok((width, height.clamp(1, u64::from(MAX_HEIGHT)) as u32))
}

/// Parse the comma-separated candidate positions the FFI hands over.
///
/// Entries are seconds and empty ones are ignored; anything else is a caller
/// bug, refused rather than silently reordering the plan.
pub(crate) fn parse_positions(list: &str) -> Result<Vec<f64>, LibMpvError> {
	let mut positions = Vec::new();
	for entry in list.split(',') {
		let entry = entry.trim();
		if entry.is_empty() {
			continue;
		}
		let position: f64 = entry.parse().map_err(|_| LibMpvError::InvalidArgument {
			what: "candidate position",
		})?;
		if !position.is_finite() || position < 0.0 {
			return Err(LibMpvError::InvalidArgument {
				what: "candidate position",
			});
		}
		positions.push(position);
	}
	Ok(positions)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::webp;

	#[test]
	fn header_fields_become_mpvs_comma_list() {
		assert_eq!(http_header_fields(""), None);
		assert_eq!(http_header_fields("  \r\n "), None);
		assert_eq!(
			http_header_fields("Authorization: Basic dTpw\r\nX-Other: 1"),
			Some("Authorization: Basic dTpw,X-Other: 1".to_string())
		);
		// A bare LF is a header separator too: the caller may build the block
		// either way.
		assert_eq!(
			http_header_fields("A: 1\nB: 2\n"),
			Some("A: 1,B: 2".to_string())
		);
	}

	#[test]
	fn positions_are_parsed_in_order_and_reject_garbage() {
		assert_eq!(parse_positions("").unwrap(), Vec::<f64>::new());
		assert_eq!(
			parse_positions("30, 15 ,3.5,0").unwrap(),
			vec![30.0, 15.0, 3.5, 0.0]
		);
		assert_eq!(parse_positions("1e-3").unwrap(), vec![0.001]);
		assert!(parse_positions("30,abc").is_err());
		assert!(parse_positions("-5").is_err());
		assert!(parse_positions("inf").is_err());
	}

	/// The surface keeps the source's shape (mpv letterboxes a mismatch) and
	/// never upscales; the height is capped so absurd metadata cannot ask for a
	/// huge allocation.
	#[test]
	fn target_size_follows_the_source_aspect() {
		assert_eq!(target_size(1920, 1080, 640).unwrap(), (640, 360));
		assert_eq!(target_size(1080, 1920, 640).unwrap(), (640, 1138));
		// Smaller than the target: keep the source size.
		assert_eq!(target_size(480, 270, 640).unwrap(), (480, 270));
		// A 1-pixel-wide video still gets one pixel of height.
		assert_eq!(target_size(4000, 1, 640).unwrap(), (640, 1));
		// An absurdly tall frame is capped rather than allocated.
		assert_eq!(target_size(10, 100_000, 640).unwrap(), (10, MAX_HEIGHT));
		// No video track.
		assert!(target_size(0, 1080, 640).is_err());
		assert!(target_size(-1, 1080, 640).is_err());
		assert!(target_size(1920, 0, 640).is_err());
	}

	#[test]
	fn the_client_is_configured_for_one_paused_frame() {
		let configured = options("");
		let has =
			|name: &str, value: &str| configured.iter().any(|(k, v)| *k == name && v == value);
		assert!(has("vo", "libmpv"), "the render context needs vo=libmpv");
		assert!(has("pause", "yes"));
		assert!(has("keep-open", "yes"));
		assert!(has("aid", "no"));
		assert!(has("sid", "no"));
		assert!(has("config", "no"));
		assert!(
			!configured.iter().any(|(k, _)| *k == "http-header-fields"),
			"no headers means no option at all"
		);
		let with_headers = options("Authorization: Basic dTpw");
		assert!(
			with_headers
				.iter()
				.any(|(k, v)| *k == "http-header-fields" && v == "Authorization: Basic dTpw")
		);
	}

	/// A real end-to-end render, when this machine has a video to point at.
	///
	/// The fixture is per-machine, like the HEIC ones: set
	/// `RCRM_MPV_POSTER_TEST_VIDEO` to a local file to exercise the whole chain
	/// (load, seek, render, blank test, encode). Without it the test says so and
	/// passes, instead of failing on a machine without media.
	#[test]
	fn renders_a_poster_from_a_local_video() {
		let Ok(path) = std::env::var("RCRM_MPV_POSTER_TEST_VIDEO") else {
			eprintln!("skipping: set RCRM_MPV_POSTER_TEST_VIDEO to a video file to run this");
			return;
		};
		// So the stage timings generate() logs reach stderr under --nocapture.
		// SAFETY: the log level is a plain atomic and takes any u8.
		unsafe { crate::rcrm_set_log_level(3) };
		let frame = generate(&path, "", &[3.0, 1.0, 0.0], 640, 82).expect("libmpv should run");
		let PosterFrame::Encoded(buffer) = frame else {
			panic!("no poster came back for {path}");
		};
		let webp = &*buffer;
		// SAFETY: the buffer is the one the encoder just produced.
		let bytes = unsafe { std::slice::from_raw_parts(webp.data, webp.data_len) };
		assert_eq!(&bytes[0..4], b"RIFF");
		assert_eq!(&bytes[8..12], b"WEBP");
		let (rgba, width, height) = zenwebp::oneshot::decode_rgba(bytes).expect("decode back");
		assert!(width > 0 && height > 0);
		assert!(width <= 640, "target width is a maximum: {width}");
		assert_eq!(rgba.len(), (width * height * 4) as usize);
		assert!(
			rgba.as_chunks::<4>().0.iter().all(|pixel| pixel[3] == 255),
			"a poster must be opaque"
		);
		unsafe { webp::free_webp_buf(Box::into_raw(buffer)) };
	}
}
