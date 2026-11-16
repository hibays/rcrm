// src/libmpv.rs
//! The process's libmpv, loaded at runtime — the render side, not media_kit's.
//!
//! media_kit puts a libmpv shared object in every app it plays in: the
//! DLL/SO next to the executable (Windows), the APK's native library directory
//! (Android), the app bundle (macOS), or — on iOS — `Mpv.framework/Mpv`, an
//! embedded, code-signed MH_DYLIB. iOS allows loading that: what it forbids is
//! executable code from outside the signed bundle, not the bundle's own dynamic
//! frameworks. So posters borrow the very build media_kit already loaded instead
//! of shipping a second copy of the library.
//!
//! Only what the poster generator needs is bound: create/initialize, a handful
//! of options, `loadfile`/`seek`, property reads, the event queue, and the
//! software render context. Every raw pointer and every `unsafe` call lives in
//! this module; `libmpv_poster.rs` is safe code on top of it.

use std::ffi::{CStr, CString, c_char, c_int, c_ulong, c_void};
use std::fmt;
use std::sync::OnceLock;
use std::time::Duration;

use libloading::Library;

/// `mpv_handle` (client.h). Opaque: this module only hands the pointer back to
/// libmpv.
#[repr(C)]
pub(crate) struct MpvHandle {
	pub(crate) _opaque: [u8; 0],
}

/// `mpv_render_context` (render.h). Opaque for the same reason.
#[repr(C)]
pub(crate) struct MpvRenderContext {
	pub(crate) _opaque: [u8; 0],
}

/// `mpv_event` (client.h). The field order is ABI, as client.h promises.
#[repr(C)]
struct MpvEvent {
	event_id: c_int,
	error: c_int,
	reply_userdata: u64,
	data: *mut c_void,
}

/// `mpv_render_frame_info` (render.h), the answer to
/// `MPV_RENDER_PARAM_NEXT_FRAME_INFO`. Field order is ABI.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct MpvRenderFrameInfo {
	/// `MPV_RENDER_FRAME_INFO_*` bits.
	pub(crate) flags: u64,
	/// Display time, in `mpv_get_time_us` units.
	pub(crate) target_time: i64,
}

/// `MPV_RENDER_FRAME_INFO_*` (render.h).
pub(crate) const FRAME_INFO_PRESENT: u64 = 1;
pub(crate) const FRAME_INFO_REDRAW: u64 = 2;
pub(crate) const FRAME_INFO_REPEAT: u64 = 4;

/// `mpv_event_end_file` (client.h), the payload of `MPV_EVENT_END_FILE`.
#[repr(C)]
struct MpvEndFile {
	reason: c_int,
	error: c_int,
	playlist_entry_id: i64,
	playlist_insert_id: i64,
	playlist_insert_num_entries: c_int,
}

/// `mpv_render_param` (render.h).
#[repr(C)]
struct RenderParam {
	/// `mpv_render_param_type`. Read by libmpv; this side only fills it in.
	kind: c_int,
	data: *mut c_void,
}

// `MPV_EVENT_*` values acted on here (client.h).
const EVENT_NONE: c_int = 0;
const EVENT_SHUTDOWN: c_int = 1;
const EVENT_END_FILE: c_int = 7;
const EVENT_FILE_LOADED: c_int = 8;
const EVENT_SEEK: c_int = 20;

// `MPV_FORMAT_*` (client.h).
const FORMAT_INT64: c_int = 4;
const FORMAT_DOUBLE: c_int = 5;

// `MPV_RENDER_PARAM_*` (render.h).
const PARAM_INVALID: c_int = 0;
const PARAM_API_TYPE: c_int = 1;
/// `MPV_RENDER_PARAM_NEXT_FRAME_INFO` (render.h): what the next render draws.
const PARAM_NEXT_FRAME_INFO: c_int = 11;
const PARAM_SW_SIZE: c_int = 17;
const PARAM_SW_FORMAT: c_int = 18;
const PARAM_SW_STRIDE: c_int = 19;
const PARAM_SW_POINTER: c_int = 20;

/// `MPV_RENDER_UPDATE_FRAME` (render.h).
const RENDER_UPDATE_FRAME: u64 = 1;

/// `MPV_ERROR_NOT_IMPLEMENTED` (client.h): a feature this libmpv build does not
/// have, which no media file will change.
const ERROR_NOT_IMPLEMENTED: c_int = -19;

/// `MPV_RENDER_API_TYPE_SW` (render.h). Nul-terminated for the C side.
const RENDER_API_SW: &[u8] = b"sw\0";

/// `MPV_RENDER_PARAM_SW_FORMAT`: 4 bytes per pixel, B,G,R and an unused byte
/// that render.h calls "uninitialized garbage (often the value 0)".
const SURFACE_FORMAT: &[u8] = b"bgr0\0";

/// Client API we need: the render API arrived in 1.28, and every libmpv
/// media_kit ships is 2.x. Kept in `c_ulong`, the type the C function returns
/// (32 bits on Windows, 64 elsewhere), so no conversion is needed at all.
const REQUIRED_API: c_ulong = (1 << 16) | 28;

/// The client API version as `(major, minor)`.
fn api_major_minor(version: c_ulong) -> (c_ulong, c_ulong) {
	(version >> 16, version & 0xffff)
}

/// A libmpv build's shared library names, in the order to try them.
const fn library_names() -> &'static [&'static str] {
	// media_kit's own packaging is the authority here: it puts the very same
	// file next to the executable (Windows), in the APK's native library
	// directory (Android), beside the app bundle (macOS) or into the system
	// library path (Linux) — the player it ships has to load it, so it is there.
	if cfg!(target_os = "windows") {
		&["libmpv-2.dll", "mpv-2.dll"]
	} else if cfg!(target_os = "linux") {
		&["libmpv.so.2", "libmpv.so"]
	} else if cfg!(target_os = "macos") {
		&[
			"libmpv.2.dylib",
			"libmpv.dylib",
			"@rpath/libmpv.2.dylib",
			"@rpath/libmpv.dylib",
		]
	} else if cfg!(target_os = "android") {
		&["libmpv.so"]
	} else if cfg!(target_os = "ios") {
		// media_kit's own iOS lookup name (its `NativeLibrary` opens exactly
		// this string), then the same file by absolute bundle path. The
		// framework is embedded at `Runner.app/Frameworks/Mpv.framework`;
		// `@executable_path` and `@rpath` cover the two ways dyld can be
		// pointed at it without relying on a relative-path search rule.
		&[
			"Mpv.framework/Mpv",
			"@executable_path/Frameworks/Mpv.framework/Mpv",
			"@rpath/Mpv.framework/Mpv",
		]
	} else {
		&[]
	}
}

/// Why a libmpv poster could not be produced.
///
/// [LibMpvError::Unavailable] is the variant the caller acts on: this platform
/// has no direct-render backend at all (no library, a missing symbol, or a
/// client API older than the software renderer), where every other variant is a
/// per-file failure that another file may well survive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LibMpvError {
	/// libmpv cannot be used in this process, and nothing about the media will
	/// change that.
	Unavailable { reason: String },
	/// libmpv rejected a call.
	Call {
		call: &'static str,
		code: c_int,
		message: String,
	},
	/// The file did not load, or it has no video track.
	Load { message: String },
	/// A stage did not finish inside its deadline.
	Timeout {
		stage: &'static str,
		timeout: Duration,
	},
	/// An argument could not be represented as a C string (an interior NUL).
	InvalidArgument { what: &'static str },
	/// The WebP encoder refused the rendered frame.
	Encode,
}

impl LibMpvError {
	/// Whether this failure means "no libmpv backend on this platform" rather
	/// than "this file produced no poster".
	pub(crate) fn is_unavailable(&self) -> bool {
		matches!(self, Self::Unavailable { .. })
	}
}

impl fmt::Display for LibMpvError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Unavailable { reason } => write!(f, "libmpv unavailable: {reason}"),
			Self::Call {
				call,
				code,
				message,
			} => write!(f, "{call} failed ({code}): {message}"),
			Self::Load { message } => write!(f, "file did not load: {message}"),
			Self::Timeout { stage, timeout } => {
				write!(f, "{stage} timed out after {timeout:?}")
			}
			Self::InvalidArgument { what } => write!(f, "{what} contains a NUL byte"),
			Self::Encode => write!(f, "the WebP encoder refused the frame"),
		}
	}
}

impl std::error::Error for LibMpvError {}

/// The libmpv functions this module calls, resolved once.
///
/// Copied out of libloading's symbols as plain function pointers: `Symbol`
/// borrows the library, which would put a lifetime on every type here, and the
/// pointers are equally valid because the library is never unloaded.
#[derive(Clone, Copy)]
pub(crate) struct Api {
	client_api_version: unsafe extern "C" fn() -> c_ulong,
	error_string: unsafe extern "C" fn(c_int) -> *const c_char,
	create: unsafe extern "C" fn() -> *mut MpvHandle,
	initialize: unsafe extern "C" fn(*mut MpvHandle) -> c_int,
	terminate_destroy: unsafe extern "C" fn(*mut MpvHandle),
	set_option_string: unsafe extern "C" fn(*mut MpvHandle, *const c_char, *const c_char) -> c_int,
	command: unsafe extern "C" fn(*mut MpvHandle, *const *const c_char) -> c_int,
	get_property: unsafe extern "C" fn(*mut MpvHandle, *const c_char, c_int, *mut c_void) -> c_int,
	wait_event: unsafe extern "C" fn(*mut MpvHandle, f64) -> *mut MpvEvent,
	render_create:
		unsafe extern "C" fn(*mut *mut MpvRenderContext, *mut MpvHandle, *mut RenderParam) -> c_int,
	render_free: unsafe extern "C" fn(*mut MpvRenderContext),
	render_update: unsafe extern "C" fn(*mut MpvRenderContext) -> u64,
	render: unsafe extern "C" fn(*mut MpvRenderContext, *mut RenderParam) -> c_int,
	render_get_info: unsafe extern "C" fn(*mut MpvRenderContext, RenderParam) -> c_int,
	render_report_swap: unsafe extern "C" fn(*mut MpvRenderContext),
}

impl Api {
	/// libmpv's own description of an error code.
	fn error_message(&self, code: c_int) -> String {
		// SAFETY: mpv_error_string accepts any int and returns a static string.
		let text = unsafe { (self.error_string)(code) };
		if text.is_null() {
			return format!("error code {code}");
		}
		// SAFETY: a non-null mpv_error_string answer is a nul-terminated C
		// string with static lifetime.
		unsafe { CStr::from_ptr(text) }
			.to_string_lossy()
			.into_owned()
	}

	fn call_error(&self, call: &'static str, code: c_int) -> LibMpvError {
		LibMpvError::Call {
			call,
			code,
			message: self.error_message(code),
		}
	}
}

/// The resolved function table, or why there is none.
static API: OnceLock<Result<&'static Api, LibMpvError>> = OnceLock::new();

/// Resolve libmpv, loading it on first use.
///
/// The answer is cached for the process, failure included: a missing library is
/// a property of the installation, not of the request.
pub(crate) fn api() -> Result<&'static Api, LibMpvError> {
	match API.get_or_init(load) {
		Ok(api) => Ok(*api),
		Err(error) => Err(error.clone()),
	}
}

fn load() -> Result<&'static Api, LibMpvError> {
	let mut tried = Vec::new();
	for name in library_names() {
		// SAFETY: opening a shared library runs its initializers. That is the
		// same trust the app already places in the libmpv its player uses, and
		// it is the same build of it.
		let library = match unsafe { Library::new(name) } {
			Ok(library) => library,
			Err(error) => {
				tried.push(format!("{name}: {error}"));
				continue;
			}
		};
		// A candidate can open and still be the wrong image (a stale copy of
		// the framework without the render API, say). Try the remaining names
		// rather than declaring the platform unavailable from the first one.
		// Bind BEFORE leaking: a failed candidate must drop, or its handle (and
		// any initializers it ran) stays in the process for nothing.
		let api = match bind(&library) {
			Ok(api) => api,
			Err(error) => {
				tried.push(format!("{name}: {error}"));
				continue;
			}
		};
		// Leaked on purpose: the function pointers stored in `Api` point into
		// this library, so it must outlive every call — for the whole process,
		// exactly as media_kit's own handle does.
		let _library: &'static Library = Box::leak(Box::new(library));
		let api: &'static Api = Box::leak(Box::new(api));
		rcrm_core::log_debug!("[poster] libmpv loaded from {name}");
		return Ok(api);
	}
	Err(LibMpvError::Unavailable {
		reason: format!(
			"no usable libmpv shared library found (tried {})",
			tried.join("; ")
		),
	})
}

/// Look one symbol up, copied out of its borrow of the library.
macro_rules! bind {
	($library:expr, $ty:ty, $name:literal) => {{
		// SAFETY: the name is the exact C symbol from client.h/render.h, the
		// type is the function's real signature, and the library is leaked so
		// the pointer stays valid.
		match unsafe { $library.get::<$ty>(concat!($name, "\0").as_bytes()) } {
			Ok(symbol) => *symbol,
			Err(error) => {
				return Err(LibMpvError::Unavailable {
					reason: format!("libmpv has no {}: {error}", $name),
				});
			}
		}
	}};
}

fn bind(library: &Library) -> Result<Api, LibMpvError> {
	let api = Api {
		client_api_version: bind!(
			library,
			unsafe extern "C" fn() -> c_ulong,
			"mpv_client_api_version"
		),
		error_string: bind!(
			library,
			unsafe extern "C" fn(c_int) -> *const c_char,
			"mpv_error_string"
		),
		create: bind!(
			library,
			unsafe extern "C" fn() -> *mut MpvHandle,
			"mpv_create"
		),
		initialize: bind!(
			library,
			unsafe extern "C" fn(*mut MpvHandle) -> c_int,
			"mpv_initialize"
		),
		terminate_destroy: bind!(
			library,
			unsafe extern "C" fn(*mut MpvHandle),
			"mpv_terminate_destroy"
		),
		set_option_string: bind!(
			library,
			unsafe extern "C" fn(*mut MpvHandle, *const c_char, *const c_char) -> c_int,
			"mpv_set_option_string"
		),
		command: bind!(
			library,
			unsafe extern "C" fn(*mut MpvHandle, *const *const c_char) -> c_int,
			"mpv_command"
		),
		get_property: bind!(
			library,
			unsafe extern "C" fn(*mut MpvHandle, *const c_char, c_int, *mut c_void) -> c_int,
			"mpv_get_property"
		),
		wait_event: bind!(
			library,
			unsafe extern "C" fn(*mut MpvHandle, f64) -> *mut MpvEvent,
			"mpv_wait_event"
		),
		render_create: bind!(
			library,
			unsafe extern "C" fn(
				*mut *mut MpvRenderContext,
				*mut MpvHandle,
				*mut RenderParam,
			) -> c_int,
			"mpv_render_context_create"
		),
		render_free: bind!(
			library,
			unsafe extern "C" fn(*mut MpvRenderContext),
			"mpv_render_context_free"
		),
		render_update: bind!(
			library,
			unsafe extern "C" fn(*mut MpvRenderContext) -> u64,
			"mpv_render_context_update"
		),
		render: bind!(
			library,
			unsafe extern "C" fn(*mut MpvRenderContext, *mut RenderParam) -> c_int,
			"mpv_render_context_render"
		),
		render_get_info: bind!(
			library,
			unsafe extern "C" fn(*mut MpvRenderContext, RenderParam) -> c_int,
			"mpv_render_context_get_info"
		),
		render_report_swap: bind!(
			library,
			unsafe extern "C" fn(*mut MpvRenderContext),
			"mpv_render_context_report_swap"
		),
	};
	// SAFETY: mpv_client_api_version takes nothing and returns a plain integer.
	let version = unsafe { (api.client_api_version)() };
	let (major, minor) = api_major_minor(version);
	if version < REQUIRED_API {
		return Err(LibMpvError::Unavailable {
			reason: format!(
				"libmpv client API {major}.{minor} is older than the required {}.{}",
				REQUIRED_API >> 16,
				REQUIRED_API & 0xffff
			),
		});
	}
	Ok(api)
}

/// One mpv event this module acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Event {
	/// The file is loaded and its tracks are known.
	FileLoaded,
	/// A seek request started (`MPV_EVENT_SEEK`).
	Seek,
	/// Playback of the file ended; the error says why when mpv reports one (a
	/// missing URL, a refused TLS peer, a broken container).
	EndFile { error: Option<String> },
	/// mpv is shutting down under us.
	Shutdown,
	/// An event the poster generator does not act on.
	Other,
	/// The queue was empty when the wait expired.
	Timeout,
}

/// One initialized mpv client, created with `pause=yes` and a software video
/// output.
///
/// Drop calls `mpv_terminate_destroy`, which blocks until the core's threads
/// have stopped. A [RenderContext] must be gone by then (render.h), which its
/// `&Mpv` borrow forces.
pub(crate) struct Mpv {
	api: &'static Api,
	handle: *mut MpvHandle,
}

impl Mpv {
	/// Create a client with [options] applied and initialization done.
	///
	/// Options are only accepted before `mpv_initialize`, which is why they
	/// arrive here rather than as setters. A rejected one is logged and
	/// otherwise ignored: the client still works, and the option that matters
	/// (`vo=libmpv`) fails loudly when the render context cannot be created.
	pub(crate) fn create(options: &[(&str, String)]) -> Result<Self, LibMpvError> {
		let api = api()?;
		// SAFETY: mpv_create has no preconditions and only returns a handle or
		// null.
		let handle = unsafe { (api.create)() };
		if handle.is_null() {
			return Err(LibMpvError::Unavailable {
				reason: "mpv_create returned null".to_string(),
			});
		}
		let mpv = Self { api, handle };
		for (name, value) in options {
			if let Err(error) = mpv.set_option(name, value) {
				// An error level, not debug: the options in `options()` are what
				// keep this client paused, windowless and header-authenticated,
				// so a libmpv that renamed one would silently change behaviour —
				// and this line is the only place that says so.
				rcrm_core::log_error!("[poster] libmpv rejected option {name}={value}: {error}");
			}
		}
		// SAFETY: the handle is valid and not initialized yet; mpv_initialize
		// reports failure as a negative code.
		let code = unsafe { (mpv.api.initialize)(mpv.handle) };
		if code < 0 {
			return Err(mpv.api.call_error("mpv_initialize", code));
		}
		Ok(mpv)
	}

	fn set_option(&self, name: &str, value: &str) -> Result<(), LibMpvError> {
		let name = cstring(name, "option name")?;
		let value = cstring(value, "option value")?;
		// SAFETY: both strings outlive the call and the handle is valid.
		let code =
			unsafe { (self.api.set_option_string)(self.handle, name.as_ptr(), value.as_ptr()) };
		if code < 0 {
			Err(self.api.call_error("mpv_set_option_string", code))
		} else {
			Ok(())
		}
	}

	/// Run a command synchronously, e.g. `loadfile` or `seek`.
	pub(crate) fn command(&self, args: &[&str]) -> Result<(), LibMpvError> {
		let owned: Vec<CString> = args
			.iter()
			.map(|argument| cstring(argument, "command argument"))
			.collect::<Result<_, _>>()?;
		let mut argv: Vec<*const c_char> = owned.iter().map(|argument| argument.as_ptr()).collect();
		argv.push(std::ptr::null());
		// SAFETY: argv is a null-terminated array of valid C strings and the
		// handle is valid. mpv copies what it needs before returning.
		let code = unsafe { (self.api.command)(self.handle, argv.as_ptr()) };
		if code < 0 {
			Err(self.api.call_error("mpv_command", code))
		} else {
			Ok(())
		}
	}

	/// Read a numeric property, or `None` when libmpv does not have it (yet).
	pub(crate) fn get_f64(&self, name: &str) -> Option<f64> {
		let name = CString::new(name).ok()?;
		let mut value = 0f64;
		// SAFETY: the name is a valid C string and `value` is a live f64 of
		// the layout MPV_FORMAT_DOUBLE requires.
		let code = unsafe {
			(self.api.get_property)(
				self.handle,
				name.as_ptr(),
				FORMAT_DOUBLE,
				std::ptr::from_mut(&mut value).cast(),
			)
		};
		(code >= 0).then_some(value)
	}

	/// Read an integer property (`width`, `dwidth`, ...).
	pub(crate) fn get_i64(&self, name: &str) -> Option<i64> {
		let name = CString::new(name).ok()?;
		let mut value = 0i64;
		// SAFETY: as in `get_f64`, with MPV_FORMAT_INT64's layout.
		let code = unsafe {
			(self.api.get_property)(
				self.handle,
				name.as_ptr(),
				FORMAT_INT64,
				std::ptr::from_mut(&mut value).cast(),
			)
		};
		(code >= 0).then_some(value)
	}

	/// Wait up to [timeout] for the next event.
	pub(crate) fn wait_event(&self, timeout: Duration) -> Event {
		// SAFETY: the handle is valid; mpv_wait_event returns a pointer into
		// libmpv's own queue, valid until the next wait on this handle.
		let event = unsafe { (self.api.wait_event)(self.handle, timeout.as_secs_f64()) };
		if event.is_null() {
			return Event::Timeout;
		}
		// SAFETY: a non-null event points at a live `mpv_event`.
		let event = unsafe { &*event };
		match event.event_id {
			EVENT_NONE => Event::Timeout,
			EVENT_FILE_LOADED => Event::FileLoaded,
			EVENT_SEEK => Event::Seek,
			EVENT_SHUTDOWN => Event::Shutdown,
			EVENT_END_FILE => {
				let error = if event.data.is_null() {
					None
				} else {
					// SAFETY: END_FILE's payload is an `mpv_event_end_file`.
					let end = unsafe { &*event.data.cast::<MpvEndFile>() };
					(end.error < 0).then(|| self.api.error_message(end.error))
				};
				Event::EndFile { error }
			}
			_ => Event::Other,
		}
	}
}

impl Drop for Mpv {
	fn drop(&mut self) {
		// SAFETY: the handle came from mpv_create and is destroyed once; a
		// render context created from it is already gone, because
		// `RenderContext` borrows this client.
		unsafe { (self.api.terminate_destroy)(self.handle) };
	}
}

/// A software render context: libmpv draws each frame into memory we own, so no
/// window, GPU context or Dart buffer is involved.
///
/// render.h requires one thread to create, use and free a context. A poster job
/// runs entirely on its own thread, so that holds by construction.
pub(crate) struct RenderContext<'mpv> {
	api: &'static Api,
	context: *mut MpvRenderContext,
	/// Keeps the client alive and un-destroyed for as long as the context
	/// exists; render.h requires the context to be freed first.
	_mpv: &'mpv Mpv,
}

impl<'mpv> RenderContext<'mpv> {
	/// Create a software render context on [mpv], whose video output must be
	/// `vo=libmpv` (set before initialization).
	pub(crate) fn new(mpv: &'mpv Mpv) -> Result<Self, LibMpvError> {
		let api = mpv.api;
		// render.h's "Type: char*" means the data field IS the string, not a
		// pointer to one (the other params DO point at their value). Passing the
		// address of this pointer makes libmpv read garbage and answer
		// MPV_ERROR_NOT_IMPLEMENTED.
		let mut params = [
			RenderParam {
				kind: PARAM_API_TYPE,
				data: RENDER_API_SW.as_ptr().cast_mut().cast(),
			},
			RenderParam {
				kind: PARAM_INVALID,
				data: std::ptr::null_mut(),
			},
		];
		let mut context: *mut MpvRenderContext = std::ptr::null_mut();
		// SAFETY: `params` is a terminator-ended array of the documented shape
		// and the client is already initialized; the context is written once.
		let code = unsafe { (api.render_create)(&mut context, mpv.handle, params.as_mut_ptr()) };
		if code == ERROR_NOT_IMPLEMENTED {
			// This libmpv has no software renderer. That is a property of the
			// build, not of the media, so report "no backend here": every file
			// would fail the same way.
			return Err(LibMpvError::Unavailable {
				reason: format!(
					"this libmpv exposes no software renderer: {}",
					api.error_message(code)
				),
			});
		}
		if code < 0 {
			return Err(api.call_error("mpv_render_context_create", code));
		}
		if context.is_null() {
			return Err(LibMpvError::Call {
				call: "mpv_render_context_create",
				code,
				message: "no context was written".to_string(),
			});
		}
		Ok(Self {
			api,
			context,
			_mpv: mpv,
		})
	}

	/// What the next [Self::render] would draw, or `None` when this libmpv
	/// does not answer the question.
	pub(crate) fn frame_info(&self) -> Option<MpvRenderFrameInfo> {
		let mut info = MpvRenderFrameInfo {
			flags: 0,
			target_time: 0,
		};
		// render.h takes the parameter BY VALUE (`mpv_render_param param`), not
		// as a terminator-ended array: the struct is the whole argument.
		let param = RenderParam {
			kind: PARAM_NEXT_FRAME_INFO,
			data: std::ptr::from_mut(&mut info).cast(),
		};
		// SAFETY: the context is live and used from its own thread; `param` names
		// the documented type and `info` outlives the call.
		let code = unsafe { (self.api.render_get_info)(self.context, param) };
		(code >= 0).then_some(info)
	}

	/// Whether a new frame is ready to be drawn.
	pub(crate) fn has_frame(&self) -> bool {
		// SAFETY: the context is live and used from its own thread.
		let flags = unsafe { (self.api.render_update)(self.context) };
		flags & RENDER_UPDATE_FRAME != 0
	}

	/// Draw the pending frame into [surface] at the surface's own size.
	pub(crate) fn render(&self, surface: &mut Surface) -> Result<(), LibMpvError> {
		// render.h's SW_SIZE is `int[2]`; Surface::new keeps both dimensions far
		// below i32::MAX (see its contract).
		let mut size = [surface.width as c_int, surface.height as c_int];
		let mut stride = surface.stride;
		let mut params = [
			RenderParam {
				kind: PARAM_SW_SIZE,
				data: std::ptr::from_mut(&mut size).cast(),
			},
			RenderParam {
				kind: PARAM_SW_FORMAT,
				// The C side wants a non-const char*, and never writes to it.
				data: SURFACE_FORMAT.as_ptr().cast_mut().cast(),
			},
			RenderParam {
				kind: PARAM_SW_STRIDE,
				data: std::ptr::from_mut(&mut stride).cast(),
			},
			RenderParam {
				kind: PARAM_SW_POINTER,
				data: surface.pointer().cast(),
			},
			RenderParam {
				kind: PARAM_INVALID,
				data: std::ptr::null_mut(),
			},
		];
		// SAFETY: the surface is exclusively ours for the call, its pointer is
		// 64-byte aligned and at least `stride * height` bytes long, and every
		// parameter matches the type render.h documents for it.
		let code = unsafe { (self.api.render)(self.context, params.as_mut_ptr()) };
		if code < 0 {
			Err(self.api.call_error("mpv_render_context_render", code))
		} else {
			Ok(())
		}
	}

	/// Tell libmpv the frame was consumed. Without it `has_frame` keeps
	/// reporting the same frame, which is how a stale poster gets rendered.
	pub(crate) fn report_swap(&self) {
		// SAFETY: the context is live and used from its own thread.
		unsafe { (self.api.render_report_swap)(self.context) };
	}
}

impl Drop for RenderContext<'_> {
	fn drop(&mut self) {
		// SAFETY: the context was created here, is freed once, and its client
		// is still alive (`_mpv`).
		unsafe { (self.api.render_free)(self.context) };
	}
}

/// A BGR0 surface libmpv renders one frame into.
///
/// The pointer is 64-byte aligned and the stride is a multiple of the 4-byte
/// pixel size, which is the fast path render.h describes; the storage also keeps
/// one alignment unit of slack after the last row, because render.h allows a
/// scaler to write into that padding.
pub(crate) struct Surface {
	/// Raw storage; the frame starts at [Surface::offset] inside it.
	storage: Vec<u8>,
	offset: usize,
	width: u32,
	height: u32,
	stride: usize,
}

/// Alignment render.h asks for, for the fast scaler paths.
const SURFACE_ALIGN: usize = 64;
/// BGR0: 4 bytes per pixel.
const SURFACE_BPP: usize = 4;
/// Upper bound on one frame buffer: a 640-wide portrait poster at the tallest
/// surface `target_size` allows is ~21 MiB, so 32 MiB admits every real frame
/// with room to spare and refuses an accidental runaway allocation.
const MAX_SURFACE_BYTES: usize = 32 * 1024 * 1024;

impl Surface {
	/// A surface of `width` x `height` pixels.
	///
	/// The only caller is `generate`, through `target_size`: width is capped at
	/// the requested poster width (640 from Dart) and height at `MAX_HEIGHT`, so
	/// the product is a few megabytes. The `debug_assert` states that contract
	/// for the next caller without costing anything in release.
	pub(crate) fn new(width: u32, height: u32) -> Self {
		let stride = width as usize * SURFACE_BPP;
		let len = stride * height as usize;
		debug_assert!(
			len <= MAX_SURFACE_BYTES,
			"surface of {width}x{height} is {len} bytes, above the {MAX_SURFACE_BYTES}-byte bound"
		);
		let storage = vec![0u8; len + SURFACE_ALIGN];
		let base = storage.as_ptr() as usize;
		let offset = (SURFACE_ALIGN - base % SURFACE_ALIGN) % SURFACE_ALIGN;
		Self {
			storage,
			offset,
			width,
			height,
			stride,
		}
	}

	/// The surface's first pixel, aligned as [SURFACE_ALIGN] asks.
	///
	/// The write happens in libmpv, through this pointer. `&self` is sound
	/// here because the pointer is the buffer pointer the `Vec` stores — a
	/// shared borrow of the `Vec` freezes the `Vec`'s own bytes, not the heap
	/// allocation it points at (and no `&[u8]` into that allocation is alive
	/// while the frame is being written). A `slice`-derived pointer would be a
	/// different story: that one would be read-only.
	fn pointer(&self) -> *mut u8 {
		// SAFETY: `offset + stride * height` fits the allocation by
		// construction, so this stays in bounds.
		unsafe { self.storage.as_ptr().add(self.offset) }.cast_mut()
	}

	/// The rendered pixels, tightly packed at `stride == width * 4`.
	///
	/// Always `width * height * 4` bytes, which is the length the encoder
	/// requires; the opaque-alpha pass rewrites them through this view.
	pub(crate) fn pixels_mut(&mut self) -> &mut [u8] {
		let end = self.offset + self.stride * self.height as usize;
		&mut self.storage[self.offset..end]
	}

	/// Pixel dimensions, as `(width, height)`.
	pub(crate) fn size(&self) -> (u32, u32) {
		(self.width, self.height)
	}
}

/// A CString, or the error naming the argument that could not be one.
fn cstring(value: &str, what: &'static str) -> Result<CString, LibMpvError> {
	CString::new(value).map_err(|_| LibMpvError::InvalidArgument { what })
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn api_version_splits_into_major_minor() {
		assert_eq!(api_major_minor(0x0002_0002), (2, 2));
		assert_eq!(api_major_minor(0x0001_001c), (1, 28));
		assert_eq!(api_major_minor(0), (0, 0));
	}

	/// A surface must satisfy render.h's alignment contract whatever the
	/// allocator hands back, and must be exactly `width * height * 4` bytes for
	/// the encoder.
	#[test]
	fn surface_is_aligned_and_tightly_packed() {
		for (width, height) in [(640u32, 360u32), (640, 1138), (17, 3), (1, 1)] {
			let mut surface = Surface::new(width, height);
			// `len = stride * height` with the frame tightly packed, so this
			// pins `stride == width * 4` as well as the size.
			assert_eq!(
				surface.pixels_mut().len(),
				width as usize * height as usize * 4
			);
			assert_eq!(
				surface.pointer() as usize % SURFACE_ALIGN,
				0,
				"pointer must be {SURFACE_ALIGN}-aligned for {width}x{height}"
			);
			assert_eq!(surface.size(), (width, height));
		}
	}

	#[test]
	fn only_an_unavailable_error_means_no_backend() {
		let error = LibMpvError::Unavailable {
			reason: "test".to_string(),
		};
		assert!(error.is_unavailable());
		assert!(!LibMpvError::Encode.is_unavailable());
		assert_eq!(error.to_string(), "libmpv unavailable: test");
	}
}
