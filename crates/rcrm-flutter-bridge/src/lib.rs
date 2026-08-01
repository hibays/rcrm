// src/lib.rs
// rcrm-flutter-bridge — C-ABI FFI exports for Flutter integration
// Copyleft (©) 2024-2025 hibays
//
// Exposes rcrm-core (crypt) + rcrm-server (WebDAV) functionality as
// `extern "C"` functions callable from Dart via `dart:ffi`.
//
// ## Memory ownership rules (Dart side MUST follow):
//   1. Strings returned by `rcrm_*` functions are malloc'd C strings —
//      Dart must call `rcrm_free_string` after use.
//   2. Server handles returned by `rcrm_start_server` are opaque i32 ids —
//      Dart must call `rcrm_free_server` when done (which calls stop+free).
//   3. Strings passed *to* `rcrm_*` functions are borrowed — Rust copies them
//      immediately, so Dart may free them after the call returns.
//
// ## Thread safety:
//   All public functions acquire internal locks. They are safe to call
//   from any Dart isolate (thread), but many are blocking — call them on
//   a background isolate in Flutter.

#[cfg(feature = "mobile-decode")]
mod avif;
#[cfg(feature = "mobile-decode")]
mod decode;
#[cfg(feature = "mobile-decode")]
mod jxl;

mod crypt_ops;
mod server;
mod tls_cert;
mod webp;

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use zeroize::Zeroizing;

/// Parse the password argument into owned, zeroizing copies.
///
/// Accepts a JSON array of strings (`["pw1","pw2"]`) so multiple passwords
/// can be supplied (different files may use different keys, mirroring the
/// CLI's `serve` accumulation). For backward compatibility a bare string is
/// treated as a single password. Empty entries are dropped. Each returned
/// `Zeroizing<String>` wipes its bytes when dropped.
unsafe fn parse_passwords(ptr: *const c_char) -> Vec<Zeroizing<String>> {
	let s = unsafe { cstr_to_str(ptr) };
	if s.is_empty() {
		return Vec::new();
	}
	if let Ok(list) = serde_json::from_str::<Vec<String>>(s) {
		return list
			.into_iter()
			.filter(|p| !p.is_empty())
			.map(Zeroizing::new)
			.collect();
	}
	vec![Zeroizing::new(s.to_string())]
}

// =======================
// String helpers
// =======================

/// Convert a null-terminated C string to a Rust &str.
/// Returns "" for null pointers (tolerate Dart passing null).
unsafe fn cstr_to_str<'a>(ptr: *const c_char) -> &'a str {
	if ptr.is_null() {
		return "";
	}
	unsafe { CStr::from_ptr(ptr) }.to_str().unwrap_or("")
}

/// Convert a Rust string to a heap-allocated C string.
/// Caller (Dart) must free with `rcrm_free_string`.
fn str_to_cstring(s: &str) -> *mut c_char {
	CString::new(s)
		.unwrap_or_else(|_| CString::new("").unwrap())
		.into_raw()
}

// =======================
// Memory management
// =======================

/// Free a string previously returned by any `rcrm_*` function.
/// Safe to call with null (no-op).
///
/// # Safety
/// `ptr` must be either null or a pointer previously returned by an
/// `rcrm_*` function. Any other pointer is undefined behavior.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rcrm_free_string(ptr: *mut c_char) {
	if ptr.is_null() {
		return;
	}
	unsafe {
		drop(CString::from_raw(ptr));
	}
}

// =======================
// Server operations
// =======================

/// Start the projection WebDAV server.
///
/// # Arguments
/// * `dirs_json` — JSON array of directory paths, e.g. `["/mnt/media","/mnt/backup"]`
/// * `passwords_json` — JSON array of decryption passwords, e.g. `["pw1","pw2"]`
///   (a bare string is accepted as a single password)
/// * `bind_addr` — bind address, e.g. "127.0.0.1"
/// * `port` — port number (0 = OS picks)
///
/// # Returns
/// Always `1` if the start request was accepted (a background thread then
/// scans directories, verifies passwords, and starts the server). The actual
/// outcome is reported asynchronously via `rcrm_get_server_status`:
///   * `2`  — running (call `rcrm_get_server_url` for the base URL)
///   * `-2` — some encrypted files could not be opened by any key (server NOT
///     started — call `rcrm_last_verify()` for the encrypted/locked
///     counts, then start again with more passwords)
///   * `-1` — error (call `rcrm_last_error()`)
///
/// The returned `1` is a fixed handle; do not use it to distinguish success
/// from failure — poll `rcrm_get_server_status` instead.
///
/// # Safety
/// `dirs_json`, `password`, and `bind_addr` must be non-null pointers to
/// null-terminated UTF-8 C strings. Copied immediately — caller may free
/// after return.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rcrm_start_server(
	dirs_json: *const c_char,
	password: *const c_char,
	bind_addr: *const c_char,
	port: u16,
) -> i32 {
	let dirs_str = unsafe { cstr_to_str(dirs_json) };
	let passwords = unsafe { parse_passwords(password) };
	let bind_str = unsafe { cstr_to_str(bind_addr) };
	server::start(dirs_str, &passwords, bind_str, port)
}

/// Stop and free a server previously started with `rcrm_start_server`.
/// Returns 0 on success, -1 if the handle was invalid.
///
/// # Safety
/// `handle` must be a valid server handle returned by `rcrm_start_server`
/// and must not have been freed already.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rcrm_stop_server(handle: i32) -> i32 {
	server::stop(handle)
}

/// Get the base URL of a running server (e.g. "http://127.0.0.1:8080/").
/// Returns a malloc'd string — caller must `rcrm_free_string`.
/// Returns null if the handle is invalid or server is not running.
///
/// # Safety
/// `handle` must be a valid server handle returned by `rcrm_start_server`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rcrm_get_server_url(handle: i32) -> *mut c_char {
	match server::get_url(handle) {
		Some(url) => str_to_cstring(&url),
		None => std::ptr::null_mut(),
	}
}

/// Get server status: 0 = stopped, 1 = running, -1 = invalid handle.
///
/// # Safety
/// `handle` must be a valid server handle returned by `rcrm_start_server`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rcrm_get_server_status(handle: i32) -> i32 {
	server::status(handle)
}

/// Get the random HTTP Basic Auth credentials for this server session.
///
/// Returns a JSON string (malloc'd — call `rcrm_free_string`):
/// `{"username":"abc12345","password":"xyz67890abcdef12"}`
///
/// Returns null if the handle is invalid or server is not running.
///
/// # Safety
/// `handle` must be a valid server handle returned by `rcrm_start_server`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rcrm_get_auth_credentials(handle: i32) -> *mut c_char {
	match server::get_auth_json(handle) {
		Some(json) => str_to_cstring(&json),
		None => std::ptr::null_mut(),
	}
}

// =======================
// Crypt operations
// =======================

/// Encrypt or decrypt a folder in-place.
///
/// # Arguments
/// * `path` — absolute path to the folder
/// * `password` — encryption/decryption password
/// * `is_encrypt` — 0 = decrypt, 1 = encrypt
///
/// # Returns
/// 0 on success, -1 on error (call `rcrm_last_error`).
///
/// # Safety
/// `path` and `password` must be non-null pointers to null-terminated
/// UTF-8 C strings. Copied immediately — caller may free after return.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rcrm_crypt_folder(
	path: *const c_char,
	password: *const c_char,
	is_encrypt: i32,
) -> i32 {
	let path_str = unsafe { cstr_to_str(path) };
	let pw_str = unsafe { cstr_to_str(password) };
	crypt_ops::crypt_folder(path_str, pw_str, is_encrypt != 0)
}

// =======================
// Verification result
// =======================

/// Get the result of the most recent `rcrm_start_server` verification.
///
/// Returns a malloc'd JSON string `{"encrypted":N,"locked":M}` (call
/// `rcrm_free_string`), where `locked` is how many encrypted files no provided
/// key could open. After `rcrm_start_server` returns -2, read this to decide
/// whether to prompt for another password.
///
/// # Safety
/// Must not be called concurrently with `rcrm_start_server` from another
/// thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rcrm_last_verify() -> *mut c_char {
	server::last_verify()
}

// =======================
// Error reporting
// =======================

/// Get the last error message.
/// Returns a malloc'd string — caller must `rcrm_free_string`.
/// Returns null if no error has occurred.
///
/// # Safety
/// Must not be called concurrently with operations that set error state
/// from another thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rcrm_last_error() -> *mut c_char {
	server::last_error()
}

// =======================
// Version
// =======================

/// Get the bridge library version string.
///
/// # Safety
/// Always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rcrm_version() -> *mut c_char {
	str_to_cstring(env!("CARGO_PKG_VERSION"))
}

/// Check if JPEG frame is blank (mean luminance <20 or >235).
///
/// # Safety
/// `data` must be a valid pointer to at least `len` bytes of JPEG data.
/// `len` must be > 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rcrm_is_blank_frame(data: *const u8, len: usize) -> i32 {
	if data.is_null() || len == 0 {
		return -1;
	}
	let bytes = unsafe { std::slice::from_raw_parts(data, len) };
	let mut dec =
		zune_jpeg::JpegDecoder::new(zune_jpeg::zune_core::bytestream::ZCursor::new(bytes));
	match dec.decode() {
		Ok(pixels) => {
			if pixels.len() < 300 {
				return -1;
			}
			let mut sum: f64 = 0.0;
			for c in pixels.chunks_exact(3) {
				sum += 0.299 * c[0] as f64 + 0.587 * c[1] as f64 + 0.114 * c[2] as f64;
			}
			let avg = sum / (pixels.len() / 3) as f64;
			if !(20.0..=235.0).contains(&avg) { 1 } else { 0 }
		}
		Err(_) => -1,
	}
}

// =======================
// Mobile image decoders (Android/iOS) — async via thread + callback
// =======================

/// Callback invoked from a spawned thread when decode completes.
/// `result` is null on failure, otherwise must be freed via `rcrm_free_decode_buf`.
/// `ctx` is the opaque user pointer passed to the async decode function.
#[cfg(feature = "mobile-decode")]
type DecodeCallback = unsafe extern "C" fn(*mut decode::DecodeBuf, *mut std::ffi::c_void);

/// Asynchronous decode: AVIF image bytes → raw RGBA.
///
/// Copies the input data immediately (synchronous), then spawns a thread
/// for the actual decode. When done, calls `callback(result, ctx)` from
/// the spawned thread.
///
/// # Safety
/// `data` must be a valid pointer to at least `len` bytes. `callback` may
/// be null (no-op). `ctx` is passed through to the callback verbatim and
/// must stay valid for the entire duration of the spawned thread.
#[cfg(feature = "mobile-decode")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rcrm_decode_avif_async(
	data: *const u8,
	len: usize,
	target_width: u32,
	callback: Option<DecodeCallback>,
	ctx: *mut std::ffi::c_void,
) {
	// Zero-copy: take ownership of the Dart calloc buffer via from_raw_parts.
	// Rust's Vec::drop will free it when the spawned thread finishes.
	// data.is_null() || len == 0 is checked above, so from_raw_parts is safe.
	let bytes = unsafe { Vec::from_raw_parts(data as *mut u8, len, len) };
	// `ctx` is an opaque integer (request ID) from Dart — never dereferenced,
	// simply passed through. Cast to usize so the closure is Send.
	let ctx_raw = ctx as usize;
	std::thread::spawn(move || {
		let result = if bytes.is_empty() {
			None
		} else {
			decode::decode_avif(&bytes, target_width)
		};
		let ptr = match result {
			Some(buf) => Box::into_raw(buf),
			None => std::ptr::null_mut(),
		};
		if let Some(cb) = callback {
			unsafe { cb(ptr, ctx_raw as *mut std::ffi::c_void) };
		}
	});
}

/// Asynchronous decode: JXL image bytes → raw RGBA.
///
/// Same contract as `rcrm_decode_avif_async`.
///
/// # Safety
/// `data` must be a valid pointer to at least `len` bytes. `callback` may
/// be null (no-op). `ctx` is passed through to the callback verbatim and
/// must be valid for the entire duration of the spawned thread.
#[cfg(feature = "mobile-decode")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rcrm_decode_jxl_async(
	data: *const u8,
	len: usize,
	target_width: u32,
	callback: Option<DecodeCallback>,
	ctx: *mut std::ffi::c_void,
) {
	// Zero-copy: same as rcrm_decode_avif_async.
	let bytes = unsafe { Vec::from_raw_parts(data as *mut u8, len, len) };
	let ctx_raw = ctx as usize;
	std::thread::spawn(move || {
		let result = if bytes.is_empty() {
			None
		} else {
			decode::decode_jxl(&bytes, target_width)
		};
		let ptr = match result {
			Some(buf) => Box::into_raw(buf),
			None => std::ptr::null_mut(),
		};
		if let Some(cb) = callback {
			unsafe { cb(ptr, ctx_raw as *mut std::ffi::c_void) };
		}
	});
}

/// Free a DecodeBuf returned by `rcrm_decode_avif_async` or `rcrm_decode_jxl_async`.
///
/// # Safety
/// `ptr` must be a pointer previously returned by one of the decode
/// functions, or null. Must not be freed twice.
#[cfg(feature = "mobile-decode")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rcrm_free_decode_buf(ptr: *mut decode::DecodeBuf) {
	unsafe { decode::free_decode_buf(ptr) }
}

/// Set the runtime log level for all Rust libraries.
/// 0 = silent, 1 = errors only, 2 = info (default), 3 = debug verbose.
///
/// # Safety
/// Always safe to call — takes a plain `u8` with no pointer preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rcrm_set_log_level(level: u8) {
	rcrm_core::log_level::set(level);
}

// =======================
// TV cast receiver TLS
// =======================

/// Generate a self-signed TLS certificate + private key for the TV cast
/// receiver (Android TV side of the QR-code pairing feature).
///
/// Returns a malloc'd JSON string `{"cert":"<PEM>","key":"<PEM>"}` on success
/// or `{"error":"..."}` on failure — caller must `rcrm_free_string`.
/// The key is PKCS#8 PEM (ECDSA P-256), 10-year validity.
///
/// # Safety
/// Always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rcrm_generate_tv_cert() -> *mut c_char {
	match tls_cert::generate() {
		Ok((cert, key)) => {
			str_to_cstring(&serde_json::json!({"cert": cert, "key": key.as_str()}).to_string())
		}
		Err(e) => str_to_cstring(&serde_json::json!({"error": e}).to_string()),
	}
}

// =======================
// Thumbnail WebP encoding (all platforms — not gated to mobile-decode)
// =======================

/// Encode raw RGBA pixels as lossy WebP (for the on-disk thumbnail cache).
///
/// # Arguments
/// * `data` — RGBA8 pixels, `width * height * 4` bytes
/// * `len` — byte length (must equal `width * height * 4`)
/// * `width`, `height` — image dimensions
/// * `quality` — 0-100 (thumbnails typically 70-85)
///
/// # Returns
/// A malloc'd `WebpBuf` (free with `rcrm_free_webp_buf`) whose `data` holds
/// the WebP bytes and `data_len` the encoded length, or null on failure.
///
/// # Safety
/// `data` must be a valid pointer to at least `len` bytes. The returned
/// pointer must be freed with `rcrm_free_webp_buf`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rcrm_encode_thumb_webp(
	data: *const u8,
	len: usize,
	width: u32,
	height: u32,
	quality: u8,
) -> *mut webp::WebpBuf {
	match unsafe { webp::encode_rgba_webp(data, len, width, height, quality) } {
		Some(buf) => Box::into_raw(buf),
		None => std::ptr::null_mut(),
	}
}

/// Free a `WebpBuf` returned by `rcrm_encode_thumb_webp`.
///
/// # Safety
/// `ptr` must be null or a pointer previously returned by
/// `rcrm_encode_thumb_webp`. Must not be freed twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rcrm_free_webp_buf(ptr: *mut webp::WebpBuf) {
	unsafe { webp::free_webp_buf(ptr) }
}
