// src/server.rs
// rcrm-flutter-bridge — server lifecycle management

use rand::RngExt;
use std::ffi::CString;
use std::net::SocketAddr;
use std::os::raw::c_char;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::thread;
use std::time::Duration;
use zeroize::Zeroizing;

use parking_lot::Mutex;
use std::sync::LazyLock as Lazy;

use rcrm_core::Manager;
use rcrm_server::serve::{
	AuthConfig, FileCache, Protocol, Server, ServerContext, generate_mount_names,
};

// =======================
// Global server state
// =======================

struct ServerState {
	shutdown: Arc<AtomicBool>,
	url: String,
	/// Randomly generated HTTP Basic Auth credentials.
	auth_username: String,
	auth_password: Zeroizing<String>,
}

static SERVER: Lazy<Mutex<Option<ServerState>>> = Lazy::new(|| Mutex::new(None));
/// 0=idle, 1=starting (bg thread), 2=running, -1=error, -2=locked
static START_STATUS: AtomicI32 = AtomicI32::new(0);
static LAST_ERROR: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));

// --- Persistent scan cache: populated on first call, reused on retries ---
/// All encrypted file paths + mount index, set after first directory scan.
static SCANNED_PATHS: Lazy<Mutex<Vec<(usize, PathBuf)>>> = Lazy::new(|| Mutex::new(Vec::new()));
/// Files that are still locked (no accepted key can open them).
static LOCKED_PATHS: Lazy<Mutex<Vec<PathBuf>>> = Lazy::new(|| Mutex::new(Vec::new()));
/// Keys that have successfully opened at least one file.
static ACCEPTED_KEYS: Lazy<Mutex<Vec<Zeroizing<String>>>> = Lazy::new(|| Mutex::new(Vec::new()));
/// How many files have been unlocked so far.
static UNLOCKED_COUNT: AtomicU64 = AtomicU64::new(0);
/// Original canonicalized directory paths, cached after first scan.
static CACHED_DIRS: Lazy<Mutex<Vec<PathBuf>>> = Lazy::new(|| Mutex::new(Vec::new()));

pub(crate) fn set_error(msg: impl Into<String>) {
	*LAST_ERROR.lock() = Some(msg.into());
}
pub(crate) fn clear_error() {
	*LAST_ERROR.lock() = None;
}

pub fn last_error() -> *mut c_char {
	match &*LAST_ERROR.lock() {
		Some(msg) => CString::new(msg.as_str()).unwrap_or_default().into_raw(),
		None => std::ptr::null_mut(),
	}
}

pub fn last_verify() -> *mut c_char {
	let total = SCANNED_PATHS.lock().len() as u64;
	let locked = LOCKED_PATHS.lock().len() as u64;
	let json = format!(r#"{{"encrypted":{},"locked":{}}}"#, total, locked);
	CString::new(json).unwrap_or_default().into_raw()
}

fn random_string(len: usize) -> String {
	let mut rng = rand::rng();
	(0..len)
		.map(|_| rng.sample(rand::distr::Alphanumeric) as char)
		.collect()
}

// =======================
// Public API
// =======================

/// Build a Manager holding every provided key (first key in the constructor,
/// the rest via use_added_key). Used for both verification and serving so a
/// single Manager covers files that use different passwords.
fn build_manager(passwords: &[Zeroizing<String>]) -> Manager {
	let mut it = passwords.iter();
	let first = it.next().map(|p| p.as_bytes());
	let mut manager = Manager::new(true, true, 2048, rcrm_core::is_supported_file, 4, first);
	for p in it {
		manager.use_added_key(p.as_bytes());
	}
	manager
}

/// Start the server. First call: scans directories, caches paths, verifies
/// all files against the provided passwords. Subsequent calls with additional
/// passwords: only verifies the NEW password against still-locked files.
/// When all files are unlocked, starts the WebDAV server.
pub fn start(dirs_json: &str, passwords: &[Zeroizing<String>], bind_addr: &str, port: u16) -> i32 {
	clear_error();

	let bind_addr = bind_addr.to_string();
	// Keep passwords inside Zeroizing the whole way across the thread
	// boundary: never copy them into a plain String (which would leave an
	// uncleaned copy in the heap).
	let pw_vec: Vec<Zeroizing<String>> = passwords
		.iter()
		.map(|z| Zeroizing::new(z.as_str().to_string()))
		.collect();
	let dirs_owned = dirs_json.to_string();

	START_STATUS.store(1, Ordering::SeqCst);

	thread::Builder::new()
		.name("rcrm-startup".into())
		.spawn(move || {
			// Already Zeroizing — no re-wrap needed.
			let passwords: Vec<Zeroizing<String>> = pw_vec;

			// --- Step 1: if first call, scan directories ---
			{
				let mut cached = SCANNED_PATHS.lock();
				if cached.is_empty() {
					// Parse dirs
					let dirs: Vec<String> = match serde_json::from_str(&dirs_owned) {
						Ok(d) => d,
						Err(e) => {
							set_error(format!("Invalid dirs JSON: {e}"));
							START_STATUS.store(-1, Ordering::SeqCst);
							return;
						}
					};
					let dirs: Vec<PathBuf> = dirs
						.into_iter()
						.map(|d| {
							dunce::canonicalize(PathBuf::from(&d))
								.unwrap_or_else(|_| PathBuf::from(&d))
						})
						.collect();
					for d in &dirs {
						if !d.exists() {
							set_error(format!("Dir not found: {}", d.display()));
							START_STATUS.store(-1, Ordering::SeqCst);
							return;
						}
						if !d.is_dir() {
							set_error(format!("Not a dir: {}", d.display()));
							START_STATUS.store(-1, Ordering::SeqCst);
							return;
						}
					}
					// Scan once, cache forever
					let mut all: Vec<(usize, PathBuf)> = Vec::new();
					for (idx, d) in dirs.iter().enumerate() {
						let (_n, enc) =
							rcrm_core::resolve_ne_path_from_dir_with_progress(d, |_| {});
						for fp in enc {
							all.push((idx, fp));
						}
					}
					*cached = all;
					// Cache the canonicalized dirs for Step 3.
					*CACHED_DIRS.lock() = dirs;
				}
			}

			let all_paths = SCANNED_PATHS.lock().clone();

			// --- Step 2: try NEW passwords against locked files ---
			// On first call, LOCKED_PATHS starts empty — move all files there.
			{
				let mut locked = LOCKED_PATHS.lock();
				if locked.is_empty() {
					for (_, fp) in &all_paths {
						locked.push(fp.clone());
					}
				}
			}

			let all_keys: Vec<Zeroizing<String>> = {
				let accepted = ACCEPTED_KEYS.lock();
				let mut keys = accepted.clone();
				keys.extend(passwords.clone());
				keys
			};
			let manager = build_manager(&all_keys);

			// Verify remaining locked files
			let locked_snapshot = LOCKED_PATHS.lock().clone();
			let mut still_locked: Vec<PathBuf> = Vec::new();
			let mut newly_unlocked = 0u64;

			for fp in &locked_snapshot {
				let ok = std::fs::File::open(fp)
					.ok()
					.and_then(|mut f| manager.read_file_header_any_key(&mut f).ok())
					.is_some();
				if ok {
					newly_unlocked += 1;
				} else {
					still_locked.push(fp.clone());
				}
			}

			UNLOCKED_COUNT.fetch_add(newly_unlocked, Ordering::Relaxed);
			*LOCKED_PATHS.lock() = still_locked;

			let remaining_locked = LOCKED_PATHS.lock().len() as u64;
			// On first attempt: if no files opened, password is wrong
			if newly_unlocked == 0 && UNLOCKED_COUNT.load(Ordering::Relaxed) == 0 {
				START_STATUS.store(-2, Ordering::SeqCst);
				return;
			}

			// If some files were unlocked this round, save the keys that worked
			if newly_unlocked > 0 {
				ACCEPTED_KEYS.lock().extend(passwords);
			}

			// Still locked? Need more passwords
			if remaining_locked > 0 {
				// Return -2 so Dart knows some files are still locked.
				// The `last_verify()` now reports `encrypted=total, locked=remaining`.
				START_STATUS.store(-2, Ordering::SeqCst);
				return;
			}

			// --- Step 3: all files unlocked, start server ---
			let all_keys = ACCEPTED_KEYS.lock().clone();
			let manager = build_manager(&all_keys);
			let session_key = match rcrm_core::SessionKey::generate() {
				Ok(k) => Arc::new(k),
				Err(e) => {
					set_error(format!("mlock failed: {e}"));
					START_STATUS.store(-1, Ordering::SeqCst);
					return;
				}
			};

			let dirs: Vec<PathBuf> = CACHED_DIRS.lock().clone();

			let mount_names = generate_mount_names(&dirs);
			let cache = Arc::new(FileCache::new());
			let manager = Arc::new(manager);
			let auth_username = random_string(8);
			let auth_password = Zeroizing::new(random_string(16));

			let ctx = ServerContext {
				mounts: mount_names,
				manager,
				session_key,
				cache,
				tls_config: None,
				require_tls: false,
				implicit_tls: false,
				protocol: Protocol::WebDav,
				max_connections: 50,
				auth: AuthConfig::with_credentials(auth_username.clone(), &auth_password),
				idle_timeout: Duration::from_secs(300),
			};

			let bind_socket: SocketAddr = match format!("{bind_addr}:{port}").parse() {
				Ok(a) => a,
				Err(e) => {
					set_error(format!("Invalid bind: {e}"));
					START_STATUS.store(-1, Ordering::SeqCst);
					return;
				}
			};
			let server = Server::new(ctx, bind_socket);
			let (listener, local_addr) = match server.bind() {
				Ok(x) => x,
				Err(e) => {
					set_error(format!("Bind failed: {e}"));
					START_STATUS.store(-1, Ordering::SeqCst);
					return;
				}
			};
			let url = format!("http://{}", local_addr);
			let shutdown = Arc::new(AtomicBool::new(false));
			let sd = shutdown.clone();
			let _serve_thread = thread::Builder::new()
				.name("rcrm-webdav".into())
				.spawn(move || {
					if let Err(e) = server.serve(listener, sd) {
						rcrm_core::log_error!("[bridge] Server error: {e}");
					}
				})
				.expect("spawn serve");

			*SERVER.lock() = Some(ServerState {
				shutdown,
				url,
				auth_username,
				auth_password,
			});
			START_STATUS.store(2, Ordering::SeqCst);
		})
		.expect("spawn startup");

	1
}

pub fn stop(handle: i32) -> i32 {
	clear_error();
	if handle != 1 {
		set_error("Invalid handle");
		return -1;
	}
	// Wait for any in-progress start() background thread to finish
	// before clearing shared statics, avoiding a race where the
	// thread writes stale data back after we've cleared it.
	while START_STATUS.load(Ordering::SeqCst) == 1 {
		std::thread::sleep(std::time::Duration::from_millis(50));
	}
	let mut g = SERVER.lock();
	if let Some(s) = g.take() {
		s.shutdown.store(true, Ordering::SeqCst);
		// Detach the server thread — it drains active connections for up
		// to 10s after shutdown. Joining here would block the Flutter UI
		// thread via the synchronous FFI call.
	}
	drop(g);
	// Reset scan cache so next start is fresh
	SCANNED_PATHS.lock().clear();
	LOCKED_PATHS.lock().clear();
	ACCEPTED_KEYS.lock().clear();
	CACHED_DIRS.lock().clear();
	UNLOCKED_COUNT.store(0, Ordering::Relaxed);
	START_STATUS.store(0, Ordering::SeqCst);
	0
}

pub fn get_url(handle: i32) -> Option<String> {
	if handle != 1 {
		return None;
	}
	SERVER.lock().as_ref().map(|s| s.url.clone())
}

pub fn status(handle: i32) -> i32 {
	if handle != 1 {
		return -1;
	}
	START_STATUS.load(Ordering::SeqCst)
}

pub fn get_auth_json(handle: i32) -> Option<String> {
	if handle != 1 {
		return None;
	}
	SERVER.lock().as_ref().map(|s| {
		serde_json::json!({"username":s.auth_username,"password":&*s.auth_password}).to_string()
	})
}
