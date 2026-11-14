// src/server.rs
// rcrm-flutter-bridge — server lifecycle management

use rand::RngExt;
use std::ffi::CString;
use std::net::SocketAddr;
use std::os::raw::c_char;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::thread;
use std::thread::JoinHandle;
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

/// Owned lifecycle of the single server instance.
///
/// This replaces the previous scatter of `SERVER` plus five cache statics.
/// `start()` and `stop()` operate on this one object behind a lock, which is
/// what makes the start/stop race impossible: a `stop()` that tears the server
/// down and an in-flight `start_body` that is about to *register* a server are
/// mutually exclusive under the same `Mutex`. Either `stop()` sees the server
/// and shuts it down, or `start_body` registers it — and `stop()` (which needs
/// the lock to look) is blocked until that registration completes, after which
/// it tears the server down. A server can never be left running after `stop()`
/// returns.
///
/// `cancel` is the one bit of shared state used to abort a still-scanning
/// startup *without* blocking `stop()`: `stop()` flips it and returns
/// immediately; `start_body` checks it at its yield points and self-destructs
/// before binding a server. It is owned here (and cloned into the task), not a
/// free-floating global — the same cancellation token the running server
/// already uses (`ServerState.shutdown`).
struct Session {
	/// Background `start()` task, present only while it is alive. `start()`
	/// owns this slot: it stores the `JoinHandle` after spawning and takes it
	/// back (joining) on the next takeover. `stop()` leaves it in place so the
	/// task can self-destruct and the next `start()` can reap it.
	startup: Option<JoinHandle<()>>,
	/// A running server, present only after the startup task finishes Step 3.
	server: Option<ServerState>,
	/// Signalled by `stop()` (and by a takeover `start()`) to abort an in-flight
	/// startup before it binds. Cloned into the task.
	cancel: Arc<AtomicBool>,
	/// All encrypted file paths + mount index, set after first directory scan.
	scanned: Vec<(usize, PathBuf)>,
	/// Files that are still locked (no accepted key can open them).
	locked: Vec<PathBuf>,
	/// Keys that have successfully opened at least one file.
	accepted: Vec<Zeroizing<String>>,
	/// Original canonicalized directory paths, cached after first scan.
	cached_dirs: Vec<PathBuf>,
	/// How many files have been unlocked so far.
	unlocked: u64,
}

impl Session {
	fn new() -> Self {
		Session {
			startup: None,
			server: None,
			cancel: Arc::new(AtomicBool::new(false)),
			scanned: Vec::new(),
			locked: Vec::new(),
			accepted: Vec::new(),
			cached_dirs: Vec::new(),
			unlocked: 0,
		}
	}

	/// Clear the scan/unlock caches. Used both when tearing a session down and
	/// when an in-flight startup self-destructs.
	fn reset_caches(&mut self) {
		self.scanned.clear();
		self.locked.clear();
		self.accepted.clear();
		self.cached_dirs.clear();
		self.unlocked = 0;
	}
}

static SESSION: Lazy<Mutex<Session>> = Lazy::new(|| Mutex::new(Session::new()));
/// 0=idle, 1=starting (bg thread), 2=running, -1=error, -2=locked
static START_STATUS: AtomicI32 = AtomicI32::new(0);
static LAST_ERROR: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));

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
	let total = SESSION.lock().scanned.len() as u64;
	let locked = SESSION.lock().locked.len() as u64;
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

/// Build a Manager holding every provided key. Used for both verification
/// and serving so one Manager covers files with different passwords.
///
/// Duplicates are dropped: the multi-password flow concatenates the already
/// accepted keys with the newly typed ones, and re-typing an accepted
/// password would otherwise register the same index twice — which `Manager`
/// treats as a programming error and panics on.
fn build_manager(passwords: &[Zeroizing<String>]) -> Manager {
	let mut unique: Vec<&[u8]> = Vec::with_capacity(passwords.len());
	for p in passwords {
		let bytes = p.as_bytes();
		let idx = rcrm_core::key_index(bytes);
		if !unique.iter().any(|q| rcrm_core::key_index(q) == idx) {
			unique.push(bytes);
		}
	}

	let mut it = unique.into_iter();
	let first = it.next();
	let mut manager = Manager::new(true, true, 2048, rcrm_core::is_supported_file, 4, first);
	for p in it {
		manager.use_added_key(p);
	}
	manager
}

/// Start the server. First call: scans directories, caches paths, verifies
/// all files against the provided passwords. Subsequent calls with additional
/// passwords: only verifies the NEW password against still-locked files.
/// When all files are unlocked, starts the WebDAV server.
pub fn start(dirs_json: &str, passwords: &[Zeroizing<String>], bind_addr: &str, port: u16) -> i32 {
	clear_error();

	// Keep passwords inside Zeroizing the whole way across the thread
	// boundary: never copy them into a plain String (which would leave an
	// uncleaned copy in the heap).
	let pw_vec: Vec<Zeroizing<String>> = passwords
		.iter()
		.map(|z| Zeroizing::new(z.as_str().to_string()))
		.collect();
	let dirs_owned = dirs_json.to_string();
	let bind_addr_owned = bind_addr.to_string();

	START_STATUS.store(1, Ordering::SeqCst);

	// Take over any prior session so a fresh start never stacks a second
	// server on the same files. Resetting the caches is *conditional*: only
	// when we actually tore down a running server. The multi-password flow
	// (start → locked → start with another key) has no server running between
	// attempts, so its incremental scan + still-locked set + accumulated
	// accepted keys must be preserved — re-scanning and re-verifying the whole
	// library on every added key would be a serious regression for large
	// libraries. (See `library_setup_screen._connect`: it passes the full
	// password union, but the per-attempt cost is dominated by the scan.)
	{
		let (took_over, startup) = {
			let mut g = SESSION.lock();
			let prev = g.server.take();
			let took = prev.is_some();
			if let Some(s) = prev {
				// Signal the running server's accept loop + per-connection
				// threads to drain and exit.
				s.shutdown.store(true, Ordering::SeqCst);
			}
			// Cancel any in-flight startup and reap its handle later, outside
			// the lock.
			let startup = g.startup.take();
			g.cancel.store(true, Ordering::SeqCst);
			(took, startup)
		};
		let mut took_over = took_over;
		if let Some(h) = startup {
			// Reap outside the lock: the cancelled task locks `SESSION` itself
			// while it tears down, and joining while we hold the lock would
			// deadlock. Joining is only ever blocking here in the pathological
			// "start while a start is still running" case, which the UI does
			// not normally do.
			let _ = h.join();
			// The reaped task may have registered a server between our take and
			// its own cancel check — reap and shut it down too.
			let mut g = SESSION.lock();
			if let Some(s) = g.server.take() {
				s.shutdown.store(true, Ordering::SeqCst);
				took_over = true;
			}
		}
		let mut g = SESSION.lock();
		if took_over {
			g.reset_caches();
		}
		// A fresh run starts with cancellation cleared.
		g.cancel.store(false, Ordering::SeqCst);
	}

	let cancel = SESSION.lock().cancel.clone();

	// `start()` owns the `startup` handle slot: store it now so a later
	// takeover can join this task.
	let handle = thread::Builder::new()
		.name("rcrm-startup".into())
		.spawn(move || {
			// A panic here would leave the Dart side polling "starting"
			// forever — `stop()` waits for a terminal status on the UI
			// thread.
			let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
				start_body(pw_vec, dirs_owned, bind_addr_owned, port, cancel)
			}));
			if let Err(payload) = outcome {
				// Surface the panic text: the one that can realistically
				// reach here is "Index (...) of key exists!".
				let detail = if let Some(s) = payload.downcast_ref::<&str>() {
					(*s).to_string()
				} else if let Some(s) = payload.downcast_ref::<String>() {
					s.clone()
				} else {
					"unknown panic".to_string()
				};
				set_error(format!(
					"Internal error while starting the server: {detail}"
				));
				START_STATUS.store(-1, Ordering::SeqCst);
			}
			// The startup task is done. It never touches `startup` itself; the
			// slot stays set (a finished handle, harmless) until the next
			// `start()` reaps it, or reflects a still-running task while alive.
		})
		.expect("spawn startup");
	SESSION.lock().startup = Some(handle);

	1
}

/// The startup sequence that runs on the background thread.
///
/// Split out of `start()` so it can run under `catch_unwind`: a panic must
/// still leave `START_STATUS` on a terminal value. `cancel` lets `stop()` abort
/// an in-flight startup without blocking: we check it at the points where we
/// could otherwise go on to bind and serve.
fn start_body(
	passwords: Vec<Zeroizing<String>>,
	dirs_json: String,
	bind_addr: String,
	port: u16,
	cancel: Arc<AtomicBool>,
) {
	// --- Step 1: scan directories (once) ---
	// The cache lives in `SESSION`. We don't hold the lock across the
	// (possibly long) directory walk: peek, drop, scan into locals, write back.
	// This is what lets `stop()` set `cancel` and return immediately even while
	// we are still scanning.
	let all_paths = {
		let g = SESSION.lock();
		if !g.scanned.is_empty() {
			g.scanned.clone()
		} else {
			drop(g);
			let dirs: Vec<String> = match serde_json::from_str(&dirs_json) {
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
					dunce::canonicalize(PathBuf::from(&d)).unwrap_or_else(|_| PathBuf::from(&d))
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
				let (_n, enc) = rcrm_core::resolve_ne_path_from_dir_with_progress(d, |_| {});
				for fp in enc {
					all.push((idx, fp));
				}
			}
			let mut g = SESSION.lock();
			if g.scanned.is_empty() {
				g.scanned = all;
				g.cached_dirs = dirs.clone();
			}
			g.scanned.clone()
		}
	};

	// A stop() may have arrived while we scanned. Bail before doing any
	// irreversible work — no server has been created, so there is nothing to
	// tear down beyond the (already discarded) scan cache.
	if cancel.load(Ordering::SeqCst) {
		let mut g = SESSION.lock();
		g.reset_caches();
		START_STATUS.store(0, Ordering::SeqCst);
		return;
	}

	// --- Step 2: try NEW passwords against locked files ---
	// On first call, LOCKED_PATHS starts empty — move all files there.
	{
		let mut g = SESSION.lock();
		if g.locked.is_empty() {
			for (_, fp) in &all_paths {
				g.locked.push(fp.clone());
			}
		}
	}

	let all_keys: Vec<Zeroizing<String>> = {
		let g = SESSION.lock();
		let mut keys = g.accepted.clone();
		keys.extend(passwords.clone());
		keys
	};
	let manager = build_manager(&all_keys);

	// Verify remaining locked files
	let locked_snapshot = SESSION.lock().locked.clone();
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

	{
		let mut g = SESSION.lock();
		g.unlocked += newly_unlocked;
		g.locked = still_locked;
	}

	let remaining_locked = SESSION.lock().locked.len() as u64;
	// On first attempt: if no files opened, password is wrong
	if newly_unlocked == 0 && SESSION.lock().unlocked == 0 {
		START_STATUS.store(-2, Ordering::SeqCst);
		return;
	}

	// If some files were unlocked this round, save the keys that worked
	if newly_unlocked > 0 {
		SESSION.lock().accepted.extend(passwords);
	}

	// Still locked? Need more passwords
	if remaining_locked > 0 {
		// Return -2 so Dart knows some files are still locked.
		// The `last_verify()` now reports `encrypted=total, locked=remaining`.
		START_STATUS.store(-2, Ordering::SeqCst);
		return;
	}

	// Guard against a stop() that landed during verification: if cancellation
	// was requested we must not bind a server the UI believes is stopped.
	if cancel.load(Ordering::SeqCst) {
		let mut g = SESSION.lock();
		g.reset_caches();
		START_STATUS.store(0, Ordering::SeqCst);
		return;
	}

	// --- Step 3: all files unlocked, start server ---
	// Reuse Step 2's manager: it already holds the accepted keys
	// (ACCEPTED_KEYS was extended above), and rebuilding it would run the
	// whole Argon2id derivation a second time.
	let session_key = match rcrm_core::SessionKey::generate() {
		Ok(k) => Arc::new(k),
		Err(e) => {
			set_error(format!("mlock failed: {e}"));
			START_STATUS.store(-1, Ordering::SeqCst);
			return;
		}
	};

	let dirs: Vec<PathBuf> = SESSION.lock().cached_dirs.clone();

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

	// Build the server state, then register it under the session lock. The
	// registration and `stop()`'s teardown are mutually exclusive under that
	// lock, so a concurrent stop() can never miss a live server. We also check
	// `cancel` one final time under the lock: if stop() won the race we discard
	// the server we just built and never spawn its serve thread.
	let server_state = ServerState {
		shutdown,
		url,
		auth_username,
		auth_password,
	};
	let sd = server_state.shutdown.clone();
	{
		let mut g = SESSION.lock();
		if cancel.load(Ordering::SeqCst) {
			// stop() asked us to abort after we bound but before we published.
			START_STATUS.store(0, Ordering::SeqCst);
			return;
		}
		g.server = Some(server_state);
	}
	// Commit to serving: only now spawn the detached serve thread. If the check
	// above had lost the race, we would have returned without spawning it.
	let _serve_thread = thread::Builder::new()
		.name("rcrm-webdav".into())
		.spawn(move || {
			if let Err(e) = server.serve(listener, sd) {
				rcrm_core::log_error!("[bridge] Server error: {e}");
			}
		})
		.expect("spawn serve");
	START_STATUS.store(2, Ordering::SeqCst);
}

pub fn stop(handle: i32) -> i32 {
	clear_error();
	if handle != 1 {
		set_error("Invalid handle");
		return -1;
	}
	// Ask any in-flight startup to abort. This is non-blocking: the task
	// self-destructs at its next yield point and never binds a server, so a
	// `stop()` that returns "stopped" can never leave a server running. We do
	// not reset `cancel` here — it stays set until the task acknowledges it (or
	// until the next `start()` clears it), so the task cannot read a stale
	// "false" and go on to bind.
	let cancel = SESSION.lock().cancel.clone();
	cancel.store(true, Ordering::SeqCst);

	let mut g = SESSION.lock();
	// Case 1: a server is already running — signal its serve thread to drain
	// and exit. The serve thread is detached; we don't join it.
	if let Some(s) = g.server.take() {
		s.shutdown.store(true, Ordering::SeqCst);
	}
	// Case 2: a startup is still in flight. We already asked it to cancel and
	// leave its `startup` handle in place so the task can self-destruct and the
	// next `start()` can reap it. We do not join here — stop() must return
	// immediately to the UI thread.
	g.reset_caches();
	START_STATUS.store(0, Ordering::SeqCst);
	0
}

pub fn get_url(handle: i32) -> Option<String> {
	if handle != 1 {
		return None;
	}
	SESSION.lock().server.as_ref().map(|s| s.url.clone())
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
	SESSION.lock().server.as_ref().map(|s| {
		serde_json::json!({"username":s.auth_username,"password":&*s.auth_password}).to_string()
	})
}
