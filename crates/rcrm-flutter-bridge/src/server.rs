// src/server.rs
// rcrm-flutter-bridge — server lifecycle management

use rand::RngExt;
use std::ffi::CString;
use std::net::SocketAddr;
use std::os::raw::c_char;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
/// down and an in-flight `run_start` that is about to *register* a server are
/// mutually exclusive under the same `Mutex`. Either `stop()` sees the server
/// and shuts it down, or `run_start` registers it — and `stop()` (which needs
/// the lock to look) is blocked until that registration completes, after which
/// it tears the server down. A server can never be left running after `stop()`
/// returns.
///
/// `cancel` is the one bit of shared state used to abort a still-scanning
/// startup *without* blocking `stop()`: `stop()` flips it and returns
/// immediately; `run_start` checks it at its yield points and self-destructs
/// before binding a server. It is owned here (and cloned into the task), not a
/// free-floating global. A running server has a separate `shutdown` flag in
/// `ServerState`, set at the same time but consumed by its own serve thread.
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
	/// Files that are still locked (no key in the keyring can open them).
	locked: Vec<PathBuf>,
	/// The one keyring that owns every derived key. Lives across the
	/// start → locked → start attempts so an added password costs exactly one
	/// Argon2id derivation, and is moved into the server once it starts.
	keyring: Option<Manager>,
	/// Original canonicalized directory paths — the session's identity. A
	/// changed dir list invalidates every cache.
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
			keyring: None,
			cached_dirs: Vec::new(),
			unlocked: 0,
		}
	}

	/// Clear the whole session: scan caches and keys. Used when tearing a
	/// session down, on a takeover of a running server, and when an in-flight
	/// startup self-destructs.
	fn reset_caches(&mut self) {
		self.scanned.clear();
		self.locked.clear();
		self.keyring = None;
		self.cached_dirs.clear();
		self.unlocked = 0;
	}
}

static SESSION: Lazy<Mutex<Session>> = Lazy::new(|| Mutex::new(Session::new()));
static LAST_ERROR: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));

/// A password buffer Rust allocated and Dart writes into. The address is the
/// opaque identity handed across the ABI; the bytes and their exact length
/// never leave this module.
struct PasswordBuffer {
	addr: usize,
	bytes: Zeroizing<Vec<u8>>,
}

/// The single outstanding password buffer. Allocating a new one replaces (and
/// zeroizes) any previous buffer, so a buffer orphaned by a Dart-side throw
/// cannot accumulate. Only the address crosses the ABI — no length, and no
/// `Vec::from_raw_parts` on a caller-supplied size.
static PENDING_PASSWORD: Lazy<Mutex<Option<PasswordBuffer>>> = Lazy::new(|| Mutex::new(None));

/// Codes pushed to Dart through the registered server-event listener. The
/// `PROGRESS` is feedback-only and never ends a start attempt.
pub(crate) mod event {
	pub const PROGRESS: i32 = 1;
	pub const STOPPED: i32 = 0;
	pub const ERROR: i32 = -1;
	pub const LOCKED: i32 = -2;
	pub const RUNNING: i32 = 2;
}

/// All event data is passed as plain integers — no heap allocation on either
/// side, so the callback has no string to free and no leak path. Meanings by
/// code: PROGRESS(a=phase 0 scan / 1 verify, b=done, c=total), LOCKED(a=encrypted,
/// b=locked, c=unlocked), others ignore the values.
type ServerEventFn = unsafe extern "C" fn(i32, i32, i32, i32);
static SERVER_EVENT_CB: Lazy<Mutex<Option<ServerEventFn>>> = Lazy::new(|| Mutex::new(None));

/// Register the one Dart listener for start progress and terminal outcomes.
/// Passing `None` unregisters it; the pointer is copied into Rust and never
/// stored as a borrowed reference.
pub fn register_event_callback(cb: Option<ServerEventFn>) {
	*SERVER_EVENT_CB.lock() = cb;
}

/// Push one event. Pure integers — no allocation, nothing for Dart to free.
fn emit_event(code: i32, a: i32, b: i32, c: i32) {
	let cb = *SERVER_EVENT_CB.lock();
	if let Some(f) = cb {
		unsafe { f(code, a, b, c) };
	}
}

/// Push a terminal event to the Dart listener, so the UI never waits for a
/// poll tick.
fn finish(code: i32) {
	emit_event(code, 0, 0, 0);
}

/// The locked verdict carries the three counts the setup screen needs to
/// choose its message.
fn finish_locked() {
	let (encrypted, locked, unlocked) = {
		let g = SESSION.lock();
		(
			g.scanned.len() as i32,
			g.locked.len() as i32,
			g.unlocked as i32,
		)
	};
	emit_event(event::LOCKED, encrypted, locked, unlocked);
}

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

/// Allocate a zeroed buffer of exactly `len` bytes for Dart to write the
/// password into. Rust keeps the allocation and its length; `start()` looks it
/// up by address and takes ownership back. No length crosses the ABI, so a
/// mismatched `len` cannot cause an out-of-bounds zeroize or free. Returns
/// null only when `len == 0` (empty password).
pub fn password_buffer(len: usize) -> *mut u8 {
	if len == 0 {
		return std::ptr::null_mut();
	}
	let mut bytes = Zeroizing::new(vec![0u8; len]);
	let addr = bytes.as_mut_ptr() as usize;
	// Replacing the entry drops the old buffer, zeroizing any orphan left by a
	// previously failed start.
	*PENDING_PASSWORD.lock() = Some(PasswordBuffer { addr, bytes });
	addr as *mut u8
}

/// Take back the buffer Dart wrote into. `None` means it was never allocated
/// (or was already consumed) — a contract violation, surfaced as an error.
fn take_password(ptr: *const u8) -> Option<Zeroizing<Vec<u8>>> {
	let mut pending = PENDING_PASSWORD.lock();
	if ptr.is_null() {
		return None;
	}
	if pending.as_ref().is_none_or(|buf| buf.addr != ptr as usize) {
		return None;
	}
	pending.take().map(|buf| buf.bytes)
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

/// An empty keyring. The parameters are fixed by the on-disk format: 2048 is
/// the head calibration and 4 is the worker count used by the CLI's `serve`.
fn new_keyring() -> Manager {
	Manager::new(true, true, 2048, rcrm_core::is_supported_file, 4, None)
}

/// Owns the keyring while a startup attempt runs. A normal exit (locked, or a
/// panic) returns the manager to `SESSION` so keys the user paid to derive
/// survive another attempt. A cancel/stop leaves `cancel` set, so the guard
/// drops the manager instead — its locked pages zeroize on drop.
struct KeyringGuard {
	manager: Option<Manager>,
	cancel: Arc<AtomicBool>,
}

impl KeyringGuard {
	/// Emit a terminal verdict only while this attempt is still the current
	/// one. A superseded attempt must stay silent: its event would otherwise
	/// land on the newer attempt's subscriber and drive the wrong state (F2).
	fn verdict(&self, code: i32) {
		if !self.cancel.load(Ordering::SeqCst) {
			finish(code);
		}
	}

	fn verdict_locked(&self) {
		if self.cancel.load(Ordering::SeqCst) {
			return;
		}
		finish_locked();
	}
}

impl Drop for KeyringGuard {
	fn drop(&mut self) {
		if let Some(manager) = self.manager.take()
			&& !self.cancel.load(Ordering::SeqCst)
		{
			SESSION.lock().keyring = Some(manager);
		}
	}
}

/// Parse and canonicalize the directory list passed over FFI. Returns the
/// error text (not `io::Error`) because this is reported through the event
/// channel. A missing/non-directory path is rejected before any cache is
/// touched, so a bad `dirs_json` can never poison the session.
fn canonical_dirs(dirs_json: &str) -> Result<Vec<PathBuf>, String> {
	let dirs: Vec<String> =
		serde_json::from_str(dirs_json).map_err(|e| format!("Invalid dirs JSON: {e}"))?;
	let mut out = Vec::with_capacity(dirs.len());
	for d in dirs {
		let path = dunce::canonicalize(&d).unwrap_or_else(|_| PathBuf::from(&d));
		if !path.exists() {
			return Err(format!("Dir not found: {}", path.display()));
		}
		if !path.is_dir() {
			return Err(format!("Not a dir: {}", path.display()));
		}
		out.push(path);
	}
	Ok(out)
}

/// Start the server. Scans directories once, derives the newly supplied
/// password into the persistent keyring, then verifies the still-locked files
/// with every key held. When all files are unlocked, starts the `WebDAV` server.
/// `password` is the pointer from `rcrm_password_buffer`, or null for plaintext.
pub fn start(dirs_json: &str, password: *const u8, bind_addr: &str, port: u16) -> i32 {
	clear_error();

	// Validate inputs first — pure checks, no session mutation. The single
	// teardown below runs regardless of the outcome, so a rejected start still
	// leaves no prior server or in-flight attempt behind.
	let dirs = canonical_dirs(dirs_json);
	let password = if password.is_null() {
		Ok(Zeroizing::new(Vec::new())) // plaintext folders
	} else {
		take_password(password)
			.ok_or_else(|| "password buffer was not allocated by password_buffer()".to_string())
	};
	let bind_addr_owned = bind_addr.to_string();

	// Take over any prior session so a fresh start never stacks a second
	// server. Caches are reset when a running server was torn down OR when the
	// directory set changed. For the SAME library across locked attempts there
	// is no server running, so the incremental scan + still-locked set + derived
	// keyring are preserved — re-deriving every accepted key on every attempt
	// would be a serious regression for large libraries.
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
		// A fresh run gets a NEW cancel token: a stale `stop()` holding the
		// previous Arc cannot cancel this attempt. Reset when a server was
		// taken over or the directory set changed (F1), or when validation
		// failed — in all cases the prior session is no longer usable.
		let cancel = Arc::new(AtomicBool::new(false));
		let mut g = SESSION.lock();
		let dirs_changed = match &dirs {
			Ok(d) => g.cached_dirs != *d,
			Err(_) => true,
		};
		if took_over || dirs_changed {
			g.reset_caches();
		}
		g.cancel = cancel;
	}

	// Now surface any validation failure. The session is already clean.
	let dirs = match dirs {
		Ok(d) => d,
		Err(e) => {
			set_error(e);
			finish(event::ERROR);
			return 1;
		}
	};
	let password = match password {
		Ok(p) => p,
		Err(e) => {
			set_error(e);
			finish(event::ERROR);
			return 1;
		}
	};

	// Move the persistent keyring into the startup task. The takeover above
	// may have cleared it (new library), which is why this happens after it.
	let (keyring, cancel) = {
		let mut g = SESSION.lock();
		(g.keyring.take(), Arc::clone(&g.cancel))
	};

	// `start()` owns the `startup` handle slot: store it now so a later
	// takeover can join this task. Panic handling lives inside `start_body`,
	// where it goes through the same `KeyringGuard::verdict` as every other
	// terminal — so it needs no second handle to the cancel token.
	let spawned = thread::Builder::new()
		.name("rcrm-startup".into())
		.spawn(move || {
			start_body(
				KeyringGuard {
					manager: keyring,
					cancel,
				},
				password,
				dirs,
				&bind_addr_owned,
				port,
			);
			// The startup task is done. It never touches `startup` itself; the
			// slot stays set (a finished handle, harmless) until the next
			// `start()` reaps it, or reflects a still-running task while alive.
		});
	// A spawn failure must still emit a terminal event, or Dart's
	// `terminal.future` hangs forever. On error the closure (and with it the
	// `Zeroizing` password and keyring) is dropped, so nothing leaks.
	match spawned {
		Ok(handle) => SESSION.lock().startup = Some(handle),
		Err(e) => {
			set_error(format!("failed to spawn startup thread: {e}"));
			finish(event::ERROR);
		}
	}

	1
}

/// Entry point of the startup thread. The guard stays here (borrowed by the
/// work below) so both normal and panic terminals go through one
/// `KeyringGuard::verdict` — a cancelled attempt never emits into a newer
/// attempt's subscriber, and no second cancel handle is needed.
fn start_body(
	mut keyring: KeyringGuard,
	password: Zeroizing<Vec<u8>>,
	dirs: Vec<PathBuf>,
	bind_addr: &str,
	port: u16,
) {
	let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
		run_start(&mut keyring, password, dirs, bind_addr, port);
	}));
	if let Err(payload) = outcome {
		// The panic text that can realistically reach here is
		// "Index (...) of key exists!" from a duplicate key index.
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
		keyring.verdict(event::ERROR);
	}
}

/// The startup sequence. `cancel` lets `stop()` abort an in-flight startup
/// without blocking: we check it at the points where we could otherwise go on
/// to bind and serve.
fn run_start(
	keyring: &mut KeyringGuard,
	password: Zeroizing<Vec<u8>>,
	dirs: Vec<PathBuf>,
	bind_addr: &str,
	port: u16,
) {
	emit_event(event::PROGRESS, 0, 0, 0);

	// --- Step 1: scan directories (once) ---
	// `dirs` was parsed and canonicalized in `start()`. The cache lives in
	// `SESSION`; we don't hold the lock across the (possibly long) walk, which
	// is what lets `stop()` cancel and return immediately.
	let all_paths = {
		let g = SESSION.lock();
		if g.scanned.is_empty() {
			drop(g);
			let mut all: Vec<(usize, PathBuf)> = Vec::new();
			for (idx, d) in dirs.iter().enumerate() {
				let (_n, enc) = rcrm_core::resolve_ne_path_from_dir_with_progress(d, |_| {});
				for fp in enc {
					all.push((idx, fp));
				}
			}
			let mut g = SESSION.lock();
			g.scanned = all;
			g.cached_dirs = dirs;
			g.scanned.clone()
		} else {
			g.scanned.clone()
		}
	};

	// A stop() may have arrived while we scanned. Bail before doing any
	// irreversible work — no server has been created, so there is nothing to
	// tear down beyond the (already discarded) scan cache.
	if keyring.cancel.load(Ordering::SeqCst) {
		SESSION.lock().reset_caches();
		// Stay silent: a cancelled start is either replaced by a newer start
		// (which emits its own verdict) or followed by Dart's own state reset.
		// A STOPPED here would land on the newer attempt's subscriber (F2).
		return;
	}

	// --- Step 2: derive ONLY this newly typed password into the keyring ---
	// Keys already in the keyring keep their derived pages across attempts:
	// adding the Nth password costs one Argon2id, never N. A repeated password
	// is skipped by index instead of panicking inside `Manager`.
	let manager = keyring.manager.get_or_insert_with(new_keyring);
	if !password.is_empty() {
		let idx = rcrm_core::key_index(password.as_slice());
		if !manager.has_key_index(idx) {
			manager.use_added_key(password.as_slice());
		}
	}
	// The plaintext is no longer needed: wipe it now rather than keeping it
	// alive through the whole scan + verification phase.
	drop(password);

	// On first call, the locked set starts empty — move all files there.
	{
		let mut g = SESSION.lock();
		if g.locked.is_empty() {
			for (_, fp) in &all_paths {
				g.locked.push(fp.clone());
			}
		}
	}

	// Verify remaining locked files, reporting progress to Dart as we go.
	let locked_snapshot = SESSION.lock().locked.clone();
	let total = locked_snapshot.len();
	emit_event(event::PROGRESS, 1, 0, total as i32);
	let step = (total / 50).max(1);
	let mut still_locked: Vec<PathBuf> = Vec::new();
	let mut newly_unlocked = 0u64;

	for (i, fp) in locked_snapshot.iter().enumerate() {
		let ok = std::fs::File::open(fp)
			.ok()
			.and_then(|mut f| {
				keyring
					.manager
					.as_ref()
					.expect("keyring initialized above")
					.read_file_header_any_key(&mut f)
					.ok()
			})
			.is_some();
		if ok {
			newly_unlocked += 1;
		} else {
			still_locked.push(fp.clone());
		}
		let done = i + 1;
		if done % step == 0 || done == total {
			emit_event(event::PROGRESS, 1, done as i32, total as i32);
		}
	}

	{
		let mut g = SESSION.lock();
		g.unlocked += newly_unlocked;
		g.locked = still_locked;
	}

	let remaining_locked = SESSION.lock().locked.len() as u64;
	// On first attempt: if no files opened, password is wrong.
	if newly_unlocked == 0 && SESSION.lock().unlocked == 0 {
		keyring.verdict_locked();
		return;
	}

	// Still locked? Need more passwords. The event carries the counts, so Dart
	// needs no extra FFI round-trip.
	if remaining_locked > 0 {
		keyring.verdict_locked();
		return;
	}

	// Guard against a stop() that landed during verification: if cancellation
	// was requested we must not bind a server the UI believes is stopped.
	if keyring.cancel.load(Ordering::SeqCst) {
		SESSION.lock().reset_caches();
		// Stay silent — see the cancel check above.
		return;
	}

	// --- Step 3: all files unlocked, start server ---
	// Move the keyring into the server: its keys are already derived, and the
	// server is the only owner from here. The guard sees None and does not put
	// it back into SESSION.
	let session_key = match rcrm_core::SessionKey::generate() {
		Ok(k) => Arc::new(k),
		Err(e) => {
			set_error(format!("mlock failed: {e}"));
			keyring.verdict(event::ERROR);
			return;
		}
	};

	let dirs: Vec<PathBuf> = SESSION.lock().cached_dirs.clone();

	let mount_names = generate_mount_names(&dirs);
	let cache = Arc::new(FileCache::new());
	let manager = Arc::new(
		keyring
			.manager
			.take()
			.expect("keyring initialized before verification"),
	);
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
			keyring.verdict(event::ERROR);
			return;
		}
	};
	let server = Server::new(ctx, bind_socket);
	let (listener, local_addr) = match server.bind() {
		Ok(x) => x,
		Err(e) => {
			set_error(format!("Bind failed: {e}"));
			keyring.verdict(event::ERROR);
			return;
		}
	};
	let url = format!("http://{local_addr}");
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
	// Check-and-publish stays atomic under one lock acquisition; the callback
	// is emitted only after the lock is released (it may re-enter the bridge).
	let aborted = {
		let mut g = SESSION.lock();
		if keyring.cancel.load(Ordering::SeqCst) {
			// stop() asked us to abort after we bound but before we published.
			true
		} else {
			g.server = Some(server_state);
			false
		}
	};
	if aborted {
		// Stay silent — see the cancel check above.
		return;
	}
	// Commit to serving: only now spawn the detached serve thread. If the check
	// above had lost the race, we would have returned without spawning it.
	// A spawn failure must roll back the published server and emit a terminal
	// event — panicking here would cross the extern "C" boundary and leave
	// Dart's `terminal.future` pending forever.
	let spawned = thread::Builder::new()
		.name("rcrm-webdav".into())
		.spawn(move || {
			if let Err(e) = server.serve(listener, sd) {
				rcrm_core::log_error!("[bridge] Server error: {e}");
			}
		});
	if let Err(e) = spawned {
		SESSION.lock().server = None;
		set_error(format!("failed to spawn serve thread: {e}"));
		keyring.verdict(event::ERROR);
		return;
	}
	keyring.verdict(event::RUNNING);
}

pub fn stop(handle: i32) -> i32 {
	clear_error();
	if handle != 1 {
		set_error("Invalid handle");
		return -1;
	}
	// Ask the CURRENT in-flight startup to abort. Clone the token and set it
	// under one lock acquisition: a concurrent `start()` replaces the token
	// with a fresh one, and setting a stale clone afterwards would leave the
	// new attempt running. Non-blocking — the task self-destructs at its next
	// yield point, so `stop()` returning can never leave a server bound.
	let mut g = SESSION.lock();
	let cancel = Arc::clone(&g.cancel);
	cancel.store(true, Ordering::SeqCst);
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
	drop(g);
	// Emit from the calling thread, never from the cancelled task: a late
	// task event could otherwise land on a newer attempt's subscriber.
	finish(event::STOPPED);
	0
}

pub fn get_url(handle: i32) -> Option<String> {
	if handle != 1 {
		return None;
	}
	SESSION.lock().server.as_ref().map(|s| s.url.clone())
}

pub fn get_auth_json(handle: i32) -> Option<String> {
	if handle != 1 {
		return None;
	}
	SESSION.lock().server.as_ref().map(|s| {
		serde_json::json!({"username":s.auth_username,"password":&*s.auth_password}).to_string()
	})
}
