// src/serve/mod.rs
// rcrm - Projection FTP(S) server.
// Copyleft (©) 2024-2025 hibays
//
// Read-only FTP(S) server that "projects" the original plaintext of
// rcrm-encrypted files to FTP clients without ever writing it back to disk.
// See `project.rs` for the projection mechanism and `ftp.rs` for the
// protocol implementation.

pub mod ftp;
pub mod tls;

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use blake2::{Blake2s256, Digest};

use crate::{Manager, ProjectedFile, SessionKey, is_valid_encrypted_file_name};
use ftp::FtpSession;

// =======================
// FileCache: lazy, thread-safe cache of projected encrypted files
// =======================

/// Lazily-populated, thread-safe cache of `ProjectedFile`s. Entries are
/// created on first access (LIST/RETR/SIZE) and kept for the lifetime of
/// the server. Only encrypted files (matching the `.<b72>` pattern) are
/// cached — plain files are served directly from disk.
pub struct FileCache {
	/// disk path → projected file
	files: RwLock<HashMap<PathBuf, Arc<ProjectedFile>>>,
	/// (parent dir, decrypted virtual name) → disk path
	name_index: RwLock<HashMap<(PathBuf, String), PathBuf>>,
}

impl Default for FileCache {
	fn default() -> Self {
		Self::new()
	}
}

impl FileCache {
	pub fn new() -> Self {
		FileCache {
			files: RwLock::new(HashMap::new()),
			name_index: RwLock::new(HashMap::new()),
		}
	}

	/// Return a cached entry if present, without touching disk.
	pub fn get(&self, disk_path: &Path) -> Option<Arc<ProjectedFile>> {
		self.files.read().unwrap().get(disk_path).cloned()
	}

	/// Get-or-open: if the file is already cached, return it; otherwise
	/// open it as a `ProjectedFile` (decrypting + caching the head for
	/// partial files) and store it.
	pub fn get_or_open(
		&self,
		disk_path: &Path,
		manager: &Manager,
		session_key: &SessionKey,
	) -> io::Result<Arc<ProjectedFile>> {
		// Fast path: read lock
		if let Some(pf) = self.files.read().unwrap().get(disk_path) {
			return Ok(Arc::clone(pf));
		}
		// Slow path: write lock
		let mut files = self.files.write().unwrap();
		// Double-check after acquiring write lock
		if let Some(pf) = files.get(disk_path) {
			return Ok(Arc::clone(pf));
		}
		let pf = Arc::new(ProjectedFile::open(disk_path, manager, session_key)?);
		let parent = disk_path.parent().map(|p| p.to_path_buf());
		let vname = pf.virtual_name().to_string();
		files.insert(disk_path.to_path_buf(), Arc::clone(&pf));
		drop(files);
		if let Some(parent) = parent {
			self.name_index
				.write()
				.unwrap()
				.insert((parent, vname), disk_path.to_path_buf());
		}
		Ok(pf)
	}

	/// Look up the disk path of an encrypted file by its (parent dir,
	/// decrypted virtual name). Returns `None` if not indexed.
	pub fn resolve_virtual_name(&self, parent: &Path, virtual_name: &str) -> Option<PathBuf> {
		let key = (parent.to_path_buf(), virtual_name.to_string());
		self.name_index.read().unwrap().get(&key).cloned()
	}
}

// =======================
// AuthConfig: FTP-level authentication (separate from the encryption key)
// =======================

#[derive(Clone)]
pub struct AuthConfig {
	/// Required username. If `None`, anonymous access is allowed (only safe
	/// on loopback).
	pub user: Option<String>,
	/// BLAKE2s-256 hash of the required password (if any). The plaintext is
	/// never kept in memory after startup.
	pub pass_hash: Option<[u8; 32]>,
}

impl AuthConfig {
	pub fn no_auth() -> Self {
		AuthConfig {
			user: None,
			pass_hash: None,
		}
	}

	pub fn with_credentials(user: String, pass: &str) -> Self {
		let mut hasher = Blake2s256::new();
		hasher.update(pass.as_bytes());
		let hash: [u8; 32] = hasher.finalize().into();
		AuthConfig {
			user: Some(user),
			pass_hash: Some(hash),
		}
	}

	/// Verify a (user, pass) pair. Returns `true` if access should be
	/// granted.
	pub fn verify(&self, user: &str, pass: &str) -> bool {
		match (&self.user, &self.pass_hash) {
			(None, None) => true, // anonymous
			(Some(required_user), Some(required_hash)) => {
				if user != required_user {
					return false;
				}
				let mut hasher = Blake2s256::new();
				hasher.update(pass.as_bytes());
				let hash: [u8; 32] = hasher.finalize().into();
				hash == *required_hash
			}
			_ => false,
		}
	}
}

// =======================
// ServerContext: shared, immutable state for all connections
// =======================

pub struct ServerContext {
	pub root: PathBuf,
	pub manager: Arc<Manager>,
	pub session_key: Arc<SessionKey>,
	pub cache: Arc<FileCache>,
	pub tls_config: Option<Arc<rustls::ServerConfig>>,
	pub require_tls: bool,
	/// Implicit FTPS mode: the control connection is wrapped in TLS
	/// immediately on accept (no AUTH TLS negotiation). Data connections
	/// default to encrypted (PROT P) in this mode.
	pub implicit_tls: bool,
	pub max_connections: usize,
	pub auth: AuthConfig,
	pub idle_timeout: Duration,
}

// =======================
// Server: accept loop + connection spawning
// =======================

pub struct Server {
	ctx: Arc<ServerContext>,
	bind: SocketAddr,
}

impl Server {
	pub fn new(ctx: ServerContext, bind: SocketAddr) -> Self {
		Server {
			ctx: Arc::new(ctx),
			bind,
		}
	}

	/// Bind the control listener and return it along with the actual bound
	/// address (useful when binding to port 0 for an ephemeral port).
	pub fn bind(&self) -> io::Result<(TcpListener, SocketAddr)> {
		let listener = TcpListener::bind(self.bind)?;
		let addr = listener.local_addr()?;
		Ok((listener, addr))
	}

	/// Run the accept loop on a pre-bound listener. Spawns one OS thread
	/// per connection (capped at `max_connections`).
	pub fn serve(self, listener: TcpListener, shutdown: Arc<AtomicBool>) -> io::Result<()> {
		// Non-blocking so we can poll the shutdown flag.
		listener.set_nonblocking(true)?;
		eprintln!(
			"[serve] listening on {} (root: {})",
			listener.local_addr()?,
			self.ctx.root.display()
		);
		if self.ctx.tls_config.is_some() {
			eprintln!("[serve] FTPS enabled (AUTH TLS)");
		}
		if self.ctx.require_tls {
			eprintln!("[serve] TLS required — plaintext AUTH rejected");
		}

		let active = Arc::new(AtomicUsize::new(0));

		while !shutdown.load(Ordering::Relaxed) {
			match listener.accept() {
				Ok((stream, addr)) => {
					if active.load(Ordering::Relaxed) >= self.ctx.max_connections {
						eprintln!("[serve] {} rejected: too many connections", addr);
						drop(stream);
						continue;
					}
					active.fetch_add(1, Ordering::Relaxed);

					let ctx = Arc::clone(&self.ctx);
					let active_clone = Arc::clone(&active);
					let shutdown_clone = Arc::clone(&shutdown);

					std::thread::Builder::new()
						.name(format!("ftp-{}", addr))
						.spawn(move || {
							let _ = handle_connection(stream, addr, ctx, shutdown_clone);
							active_clone.fetch_sub(1, Ordering::Relaxed);
						})?;
				}
				Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
					std::thread::sleep(Duration::from_millis(50));
				}
				Err(e) => {
					eprintln!("[serve] accept error: {}", e);
					std::thread::sleep(Duration::from_millis(100));
				}
			}
		}

		// Drain remaining connections (best-effort).
		eprintln!(
			"[serve] shutting down, waiting for {} active connection(s)",
			active.load(Ordering::Relaxed)
		);
		let drain_deadline = std::time::Instant::now() + Duration::from_secs(10);
		while active.load(Ordering::Relaxed) > 0 && std::time::Instant::now() < drain_deadline {
			std::thread::sleep(Duration::from_millis(100));
		}
		Ok(())
	}

	/// Convenience: bind + serve in one call. Blocks the calling thread.
	pub fn run(self, shutdown: Arc<AtomicBool>) -> io::Result<()> {
		let (listener, _) = self.bind()?;
		self.serve(listener, shutdown)
	}
}

fn handle_connection(
	stream: TcpStream,
	addr: SocketAddr,
	ctx: Arc<ServerContext>,
	shutdown: Arc<AtomicBool>,
) -> io::Result<()> {
	// The listener is non-blocking (so we can poll the shutdown flag), and
	// accepted sockets inherit that mode. Switch back to blocking for the
	// session — FTP command handling is a blocking, line-oriented loop.
	stream.set_nonblocking(false)?;
	// Apply TCP-level idle timeouts via set_read_timeout. The session loop
	// enforces idle-reset on each command.
	let _ = stream.set_read_timeout(Some(ctx.idle_timeout));
	let _ = stream.set_write_timeout(Some(ctx.idle_timeout));

	let mut session = FtpSession::new(stream, ctx, addr, shutdown);
	session.handle()
}

/// Resolve an FTP virtual path (relative to the server root) to a disk
/// path, normalizing `.` and `..` segments without escaping the root.
pub fn resolve_disk_path(root: &Path, cwd: &str, ftp_path: &str) -> PathBuf {
	// Decide whether the path is absolute (FTP-style, leading '/') or
	// relative to cwd.
	let combined = if ftp_path.starts_with('/') {
		ftp_path.to_string()
	} else {
		format!("{}/{}", cwd.trim_end_matches('/'), ftp_path)
	};

	// Normalize segments manually — do NOT use PathBuf methods that might
	// allow escaping root.
	let mut stack: Vec<String> = Vec::new();
	for seg in combined.split('/') {
		if seg.is_empty() || seg == "." {
			continue;
		}
		if seg == ".." {
			stack.pop();
		} else {
			stack.push(seg.to_string());
		}
	}

	let mut disk = root.to_path_buf();
	for seg in stack {
		disk.push(seg);
	}
	disk
}

/// Convert a disk path (under root) back to an FTP virtual path string.
pub fn disk_to_ftp_path(root: &Path, disk: &Path) -> String {
	match disk.strip_prefix(root) {
		Ok(rel) => {
			let s = rel.to_string_lossy().replace('\\', "/");
			if s.is_empty() {
				"/".to_string()
			} else {
				format!("/{}", s)
			}
		}
		Err(_) => "/".to_string(),
	}
}

/// Check whether `name` looks like an rcrm encrypted filename (`.<b72>`).
pub fn is_encrypted_name(name: &str) -> bool {
	is_valid_encrypted_file_name(name)
}
