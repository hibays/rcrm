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
pub mod webdav;

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use blake2::{Blake2s256, Digest};

use ftp::FtpSession;
use rcrm_core::{Manager, ProjectedFile, SessionKey, is_valid_encrypted_file_name};

// =======================
// FileCache: lazy, thread-safe cache of projected encrypted files
// =======================

/// Lazily-populated, thread-safe cache of `ProjectedFile`s. Entries are
/// created on first access (LIST/RETR/SIZE) and kept for the lifetime of
/// the server. Only encrypted files (matching the `.<b72>` pattern) are
/// cached — plain files are served directly from disk.
///
/// The `mount_idx` in `name_index` disambiguates virtual names across
/// different mounts (two encrypted files in different mounts may project
/// to the same virtual name).
pub struct FileCache {
	/// disk path → projected file
	files: RwLock<HashMap<PathBuf, Arc<ProjectedFile>>>,
	/// (mount_idx, parent dir, decrypted virtual name) → disk path
	name_index: RwLock<HashMap<(usize, PathBuf, String), PathBuf>>,
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
	///
	/// `mount_idx` is used to key the name index so that virtual names
	/// from different mounts don't collide.
	///
	/// The expensive file-open + header-decrypt work happens *outside* the
	/// write lock, so concurrent requests to different files don't block
	/// each other. The double-check at insert time guards against the race
	/// where two threads open the same file simultaneously.
	pub fn get_or_open(
		&self,
		disk_path: &Path,
		manager: &Manager,
		session_key: &SessionKey,
		mount_idx: usize,
	) -> io::Result<Arc<ProjectedFile>> {
		// Fast path: read lock.
		if let Some(pf) = self.files.read().unwrap().get(disk_path) {
			return Ok(Arc::clone(pf));
		}

		// Slow path: open (I/O + crypto) outside any lock, so other
		// threads can still hit the fast path for different files.
		let pf = Arc::new(ProjectedFile::open(disk_path, manager, session_key)?);
		let parent = disk_path.parent().map(|p| p.to_path_buf());
		let vname = pf.virtual_name().to_string();

		// Insert under write lock — short, no I/O.
		{
			let mut files = self.files.write().unwrap();
			if let Some(existing) = files.get(disk_path) {
				return Ok(Arc::clone(existing));
			}
			files.insert(disk_path.to_path_buf(), Arc::clone(&pf));
		}
		if let Some(parent) = parent {
			self.name_index
				.write()
				.unwrap()
				.insert((mount_idx, parent, vname), disk_path.to_path_buf());
		}
		Ok(pf)
	}

	/// Look up the disk path of an encrypted file by its (mount_idx,
	/// parent dir, decrypted virtual name). Returns `None` if not indexed.
	pub fn resolve_virtual_name(
		&self,
		mount_idx: usize,
		parent: &Path,
		virtual_name: &str,
	) -> Option<PathBuf> {
		let key = (mount_idx, parent.to_path_buf(), virtual_name.to_string());
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
// Protocol: which wire protocol the server speaks
// =======================

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Protocol {
	/// Plain or Explicit FTPS (AUTH TLS upgrade) — selected by --ftpes /
	/// no TLS flag. `implicit_tls` on ServerContext is false.
	Ftp,
	/// Implicit FTPS — selected by --ftps. `implicit_tls` is true.
	FtpImplicitTls,
	/// Plain HTTP WebDAV — selected by --http.
	WebDav,
	/// HTTPS WebDAV (implicit TLS) — selected by --https.
	WebDavHttps,
}

impl Protocol {
	pub fn is_webdav(self) -> bool {
		matches!(self, Protocol::WebDav | Protocol::WebDavHttps)
	}

	pub fn implicit_tls(self) -> bool {
		matches!(self, Protocol::FtpImplicitTls | Protocol::WebDavHttps)
	}
}

// =======================
// Mount: a single root directory in the virtual filesystem
// =======================

/// A single root directory mounted into the virtual filesystem.
/// In single-root mode (`mounts.len() == 1`), the mount name is ignored
/// and the virtual filesystem is flat (backward-compatible behaviour).
/// In multi-root mode, each mount appears as a top-level directory named
/// by `mount_name`.
#[derive(Clone)]
pub struct Mount {
	pub disk_path: PathBuf,
	/// Virtual directory name at the top level.
	pub mount_name: String,
}

/// Generate unique mount names from a list of root paths.
///
/// Each mount is named after the last component of its canonical path
/// (e.g. `/home/user/Videos` → `Videos`). When two mounts would share
/// the same name, the duplicates are disambiguated with a `_2`, `_3`, …
/// suffix so every mount has a unique name.
pub fn generate_mount_names(paths: &[PathBuf]) -> Vec<Mount> {
	let mut seen: HashMap<String, usize> = HashMap::new();

	// First pass: count occurrences of each base name.
	for p in paths {
		let base = p
			.file_name()
			.and_then(|s| s.to_str())
			.unwrap_or("root")
			.to_string();
		let base = if base.is_empty() {
			"root".to_string()
		} else {
			base
		};
		*seen.entry(base).or_insert(0) += 1;
	}

	// Second pass: assign unique names.
	let mut counts: HashMap<String, usize> = HashMap::new();
	paths
		.iter()
		.map(|p| {
			let base = p
				.file_name()
				.and_then(|s| s.to_str())
				.unwrap_or("root")
				.to_string();
			let base = if base.is_empty() {
				"root".to_string()
			} else {
				base
			};
			let cnt = counts.entry(base.clone()).or_insert(0);
			*cnt += 1;
			let name = if *seen.get(&base).unwrap_or(&1) > 1 {
				// Collision — disambiguate.
				format!("{}_{}", base, cnt)
			} else {
				base
			};
			Mount {
				disk_path: p.clone(),
				mount_name: name,
			}
		})
		.collect()
}

// =======================
// ServerContext: shared, immutable state for all connections
// =======================

pub struct ServerContext {
	/// Mounted root directories. In single-root mode (len == 1) the
	/// virtual filesystem is flat for backward compatibility.
	pub mounts: Vec<Mount>,
	pub manager: Arc<Manager>,
	pub session_key: Arc<SessionKey>,
	pub cache: Arc<FileCache>,
	pub tls_config: Option<Arc<rustls::ServerConfig>>,
	pub require_tls: bool,
	/// Implicit TLS (Implicit FTPS or HTTPS WebDAV): the connection is
	/// TLS-wrapped immediately on accept.
	pub implicit_tls: bool,
	/// Which wire protocol to speak. Determines whether `handle_connection`
	/// dispatches to the FTP session or the WebDAV handler.
	pub protocol: Protocol,
	pub max_connections: usize,
	pub auth: AuthConfig,
	pub idle_timeout: Duration,
}

impl ServerContext {
	/// True when more than one mount is configured (mount-point mode).
	pub fn is_multi_root(&self) -> bool {
		self.mounts.len() > 1
	}

	/// The single disk root — only valid when `!is_multi_root()`.
	pub fn single_root(&self) -> &Path {
		&self.mounts[0].disk_path
	}

	/// Look up a mount by its virtual name. Returns `None` if no mount
	/// has that name (or in single-root mode where mount names are
	/// invisible).
	pub fn mount_by_name(&self, name: &str) -> Option<(usize, &Mount)> {
		self.mounts
			.iter()
			.enumerate()
			.find(|(_, m)| m.mount_name.eq_ignore_ascii_case(name))
	}
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
		TcpListener::bind(self.bind)
			.map_err(|e| {
				// Produce a human-friendly message for the common case: port
				// already in use. The raw OS error is preserved as the source.
				if e.kind() == io::ErrorKind::AddrInUse {
					io::Error::new(
						e.kind(),
						format!(
							"Port {} on {} is already in use (likely another rcrm/FTP/web \
						 server instance). Stop the other process or specify a different \
						 port with --port. (OS: {})",
							self.bind.port(),
							self.bind.ip(),
							e
						),
					)
				} else {
					io::Error::new(
						e.kind(),
						format!(
							"Failed to bind {}:{}: {}",
							self.bind.ip(),
							self.bind.port(),
							e
						),
					)
				}
			})
			.and_then(|listener| {
				listener
					.local_addr()
					.map(|addr| (listener, addr))
					.map_err(|e| {
						io::Error::new(e.kind(), format!("Failed to get bound address: {}", e))
					})
			})
	}

	/// Run the accept loop on a pre-bound listener. Spawns one OS thread
	/// per connection (capped at `max_connections`).
	pub fn serve(self, listener: TcpListener, shutdown: Arc<AtomicBool>) -> io::Result<()> {
		// Non-blocking so we can poll the shutdown flag.
		listener.set_nonblocking(true)?;
		eprintln!(
			"[serve] listening on {} (roots: {})",
			listener.local_addr()?,
			self.ctx
				.mounts
				.iter()
				.map(|m| m.disk_path.display().to_string())
				.collect::<Vec<_>>()
				.join(", ")
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
	// session — both FTP and WebDAV handlers are blocking.
	stream.set_nonblocking(false)?;
	let _ = stream.set_read_timeout(Some(ctx.idle_timeout));
	let _ = stream.set_write_timeout(Some(ctx.idle_timeout));

	match ctx.protocol {
		Protocol::Ftp | Protocol::FtpImplicitTls => {
			let mut session = FtpSession::new(stream, ctx, addr, shutdown);
			session.handle()
		}
		Protocol::WebDav | Protocol::WebDavHttps => {
			webdav::handle_session(stream, ctx, addr, shutdown)
		}
	}
}

// =======================
// Path resolution (multi-root aware)
// =======================

/// Result of resolving a virtual path against the server's mounts.
#[derive(Clone)]
pub struct ResolvedMount {
	/// Which mount (index into `ServerContext.mounts`) the path lives in.
	pub mount_idx: usize,
	/// Absolute disk path.
	pub disk_path: PathBuf,
}

/// Resolve an FTP virtual path to a `(mount_idx, disk_path)` pair.
///
/// **Single-root mode** (`mounts.len() == 1`): the virtual filesystem is
/// flat — path resolution is identical to the pre-multi-root behaviour
/// (the mount name is invisible). `mount_idx` is always 0.
///
/// **Multi-root mode** (`mounts.len() > 1`): the first segment of an
/// absolute path is interpreted as a mount name. Relative paths are
/// resolved within the mount implied by `cwd`.
///
/// Returns `NotFound` if the requested mount or directory does not exist.
pub fn resolve_disk_path(
	mounts: &[Mount],
	cwd: &str,
	ftp_path: &str,
	is_multi: bool,
) -> io::Result<ResolvedMount> {
	if !is_multi {
		// Single-root: flat virtual filesystem (backward-compatible).
		let disk = resolve_flat_path(&mounts[0].disk_path, cwd, ftp_path);
		return Ok(ResolvedMount {
			mount_idx: 0,
			disk_path: disk,
		});
	}

	// Multi-root: first segment = mount name.
	let combined = if ftp_path.starts_with('/') {
		ftp_path.to_string()
	} else {
		format!("{}/{}", cwd.trim_end_matches('/'), ftp_path)
	};

	let mut segments: Vec<&str> = combined
		.split('/')
		.filter(|s| !s.is_empty() && *s != ".")
		.collect();

	// Extract mount name from the first segment. If the path is "/" or
	// empty, we're at the virtual root (no mount selected).
	let mount_idx = if let Some(first) = segments.first() {
		match mounts
			.iter()
			.enumerate()
			.find(|(_, m)| m.mount_name == *first)
		{
			Some((idx, _)) => {
				segments.remove(0); // consume mount segment
				idx
			}
			None => {
				// First segment doesn't match any mount — the path might
				// be relative within a mount implied by cwd.
				return resolve_relative_in_cwd(mounts, cwd, &segments);
			}
		}
	} else {
		// Path is "/" — virtual root.
		return Err(io::Error::new(io::ErrorKind::NotFound, "virtual root"));
	};

	// Build disk path under the resolved mount.
	let mount_root = &mounts[mount_idx].disk_path;
	let mut disk = mount_root.clone();
	for seg in &segments {
		if *seg == ".." {
			// Prevent escaping the mount root.
			if disk == *mount_root {
				continue;
			}
			disk.pop();
		} else {
			disk.push(seg);
		}
	}

	Ok(ResolvedMount {
		mount_idx,
		disk_path: disk,
	})
}

/// Resolve a relative path when cwd already implies a mount.
fn resolve_relative_in_cwd(
	mounts: &[Mount],
	cwd: &str,
	segments: &[&str],
) -> io::Result<ResolvedMount> {
	// Parse cwd to find which mount it's in.
	let cwd_segs: Vec<&str> = cwd.split('/').filter(|s| !s.is_empty()).collect();

	if let Some(first) = cwd_segs.first()
		&& let Some((idx, _)) = mounts
			.iter()
			.enumerate()
			.find(|(_, m)| m.mount_name == *first)
	{
		let mount_root = &mounts[idx].disk_path;
		let mut disk = mount_root.clone();
		// Push remaining cwd segments (after mount name).
		for seg in cwd_segs.iter().skip(1) {
			disk.push(seg);
		}
		// Push requested segments.
		for seg in segments {
			if *seg == ".." {
				if disk != *mount_root {
					disk.pop();
				}
			} else {
				disk.push(seg);
			}
		}
		return Ok(ResolvedMount {
			mount_idx: idx,
			disk_path: disk,
		});
	}
	Err(io::Error::new(io::ErrorKind::NotFound, "not in a mount"))
}

/// Single-root flat resolution (original behaviour).
fn resolve_flat_path(root: &Path, cwd: &str, ftp_path: &str) -> PathBuf {
	let combined = if ftp_path.starts_with('/') {
		ftp_path.to_string()
	} else {
		format!("{}/{}", cwd.trim_end_matches('/'), ftp_path)
	};
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

/// Convert a `(mount_idx, disk_path)` back to an FTP virtual path string.
///
/// **Single-root**: equivalent to the old `disk_to_ftp_path` — strips the
/// single root prefix.
///
/// **Multi-root**: prepends the mount name, e.g. `/Videos/sub/file.mp4`.
pub fn disk_to_ftp_path(mounts: &[Mount], mount_idx: usize, disk: &Path, is_multi: bool) -> String {
	if !is_multi {
		// Single-root flat mode.
		match disk.strip_prefix(&mounts[0].disk_path) {
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
	} else {
		// Multi-root: prepend mount name.
		let mount_name = &mounts[mount_idx].mount_name;
		match disk.strip_prefix(&mounts[mount_idx].disk_path) {
			Ok(rel) => {
				let s = rel.to_string_lossy().replace('\\', "/");
				if s.is_empty() {
					format!("/{}", mount_name)
				} else {
					format!("/{}/{}", mount_name, s)
				}
			}
			Err(_) => format!("/{}", mount_name),
		}
	}
}

/// Build the virtual root listing (only for multi-root mode).
///
/// Returns a list of `DirEntry`-like items representing mount points
/// (directories). In single-root mode, this is never called — the normal
/// `list_dir` handles `/`.
pub fn virtual_root_entries(mounts: &[Mount]) -> Vec<MountDirEntry> {
	mounts
		.iter()
		.map(|m| MountDirEntry {
			virtual_name: m.mount_name.clone(),
			is_dir: true,
			size: 0,
			disk_path: Some(m.disk_path.clone()),
		})
		.collect()
}

/// Lightweight directory entry for the virtual root listing.
/// `disk_path` is `Some` for mount points, `None` for plain entries.
pub struct MountDirEntry {
	pub virtual_name: String,
	pub is_dir: bool,
	pub size: u64,
	pub disk_path: Option<PathBuf>,
}

/// Check whether `name` looks like an rcrm encrypted filename (`.<b72>`).
pub fn is_encrypted_name(name: &str) -> bool {
	is_valid_encrypted_file_name(name)
}

/// Returns true if the ftp_path refers to the virtual root `/` in
/// multi-root mode (where `/` shows mount points rather than real files).
pub fn is_virtual_root(ftp_path: &str, is_multi: bool) -> bool {
	is_multi && (ftp_path == "/" || ftp_path.is_empty())
}
