// src/serve/ftp.rs
// rcrm - FTP protocol implementation (per-connection session).
// Copyleft (©) 2024-2025 hibays
//
// Implements the subset of FTP required for read-only projection:
//   USER/PASS, AUTH TLS, PBSZ, PROT, SYST, FEAT, PWD, CWD, CDUP, TYPE I,
//   PASV, EPSV, LIST, NLST, MLSD, RETR, SIZE, MDTM, REST, ABOR, QUIT,
//   NOOP, OPTS UTF8.
// All write commands (STOR/DELE/MKD/RMD/RNFR/RNTO/...) are rejected with
// 550. The server enforces a strict read-only contract.

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::{ServerContext, disk_to_ftp_path, resolve_disk_path};
use rcrm_core::{ProjectedFile, is_supported_file};

// =======================
// Control / data stream abstraction
// =======================

/// Either a plain TCP stream or a rustls TLS stream. Implements Read+Write
/// so the session loop can treat both uniformly.
///
/// The `Tls` variant is large (~1176 bytes — it contains the full TLS
/// session state). We accept this to avoid a heap indirection on every
/// read/write; there's only one `Stream` per connection.
#[allow(clippy::large_enum_variant)]
pub enum Stream {
	Plain(TcpStream),
	Tls(rustls::StreamOwned<rustls::ServerConnection, TcpStream>),
}

impl Read for Stream {
	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		match self {
			Stream::Plain(s) => s.read(buf),
			Stream::Tls(s) => s.read(buf),
		}
	}
}

impl Write for Stream {
	fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
		match self {
			Stream::Plain(s) => s.write(buf),
			Stream::Tls(s) => s.write(buf),
		}
	}
	fn flush(&mut self) -> io::Result<()> {
		match self {
			Stream::Plain(s) => s.flush(),
			Stream::Tls(s) => s.flush(),
		}
	}
}

impl Stream {
	fn shutdown(&mut self) {
		match self {
			Stream::Plain(s) => {
				let _ = s.shutdown(std::net::Shutdown::Both);
			}
			Stream::Tls(s) => {
				// Send TLS close_notify, flush it to the socket, then
				// half-close TCP (write side) so the peer sees EOF after
				// the close_notify rather than a truncated connection.
				let rustls::StreamOwned { conn, sock } = s;
				conn.send_close_notify();
				let _ = conn.write_tls(sock);
				let _ = sock.flush();
				let _ = sock.shutdown(std::net::Shutdown::Write);
			}
		}
	}
}

// =======================
// LineReader: buffered line reader over any Read
// =======================

struct LineReader {
	buf: Vec<u8>,
}

impl LineReader {
	fn new() -> Self {
		LineReader {
			buf: Vec::with_capacity(512),
		}
	}

	/// Read one CRLF-terminated line. Returns the line without the trailing
	/// CRLF. Returns Err on EOF or I/O error.
	fn read_line(&mut self, stream: &mut impl Read) -> io::Result<String> {
		loop {
			if let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
				let line: Vec<u8> = self.buf.drain(..=pos).collect();
				let end = if line.ends_with(b"\r\n") {
					line.len() - 2
				} else if line.ends_with(b"\n") {
					line.len() - 1
				} else {
					line.len()
				};
				return Ok(String::from_utf8_lossy(&line[..end]).into_owned());
			}
			let mut tmp = [0u8; 1024];
			let n = stream.read(&mut tmp)?;
			if n == 0 {
				return Err(io::Error::new(
					io::ErrorKind::UnexpectedEof,
					"control connection closed",
				));
			}
			self.buf.extend_from_slice(&tmp[..n]);
		}
	}
}

// =======================
// FtpSession
// =======================

pub struct FtpSession {
	control: Stream,
	reader: LineReader,
	ctx: Arc<ServerContext>,
	addr: SocketAddr,
	cwd: String,
	rest_offset: Option<u64>,
	data_listener: Option<TcpListener>,
	data_addr: Option<SocketAddr>,
	data_tls: bool, // PROT P — encrypt data connections
	authed: bool,
	username: Option<String>,
	use_tls: bool, // control connection upgraded to TLS
	shutdown: Arc<AtomicBool>,
}

impl FtpSession {
	pub fn new(
		stream: TcpStream,
		ctx: Arc<ServerContext>,
		addr: SocketAddr,
		shutdown: Arc<AtomicBool>,
	) -> Self {
		// Implicit FTPS: wrap the control connection in TLS immediately.
		// The TLS handshake happens lazily on the first read/write.
		let (control, use_tls, data_tls) = if ctx.implicit_tls {
			let tls_config = ctx
				.tls_config
				.as_ref()
				.expect("implicit_tls requires tls_config")
				.clone();

			// Implicit FTPS handshake timeout. If the client speaks plain
			// FTP (e.g. FileZilla in FTPES mode connecting to an implicit-
			// FTPS port) no TLS ClientHello ever arrives. Without a short
			// read timeout the server would hang for the full idle_timeout
			// (default 300s). 5s is enough for any real TLS client to send
			// its ClientHello while failing fast on protocol mismatch.
			let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));

			let conn = rustls::ServerConnection::new(tls_config)
				.expect("TLS ServerConnection creation failed");
			let mut tls_stream = rustls::StreamOwned::new(conn, stream);

			// Force the TLS handshake now (rather than lazily on the first
			// 220 write) so a protocol-mismatch failure surfaces here with
			// a clear log line instead of an opaque write error later.
			match tls_stream.flush() {
				Ok(_) => (
					Stream::Tls(tls_stream),
					true,
					true, // Implicit FTPS → data connections default to encrypted
				),
				Err(e) => {
					eprintln!(
						"[ftp:{}] implicit FTPS handshake failed: {}. \
						 Client may be using plain FTP or FTPES instead of implicit FTPS.",
						addr, e
					);
					// Return a closed dummy stream — handle() will detect
					// `implicit_tls && !use_tls` and exit immediately.
					(Stream::Plain(dummy_stream()), false, false)
				}
			}
		} else {
			(Stream::Plain(stream), false, false)
		};

		FtpSession {
			control,
			reader: LineReader::new(),
			ctx,
			addr,
			cwd: "/".to_string(),
			rest_offset: None,
			data_listener: None,
			data_addr: None,
			data_tls,
			authed: false,
			username: None,
			use_tls,
			shutdown,
		}
	}

	/// Main command loop. Runs until QUIT, connection close, or shutdown.
	pub fn handle(&mut self) -> io::Result<()> {
		// If implicit TLS was requested but the client spoke plaintext, the
		// constructor already sent a 530 and left us with a closed dummy
		// socket. Skip the welcome banner and exit immediately.
		if self.ctx.implicit_tls && !self.use_tls {
			return Ok(());
		}

		self.send(220, "rcrm projection FTP server ready")?;

		while !self.shutdown.load(Ordering::Relaxed) {
			let line = match self.reader.read_line(&mut self.control) {
				Ok(l) => l,
				Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
				Err(e) if e.kind() == io::ErrorKind::TimedOut => {
					self.send(421, "Idle timeout — goodbye")?;
					break;
				}
				Err(e) => {
					eprintln!("[ftp:{}] read error: {}", self.addr, e);
					break;
				}
			};

			let line = line.trim();
			if line.is_empty() {
				continue;
			}

			let (verb, arg) = match line.split_once(' ') {
				Some((v, a)) => (v.to_uppercase(), a.trim().to_string()),
				None => (line.to_uppercase(), String::new()),
			};

			eprintln!("[ftp:{}] CMD {} {}", self.addr, verb, arg);

			let quit = match verb.as_str() {
				"USER" => self.cmd_user(&arg),
				"PASS" => self.cmd_pass(&arg),
				"AUTH" => self.cmd_auth(&arg),
				"PBSZ" => self.cmd_pbsz(&arg),
				"PROT" => self.cmd_prot(&arg),
				"SYST" => self.cmd_syst(),
				"FEAT" => self.cmd_feat(),
				"PWD" | "XPWD" => self.cmd_pwd(),
				"CWD" | "XCWD" => self.cmd_cwd(&arg),
				"CDUP" | "XCUP" => self.cmd_cdup(),
				"TYPE" => self.cmd_type(&arg),
				"PASV" => self.cmd_pasv(),
				"EPSV" => self.cmd_epsv(&arg),
				"LIST" => self.cmd_list(&arg, false),
				"NLST" => self.cmd_list(&arg, true),
				"MLSD" => self.cmd_mlsd(&arg),
				"RETR" => self.cmd_retr(&arg),
				"SIZE" => self.cmd_size(&arg),
				"MDTM" => self.cmd_mdtm(&arg),
				"REST" => self.cmd_rest(&arg),
				"ABOR" => self.cmd_abor(),
				"NOOP" => self.send(200, "OK"),
				"OPTS" => self.cmd_opts(&arg),
				"QUIT" => {
					let _ = self.send(221, "Goodbye");
					break;
				}
				// Read-only enforcement: reject all mutating commands.
				"STOR" | "STOU" | "APPE" | "DELE" | "MKD" | "XMKD" | "RMD" | "XRMD" | "RNFR"
				| "RNTO" | "SITE" | "SMNT" | "ALLO" => {
					self.send(550, "Read-only server: write commands disabled")
				}
				_ => self.send(502, "Command not implemented"),
			};

			if let Err(e) = quit {
				if e.kind() == io::ErrorKind::UnexpectedEof {
					break;
				}
				eprintln!("[ftp:{}] handler error: {}", self.addr, e);
				break;
			}
		}

		self.control.shutdown();
		Ok(())
	}

	// ------------------- response helpers -------------------

	fn send(&mut self, code: u16, msg: &str) -> io::Result<()> {
		let line = format!("{} {}\r\n", code, msg);
		eprintln!("[ftp:{}] RSP {} {}", self.addr, code, msg);
		self.control.write_all(line.as_bytes())?;
		self.control.flush()
	}

	fn send_multi(&mut self, code: u16, lines: &[&str]) -> io::Result<()> {
		// RFC 959 multi-line format. The first and every continuation line
		// begin with `<code>-` until the final line `<code> `. This matches
		// the format used by vsftpd/proftpd and is the most widely
		// compatible variant (some clients, e.g. VLC, stall on the
		// space-prefixed continuation lines).
		//   211-First line\r\n
		//   211-Second line\r\n
		//   211 Last line\r\n
		let mut out = String::new();
		for (i, line) in lines.iter().enumerate() {
			if i == lines.len() - 1 {
				out.push_str(&format!("{} {}\r\n", code, line));
			} else {
				out.push_str(&format!("{}-{}\r\n", code, line));
			}
		}
		eprintln!(
			"[ftp:{}] RSP {} (multi: {} lines)",
			self.addr,
			code,
			lines.len()
		);
		self.control.write_all(out.as_bytes())?;
		self.control.flush()
	}

	// ------------------- command handlers -------------------

	fn cmd_user(&mut self, arg: &str) -> io::Result<()> {
		self.username = Some(arg.to_string());
		self.authed = false;
		if self.ctx.auth.user.is_none() {
			// Anonymous mode — accept immediately, no password needed.
			self.authed = true;
			self.send(230, "Anonymous login OK")
		} else {
			self.send(331, "Password required")
		}
	}

	fn cmd_pass(&mut self, arg: &str) -> io::Result<()> {
		if self.ctx.auth.user.is_none() {
			return self.send(230, "Anonymous login OK");
		}
		let user = self.username.as_deref().unwrap_or("");
		if self.ctx.auth.verify(user, arg) {
			self.authed = true;
			self.send(230, "Login OK")
		} else {
			self.send(530, "Login incorrect")
		}
	}

	fn cmd_auth(&mut self, arg: &str) -> io::Result<()> {
		// AUTH TLS is only for Explicit FTPS. Implicit FTPS connections are
		// already TLS-wrapped before any FTP command is read.
		if self.ctx.implicit_tls {
			return self.send(503, "Already in TLS (implicit FTPS)");
		}
		if self.ctx.tls_config.is_none() {
			return self.send(502, "TLS not configured");
		}
		if arg.to_uppercase() != "TLS" && arg.to_uppercase() != "TLS-C" {
			return self.send(504, "Only AUTH TLS supported");
		}
		if self.use_tls {
			return self.send(503, "Already in TLS");
		}
		self.send(234, "Proceed with negotiation")?;
		// Hand off the underlying TcpStream to rustls. We must extract it
		// from the Stream enum first.
		let plain = std::mem::replace(&mut self.control, Stream::Plain(dummy_stream()));
		let tcp = match plain {
			Stream::Plain(tcp) => tcp,
			Stream::Tls(_) => {
				return Err(io::Error::new(
					io::ErrorKind::AlreadyExists,
					"control already TLS",
				));
			}
		};
		let tls_config = self.ctx.tls_config.as_ref().unwrap().clone();
		let conn = rustls::ServerConnection::new(tls_config)
			.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
		let stream = rustls::StreamOwned::new(conn, tcp);
		self.control = Stream::Tls(stream);
		self.use_tls = true;
		Ok(())
	}

	fn cmd_pbsz(&mut self, _arg: &str) -> io::Result<()> {
		if !self.use_tls {
			return self.send(503, "PBSZ requires TLS");
		}
		self.send(200, "PBSZ=0")
	}

	fn cmd_prot(&mut self, arg: &str) -> io::Result<()> {
		if !self.use_tls {
			return self.send(503, "PROT requires TLS");
		}
		match arg.to_uppercase().as_str() {
			"C" => {
				// PROT C is rejected in implicit FTPS — the whole point of
				// implicit FTPS is end-to-end encryption. Allowing clear
				// data would defeat that.
				if self.ctx.implicit_tls {
					self.send(534, "Clear data not allowed in implicit FTPS")
				} else {
					self.data_tls = false;
					self.send(200, "Protection level: Clear")
				}
			}
			"P" => {
				self.data_tls = true;
				self.send(200, "Protection level: Private")
			}
			_ => self.send(504, "Only PROT C / PROT P supported"),
		}
	}

	fn cmd_syst(&mut self) -> io::Result<()> {
		self.send(215, "UNIX Type: L8")
	}

	fn cmd_feat(&mut self) -> io::Result<()> {
		// RFC 2389: each feature on its own line. AUTH TLS / PBSZ / PROT
		// are only advertised for Explicit FTPS (AUTH TLS upgrade). For
		// Implicit FTPS the connection is already TLS — AUTH TLS is not
		// applicable. Plain FTP never advertises TLS features (this also
		// avoids confusing clients like VLC that may try TLS upgrade and
		// stall when the server has no TLS configured).
		let mut lines: Vec<&str> = vec!["Features:", "UTF8"];
		if self.ctx.tls_config.is_some() && !self.ctx.implicit_tls {
			lines.push("AUTH TLS");
			lines.push("PBSZ");
			lines.push("PROT");
		}
		lines.push("SIZE");
		lines.push("MDTM");
		lines.push("REST STREAM");
		lines.push("MLSD");
		lines.push("EPSV");
		lines.push("PASV");
		lines.push("End");
		self.send_multi(211, &lines)
	}

	fn cmd_pwd(&mut self) -> io::Result<()> {
		self.send(257, &format!("\"{}\" is current directory", self.cwd))
	}

	fn cmd_cwd(&mut self, arg: &str) -> io::Result<()> {
		if !self.authed {
			return self.send(530, "Not logged in");
		}
		let target = resolve_disk_path(&self.ctx.root, &self.cwd, arg);
		if !target.is_dir() {
			return self.send(550, "No such directory");
		}
		self.cwd = disk_to_ftp_path(&self.ctx.root, &target);
		self.send(250, &format!("Directory changed to {}", self.cwd))
	}

	fn cmd_cdup(&mut self) -> io::Result<()> {
		self.cmd_cwd("..")
	}

	fn cmd_type(&mut self, arg: &str) -> io::Result<()> {
		match arg.to_uppercase().as_str() {
			"I" | "L 8" | "L8" => self.send(200, "Type set to I (binary)"),
			"A" | "A N" => self.send(200, "Type set to A (ascii)"),
			_ => self.send(504, "Only TYPE I / A supported"),
		}
	}

	// ------------------- PASV / EPSV -------------------

	fn cmd_pasv(&mut self) -> io::Result<()> {
		if !self.authed {
			return self.send(530, "Not logged in");
		}
		// Close any previous listener.
		self.data_listener = None;
		self.data_addr = None;

		// Bind the data listener on the server-side local IP of the control
		// connection — the same interface the client already reached us on.
		// Using `self.addr.ip()` (the *client's* IP) here is wrong: binding
		// to a foreign IP fails with WSAEADDRNOTAVAIL (10049) on Windows
		// and EADDRNOTAVAIL on Unix when the client is on another host.
		let local_ip = self
			.control_local_ip()
			.unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)));
		let listener = TcpListener::bind(SocketAddr::new(local_ip, 0))?;
		listener.set_nonblocking(false)?;
		let local = listener.local_addr()?;
		let port = local.port();

		// PASV only supports IPv4 — the 227 response encodes a 4-octet IP.
		// Fall back to EPSV for IPv6. The IP we advertise is the server-side
		// local IP of the control connection (the address the client already
		// used to reach us, so it is routable back).
		let octets = match local_ip {
			std::net::IpAddr::V4(v4) => v4.octets(),
			std::net::IpAddr::V6(_) => {
				return self.send(522, "Use EPSV for IPv6 connections");
			}
		};
		let p1 = (port >> 8) & 0xff;
		let p2 = port & 0xff;

		self.data_listener = Some(listener);
		self.data_addr = Some(local);

		self.send(
			227,
			&format!(
				"Entering Passive Mode ({},{},{},{},{},{})",
				octets[0], octets[1], octets[2], octets[3], p1, p2
			),
		)
	}

	fn cmd_epsv(&mut self, arg: &str) -> io::Result<()> {
		if !self.authed {
			return self.send(530, "Not logged in");
		}
		// EPSV supports an optional protocol argument ("1" for IPv4, "2" for
		// IPv6, "ALL" for either). We accept any.
		let _ = arg;
		self.data_listener = None;
		self.data_addr = None;

		// Bind on the server-side local IP of the control connection (same
		// fix as PASV — see the comment there for why `self.addr.ip()` is
		// wrong).
		let local_ip = self
			.control_local_ip()
			.unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)));
		let listener = TcpListener::bind(SocketAddr::new(local_ip, 0))?;
		listener.set_nonblocking(false)?;
		let local = listener.local_addr()?;
		let port = local.port();

		self.data_listener = Some(listener);
		self.data_addr = Some(local);

		self.send(
			229,
			&format!("Entering Extended Passive Mode (|||{}|)", port),
		)
	}

	/// Accept the pending data connection (from PASV/EPSV). Applies a 30s
	/// timeout. Wraps in TLS if `data_tls` is set.
	fn accept_data(&mut self) -> io::Result<Stream> {
		let listener = self
			.data_listener
			.take()
			.ok_or_else(|| io::Error::other("no PASV data listener"))?;

		listener.set_nonblocking(true)?;
		let deadline = Instant::now() + Duration::from_secs(30);
		let tcp = loop {
			match listener.accept() {
				Ok((s, _)) => break s,
				Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
					if Instant::now() >= deadline {
						return Err(io::Error::new(
							io::ErrorKind::TimedOut,
							"data connect timeout",
						));
					}
					std::thread::sleep(Duration::from_millis(20));
				}
				Err(e) => return Err(e),
			}
		};
		// The accepted socket inherits non-blocking mode from the listener —
		// switch back to blocking so reads/writes behave normally.
		tcp.set_nonblocking(false)?;
		let _ = tcp.set_nodelay(true);
		let _ = tcp.set_read_timeout(Some(Duration::from_secs(60)));
		let _ = tcp.set_write_timeout(Some(Duration::from_secs(60)));

		if self.data_tls {
			let tls_config = self
				.ctx
				.tls_config
				.as_ref()
				.ok_or_else(|| io::Error::other("TLS not configured"))?
				.clone();
			let conn = rustls::ServerConnection::new(tls_config)
				.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
			Ok(Stream::Tls(rustls::StreamOwned::new(conn, tcp)))
		} else {
			Ok(Stream::Plain(tcp))
		}
	}

	/// Get the local IP of the control connection (for PASV response).
	fn control_local_ip(&self) -> Option<std::net::IpAddr> {
		match &self.control {
			Stream::Plain(s) => s.local_addr().ok().map(|a| a.ip()),
			Stream::Tls(s) => s.get_ref().local_addr().ok().map(|a| a.ip()),
		}
	}

	// ------------------- LIST / NLST / MLSD -------------------

	fn cmd_list(&mut self, arg: &str, names_only: bool) -> io::Result<()> {
		if !self.authed {
			return self.send(530, "Not logged in");
		}
		// Some clients send options like "-la" before the path.
		let path_arg = arg
			.split_whitespace()
			.find(|s| !s.starts_with('-'))
			.unwrap_or("");
		let target = resolve_disk_path(&self.ctx.root, &self.cwd, path_arg);
		let dir = if target.is_dir() {
			target.clone()
		} else if target.exists() {
			// Listing a single file — return just that entry.
			let parent = target.parent().unwrap_or(&self.ctx.root).to_path_buf();
			let entries = self.list_dir(&parent)?;
			let single: Vec<DirEntry> = entries
				.into_iter()
				.filter(|e| e.disk_path == target)
				.collect();
			return self.stream_listing(single, names_only);
		} else {
			return self.send(550, "No such file or directory");
		};

		match self.list_dir(&dir) {
			Ok(entries) => self.stream_listing(entries, names_only),
			Err(e) => {
				eprintln!("[ftp:{}] list error: {}", self.addr, e);
				self.send(550, "Failed to list directory")
			}
		}
	}

	fn cmd_mlsd(&mut self, arg: &str) -> io::Result<()> {
		if !self.authed {
			return self.send(530, "Not logged in");
		}
		let target = resolve_disk_path(&self.ctx.root, &self.cwd, arg);
		let dir = if target.is_dir() {
			target
		} else {
			return self.send(550, "No such directory");
		};
		match self.list_dir(&dir) {
			Ok(entries) => self.stream_mlsd(entries),
			Err(e) => {
				eprintln!("[ftp:{}] mlsd error: {}", self.addr, e);
				self.send(550, "Failed to list directory")
			}
		}
	}

	/// Build the directory entry list for `dir`, applying projection:
	///   * Encrypted (`.<b72>`) files are opened and shown with their
	///     decrypted virtual name and virtual (original) size.
	///   * Plain files and subdirectories are shown as-is.
	fn list_dir(&self, dir: &Path) -> io::Result<Vec<DirEntry>> {
		let mut out = Vec::new();
		let rd = std::fs::read_dir(dir)?;
		for entry in rd.flatten() {
			let path = entry.path();
			let name = entry.file_name().to_string_lossy().into_owned();
			let meta = match entry.metadata() {
				Ok(m) => m,
				Err(_) => continue,
			};

			if meta.is_dir() {
				out.push(DirEntry {
					disk_path: path,
					virtual_name: name,
					is_dir: true,
					size: meta.len(),
					mtime: meta.modified().ok(),
				});
			} else if is_encrypted_name(&name) {
				// Try to open as projected — if it fails (wrong key), skip.
				match self
					.ctx
					.cache
					.get_or_open(&path, &self.ctx.manager, &self.ctx.session_key)
				{
					Ok(pf) => {
						out.push(DirEntry {
							disk_path: path,
							virtual_name: pf.virtual_name().to_string(),
							is_dir: false,
							size: pf.virtual_size(),
							mtime: meta.modified().ok(),
						});
					}
					Err(_) => {
						// Wrong key or corrupt — hide the file entirely.
						continue;
					}
				}
			} else {
				out.push(DirEntry {
					disk_path: path,
					virtual_name: name,
					is_dir: false,
					size: meta.len(),
					mtime: meta.modified().ok(),
				});
			}
		}
		Ok(out)
	}

	fn stream_listing(&mut self, entries: Vec<DirEntry>, names_only: bool) -> io::Result<()> {
		// 150 Opening data connection
		self.send(150, "Opening data connection")?;
		let mut data = match self.accept_data() {
			Ok(s) => s,
			Err(e) => {
				self.send(425, &format!("Cannot open data connection: {}", e))?;
				return Ok(());
			}
		};

		let mut buf = Vec::with_capacity(4096);
		for e in &entries {
			if names_only {
				buf.extend_from_slice(e.virtual_name.as_bytes());
				buf.extend_from_slice(b"\r\n");
			} else {
				buf.extend_from_slice(format_unix_listing(e).as_bytes());
			}
		}

		let result = data.write_all(&buf).and_then(|_| data.flush());
		data.shutdown();

		match result {
			Ok(_) => self.send(226, "Transfer complete"),
			Err(e) => {
				eprintln!("[ftp:{}] list transfer error: {}", self.addr, e);
				self.send(426, "Transfer aborted")
			}
		}
	}

	fn stream_mlsd(&mut self, entries: Vec<DirEntry>) -> io::Result<()> {
		self.send(150, "Opening data connection")?;
		let mut data = match self.accept_data() {
			Ok(s) => s,
			Err(e) => {
				self.send(425, &format!("Cannot open data connection: {}", e))?;
				return Ok(());
			}
		};

		let mut buf = Vec::with_capacity(4096);
		for e in &entries {
			buf.extend_from_slice(format_mlsd_entry(e).as_bytes());
		}

		let result = data.write_all(&buf).and_then(|_| data.flush());
		data.shutdown();

		match result {
			Ok(_) => self.send(226, "Transfer complete"),
			Err(e) => {
				eprintln!("[ftp:{}] mlsd transfer error: {}", self.addr, e);
				self.send(426, "Transfer aborted")
			}
		}
	}

	// ------------------- RETR -------------------

	fn cmd_retr(&mut self, arg: &str) -> io::Result<()> {
		if !self.authed {
			return self.send(530, "Not logged in");
		}
		if !self.use_tls && self.ctx.require_tls {
			return self.send(530, "TLS required");
		}

		let disk = resolve_disk_path(&self.ctx.root, &self.cwd, arg);

		// Resolve to a projected file if the name doesn't exist on disk
		// (i.e. the client requested the decrypted virtual name).
		let resolved = self.resolve_retr_target(&disk, arg);

		let (stream_kind, size) = match resolved {
			ResolvedRetr::Plain(p) => {
				let meta = std::fs::metadata(&p)?;
				(ReadSource::Plain(p), meta.len())
			}
			ResolvedRetr::Projected(pf) => {
				let s = pf.virtual_size();
				(ReadSource::Projected(pf), s)
			}
			ResolvedRetr::NotFound => {
				return self.send(550, "No such file");
			}
		};

		let offset = self.rest_offset.take().unwrap_or(0);
		if offset > size {
			return self.send(550, "REST offset beyond EOF");
		}

		self.send(
			150,
			&format!("Opening data connection ({} bytes)", size - offset),
		)?;

		let mut data = match self.accept_data() {
			Ok(s) => s,
			Err(e) => {
				self.send(425, &format!("Cannot open data connection: {}", e))?;
				return Ok(());
			}
		};

		let result = self.stream_file(stream_kind, offset, size, &mut data);
		data.shutdown();

		match result {
			Ok(sent) => self.send(226, &format!("Transfer complete ({} bytes sent)", sent)),
			Err(e) => {
				eprintln!("[ftp:{}] retr transfer error: {}", self.addr, e);
				self.send(426, "Transfer aborted")
			}
		}
	}

	fn resolve_retr_target(&self, disk: &Path, _arg: &str) -> ResolvedRetr {
		// If the disk path exists as a regular file, serve it plain (unless
		// it's a `.<b72>` file, in which case we project it).
		if disk.is_file() {
			let name = disk.file_name().and_then(|s| s.to_str()).unwrap_or("");
			if is_encrypted_name(name) {
				if let Ok(pf) =
					self.ctx
						.cache
						.get_or_open(disk, &self.ctx.manager, &self.ctx.session_key)
				{
					return ResolvedRetr::Projected(pf);
				}
				return ResolvedRetr::NotFound;
			}
			return ResolvedRetr::Plain(disk.to_path_buf());
		}
		// Otherwise, the client likely requested the decrypted virtual name.
		// Look for a `.<b72>` file in the parent directory whose virtual
		// name matches.
		if let Some(parent) = disk.parent()
			&& let Some(req_name) = disk.file_name().and_then(|s| s.to_str())
		{
			// Fast path: name index.
			if let Some(b72_path) = self.ctx.cache.resolve_virtual_name(parent, req_name)
				&& let Some(pf) = self.ctx.cache.get(&b72_path)
			{
				return ResolvedRetr::Projected(pf);
			}
			// Slow path: scan parent directory.
			if let Ok(rd) = std::fs::read_dir(parent) {
				for entry in rd.flatten() {
					let path = entry.path();
					let name = entry.file_name().to_string_lossy().into_owned();
					if !is_encrypted_name(&name) {
						continue;
					}
					if let Ok(pf) =
						self.ctx
							.cache
							.get_or_open(&path, &self.ctx.manager, &self.ctx.session_key)
						&& pf.virtual_name() == req_name
					{
						return ResolvedRetr::Projected(pf);
					}
				}
			}
		}
		ResolvedRetr::NotFound
	}

	fn stream_file(
		&self,
		source: ReadSource,
		offset: u64,
		size: u64,
		data: &mut Stream,
	) -> io::Result<u64> {
		let mut sent = 0u64;
		let total = size.saturating_sub(offset);
		let mut buf = vec![0u8; 64 * 1024];

		match source {
			ReadSource::Plain(path) => {
				let mut f = std::fs::File::open(&path)?;
				f.seek(SeekFrom::Start(offset))?;
				while sent < total {
					let want = std::cmp::min(buf.len() as u64, total - sent) as usize;
					let n = f.read(&mut buf[..want])?;
					if n == 0 {
						break;
					}
					data.write_all(&buf[..n])?;
					sent += n as u64;
				}
			}
			ReadSource::Projected(pf) => {
				while sent < total {
					let want = std::cmp::min(buf.len() as u64, total - sent) as usize;
					let n = pf.read_at(offset + sent, &mut buf[..want], &self.ctx.session_key)?;
					if n == 0 {
						break;
					}
					data.write_all(&buf[..n])?;
					// Zeroize the buffer slice we just used (it held plaintext).
					buf[..n].fill(0);
					sent += n as u64;
				}
			}
		}
		data.flush()?;
		Ok(sent)
	}

	// ------------------- SIZE / MDTM / REST -------------------

	fn cmd_size(&mut self, arg: &str) -> io::Result<()> {
		if !self.authed {
			return self.send(530, "Not logged in");
		}
		let disk = resolve_disk_path(&self.ctx.root, &self.cwd, arg);
		match self.resolve_retr_target(&disk, arg) {
			ResolvedRetr::Plain(p) => match std::fs::metadata(&p) {
				Ok(m) => self.send(213, &format!("{}", m.len())),
				Err(_) => self.send(550, "No such file"),
			},
			ResolvedRetr::Projected(pf) => self.send(213, &format!("{}", pf.virtual_size())),
			ResolvedRetr::NotFound => self.send(550, "No such file"),
		}
	}

	fn cmd_mdtm(&mut self, arg: &str) -> io::Result<()> {
		if !self.authed {
			return self.send(530, "Not logged in");
		}
		let disk = resolve_disk_path(&self.ctx.root, &self.cwd, arg);
		// MDTM uses the on-disk file's mtime (we don't track original mtime).
		let target = match self.resolve_retr_target(&disk, arg) {
			ResolvedRetr::Plain(p) => p,
			ResolvedRetr::Projected(pf) => pf.disk_path().to_path_buf(),
			ResolvedRetr::NotFound => return self.send(550, "No such file"),
		};
		match std::fs::metadata(&target).and_then(|m| m.modified()) {
			Ok(mtime) => {
				let secs = mtime
					.duration_since(UNIX_EPOCH)
					.map(|d| d.as_secs())
					.unwrap_or(0);
				self.send(213, &format_epoch_as_ftp_timestamp(secs))
			}
			Err(_) => self.send(550, "No such file"),
		}
	}

	fn cmd_rest(&mut self, arg: &str) -> io::Result<()> {
		match arg.parse::<u64>() {
			Ok(n) => {
				self.rest_offset = Some(n);
				self.send(350, &format!("Restarting at {}", n))
			}
			Err(_) => self.send(501, "Invalid REST offset"),
		}
	}

	fn cmd_abor(&mut self) -> io::Result<()> {
		// Drop any pending data listener.
		self.data_listener = None;
		self.data_addr = None;
		self.rest_offset = None;
		self.send(226, "ABOR successful")
	}

	fn cmd_opts(&mut self, arg: &str) -> io::Result<()> {
		let upper = arg.to_uppercase();
		if upper.starts_with("UTF8") {
			self.send(200, "UTF8 enabled")
		} else {
			self.send(504, "Option not supported")
		}
	}
}

// =======================
// Directory entry representation
// =======================

struct DirEntry {
	disk_path: PathBuf,
	virtual_name: String,
	is_dir: bool,
	size: u64,
	mtime: Option<SystemTime>,
}

#[allow(clippy::large_enum_variant)]
enum ResolvedRetr {
	Plain(PathBuf),
	Projected(Arc<ProjectedFile>),
	NotFound,
}

enum ReadSource {
	Plain(PathBuf),
	Projected(Arc<ProjectedFile>),
}

// =======================
// Listing formatters
// =======================

fn format_unix_listing(e: &DirEntry) -> String {
	let type_ch = if e.is_dir { 'd' } else { '-' };
	let perms = "rwxr-xr-x";
	let links = if e.is_dir { 2 } else { 1 };
	let owner = "rcrm";
	let group = "rcrm";
	let size = e.size;
	let date = mtime_to_listing_date(e.mtime);
	format!(
		"{}{} {:>3} {:<8} {:<8} {:>12} {} {}\r\n",
		type_ch, perms, links, owner, group, size, date, e.virtual_name
	)
}

fn format_mlsd_entry(e: &DirEntry) -> String {
	let type_str = if e.is_dir { "dir" } else { "file" };
	let mut facts = vec![format!("type={}", type_str)];
	if !e.is_dir {
		facts.push(format!("size={}", e.size));
	}
	if let Some(mtime) = e.mtime {
		let secs = mtime
			.duration_since(UNIX_EPOCH)
			.map(|d| d.as_secs())
			.unwrap_or(0);
		facts.push(format!("modify={}", format_epoch_as_ftp_timestamp(secs)));
	}
	// MLSD format: "fact1;fact2;fact3; filename\r\n"
	format!("{}; {}\r\n", facts.join(";"), e.virtual_name)
}

fn mtime_to_listing_date(mtime: Option<SystemTime>) -> String {
	let secs = match mtime {
		Some(t) => t
			.duration_since(UNIX_EPOCH)
			.map(|d| d.as_secs())
			.unwrap_or(0),
		None => 0,
	};
	format_epoch_as_listing_date(secs)
}

/// FTP MLSD modify= format: YYYYMMDDHHMMSS
fn format_epoch_as_ftp_timestamp(secs: u64) -> String {
	let (year, month, day, hour, minute, second) = epoch_to_ymdhms(secs);
	format!(
		"{:04}{:02}{:02}{:02}{:02}{:02}",
		year, month, day, hour, minute, second
	)
}

/// Unix `ls -l`-style date: "Mmm DD YYYY" (always year — simpler & unambiguous).
fn format_epoch_as_listing_date(secs: u64) -> String {
	let (year, month, day, _h, _m, _s) = epoch_to_ymdhms(secs);
	const MONTHS: [&str; 12] = [
		"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
	];
	format!("{:>3} {:02} {}", MONTHS[(month - 1) as usize], day, year)
}

/// Convert epoch seconds to (year, month, day, hour, minute, second) in UTC.
/// Minimal civil-from-days algorithm (Howard Hinnant). Good enough for FTP
/// timestamps — we don't need timezone-correct display.
fn epoch_to_ymdhms(secs: u64) -> (i32, u32, u32, u32, u32, u32) {
	let days = (secs / 86400) as i64;
	let rem = secs % 86400;
	let hour = (rem / 3600) as u32;
	let minute = ((rem % 3600) / 60) as u32;
	let second = (rem % 60) as u32;

	// Civil from days (Hinnant's algorithm)
	let z = days + 719468;
	let era = if z >= 0 { z } else { z - 146096 } / 146097;
	let doe = (z - era * 146097) as u64;
	let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
	let y = yoe as i64 + era * 400;
	let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	let mp = (5 * doy + 2) / 153;
	let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
	let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
	let year = (y + (if m <= 2 { 1 } else { 0 })) as i32;
	(year, m, d, hour, minute, second)
}

// =======================
// Helpers
// =======================

fn is_encrypted_name(name: &str) -> bool {
	rcrm_core::is_valid_encrypted_file_name(name)
}

/// Create a throwaway TcpStream to satisfy the enum when swapping control
/// streams during TLS upgrade. This socket is connected to a closed peer
/// (server side is dropped immediately) and is never read or written to —
/// it exists only to satisfy the `Stream::Plain` variant during the brief
/// `mem::replace` window before the TLS stream is assigned.
fn dummy_stream() -> TcpStream {
	let listener = TcpListener::bind("127.0.0.1:0").expect("dummy bind failed");
	let addr = listener.local_addr().expect("dummy local_addr failed");
	let client = TcpStream::connect(addr).expect("dummy connect failed");
	let (_server_side, _) = listener.accept().expect("dummy accept failed");
	// Drop server_side — peer is now closed.
	client
}

// Allow is_supported_file import without warning if unused in this module.
#[allow(dead_code)]
fn _silence_unused_import() -> bool {
	is_supported_file(Path::new("."))
}
