// src/serve/webdav.rs
// rcrm - WebDAV (HTTP/HTTPS) protocol implementation.
// Copyleft (©) 2024-2025 hibays
//
// Read-only WebDAV projection of encrypted files. Implements the subset of
// WebDAV required for mounting as a network drive / browsing in file
// managers (Windows Explorer, macOS Finder, Linux GVfs, VLC):
//   OPTIONS  — DAV class 1 capability advertisement
//   PROPFIND — directory listing + resource properties (Depth: 0, 1)
//   GET      — stream projected (decrypted) file content
//   HEAD     — headers only (size, mtime, type)
//   PUT / DELETE / MKCOL / MOVE / COPY — rejected with 403 (read-only)
//
// HTTPS is implicit TLS (connection wrapped on accept), mirroring --ftps.
// Authentication uses HTTP Basic (RFC 7617), reusing the FTP AuthConfig.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;

use super::{AuthConfig, ServerContext};
use crate::is_valid_encrypted_file_name;
use crate::serve::FileCache;

// =======================
// HTTP request / response types
// =======================

struct Request {
	method: String,
	/// URL-decoded path (without query string).
	path: String,
	headers: Vec<(String, String)>,
	/// Body bytes (PROPFIND XML; GET/PUT bodies). Currently unused —
	/// PROPFIND returns a fixed propset regardless of the requested
	/// properties — but parsed for correctness and future use.
	#[allow(dead_code)]
	body: Vec<u8>,
}

impl Request {
	fn header(&self, name: &str) -> Option<&str> {
		self.headers
			.iter()
			.find(|(k, _)| k.eq_ignore_ascii_case(name))
			.map(|(_, v)| v.as_str())
	}
}

// =======================
// Entry point
// =======================

pub fn handle_session(
	stream: TcpStream,
	ctx: Arc<ServerContext>,
	addr: SocketAddr,
	shutdown: Arc<AtomicBool>,
) -> io::Result<()> {
	// HTTPS WebDAV: wrap in TLS immediately.
	let mut stream: Box<dyn ReadWrite> = if ctx.protocol == super::Protocol::WebDavHttps {
		let tls_config = ctx
			.tls_config
			.as_ref()
			.expect("WebDavHttps requires tls_config")
			.clone();

		// Short read timeout for the handshake so a plaintext client on an
		// HTTPS port fails fast instead of hanging for the idle timeout.
		let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
		let conn = rustls::ServerConnection::new(tls_config)
			.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
		let mut tls_stream = rustls::StreamOwned::new(conn, stream);
		// Force the handshake now for fast-fail on protocol mismatch.
		match tls_stream.flush() {
			Ok(_) => {}
			Err(e) => {
				eprintln!(
					"[webdav:{}] HTTPS handshake failed: {}. \
					 Client may be using plain HTTP instead of HTTPS.",
					addr, e
				);
				return Ok(());
			}
		}
		Box::new(tls_stream)
	} else {
		Box::new(stream)
	};

	// Handle requests in a keep-alive loop until the client closes or the
	// connection times out.
	while !shutdown.load(Ordering::Relaxed) {
		let req = match read_request(stream.as_mut()) {
			Ok(r) => r,
			Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
			Err(e) if e.kind() == io::ErrorKind::TimedOut => break,
			Err(e) => {
				eprintln!("[webdav:{}] read error: {}", addr, e);
				break;
			}
		};
		eprintln!("[webdav:{}] {} {}", addr, req.method, req.path);

		let keep_alive = dispatch(&req, &ctx, stream.as_mut(), &addr)?;
		if !keep_alive {
			break;
		}
	}

	Ok(())
}

// =======================
// Read HTTP request
// =======================

fn read_request(stream: &mut dyn ReadWrite) -> io::Result<Request> {
	// Read the request line + headers (up to \r\n\r\n).
	let head = read_until_double_crlf(stream)?;
	let head_str = String::from_utf8_lossy(&head);
	let mut lines = head_str.lines();
	let request_line = lines
		.next()
		.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty request"))?;

	let mut parts = request_line.split_whitespace();
	let method = parts
		.next()
		.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no method"))?
		.to_string();
	let raw_path = parts
		.next()
		.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no path"))?
		.to_string();
	let _version = parts.next().unwrap_or("HTTP/1.0");

	let path = percent_decode(raw_path.split('?').next().unwrap_or(&raw_path));

	let mut headers: Vec<(String, String)> = Vec::new();
	for line in lines {
		if let Some((k, v)) = line.split_once(':') {
			headers.push((k.trim().to_string(), v.trim().to_string()));
		}
	}

	// Read body if Content-Length is present.
	let content_length = headers
		.iter()
		.find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
		.and_then(|(_, v)| v.parse::<usize>().ok());
	let body = if let Some(cl) = content_length {
		let mut body = vec![0u8; cl];
		stream.read_exact(&mut body)?;
		body
	} else {
		Vec::new()
	};

	Ok(Request {
		method,
		path,
		headers,
		body,
	})
}

/// Read from `stream` until `\r\n\r\n` is seen, returning everything up to
/// and including the terminator.
fn read_until_double_crlf(stream: &mut dyn ReadWrite) -> io::Result<Vec<u8>> {
	let mut buf = Vec::with_capacity(1024);
	let mut byte = [0u8; 1];
	loop {
		let n = stream.read(&mut byte)?;
		if n == 0 {
			if buf.is_empty() {
				return Err(io::Error::new(
					io::ErrorKind::UnexpectedEof,
					"connection closed before headers",
				));
			}
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				"connection closed mid-headers",
			));
		}
		buf.push(byte[0]);
		if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
			break;
		}
		if buf.len() > 64 * 1024 {
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				"header too large",
			));
		}
	}
	Ok(buf)
}

// =======================
// Dispatch
// =======================

fn dispatch(
	req: &Request,
	ctx: &ServerContext,
	stream: &mut dyn ReadWrite,
	addr: &SocketAddr,
) -> io::Result<bool> {
	// Determine if the client wants the connection closed after this
	// response. HTTP/1.1 defaults to keep-alive; "Connection: close"
	// opts out.
	let client_wants_close = req
		.header("connection")
		.map(|h| h.eq_ignore_ascii_case("close"))
		.unwrap_or(false);
	let keep_alive = !client_wants_close;
	let conn_header = if keep_alive { "keep-alive" } else { "close" };

	// Authentication check (HTTP Basic).
	if !check_auth(req, &ctx.auth) {
		let body = b"<html><body>401 Unauthorized</body></html>";
		write_response(
			stream,
			401,
			"Unauthorized",
			&[
				("WWW-Authenticate", "Basic realm=\"rcrm\""),
				("Content-Type", "text/html; charset=utf-8"),
				("Connection", conn_header),
			],
			body,
		)?;
		eprintln!("[webdav:{}] 401 Unauthorized", addr);
		return Ok(keep_alive);
	}

	let method = req.method.to_uppercase();
	let result = match method.as_str() {
		"OPTIONS" => handle_options(req, ctx, stream, conn_header),
		"GET" => handle_get(req, ctx, stream, false, conn_header),
		"HEAD" => handle_get(req, ctx, stream, true, conn_header),
		"PROPFIND" => handle_propfind(req, ctx, stream, conn_header),
		// Read-only enforcement: reject all mutating methods.
		"PUT" | "DELETE" | "MKCOL" | "MOVE" | "COPY" | "PROPPATCH" | "LOCK" | "UNLOCK" => {
			let body = b"<?xml version=\"1.0\" encoding=\"utf-8\"?><D:error xmlns:D=\"DAV:\"><D:response>Read-only WebDAV: write methods disabled</D:response></D:error>";
			write_response(
				stream,
				403,
				"Forbidden",
				&[
					("Content-Type", "application/xml; charset=utf-8"),
					("Connection", conn_header),
				],
				body,
			)?;
			eprintln!("[webdav:{}] 403 {} (read-only)", addr, method);
			Ok(())
		}
		// Unknown methods.
		_ => {
			let body = b"<html><body>501 Not Implemented</body></html>";
			write_response(
				stream,
				501,
				"Not Implemented",
				&[
					("Content-Type", "text/html; charset=utf-8"),
					("Connection", conn_header),
				],
				body,
			)?;
			eprintln!("[webdav:{}] 501 {}", addr, method);
			Ok(())
		}
	};
	result.map(|()| keep_alive)
}

// =======================
// Auth (HTTP Basic)
// =======================

fn check_auth(req: &Request, auth: &AuthConfig) -> bool {
	// No auth configured (anonymous) — allow.
	if auth.user.is_none() {
		return true;
	}
	// Extract "Authorization: Basic <base64>" header.
	let header = match req.header("authorization") {
		Some(h) => h,
		None => return false,
	};
	let encoded = match h_strip(header) {
		Some(e) => e,
		None => return false,
	};
	let decoded = match base64_decode(encoded) {
		Some(d) => d,
		None => return false,
	};
	// "user:pass"
	let s = String::from_utf8_lossy(&decoded);
	let (user, pass) = match s.split_once(':') {
		Some((u, p)) => (u, p),
		None => return false,
	};
	auth.verify(user, pass)
}

/// Extract the base64 payload from "Basic <b64>".
fn h_strip(h: &str) -> Option<&str> {
	let s = h.trim();
	let rest = s
		.strip_prefix("Basic ")
		.or_else(|| s.strip_prefix("basic "))?;
	Some(rest.trim())
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
	base64::engine::general_purpose::STANDARD.decode(s).ok()
}

// =======================
// OPTIONS
// =======================

fn handle_options(
	_req: &Request,
	_ctx: &ServerContext,
	stream: &mut dyn ReadWrite,
	conn_header: &str,
) -> io::Result<()> {
	write_response(
		stream,
		200,
		"OK",
		&[
			("DAV", "1"),
			("Allow", "OPTIONS, GET, HEAD, PROPFIND"),
			("MS-Author-Via", "DAV"),
			("Connection", conn_header),
			("Content-Length", "0"),
		],
		&[],
	)?;
	Ok(())
}

// =======================
// GET / HEAD
// =======================

fn handle_get(
	req: &Request,
	ctx: &ServerContext,
	stream: &mut dyn ReadWrite,
	head_only: bool,
	conn_header: &str,
) -> io::Result<()> {
	let disk = resolve_webdav_path(&ctx.root, &req.path);

	let resolved = resolve_resource(&disk, &req.path, ctx);
	let (content_length, etag_source) = match &resolved {
		Resolved::Plain(p) => {
			let meta = std::fs::metadata(p)?;
			(meta.len(), p.clone())
		}
		Resolved::Projected(pf) => (pf.virtual_size(), pf.disk_path().to_path_buf()),
		Resolved::NotFound => {
			let body = b"<html><body>404 Not Found</body></html>";
			write_response(
				stream,
				404,
				"Not Found",
				&[
					("Content-Type", "text/html; charset=utf-8"),
					("Connection", conn_header),
				],
				body,
			)?;
			return Ok(());
		}
		Resolved::Directory => {
			// Browser-friendly directory listing. WebDAV clients use
			// PROPFIND; browsers and wget use GET. Return a simple HTML
			// page with file links so browsing from a browser works.
			let html = build_html_directory_listing(&disk, &req.path, ctx);
			let bytes = html.into_bytes();
			write_response(
				stream,
				200,
				"OK",
				&[
					("Content-Type", "text/html; charset=utf-8"),
					("Content-Length", &bytes.len().to_string()),
					("Connection", conn_header),
				],
				&bytes,
			)?;
			return Ok(());
		}
	};

	// Parse Range header (single range: "bytes=START-END").
	let range = parse_range_header(req, content_length);

	// mtime for Last-Modified + ETag.
	let mtime = std::fs::metadata(&etag_source)
		.and_then(|m| m.modified())
		.ok();
	let last_modified = mtime
		.map(http_date)
		.unwrap_or_else(|| "Thu, 01 Jan 1970 00:00:00 GMT".to_string());
	let etag = format!("\"{}-{}\"", mtime_to_epoch(mtime), content_length);

	match range {
		RangeSpec::None => {
			// Full content.
			let headers = [
				("Content-Type", content_type_for(&disk)),
				("Content-Length", content_length.to_string()),
				("Last-Modified", last_modified),
				("ETag", etag),
				("Accept-Ranges", "bytes".to_string()),
				("Connection", conn_header.to_string()),
			];
			let headers_ref: Vec<(&str, &str)> =
				headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
			write_response_head(stream, 200, "OK", &headers_ref)?;
			if !head_only {
				stream_body(&resolved, 0, content_length, ctx, stream)?;
			}
			Ok(())
		}
		RangeSpec::Full => {
			// Satisfiable range covering the whole file.
			let headers = [
				("Content-Type", content_type_for(&disk)),
				("Content-Length", content_length.to_string()),
				("Last-Modified", last_modified),
				("ETag", etag),
				("Accept-Ranges", "bytes".to_string()),
				("Connection", conn_header.to_string()),
			];
			let headers_ref: Vec<(&str, &str)> =
				headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
			write_response_head(stream, 200, "OK", &headers_ref)?;
			if !head_only {
				stream_body(&resolved, 0, content_length, ctx, stream)?;
			}
			Ok(())
		}
		RangeSpec::Partial(start, end) => {
			// Partial content (206). end is inclusive.
			let length = end - start + 1;
			let content_range = format!("bytes {}-{}/{}", start, end, content_length);
			let headers = [
				("Content-Type", content_type_for(&disk)),
				("Content-Length", length.to_string()),
				("Content-Range", content_range),
				("Last-Modified", last_modified),
				("ETag", etag),
				("Accept-Ranges", "bytes".to_string()),
				("Connection", conn_header.to_string()),
			];
			let headers_ref: Vec<(&str, &str)> =
				headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
			write_response_head(stream, 206, "Partial Content", &headers_ref)?;
			if !head_only {
				stream_body(&resolved, start, length, ctx, stream)?;
			}
			Ok(())
		}
		RangeSpec::Unsatisfiable => {
			let headers = [
				("Content-Range", format!("bytes */{}", content_length)),
				("Content-Length", "0".to_string()),
				("Connection", conn_header.to_string()),
			];
			let headers_ref: Vec<(&str, &str)> =
				headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
			write_response_head(stream, 416, "Range Not Satisfiable", &headers_ref)?;
			Ok(())
		}
	}
}

// =======================
// PROPFIND
// =======================

fn handle_propfind(
	req: &Request,
	ctx: &ServerContext,
	stream: &mut dyn ReadWrite,
	conn_header: &str,
) -> io::Result<()> {
	let disk = resolve_webdav_path(&ctx.root, &req.path);

	let depth = req
		.header("depth")
		.map(|s| s.trim().to_lowercase())
		.unwrap_or_else(|| "infinity".to_string());

	// Resolve the target.
	let target_is_dir = disk.is_dir();
	let target_exists = disk.exists();

	// If the disk path doesn't exist, it might be a virtual name (decrypted
	// name of an encrypted file). Try resolving via projection.
	if !target_exists {
		if let Some(pf) = try_resolve_virtual(&disk, ctx) {
			// Single-file PROPFIND.
			let entry = DirEntry {
				virtual_name: pf.virtual_name().to_string(),
				is_dir: false,
				size: pf.virtual_size(),
				mtime: std::fs::metadata(pf.disk_path())
					.and_then(|m| m.modified())
					.ok(),
				href: req.path.clone(),
			};
			let xml = build_propfind_xml(&[entry]);
			let bytes = xml.into_bytes();
			let headers = [
				("Content-Type", "application/xml; charset=utf-8".to_string()),
				("Content-Length", bytes.len().to_string()),
				("Connection", conn_header.to_string()),
			];
			let headers_ref: Vec<(&str, &str)> =
				headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
			write_response_head(stream, 207, "Multi-Status", &headers_ref)?;
			stream.write_all(&bytes)?;
			stream.flush()?;
			return Ok(());
		}
		let body = b"<html><body>404 Not Found</body></html>";
		write_response(
			stream,
			404,
			"Not Found",
			&[
				("Content-Type", "text/html; charset=utf-8"),
				("Connection", conn_header),
			],
			body,
		)?;
		return Ok(());
	}

	if !target_is_dir {
		// Single file. Could be plain or encrypted.
		let entry = match resolve_resource(&disk, &req.path, ctx) {
			Resolved::Plain(p) => DirEntry {
				virtual_name: disk
					.file_name()
					.and_then(|s| s.to_str())
					.unwrap_or("")
					.to_string(),
				is_dir: false,
				size: std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0),
				mtime: std::fs::metadata(&p).and_then(|m| m.modified()).ok(),
				href: req.path.clone(),
			},
			Resolved::Projected(pf) => DirEntry {
				virtual_name: pf.virtual_name().to_string(),
				is_dir: false,
				size: pf.virtual_size(),
				mtime: std::fs::metadata(pf.disk_path())
					.and_then(|m| m.modified())
					.ok(),
				href: req.path.clone(),
			},
			_ => {
				let body = b"<html><body>404 Not Found</body></html>";
				write_response(
					stream,
					404,
					"Not Found",
					&[
						("Content-Type", "text/html; charset=utf-8"),
						("Connection", conn_header),
					],
					body,
				)?;
				return Ok(());
			}
		};
		let xml = build_propfind_xml(&[entry]);
		let bytes = xml.into_bytes();
		let headers = [
			("Content-Type", "application/xml; charset=utf-8".to_string()),
			("Content-Length", bytes.len().to_string()),
			("Connection", conn_header.to_string()),
		];
		let headers_ref: Vec<(&str, &str)> =
			headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
		write_response_head(stream, 207, "Multi-Status", &headers_ref)?;
		stream.write_all(&bytes)?;
		stream.flush()?;
		return Ok(());
	}

	// Directory listing.
	let entries = match list_dir(&disk, &req.path, ctx) {
		Ok(e) => e,
		Err(e) => {
			eprintln!("[webdav] list_dir error: {}", e);
			let body = b"<html><body>500 Internal Server Error</body></html>";
			write_response(
				stream,
				500,
				"Internal Server Error",
				&[
					("Content-Type", "text/html; charset=utf-8"),
					("Connection", conn_header),
				],
				body,
			)?;
			return Ok(());
		}
	};

	// Depth: 0 → only the directory itself. Depth: 1 (or infinity) →
	// directory + immediate children. We cap infinity at depth 1 to avoid
	// runaway recursion on huge trees.
	let listing: Vec<DirEntry> = if depth == "0" {
		vec![DirEntry {
			virtual_name: disk
				.file_name()
				.and_then(|s| s.to_str())
				.unwrap_or("")
				.to_string(),
			is_dir: true,
			size: 0,
			mtime: std::fs::metadata(&disk).and_then(|m| m.modified()).ok(),
			href: req.path.clone(),
		}]
	} else {
		entries
	};

	let xml = build_propfind_xml(&listing);
	let bytes = xml.into_bytes();
	let headers = [
		("Content-Type", "application/xml; charset=utf-8".to_string()),
		("Content-Length", bytes.len().to_string()),
		("Connection", "keep-alive".to_string()),
	];
	let headers_ref: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
	write_response_head(stream, 207, "Multi-Status", &headers_ref)?;
	stream.write_all(&bytes)?;
	stream.flush()?;
	Ok(())
}

// =======================
// Resource resolution (shared with GET)
// =======================

enum Resolved {
	Plain(PathBuf),
	Projected(Arc<crate::ProjectedFile>),
	Directory,
	NotFound,
}

fn resolve_resource(disk: &Path, _req_path: &str, ctx: &ServerContext) -> Resolved {
	if disk.is_dir() {
		return Resolved::Directory;
	}
	if disk.is_file() {
		let name = disk.file_name().and_then(|s| s.to_str()).unwrap_or("");
		if is_valid_encrypted_file_name(name) {
			if let Ok(pf) = ctx.cache.get_or_open(disk, &ctx.manager, &ctx.session_key) {
				return Resolved::Projected(pf);
			}
			return Resolved::NotFound;
		}
		return Resolved::Plain(disk.to_path_buf());
	}
	// Not on disk — try virtual name resolution.
	if let Some(pf) = try_resolve_virtual(disk, ctx) {
		return Resolved::Projected(pf);
	}
	Resolved::NotFound
}

/// Look for an encrypted (`.<b72>`) file whose decrypted virtual name
/// matches the last segment of `disk`.
fn try_resolve_virtual(disk: &Path, ctx: &ServerContext) -> Option<Arc<crate::ProjectedFile>> {
	let parent = disk.parent()?;
	let req_name = disk.file_name()?.to_str()?;
	// Fast path: name index.
	if let Some(b72_path) = ctx.cache.resolve_virtual_name(parent, req_name)
		&& let Some(pf) = ctx.cache.get(&b72_path)
	{
		return Some(pf);
	}
	// Slow path: scan parent directory.
	let rd = std::fs::read_dir(parent).ok()?;
	for entry in rd.flatten() {
		let path = entry.path();
		let name = entry.file_name().to_string_lossy().into_owned();
		if !is_valid_encrypted_file_name(&name) {
			continue;
		}
		if let Ok(pf) = ctx.cache.get_or_open(&path, &ctx.manager, &ctx.session_key)
			&& pf.virtual_name() == req_name
		{
			return Some(pf);
		}
	}
	None
}

// =======================
// Directory listing
// =======================

struct DirEntry {
	virtual_name: String,
	is_dir: bool,
	size: u64,
	mtime: Option<SystemTime>,
	href: String,
}

fn list_dir(dir: &Path, base_href: &str, ctx: &ServerContext) -> io::Result<Vec<DirEntry>> {
	let mut entries = Vec::new();

	// First entry: the directory itself.
	entries.push(DirEntry {
		virtual_name: dir
			.file_name()
			.and_then(|s| s.to_str())
			.unwrap_or("/")
			.to_string(),
		is_dir: true,
		size: 0,
		mtime: std::fs::metadata(dir).and_then(|m| m.modified()).ok(),
		href: base_href.to_string(),
	});

	let rd = std::fs::read_dir(dir)?;
	for entry in rd.flatten() {
		let path = entry.path();
		let meta = match entry.metadata() {
			Ok(m) => m,
			Err(_) => continue,
		};
		let name = entry.file_name().to_string_lossy().into_owned();

		if meta.is_dir() {
			let href = format!(
				"{}/{}",
				base_href.trim_end_matches('/'),
				percent_encode(&name)
			);
			entries.push(DirEntry {
				virtual_name: name,
				is_dir: true,
				size: 0,
				mtime: meta.modified().ok(),
				href,
			});
		} else if is_valid_encrypted_file_name(&name) {
			// Projected file.
			match ctx.cache.get_or_open(&path, &ctx.manager, &ctx.session_key) {
				Ok(pf) => {
					let vname = pf.virtual_name().to_string();
					let href = format!(
						"{}/{}",
						base_href.trim_end_matches('/'),
						percent_encode(&vname)
					);
					entries.push(DirEntry {
						virtual_name: vname,
						is_dir: false,
						size: pf.virtual_size(),
						mtime: meta.modified().ok(),
						href,
					});
				}
				Err(_) => continue, // wrong key / corrupt — hide
			}
		} else {
			let href = format!(
				"{}/{}",
				base_href.trim_end_matches('/'),
				percent_encode(&name)
			);
			entries.push(DirEntry {
				virtual_name: name,
				is_dir: false,
				size: meta.len(),
				mtime: meta.modified().ok(),
				href,
			});
		}
	}

	Ok(entries)
}

// =======================
// PROPFIND XML builder
// =======================

fn build_propfind_xml(entries: &[DirEntry]) -> String {
	let mut out = String::with_capacity(2048);
	out.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
	out.push_str("<D:multistatus xmlns:D=\"DAV:\">");
	for e in entries {
		out.push_str("<D:response>");
		out.push_str(&format!("<D:href>{}</D:href>", xml_escape(&e.href)));
		out.push_str("<D:propstat><D:prop>");
		out.push_str(&format!(
			"<D:displayname>{}</D:displayname>",
			xml_escape(&e.virtual_name)
		));
		if e.is_dir {
			out.push_str("<D:resourcetype><D:collection/></D:resourcetype>");
			out.push_str("<D:getcontentlength>0</D:getcontentlength>");
		} else {
			out.push_str("<D:resourcetype/>");
			out.push_str(&format!(
				"<D:getcontentlength>{}</D:getcontentlength>",
				e.size
			));
		}
		let lm = e
			.mtime
			.map(http_date)
			.unwrap_or_else(|| "Thu, 01 Jan 1970 00:00:00 GMT".to_string());
		out.push_str(&format!("<D:getlastmodified>{}</D:getlastmodified>", lm));
		if !e.is_dir {
			out.push_str(&format!(
				"<D:getcontenttype>{}</D:getcontenttype>",
				content_type_name(&e.virtual_name)
			));
		}
		out.push_str("</D:prop>");
		out.push_str("<D:status>HTTP/1.1 200 OK</D:status>");
		out.push_str("</D:propstat>");
		out.push_str("</D:response>");
	}
	out.push_str("</D:multistatus>");
	out
}

/// Simple HTML directory listing for browser access. Not part of the DAV
/// spec, but browsers send GET on directories, not PROPFIND.
fn build_html_directory_listing(dir: &Path, url_path: &str, ctx: &ServerContext) -> String {
	let entries = list_dir(dir, url_path, ctx).unwrap_or_default();
	let mut out = String::with_capacity(4096);
	out.push_str("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>");
	out.push_str(&xml_escape(&format!("Index of {}", url_path)));
	out.push_str("</title><style>body{font-family:monospace;padding:1em}h1{font-size:1.2em}");
	out.push_str("a{text-decoration:none}a:hover{text-decoration:underline}");
	out.push_str("table{border-collapse:collapse;width:100%}");
	out.push_str("td,th{padding:2px 8px;text-align:left}");
	out.push_str("tr:nth-child(even){background:#f5f5f5}");
	out.push_str("</style></head><body><h1>");
	out.push_str(&xml_escape(&format!("Index of {}", url_path)));
	out.push_str("</h1><table><tr><th>Name</th><th>Size</th><th>Modified</th></tr>");

	for e in &entries {
		if e.href == url_path {
			continue; // skip self-entry
		}
		let size_str = if e.is_dir {
			"-".to_string()
		} else {
			format_size(e.size)
		};
		let date = e.mtime.map(http_date).unwrap_or_else(|| "-".to_string());

		out.push_str(&format!(
			"<tr><td><a href=\"{}\">{}{}</a></td><td>{}</td><td>{}</td></tr>",
			xml_escape(&e.href),
			xml_escape(&e.virtual_name),
			if e.is_dir { "/" } else { "" },
			size_str,
			date,
		));
	}
	out.push_str("</table><p><small>rcrm WebDAV server</small></p></body></html>");
	out
}

fn format_size(bytes: u64) -> String {
	const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
	let mut size = bytes as f64;
	let mut unit = 0;
	while size >= 1024.0 && unit < UNITS.len() - 1 {
		size /= 1024.0;
		unit += 1;
	}
	if unit == 0 {
		format!("{} B", bytes)
	} else {
		format!("{:.1} {}", size, UNITS[unit])
	}
}

// =======================
// Stream file body (projected or plain)
// =======================

fn stream_body(
	resolved: &Resolved,
	offset: u64,
	length: u64,
	ctx: &ServerContext,
	stream: &mut dyn ReadWrite,
) -> io::Result<()> {
	let mut buf = vec![0u8; 64 * 1024];
	let mut sent = 0u64;
	match resolved {
		Resolved::Plain(path) => {
			let mut f = std::fs::File::open(path)?;
			std::io::Seek::seek(&mut f, io::SeekFrom::Start(offset))?;
			while sent < length {
				let want = std::cmp::min(buf.len() as u64, length - sent) as usize;
				let n = f.read(&mut buf[..want])?;
				if n == 0 {
					break;
				}
				stream.write_all(&buf[..n])?;
				sent += n as u64;
			}
		}
		Resolved::Projected(pf) => {
			while sent < length {
				let want = std::cmp::min(buf.len() as u64, length - sent) as usize;
				let n = pf.read_at(offset + sent, &mut buf[..want], &ctx.session_key)?;
				if n == 0 {
					break;
				}
				stream.write_all(&buf[..n])?;
				// Zeroize the buffer slice we just used (it held plaintext).
				buf[..n].fill(0);
				sent += n as u64;
			}
		}
		_ => {}
	}
	stream.flush()?;
	Ok(())
}

// =======================
// Range parsing
// =======================

enum RangeSpec {
	None,              // No Range header.
	Full,              // Range covers the whole file (rare — clients usually don't).
	Partial(u64, u64), // start..=end (inclusive).
	Unsatisfiable,
}

fn parse_range_header(req: &Request, content_length: u64) -> RangeSpec {
	let h = match req.header("range") {
		Some(h) => h,
		None => return RangeSpec::None,
	};
	// "bytes=START-END" (END optional). Only single-range supported.
	let rest = match h.trim().strip_prefix("bytes=") {
		Some(r) => r,
		None => return RangeSpec::None,
	};
	let (start_s, end_s) = match rest.split_once('-') {
		Some(p) => p,
		None => return RangeSpec::None,
	};
	let start_s = start_s.trim();
	let end_s = end_s.trim();
	let start: u64;
	let mut end: u64;
	if start_s.is_empty() {
		// Suffix range: "bytes=-N" → last N bytes.
		let n: u64 = match end_s.parse() {
			Ok(n) => n,
			Err(_) => return RangeSpec::None,
		};
		if n == 0 || content_length == 0 {
			return RangeSpec::Unsatisfiable;
		}
		start = content_length.saturating_sub(n);
		end = content_length - 1;
	} else {
		start = match start_s.parse() {
			Ok(n) => n,
			Err(_) => return RangeSpec::None,
		};
		if end_s.is_empty() {
			end = content_length.saturating_sub(1);
		} else {
			end = match end_s.parse() {
				Ok(n) => n,
				Err(_) => return RangeSpec::None,
			};
		}
	}
	if start >= content_length {
		return RangeSpec::Unsatisfiable;
	}
	if end >= content_length {
		end = content_length - 1;
	}
	if start > end {
		return RangeSpec::Unsatisfiable;
	}
	if start == 0 && end == content_length - 1 {
		return RangeSpec::Full;
	}
	RangeSpec::Partial(start, end)
}

// =======================
// HTTP response writers
// =======================

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

fn write_response(
	stream: &mut dyn ReadWrite,
	status: u16,
	reason: &str,
	headers: &[(&str, &str)],
	body: &[u8],
) -> io::Result<()> {
	// Auto-add Content-Length if not already present and body is non-empty.
	// Without it, HTTP/1.1 keep-alive clients hang waiting for more data
	// or a connection close on 404/403/401 responses.
	let has_cl = headers
		.iter()
		.any(|(k, _)| k.eq_ignore_ascii_case("content-length"));
	let cl_str;
	let all_headers: Vec<(&str, &str)> = if !has_cl && !body.is_empty() {
		cl_str = body.len().to_string();
		let mut h = Vec::with_capacity(headers.len() + 1);
		h.extend_from_slice(headers);
		h.push(("Content-Length", &cl_str));
		h
	} else {
		headers.to_vec()
	};

	write_response_head(stream, status, reason, &all_headers)?;
	if !body.is_empty() {
		stream.write_all(body)?;
	}
	stream.flush()
}

fn write_response_head(
	stream: &mut dyn ReadWrite,
	status: u16,
	reason: &str,
	headers: &[(&str, &str)],
) -> io::Result<()> {
	let mut out = String::with_capacity(256);
	out.push_str(&format!("HTTP/1.1 {} {}\r\n", status, reason));
	for (k, v) in headers {
		out.push_str(&format!("{}: {}\r\n", k, v));
	}
	out.push_str("\r\n");
	stream.write_all(out.as_bytes())?;
	Ok(())
}

// =======================
// Path + URL helpers
// =======================

/// Resolve a WebDAV URL path to a disk path, normalizing `.` and `..`
/// without escaping root. Reuses the FTP path resolver.
fn resolve_webdav_path(root: &Path, url_path: &str) -> PathBuf {
	super::resolve_disk_path(root, "/", url_path)
}

/// Percent-decode a URL path component.
fn percent_decode(s: &str) -> String {
	let bytes = s.as_bytes();
	let mut out = Vec::with_capacity(bytes.len());
	let mut i = 0;
	while i < bytes.len() {
		if bytes[i] == b'%'
			&& i + 2 < bytes.len()
			&& let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2]))
		{
			out.push(h * 16 + l);
			i += 3;
			continue;
		}
		out.push(bytes[i]);
		i += 1;
	}
	String::from_utf8_lossy(&out).into_owned()
}

/// Percent-encode a path segment (spaces, non-ASCII, and reserved chars).
fn percent_encode(s: &str) -> String {
	let mut out = String::with_capacity(s.len());
	for b in s.bytes() {
		// Unreserved: A-Z a-z 0-9 - _ . ~
		if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
			out.push(b as char);
		} else {
			out.push_str(&format!("%{:02X}", b));
		}
	}
	out
}

fn hex(c: u8) -> Option<u8> {
	match c {
		b'0'..=b'9' => Some(c - b'0'),
		b'a'..=b'f' => Some(c - b'a' + 10),
		b'A'..=b'F' => Some(c - b'A' + 10),
		_ => None,
	}
}

fn xml_escape(s: &str) -> String {
	s.replace('&', "&amp;")
		.replace('<', "&lt;")
		.replace('>', "&gt;")
		.replace('"', "&quot;")
		.replace('\'', "&apos;")
}

// =======================
// Content type + date helpers
// =======================

fn content_type_for(path: &Path) -> String {
	let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
	content_type_name(ext)
}

/// Guess a MIME type from an extension. WebDAV clients use this for
/// streaming decisions (e.g. VLC picks a demuxer based on content-type).
fn content_type_name(ext: &str) -> String {
	let ext = ext.trim_start_matches('.').to_lowercase();
	let mime = match ext.as_str() {
		// Video
		"mp4" | "m4v" => "video/mp4",
		"avi" => "video/x-msvideo",
		"mov" => "video/quicktime",
		"wmv" => "video/x-ms-wmv",
		"mkv" => "video/x-matroska",
		"webm" => "video/webm",
		"flv" => "video/x-flv",
		"rm" | "rmvb" => "application/vnd.rn-realmedia",
		"ts" => "video/mp2t",
		// Audio
		"mp3" => "audio/mpeg",
		"wav" => "audio/wav",
		"flac" => "audio/flac",
		"aac" => "audio/aac",
		"ogg" => "audio/ogg",
		// Image
		"jpg" | "jpeg" => "image/jpeg",
		"png" => "image/png",
		"webp" => "image/webp",
		"gif" => "image/gif",
		// Text / other
		"txt" => "text/plain; charset=utf-8",
		"html" | "htm" => "text/html; charset=utf-8",
		"json" => "application/json",
		"xml" => "application/xml",
		"zip" => "application/zip",
		"pdf" => "application/pdf",
		_ => "application/octet-stream",
	};
	mime.to_string()
}

/// Format a SystemTime as an RFC 7231 HTTP date (e.g.
/// "Sun, 06 Nov 1994 08:49:37 GMT").
fn http_date(t: SystemTime) -> String {
	let secs = t
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	epoch_to_http_date(secs)
}

fn mtime_to_epoch(t: Option<SystemTime>) -> u64 {
	t.and_then(|x| x.duration_since(UNIX_EPOCH).ok())
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

/// Convert epoch seconds to an RFC 7231 date string in GMT.
fn epoch_to_http_date(secs: u64) -> String {
	let (year, month, day, hour, minute, second) = epoch_to_ymdhms(secs);
	const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
	const MONTHS: [&str; 12] = [
		"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
	];
	let day_of_week = DAYS[(secs / 86400) as usize % 7];
	format!(
		"{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
		day_of_week,
		day,
		MONTHS[(month - 1) as usize],
		year,
		hour,
		minute,
		second
	)
}

/// Civil-from-days (Howard Hinnant's algorithm).
fn epoch_to_ymdhms(secs: u64) -> (i32, u32, u32, u32, u32, u32) {
	let days = (secs / 86400) as i64;
	let rem = secs % 86400;
	let hour = (rem / 3600) as u32;
	let minute = ((rem % 3600) / 60) as u32;
	let second = (rem % 60) as u32;

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

// Silence unused-import warning for FileCache (used implicitly via ctx.cache).
#[allow(dead_code)]
fn _filecache_used(_c: &FileCache) {}
