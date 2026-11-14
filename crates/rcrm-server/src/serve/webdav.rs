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

use super::{AuthConfig, ServerContext, is_virtual_root, resolve_disk_path, virtual_root_entries};
use crate::serve::FileCache;
use rcrm_core::is_valid_encrypted_file_name;

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
	let stream: Box<dyn ReadWrite> = if ctx.protocol == super::Protocol::WebDavHttps {
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
				rcrm_core::log_info!(
					"[webdav:{}] HTTPS handshake failed: {}. \
					 Client may be using plain HTTP instead of HTTPS.",
					addr,
					e
				);
				return Ok(());
			}
		}
		Box::new(tls_stream)
	} else {
		Box::new(stream)
	};

	let mut conn = HttpConn::new(stream);

	// Handle requests in a keep-alive loop until the client closes or the
	// connection times out.
	while !shutdown.load(Ordering::Relaxed) {
		let req = match conn.read_request() {
			Ok(r) => r,
			Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
			Err(e) if e.kind() == io::ErrorKind::TimedOut => break,
			Err(e) if e.kind() == io::ErrorKind::InvalidInput => {
				let _ = Responder::for_error(conn.inner.as_mut(), &conn.last_method).respond(
					413,
					"Payload Too Large",
					&[("Content-Type", "text/plain")],
					b"request body too large",
				);
				break;
			}
			// RFC 9112 §6.3: unrecoverable framing errors get 400 and the
			// connection is closed. Responder::for_error already supplies both
			// the close policy and HEAD-safe framing.
			Err(e) if e.kind() == io::ErrorKind::InvalidData => {
				rcrm_core::log_error!("[webdav:{}] bad request framing: {}", addr, e);
				let _ = Responder::for_error(conn.inner.as_mut(), &conn.last_method).respond(
					400,
					"Bad Request",
					&[("Content-Type", "text/plain")],
					b"invalid request framing",
				);
				break;
			}
			Err(e) => {
				rcrm_core::log_error!("[webdav:{}] read error: {}", addr, e);
				break;
			}
		};
		rcrm_core::log_info!("[webdav:{}] {} {}", addr, req.method, log_safe(&req.path));

		// Scope the responder so the error path can borrow the connection
		// again. The policy (HEAD or not, keep-alive or not) belongs to this
		// one request and is derived once, by the Responder itself.
		let (result, keep_alive) = {
			let mut responder = Responder::new(conn.inner.as_mut(), &req);
			let result = dispatch(&req, &ctx, &mut responder, &addr);
			(result, responder.keep_alive())
		};
		if let Err(e) = result {
			rcrm_core::log_error!("[webdav:{}] dispatch error: {}", addr, e);
			let msg = e.to_string();
			let _ = Responder::for_error(conn.inner.as_mut(), &req.method).respond(
				500,
				"Internal Server Error",
				&[("Content-Type", "text/plain")],
				msg.as_bytes(),
			);
			break;
		}
		if !keep_alive {
			break;
		}
	}

	Ok(())
}

// =======================
// HttpConn: connection + read buffer
// =======================

/// Largest request body accepted. The body is parsed but never used, so a
/// client must not be able to make the server buffer an arbitrary amount.
const MAX_REQUEST_BODY: usize = 1024 * 1024;

/// The path for the log. A decoded URL may carry control characters, which
/// would let a client forge log lines.
fn log_safe(s: &str) -> String {
	s.chars().filter(|c| !c.is_control()).collect()
}

/// A connection plus a read buffer.
///
/// The head ends at `\r\n\r\n`, but the body may already be in the socket,
/// so the surplus is kept for the next read. The old implementation read
/// the head one byte at a time — one `recv` per header byte (~1.26 ms for a
/// 4 KiB header).
struct HttpConn {
	inner: Box<dyn ReadWrite>,
	/// Bytes read from the socket but not yet consumed.
	buf: Vec<u8>,
	/// Method of the request whose head was parsed last. Kept so a connection
	/// level error (413 while reading the body, 500 while dispatching) can
	/// still answer a HEAD request without content — at that point no
	/// `Request` value exists to ask.
	last_method: String,
}

impl HttpConn {
	fn new(inner: Box<dyn ReadWrite>) -> Self {
		HttpConn {
			inner,
			buf: Vec::with_capacity(16 * 1024),
			last_method: String::new(),
		}
	}

	/// Pull one chunk from the socket into the buffer. Returns the byte
	/// count (0 = EOF).
	fn fill(&mut self) -> io::Result<usize> {
		let mut chunk = [0u8; 8 * 1024];
		let n = self.inner.read(&mut chunk)?;
		self.buf.extend_from_slice(&chunk[..n]);
		Ok(n)
	}

	/// Read the request head (up to and including `\r\n\r\n`). The bytes
	/// after the terminator stay in the buffer for the body / next request.
	fn read_head(&mut self) -> io::Result<Vec<u8>> {
		loop {
			if let Some(pos) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
				return Ok(self.buf.drain(..=pos + 3).collect());
			}
			if self.buf.len() > 64 * 1024 {
				return Err(io::Error::new(
					io::ErrorKind::InvalidData,
					"header too large",
				));
			}
			let n = self.fill()?;
			if n == 0 {
				if self.buf.is_empty() {
					return Err(io::Error::new(
						io::ErrorKind::UnexpectedEof,
						"connection closed before headers",
					));
				}
				// The peer is gone; writing a 400 here is pointless. Keeping it
				// distinct from InvalidData (a real framing error) also avoids
				// trying to answer on a closed socket.
				return Err(io::Error::new(
					io::ErrorKind::UnexpectedEof,
					"connection closed mid-headers",
				));
			}
		}
	}

	/// Read exactly `n` bytes, consuming them from the buffer first.
	fn read_body(&mut self, n: usize) -> io::Result<Vec<u8>> {
		while self.buf.len() < n {
			let got = self.fill()?;
			if got == 0 {
				return Err(io::Error::new(
					io::ErrorKind::UnexpectedEof,
					"connection closed during body",
				));
			}
		}
		Ok(self.buf.drain(..n).collect())
	}

	/// Read one CRLF-terminated line, consuming the terminator. Used only for
	/// chunked request framing.
	fn read_line(&mut self) -> io::Result<String> {
		loop {
			if let Some(pos) = self.buf.windows(2).position(|w| w == b"\r\n") {
				let bytes: Vec<u8> = self.buf.drain(..pos).collect();
				self.buf.drain(..2);
				return String::from_utf8(bytes).map_err(|_| {
					io::Error::new(io::ErrorKind::InvalidData, "non-ASCII chunk header")
				});
			}
			if self.buf.len() > 64 * 1024 {
				return Err(io::Error::new(
					io::ErrorKind::InvalidData,
					"chunk header too large",
				));
			}
			let n = self.fill()?;
			if n == 0 {
				return Err(io::Error::new(
					io::ErrorKind::UnexpectedEof,
					"connection closed during chunked body",
				));
			}
		}
	}

	/// Decode a chunked request body (RFC 9112 §7.1). This service is read-only
	/// and never uses the body, but the bytes MUST still be consumed: anything
	/// left in the socket becomes the start of the next request on a keep-alive
	/// connection. The same 1 MiB cap applies.
	fn read_chunked_body(&mut self) -> io::Result<Vec<u8>> {
		let mut out = Vec::new();
		loop {
			let line = self.read_line()?;
			// "size[;chunk-ext]" — extensions are ignored.
			let size_str = line.split(';').next().unwrap_or("").trim();
			let size = usize::from_str_radix(size_str, 16)
				.map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size"))?;
			if size == 0 {
				// The trailer section ends at an empty line.
				loop {
					if self.read_line()?.is_empty() {
						break;
					}
				}
				break;
			}
			if out.len().saturating_add(size) > MAX_REQUEST_BODY {
				return Err(io::Error::new(
					io::ErrorKind::InvalidInput,
					"request body too large",
				));
			}
			let mut chunk = self.read_body(size)?;
			out.append(&mut chunk);
			let eol = self.read_body(2)?;
			if eol.len() != 2 || eol[0] != b'\r' || eol[1] != b'\n' {
				return Err(io::Error::new(
					io::ErrorKind::InvalidData,
					"missing CRLF after chunk data",
				));
			}
		}
		Ok(out)
	}

	/// Parse one request off the wire.
	fn read_request(&mut self) -> io::Result<Request> {
		// Read the request line + headers (up to \r\n\r\n).
		let head = self.read_head()?;
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
		// Record it before any later step can fail: the 413 path below returns
		// an error instead of a `Request`, but the response still has to honour
		// HEAD semantics (RFC 9110 §9.3.2).
		self.last_method = method.clone();
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

		// Request body framing is decided by RFC 9112 §6.3, in this order.
		// A malformed framing MUST be an unrecoverable error (400 + close),
		// never a silently ignored header: unread bytes would be parsed as the
		// next request on a keep-alive connection (request smuggling).
		let cl = headers
			.iter()
			.find(|(k, _)| k.eq_ignore_ascii_case("content-length"));
		let te = headers
			.iter()
			.find(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"));
		let body = match (cl, te) {
			(Some(_), Some(_)) => {
				return Err(io::Error::new(
					io::ErrorKind::InvalidData,
					"both Content-Length and Transfer-Encoding present",
				));
			}
			(Some((_, v)), None) => {
				// §6.3(5): an invalid Content-Length is unrecoverable. Accepting
				// a comma list of identical values is optional; rejecting it is
				// the stricter, unambiguous choice.
				let n = v.parse::<usize>().map_err(|_| {
					io::Error::new(io::ErrorKind::InvalidData, "invalid Content-Length")
				})?;
				if n > MAX_REQUEST_BODY {
					return Err(io::Error::new(
						io::ErrorKind::InvalidInput,
						"request body too large",
					));
				}
				self.read_body(n)?
			}
			(None, Some((_, v))) => {
				// §6.3(4): chunked must be the final coding; others cannot be
				// framed reliably and are refused (§6.3, 400 + close).
				let last = v.rsplit(',').next().unwrap_or("").trim();
				if !last.eq_ignore_ascii_case("chunked") {
					return Err(io::Error::new(
						io::ErrorKind::InvalidData,
						"unsupported Transfer-Encoding",
					));
				}
				self.read_chunked_body()?
			}
			(None, None) => Vec::new(),
		};

		Ok(Request {
			method,
			path,
			headers,
			body,
		})
	}
}

// =======================
// Dispatch
// =======================

fn dispatch(
	req: &Request,
	ctx: &ServerContext,
	r: &mut Responder<'_>,
	addr: &SocketAddr,
) -> io::Result<()> {
	// Authentication check (HTTP Basic) happens before method dispatch, so a
	// HEAD request reaches this branch too — the Responder already knows it.
	if !check_auth(req, &ctx.auth) {
		r.respond(
			401,
			"Unauthorized",
			&[
				("WWW-Authenticate", "Basic realm=\"rcrm\""),
				("Content-Type", "text/html; charset=utf-8"),
			],
			b"<html><body>401 Unauthorized</body></html>",
		)?;
		rcrm_core::log_info!("[webdav:{}] 401 Unauthorized", addr);
		return Ok(());
	}

	let method = req.method.to_uppercase();
	match method.as_str() {
		"OPTIONS" => handle_options(r),
		// GET and HEAD share one handler: the difference is entirely in the
		// response framing, which the Responder owns (RFC 9110 §9.3.2).
		"GET" | "HEAD" => handle_get(req, ctx, r),
		"PROPFIND" => handle_propfind(req, ctx, r),
		// Read-only enforcement: reject all mutating methods.
		"PUT" | "DELETE" | "MKCOL" | "MOVE" | "COPY" | "PROPPATCH" | "LOCK" | "UNLOCK" => {
			r.respond(
				403,
				"Forbidden",
				&[("Content-Type", "application/xml; charset=utf-8")],
				b"<?xml version=\"1.0\" encoding=\"utf-8\"?><D:error xmlns:D=\"DAV:\"><D:response>Read-only WebDAV: write methods disabled</D:response></D:error>",
			)?;
			rcrm_core::log_info!("[webdav:{}] 403 {} (read-only)", addr, method);
			Ok(())
		}
		// Unknown methods.
		_ => {
			r.respond(
				501,
				"Not Implemented",
				&[("Content-Type", "text/html; charset=utf-8")],
				b"<html><body>501 Not Implemented</body></html>",
			)?;
			rcrm_core::log_info!("[webdav:{}] 501 {}", addr, method);
			Ok(())
		}
	}
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
	let mut decoded = match base64_decode(encoded) {
		Some(d) => d,
		None => return false,
	};
	// decoded holds the plaintext "user:pass" — keep it in a scope so we
	// can wipe it before the function returns. Use strict UTF-8: the
	// credential is ASCII, so a lossy conversion would only add an
	// uncleaned heap copy for malformed input we reject anyway.
	{
		let creds = match std::str::from_utf8(&decoded) {
			Ok(s) => s,
			Err(_) => return false,
		};
		let (user, pass) = match creds.split_once(':') {
			Some((u, p)) => (u, p),
			None => return false,
		};
		let ok = auth.verify(user, pass);
		// Wipe the decoded credential buffer after verify (creds borrows
		// from it, so this must happen after the last borrow).
		use zeroize::Zeroize;
		decoded.as_mut_slice().zeroize();
		ok
	}
}

/// Extract the base64 payload from "Basic <b64>".
///
/// RFC 9110 §11.6.1: the auth-scheme is case-insensitive, and one or more
/// spaces separate it from the token. Matching only the two literal spellings
/// `Basic ` / `basic ` rejected `BASIC`, `bAsIc` and double spaces.
fn h_strip(h: &str) -> Option<&str> {
	let s = h.trim();
	let (scheme, rest) = s.split_once(char::is_whitespace)?;
	if !scheme.eq_ignore_ascii_case("Basic") {
		return None;
	}
	let token = rest.trim();
	if token.is_empty() { None } else { Some(token) }
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
	base64::engine::general_purpose::STANDARD.decode(s).ok()
}

// =======================
// OPTIONS
// =======================

fn handle_options(r: &mut Responder<'_>) -> io::Result<()> {
	r.respond(
		200,
		"OK",
		&[
			("DAV", "1"),
			("Allow", "OPTIONS, GET, HEAD, PROPFIND"),
			("MS-Author-Via", "DAV"),
		],
		&[],
	)
}

// =======================
// GET / HEAD
// =======================

fn handle_get(req: &Request, ctx: &ServerContext, r: &mut Responder<'_>) -> io::Result<()> {
	// Virtual root: serve mount-point directory listing.
	if is_virtual_root(&req.path, ctx.is_multi_root()) {
		let mount_entries = virtual_root_entries(&ctx.mounts);
		let mut html = String::with_capacity(2048);
		html.push_str(
			"<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>rcrm - Mount Points</title>",
		);
		html.push_str("<style>body{font-family:monospace;padding:1em}h1{font-size:1.2em}");
		html.push_str("a{text-decoration:none}a:hover{text-decoration:underline}");
		html.push_str("</style></head><body><h1>Mount Points</h1><ul>");
		for entry in &mount_entries {
			let href = format!("/{}/", xml_escape(&entry.virtual_name));
			html.push_str(&format!(
				"<li><a href=\"{}\">{}/</a></li>",
				href,
				xml_escape(&entry.virtual_name)
			));
		}
		html.push_str("</ul></body></html>");
		let bytes = html.into_bytes();
		r.respond(
			200,
			"OK",
			&[("Content-Type", "text/html; charset=utf-8")],
			&bytes,
		)?;
		return Ok(());
	}

	let resolved_mount = match resolve_disk_path(&ctx.mounts, "/", &req.path, ctx.is_multi_root()) {
		Ok(r) => r,
		Err(_) => return not_found(r),
	};
	let disk = resolved_mount.disk_path;
	let mount_idx = resolved_mount.mount_idx;

	let resolved = resolve_resource(&disk, &req.path, ctx, mount_idx);
	let (content_length, mtime) = match &resolved {
		Resolved::Plain { meta, .. } => (meta.len(), meta.modified().ok()),
		Resolved::Projected { pf, meta } => (
			pf.virtual_size(),
			meta.as_ref().and_then(|m| m.modified().ok()),
		),
		Resolved::NotFound => {
			let body = b"<html><body>404 Not Found</body></html>";
			r.respond(
				404,
				"Not Found",
				&[("Content-Type", "text/html; charset=utf-8")],
				body,
			)?;
			return Ok(());
		}
		Resolved::Directory => {
			// Browser-friendly directory listing. WebDAV clients use
			// PROPFIND; browsers and wget use GET. Return a simple HTML
			// page with file links so browsing from a browser works.
			let html = build_html_directory_listing(&disk, &req.path, ctx, mount_idx);
			let bytes = html.into_bytes();
			r.respond(
				200,
				"OK",
				&[("Content-Type", "text/html; charset=utf-8")],
				&bytes,
			)?;
			return Ok(());
		}
	};

	// The Content-Type comes from the VIRTUAL name — the disk name of an
	// encrypted file is its `.<b72>` hash, which has no extension at all.
	let content_type = match &resolved {
		Resolved::Plain { path, .. } => content_type_for(path),
		Resolved::Projected { pf, .. } => content_type_for(Path::new(pf.virtual_name())),
		_ => content_type_for(&disk),
	};

	// Parse Range header (single range: "bytes=START-END").
	let range = parse_range_header(req, content_length);

	let last_modified = mtime
		.map(http_date)
		.unwrap_or_else(|| "Thu, 01 Jan 1970 00:00:00 GMT".to_string());
	let etag = format!("\"{}-{}\"", mtime_to_epoch(mtime), content_length);

	// The representation is streamed from disk (a projected file can be
	// gigabytes), so `respond_stream` takes a closure rather than a `Vec`.
	// HEAD still gets the exact GET headers — including Content-Length and
	// Content-Range (RFC 9110 §9.3.2, §8.6) — and only the emitted bytes are
	// skipped. A range covering the whole file is answered with 200, not 206
	// (RFC 9110 §14.2 allows a server to satisfy a range that way).
	match range {
		RangeSpec::None | RangeSpec::Full => {
			let headers = [
				("Content-Type", content_type.clone()),
				("Last-Modified", last_modified),
				("ETag", etag),
				("Accept-Ranges", "bytes".to_string()),
			];
			let headers_ref: Vec<(&str, &str)> =
				headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
			r.respond_stream(200, "OK", &headers_ref, content_length, |s| {
				stream_body(&resolved, 0, content_length, ctx, s)
			})
		}
		RangeSpec::Partial(start, end) => {
			// Partial content (206). end is inclusive.
			let length = end - start + 1;
			let content_range = format!("bytes {}-{}/{}", start, end, content_length);
			let headers = [
				("Content-Type", content_type.clone()),
				("Content-Range", content_range),
				("Last-Modified", last_modified),
				("ETag", etag),
				("Accept-Ranges", "bytes".to_string()),
			];
			let headers_ref: Vec<(&str, &str)> =
				headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
			r.respond_stream(206, "Partial Content", &headers_ref, length, |s| {
				stream_body(&resolved, start, length, ctx, s)
			})
		}
		RangeSpec::Unsatisfiable => {
			let headers = [("Content-Range", format!("bytes */{}", content_length))];
			let headers_ref: Vec<(&str, &str)> =
				headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
			r.respond(416, "Range Not Satisfiable", &headers_ref, &[])
		}
	}
}

/// 404 for a path that does not resolve. Kept out of the handlers so a bad
/// path answers with a status code instead of dropping the connection.
fn not_found(r: &mut Responder<'_>) -> io::Result<()> {
	r.respond(
		404,
		"Not Found",
		&[("Content-Type", "text/html; charset=utf-8")],
		b"<html><body>404 Not Found</body></html>",
	)
}

// =======================
// PROPFIND
// =======================

fn handle_propfind(req: &Request, ctx: &ServerContext, r: &mut Responder<'_>) -> io::Result<()> {
	// Virtual root: return mount-point listing.
	if is_virtual_root(&req.path, ctx.is_multi_root()) {
		let mount_entries = virtual_root_entries(&ctx.mounts);
		let mut xml = String::with_capacity(2048);
		xml.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
		xml.push_str("<D:multistatus xmlns:D=\"DAV:\">");
		for entry in &mount_entries {
			let href = format!("/{}/", xml_escape(&entry.virtual_name));
			xml.push_str("<D:response>");
			xml.push_str(&format!("<D:href>{}</D:href>", href));
			xml.push_str("<D:propstat><D:prop>");
			xml.push_str(&format!(
				"<D:displayname>{}</D:displayname>",
				xml_escape(&entry.virtual_name)
			));
			xml.push_str("<D:resourcetype><D:collection/></D:resourcetype>");
			xml.push_str("<D:getcontentlength>0</D:getcontentlength>");
			xml.push_str("<D:getlastmodified>Thu, 01 Jan 1970 00:00:00 GMT</D:getlastmodified>");
			xml.push_str("</D:prop>");
			xml.push_str("<D:status>HTTP/1.1 200 OK</D:status>");
			xml.push_str("</D:propstat>");
			xml.push_str("</D:response>");
		}
		xml.push_str("</D:multistatus>");
		let bytes = xml.into_bytes();
		let headers = [("Content-Type", "application/xml; charset=utf-8".to_string())];
		let headers_ref: Vec<(&str, &str)> =
			headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
		r.respond(207, "Multi-Status", &headers_ref, &bytes)?;
		return Ok(());
	}

	let resolved_mount = match resolve_disk_path(&ctx.mounts, "/", &req.path, ctx.is_multi_root()) {
		Ok(r) => r,
		Err(_) => return not_found(r),
	};
	let disk = resolved_mount.disk_path;
	let mount_idx = resolved_mount.mount_idx;

	let depth = req
		.header("depth")
		.map(|s| s.trim().to_lowercase())
		.unwrap_or_else(|| "infinity".to_string());

	// Resolve the target — ONE metadata probe instead of `is_dir()` plus
	// `exists()` (two).
	let target_meta = std::fs::metadata(&disk).ok();
	let target_is_dir = target_meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
	let target_exists = target_meta.is_some();

	// If the disk path doesn't exist, it might be a virtual name (decrypted
	// name of an encrypted file). Try resolving via projection.
	if !target_exists {
		if let Some(pf) = try_resolve_virtual(&disk, ctx, mount_idx) {
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
			let headers = [("Content-Type", "application/xml; charset=utf-8".to_string())];
			let headers_ref: Vec<(&str, &str)> =
				headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
			r.respond(207, "Multi-Status", &headers_ref, &bytes)?;
			return Ok(());
		}
		let body = b"<html><body>404 Not Found</body></html>";
		r.respond(
			404,
			"Not Found",
			&[("Content-Type", "text/html; charset=utf-8")],
			body,
		)?;
		return Ok(());
	}

	if !target_is_dir {
		// Single file. Could be plain or encrypted.
		let entry = match resolve_resource(&disk, &req.path, ctx, mount_idx) {
			Resolved::Plain { path, meta } => DirEntry {
				virtual_name: path
					.file_name()
					.and_then(|s| s.to_str())
					.unwrap_or("")
					.to_string(),
				is_dir: false,
				size: meta.len(),
				mtime: meta.modified().ok(),
				href: req.path.clone(),
			},
			Resolved::Projected { pf, meta } => DirEntry {
				virtual_name: pf.virtual_name().to_string(),
				is_dir: false,
				size: pf.virtual_size(),
				mtime: meta.as_ref().and_then(|m| m.modified().ok()),
				href: req.path.clone(),
			},
			_ => {
				let body = b"<html><body>404 Not Found</body></html>";
				r.respond(
					404,
					"Not Found",
					&[("Content-Type", "text/html; charset=utf-8")],
					body,
				)?;
				return Ok(());
			}
		};
		let xml = build_propfind_xml(&[entry]);
		let bytes = xml.into_bytes();
		let headers = [("Content-Type", "application/xml; charset=utf-8".to_string())];
		let headers_ref: Vec<(&str, &str)> =
			headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
		r.respond(207, "Multi-Status", &headers_ref, &bytes)?;
		return Ok(());
	}

	// Directory listing.
	let entries = match list_dir(&disk, &req.path, ctx, mount_idx) {
		Ok(e) => e,
		Err(e) => {
			rcrm_core::log_error!("[webdav] list_dir error: {}", e);
			let body = b"<html><body>500 Internal Server Error</body></html>";
			r.respond(
				500,
				"Internal Server Error",
				&[("Content-Type", "text/html; charset=utf-8")],
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
	let headers = [("Content-Type", "application/xml; charset=utf-8".to_string())];
	let headers_ref: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
	r.respond(207, "Multi-Status", &headers_ref, &bytes)?;
	Ok(())
}

// =======================
// Resource resolution (shared with GET)
// =======================

enum Resolved {
	Plain {
		path: PathBuf,
		/// Metadata fetched while resolving — reused for the length and
		/// mtime so a GET does not stat the file a second time.
		meta: std::fs::Metadata,
	},
	Projected {
		pf: Arc<rcrm_core::ProjectedFile>,
		/// Metadata of the ON-DISK (encrypted) file — its mtime is what
		/// the client is told.
		meta: Option<std::fs::Metadata>,
	},
	Directory,
	NotFound,
}

fn resolve_resource(
	disk: &Path,
	_req_path: &str,
	ctx: &ServerContext,
	mount_idx: usize,
) -> Resolved {
	// One metadata probe for the whole request. The old code probed four
	// times, and on Windows each `Path::is_*` probe opens the file.
	match std::fs::metadata(disk) {
		Ok(meta) => {
			if meta.is_dir() {
				return Resolved::Directory;
			}
			let name = disk.file_name().and_then(|s| s.to_str()).unwrap_or("");
			if is_valid_encrypted_file_name(name) {
				if let Ok(pf) =
					ctx.cache
						.get_or_open(disk, &ctx.manager, &ctx.session_key, mount_idx)
				{
					return Resolved::Projected {
						pf,
						meta: Some(meta),
					};
				}
				return Resolved::NotFound;
			}
			Resolved::Plain {
				path: disk.to_path_buf(),
				meta,
			}
		}
		Err(_) => {
			// Not on disk — try virtual name resolution.
			if let Some(pf) = try_resolve_virtual(disk, ctx, mount_idx) {
				let meta = std::fs::metadata(pf.disk_path()).ok();
				return Resolved::Projected { pf, meta };
			}
			Resolved::NotFound
		}
	}
}

/// Look for an encrypted (`.<b72>`) file whose decrypted virtual name
/// matches the last segment of `disk`.
fn try_resolve_virtual(
	disk: &Path,
	ctx: &ServerContext,
	mount_idx: usize,
) -> Option<Arc<rcrm_core::ProjectedFile>> {
	let parent = disk.parent()?;
	let req_name = disk.file_name()?.to_str()?;
	// Fast path: name index.
	if let Some(b72_path) = ctx.cache.resolve_virtual_name(mount_idx, parent, req_name)
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
		if let Ok(pf) = ctx
			.cache
			.get_or_open(&path, &ctx.manager, &ctx.session_key, mount_idx)
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

fn list_dir(
	dir: &Path,
	base_href: &str,
	ctx: &ServerContext,
	mount_idx: usize,
) -> io::Result<Vec<DirEntry>> {
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
			Err(e) => {
				rcrm_core::log_error!("[webdav] metadata error for {}: {}", path.display(), e);
				continue;
			}
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
			match ctx
				.cache
				.get_or_open(&path, &ctx.manager, &ctx.session_key, mount_idx)
			{
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
				Err(_) => {
					continue; // wrong key / corrupt — hide
				}
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
				content_type_for(Path::new(&e.virtual_name))
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
fn build_html_directory_listing(
	dir: &Path,
	url_path: &str,
	ctx: &ServerContext,
	mount_idx: usize,
) -> String {
	let entries = list_dir(dir, url_path, ctx, mount_idx).unwrap_or_default();
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
		Resolved::Plain { path, .. } => {
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
		Resolved::Projected { pf, .. } => {
			// Open the encrypted file once for the whole transfer; each
			// 64 KiB chunk no longer pays for a fresh CreateFile/open.
			let mut f = std::fs::File::open(pf.disk_path())?;
			while sent < length {
				let want = std::cmp::min(buf.len() as u64, length - sent) as usize;
				let n =
					pf.read_at_with(&mut f, offset + sent, &mut buf[..want], &ctx.session_key)?;
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

/// The response side of ONE request.
///
/// Whether content may be sent (RFC 9110 §9.3.2) and whether the connection
/// stays open are properties of the REQUEST, not of individual responses.
/// Owning both here makes the rule structural: a handler cannot write a
/// response without going through a value that already knows the answer, so
/// there is no boolean to forget and no `Connection` header to repeat.
///
/// RFC 9110 §9.3.2: "The HEAD method is identical to GET except that the
/// server MUST NOT send content in the response", and the server SHOULD send
/// the same header fields as it would for GET. §8.6: a Content-Length on a
/// HEAD response MUST equal the number of octets the equivalent GET would
/// have sent as content. RFC 9112 §6.3: a response to HEAD "is always
/// terminated by the first empty line after the header fields ... and thus
/// cannot contain a message body" — stray bytes become the start of the NEXT
/// response on a keep-alive connection.
struct Responder<'a> {
	stream: &'a mut dyn ReadWrite,
	head_only: bool,
	close_after: bool,
}

impl<'a> Responder<'a> {
	fn new(stream: &'a mut dyn ReadWrite, req: &Request) -> Self {
		Responder {
			stream,
			head_only: req.method.eq_ignore_ascii_case("HEAD"),
			// RFC 9110 §7.6.1: Connection is a comma-separated token LIST,
			// not a single value — "keep-alive, close" still means close.
			close_after: req
				.header("connection")
				.map(|h| h.split(',').any(|t| t.trim().eq_ignore_ascii_case("close")))
				.unwrap_or(false),
		}
	}

	/// Connection-level failures (413 while reading the request body, 500
	/// while dispatching) have no `Request` value; the method parsed from the
	/// head is enough, and both paths close the connection anyway.
	fn for_error(stream: &'a mut dyn ReadWrite, method: &str) -> Self {
		Responder {
			stream,
			head_only: method.eq_ignore_ascii_case("HEAD"),
			close_after: true,
		}
	}

	fn keep_alive(&self) -> bool {
		!self.close_after
	}

	/// Write a complete response. `body` is the representation a GET would
	/// receive; its length is always advertised and only the bytes are
	/// suppressed for HEAD.
	fn respond(
		&mut self,
		status: u16,
		reason: &str,
		headers: &[(&str, &str)],
		body: &[u8],
	) -> io::Result<()> {
		self.write_head(status, reason, headers, body.len() as u64)?;
		if !self.head_only && !body.is_empty() {
			self.stream.write_all(body)?;
		}
		self.stream.flush()
	}

	/// Same rule for a representation that must be streamed: a projected file
	/// can be gigabytes, so it is never materialised into a `Vec`. `emit`
	/// writes exactly `content_length` bytes and is skipped entirely for HEAD.
	fn respond_stream(
		&mut self,
		status: u16,
		reason: &str,
		headers: &[(&str, &str)],
		content_length: u64,
		emit: impl FnOnce(&mut dyn ReadWrite) -> io::Result<()>,
	) -> io::Result<()> {
		self.write_head(status, reason, headers, content_length)?;
		if !self.head_only {
			emit(self.stream)?;
		}
		self.stream.flush()
	}

	/// Single source of truth for the framing fields. Handler-supplied
	/// Content-Length / Connection values are ignored: the length comes from
	/// the GET representation, the connection policy from the request. Always
	/// emitting Content-Length (even `0`) also guarantees a keep-alive client
	/// can delimit a response with no body.
	fn write_head(
		&mut self,
		status: u16,
		reason: &str,
		headers: &[(&str, &str)],
		content_length: u64,
	) -> io::Result<()> {
		let cl = content_length.to_string();
		let mut all: Vec<(&str, &str)> = Vec::with_capacity(headers.len() + 2);
		for &(k, v) in headers {
			if !k.eq_ignore_ascii_case("content-length") && !k.eq_ignore_ascii_case("connection") {
				all.push((k, v));
			}
		}
		all.push(("Content-Length", &cl));
		all.push((
			"Connection",
			if self.close_after {
				"close"
			} else {
				"keep-alive"
			},
		));
		write_response_head(self.stream, status, reason, &all)
	}
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
		"avif" => "image/avif",
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
