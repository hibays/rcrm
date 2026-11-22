// tests/webdav_integration.rs
// End-to-end tests for the WebDAV (HTTP/HTTPS) projection server.
//
// Verifies:
//   * PROPFIND lists decrypted virtual names (not .b72 hashes)
//   * GET streams the original plaintext byte-for-byte
//   * HEAD returns correct Content-Length (virtual size)
//   * Range requests work (partial content 206)
//   * Write methods (PUT/DELETE/MKCOL) are rejected with 403
//   * Plain files are served as-is
//   * HTTPS works (implicit TLS)
//   * HTTP Basic Auth

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::Engine;

use rcrm::serve::tls as tls_config;
use rcrm::serve::{AuthConfig, FileCache, Protocol, Server, ServerContext, generate_mount_names};
use rcrm::{Manager, SessionKey, is_supported_file};

// =======================
// Helpers
// =======================

fn deterministic_content(len: usize, seed: u8) -> Vec<u8> {
	let mut out = Vec::with_capacity(len);
	let mut state = seed as u32;
	for _ in 0..len {
		state ^= state << 13;
		state ^= state >> 17;
		state ^= state << 5;
		out.push((state & 0xff) as u8);
	}
	out
}

struct ServerFixture {
	addr: SocketAddr,
	shutdown: Arc<AtomicBool>,
	_thread: Option<std::thread::JoinHandle<std::io::Result<()>>>,
}

impl Drop for ServerFixture {
	fn drop(&mut self) {
		self.shutdown.store(true, Ordering::Relaxed);
	}
}

fn start_webdav_server(root: PathBuf, key: &[u8], https: bool) -> ServerFixture {
	start_webdav_server_with_auth(root, key, https, AuthConfig::no_auth())
}

fn start_webdav_server_with_auth(
	root: PathBuf,
	key: &[u8],
	https: bool,
	auth: AuthConfig,
) -> ServerFixture {
	let manager = Manager::new(true, true, 2048, is_supported_file, 6, Some(key));
	let session_key = Arc::new(SessionKey::generate().expect("mlock failed"));
	let tls_cfg = if https {
		Some(tls_config::build_ephemeral_config().expect("TLS config"))
	} else {
		None
	};
	let ctx = ServerContext {
		mounts: generate_mount_names(&[root]),
		manager: Arc::new(manager),
		session_key,
		cache: Arc::new(FileCache::new()),
		tls_config: tls_cfg,
		implicit_tls: https,
		protocol: if https {
			Protocol::WebDavHttps
		} else {
			Protocol::WebDav
		},
		max_connections: 8,
		auth,
		idle_timeout: Duration::from_secs(60),
	};
	let server = Server::new(ctx, "127.0.0.1:0".parse().unwrap());
	let (listener, addr) = server.bind().expect("bind failed");
	let shutdown = Arc::new(AtomicBool::new(false));
	let shutdown_clone = Arc::clone(&shutdown);
	let thread = std::thread::spawn(move || server.serve(listener, shutdown_clone));
	std::thread::sleep(Duration::from_millis(150));
	ServerFixture {
		addr,
		shutdown,
		_thread: Some(thread),
	}
}

/// Send a raw HTTP request over plain TCP. Returns the full response
/// (status line + headers + body).
fn http_request(addr: SocketAddr, raw: &str) -> String {
	let mut stream = TcpStream::connect(addr).expect("connect");
	stream
		.set_read_timeout(Some(Duration::from_secs(10)))
		.unwrap();
	stream.write_all(raw.as_bytes()).unwrap();
	stream.flush().unwrap();
	let mut response = String::new();
	stream.read_to_string(&mut response).expect("read");
	response
}

/// Send a raw HTTP request and return (status_line, headers, body) split.
fn http_request_split(addr: SocketAddr, raw: &str) -> (String, Vec<(String, String)>, Vec<u8>) {
	let mut stream = TcpStream::connect(addr).expect("connect");
	stream
		.set_read_timeout(Some(Duration::from_secs(10)))
		.unwrap();
	stream.write_all(raw.as_bytes()).unwrap();
	stream.flush().unwrap();

	// Read headers (until \r\n\r\n).
	let mut head = Vec::new();
	let mut buf = [0u8; 1];
	loop {
		let n = stream.read(&mut buf).unwrap();
		if n == 0 {
			break;
		}
		head.push(buf[0]);
		if head.len() >= 4 && &head[head.len() - 4..] == b"\r\n\r\n" {
			break;
		}
	}
	let head_str = String::from_utf8_lossy(&head);
	let mut lines = head_str.lines();
	let status_line = lines.next().unwrap_or("").to_string();
	let mut headers = Vec::new();
	for line in lines {
		if let Some((k, v)) = line.split_once(':') {
			headers.push((k.trim().to_string(), v.trim().to_string()));
		}
	}
	// Read body by Content-Length.
	let content_length: usize = headers
		.iter()
		.find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
		.and_then(|(_, v)| v.parse().ok())
		.unwrap_or(0);
	let mut body = vec![0u8; content_length];
	if content_length > 0 {
		stream.read_exact(&mut body).unwrap();
	}
	(status_line, headers, body)
}

/// Read a whole response on a connection the server will close, then split it
/// at the header terminator. Deliberately does NOT consume `Content-Length`
/// bytes: a HEAD response advertises the length the equivalent GET would have
/// sent (RFC 9110 §8.6) while carrying no content (§9.3.2), so a helper that
/// trusts Content-Length would block forever on a compliant HEAD answer.
fn http_response_raw(addr: SocketAddr, raw: &str) -> (String, Vec<(String, String)>, Vec<u8>) {
	let mut stream = TcpStream::connect(addr).expect("connect");
	stream
		.set_read_timeout(Some(Duration::from_secs(10)))
		.unwrap();
	stream.write_all(raw.as_bytes()).unwrap();
	stream.flush().unwrap();
	let mut buf = Vec::new();
	stream.read_to_end(&mut buf).expect("read to end");
	let pos = buf
		.windows(4)
		.position(|w| w == b"\r\n\r\n")
		.expect("no header terminator");
	let head = String::from_utf8_lossy(&buf[..pos]);
	let mut lines = head.lines();
	let status_line = lines.next().unwrap_or("").to_string();
	let mut headers = Vec::new();
	for line in lines {
		if let Some((k, v)) = line.split_once(':') {
			headers.push((k.trim().to_string(), v.trim().to_string()));
		}
	}
	(status_line, headers, buf[pos + 4..].to_vec())
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
	headers
		.iter()
		.find(|(k, _)| k.eq_ignore_ascii_case(name))
		.map(|(_, v)| v.as_str())
}

/// Send several raw requests on ONE keep-alive connection and read everything
/// the server writes until it closes. The last request must ask for close.
/// Used for RFC 9112 §6.3 framing tests: an unread body shows up as a corrupt
/// second response.
fn http_pipeline(addr: SocketAddr, raw: &str) -> Vec<u8> {
	let mut stream = TcpStream::connect(addr).expect("connect");
	stream
		.set_read_timeout(Some(Duration::from_secs(10)))
		.unwrap();
	stream.write_all(raw.as_bytes()).unwrap();
	stream.flush().unwrap();
	let mut buf = Vec::new();
	stream.read_to_end(&mut buf).expect("read to end");
	buf
}

/// A throwaway plain-text fixture used by the table-driven spec tests.
fn spec_fixture(name: &str) -> ServerFixture {
	let dir = std::env::temp_dir().join(name);
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(dir.join("sub")).unwrap();
	std::fs::write(dir.join("data.bin"), deterministic_content(1024, 7)).unwrap();
	std::fs::write(dir.join("a.txt"), b"hello").unwrap();
	let key = deterministic_content(32, 53);
	start_webdav_server(dir, &key, false)
}

// =======================
// Tests
// =======================

#[test]
fn webdav_get_projects_decrypted_content() {
	let dir = std::env::temp_dir().join("rcrm_webdav_test_get");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	let path = dir.join("video.mp4");
	let original = deterministic_content(64 * 1024, 42);
	std::fs::write(&path, &original).unwrap();

	let key = deterministic_content(32, 7);
	let manager = Manager::new(true, true, 2048, is_supported_file, 6, Some(&key));
	let _ = manager.encrypt_file(&path).unwrap();
	drop(manager);

	let fixture = start_webdav_server(dir.clone(), &key, false);
	let (status, headers, body) = http_request_split(
		fixture.addr,
		"GET /video.mp4 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
	);
	assert!(status.contains("200"), "status: {}", status);
	assert_eq!(body, original);

	// Content-Length should be the virtual (original) size.
	let cl = headers
		.iter()
		.find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
		.map(|(_, v)| v.as_str())
		.unwrap();
	assert_eq!(cl, &format!("{}", original.len()));
}

#[test]
fn webdav_propfind_lists_decrypted_names() {
	let dir = std::env::temp_dir().join("rcrm_webdav_test_propfind");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	let path = dir.join("movie.mp4");
	std::fs::write(&path, deterministic_content(8192, 1)).unwrap();

	let key = deterministic_content(32, 9);
	let manager = Manager::new(true, true, 2048, is_supported_file, 6, Some(&key));
	let enc_name = manager.encrypt_file(&path).unwrap();
	drop(manager);
	assert!(rcrm::is_valid_encrypted_file_name(&enc_name));

	let fixture = start_webdav_server(dir.clone(), &key, false);
	let response = http_request(
		fixture.addr,
		"PROPFIND / HTTP/1.1\r\nHost: localhost\r\nDepth: 1\r\nConnection: close\r\n\r\n",
	);
	assert!(response.contains("207"), "no 207: {}", response);
	assert!(
		response.contains("movie.mp4"),
		"listing missing decrypted name: {}",
		response
	);
	assert!(
		!response.contains(&enc_name),
		"listing should not contain encrypted name: {}",
		response
	);
}

#[test]
fn webdav_head_returns_virtual_size() {
	let dir = std::env::temp_dir().join("rcrm_webdav_test_head");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	let path = dir.join("sized.mp4");
	let original = deterministic_content(32 * 1024, 23);
	std::fs::write(&path, &original).unwrap();

	let key = deterministic_content(32, 23);
	let manager = Manager::new(true, true, 2048, is_supported_file, 6, Some(&key));
	let enc_name = manager.encrypt_file(&path).unwrap();
	drop(manager);

	let enc_path = dir.join(&enc_name);
	let disk_size = std::fs::metadata(&enc_path).unwrap().len();
	assert!(disk_size > original.len() as u64);

	let fixture = start_webdav_server(dir.clone(), &key, false);
	let response = http_request(
		fixture.addr,
		"HEAD /sized.mp4 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
	);
	assert!(response.contains("200"));
	assert!(response.contains("Content-Length"));
	let cl_line = response
		.lines()
		.find(|l| l.to_lowercase().starts_with("content-length:"))
		.unwrap();
	let size_str = cl_line.split(':').nth(1).unwrap().trim();
	assert_eq!(
		size_str,
		&format!("{}", original.len()),
		"HEAD Content-Length should be virtual size, not disk size"
	);
}

#[test]
fn webdav_head_never_sends_content_but_keeps_get_metadata() {
	let dir = std::env::temp_dir().join("rcrm_webdav_test_head_no_content");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(dir.join("sub")).unwrap();
	std::fs::write(dir.join("plain.txt"), b"plain text for head test").unwrap();

	let key = deterministic_content(32, 31);
	let fixture = start_webdav_server(dir, &key, false);

	// Every HEAD-reachable response path: missing file (Resolved::NotFound),
	// rejected path (not_found), directory HTML, and a normal file
	// (RangeSpec::None, which was already correct).
	for target in ["/missing.jpg", r"/..%5Csecret.txt", "/", "/plain.txt"] {
		let get = http_response_raw(
			fixture.addr,
			&format!("GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
		);
		let head = http_response_raw(
			fixture.addr,
			&format!("HEAD {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
		);
		assert_eq!(
			head.0, get.0,
			"HEAD and GET must agree on the status line for {target}"
		);
		assert!(
			head.2.is_empty(),
			"HEAD {target} sent {} content bytes; RFC 9110 §9.3.2 says MUST NOT: {:?}",
			head.2.len(),
			String::from_utf8_lossy(&head.2)
		);
		assert_eq!(
			header_value(&head.1, "content-length"),
			header_value(&get.1, "content-length"),
			"HEAD {target} must advertise the GET content length (§8.6)"
		);
		if let Some(n) =
			header_value(&get.1, "content-length").and_then(|v| v.parse::<usize>().ok())
		{
			assert_eq!(get.2.len(), n, "GET {target} body length");
		}
	}
}

#[test]
fn webdav_head_404_does_not_poison_the_next_keep_alive_request() {
	let dir = std::env::temp_dir().join("rcrm_webdav_test_head_keepalive");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();
	std::fs::write(dir.join("plain.txt"), b"KEEPALIVE-OK").unwrap();

	let key = deterministic_content(32, 37);
	let fixture = start_webdav_server(dir, &key, false);

	// Both requests on ONE connection, with no `Connection: close` on the
	// HEAD. Before the fix the 404 wrote an HTML body that RFC 9112 §6.3 makes
	// invisible to a HEAD client; those bytes became the start of the next
	// response and broke connection reuse.
	let request = concat!(
		"HEAD /missing.jpg HTTP/1.1\r\nHost: localhost\r\n\r\n",
		"GET /plain.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
	);
	let mut stream = TcpStream::connect(fixture.addr).expect("connect");
	stream
		.set_read_timeout(Some(Duration::from_secs(10)))
		.unwrap();
	stream.write_all(request.as_bytes()).unwrap();
	stream.flush().unwrap();
	let mut buf = Vec::new();
	stream.read_to_end(&mut buf).expect("read to end");

	let first_end = buf
		.windows(4)
		.position(|w| w == b"\r\n\r\n")
		.expect("no first response header terminator")
		+ 4;
	assert!(
		String::from_utf8_lossy(&buf[..first_end]).contains("404"),
		"first response should be 404: {}",
		String::from_utf8_lossy(&buf)
	);
	let rest = &buf[first_end..];
	assert!(
		rest.starts_with(b"HTTP/1.1 200"),
		"bytes after the HEAD headers must be the next status line, not content: {:?}",
		String::from_utf8_lossy(&rest[..rest.len().min(80)])
	);
	assert!(
		String::from_utf8_lossy(&buf).contains("KEEPALIVE-OK"),
		"the following GET must still be served: {}",
		String::from_utf8_lossy(&buf)
	);
}

#[test]
fn webdav_head_errors_carry_no_content() {
	let dir = std::env::temp_dir().join("rcrm_webdav_test_head_errors");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();
	std::fs::write(dir.join("a.txt"), b"hello").unwrap();
	let key = deterministic_content(32, 43);

	// 401 is raised before method dispatch.
	let authed = start_webdav_server_with_auth(
		dir.clone(),
		&key,
		false,
		AuthConfig::with_credentials("alice".to_string(), "secret123"),
	);
	let get401 = http_response_raw(
		authed.addr,
		"GET /a.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
	);
	let head401 = http_response_raw(
		authed.addr,
		"HEAD /a.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
	);
	assert!(head401.0.contains("401"), "{}", head401.0);
	assert!(head401.2.is_empty(), "HEAD 401 must not carry content");
	assert_eq!(
		header_value(&head401.1, "content-length"),
		header_value(&get401.1, "content-length"),
		"HEAD 401 keeps the GET content length (§8.6)"
	);

	// 413 is raised while reading the request body, when no `Request` value
	// exists yet — `HttpConn::last_method` is what makes this one correct.
	let open = start_webdav_server(dir, &key, false);
	let oversized = "Content-Length: 2000000\r\nConnection: close\r\n\r\n";
	let get413 = http_response_raw(
		open.addr,
		&format!("GET / HTTP/1.1\r\nHost: localhost\r\n{oversized}"),
	);
	let head413 = http_response_raw(
		open.addr,
		&format!("HEAD / HTTP/1.1\r\nHost: localhost\r\n{oversized}"),
	);
	assert!(head413.0.contains("413"), "{}", head413.0);
	assert!(head413.2.is_empty(), "HEAD 413 must not carry content");
	assert_eq!(
		header_value(&head413.1, "content-length"),
		header_value(&get413.1, "content-length"),
		"HEAD 413 keeps the GET content length (§8.6)"
	);
}

// =======================
// RFC boundary tables
// =======================

/// RFC 9110 §14.2 / §14.4 / §15.3.7: single-range parsing, clamping,
/// unsatisfiable ranges, suffix ranges, and the "ignore an invalid Range"
/// fallback. Each case also pins Content-Length == actual body length (§8.6).
#[test]
fn webdav_range_boundaries_follow_rfc9110() {
	let fixture = spec_fixture("rcrm_webdav_spec_range");
	let data = deterministic_content(1024, 7);
	let n = data.len();

	let cases: Vec<(String, u16, Option<String>, Vec<u8>)> = vec![
		(
			"bytes=0-0".into(),
			206,
			Some(format!("bytes 0-0/{n}")),
			data[0..1].to_vec(),
		),
		(
			"bytes=0-9".into(),
			206,
			Some(format!("bytes 0-9/{n}")),
			data[0..10].to_vec(),
		),
		(
			"bytes=10-".into(),
			206,
			Some(format!("bytes 10-{}/{n}", n - 1)),
			data[10..].to_vec(),
		),
		(
			"bytes=-5".into(),
			206,
			Some(format!("bytes {}-{}/{n}", n - 5, n - 1)),
			data[n - 5..].to_vec(),
		),
		// A range covering the whole representation is answered with 200,
		// which §14.2 explicitly permits.
		("bytes=0-1023".into(), 200, None, data.clone()),
		("bytes=0-999999".into(), 200, None, data.clone()),
		("bytes=0-".into(), 200, None, data.clone()),
		// §14.2: unsatisfiable ranges get 416 with "bytes */<complete-length>".
		(
			"bytes=1024-".into(),
			416,
			Some(format!("bytes */{n}")),
			vec![],
		),
		(
			"bytes=9999-10000".into(),
			416,
			Some(format!("bytes */{n}")),
			vec![],
		),
		(
			"bytes=20-10".into(),
			416,
			Some(format!("bytes */{n}")),
			vec![],
		),
		("bytes=-0".into(), 416, Some(format!("bytes */{n}")), vec![]),
		// A Range a server cannot parse is ignored → 200 full representation.
		("bytes=abc".into(), 200, None, data.clone()),
		("bytes=0-1,5-6".into(), 200, None, data.clone()),
		("bytes=".into(), 200, None, data.clone()),
		("bytes=5".into(), 200, None, data.clone()),
		("items=0-5".into(), 200, None, data.clone()),
		(
			"bytes=0-999999999999999999999999".into(),
			200,
			None,
			data.clone(),
		),
	];
	for (range, status, cr, expected) in cases {
		let (line, headers, body) = http_response_raw(
			fixture.addr,
			&format!(
				"GET /data.bin HTTP/1.1\r\nHost: localhost\r\nRange: {range}\r\nConnection: close\r\n\r\n"
			),
		);
		assert!(
			line.contains(&status.to_string()),
			"Range {range:?}: {line}"
		);
		assert_eq!(
			header_value(&headers, "content-range").map(str::to_string),
			cr,
			"Range {range:?}: Content-Range"
		);
		assert_eq!(body, expected, "Range {range:?}: body");
		let cl = header_value(&headers, "content-length")
			.and_then(|v| v.parse::<usize>().ok())
			.expect("Content-Length present");
		assert_eq!(cl, body.len(), "Range {range:?}: §8.6 Content-Length");
	}
}

/// RFC 9110 §9.3.2: HEAD SHOULD return the same header fields as GET. Compare
/// the WHOLE header set (not just Content-Length) across 200 / 206 / 416 and
/// the range-ignored fallback, while the content itself stays absent.
#[test]
fn webdav_head_matches_get_header_fields() {
	let fixture = spec_fixture("rcrm_webdav_spec_head_headers");
	for range in [
		"",
		"bytes=0-9",
		"bytes=1024-",
		"bytes=0-1023",
		"bytes=0-999999",
	] {
		let extra = if range.is_empty() {
			String::new()
		} else {
			format!("Range: {range}\r\n")
		};
		let get = http_response_raw(
			fixture.addr,
			&format!(
				"GET /data.bin HTTP/1.1\r\nHost: localhost\r\n{extra}Connection: close\r\n\r\n"
			),
		);
		let head = http_response_raw(
			fixture.addr,
			&format!(
				"HEAD /data.bin HTTP/1.1\r\nHost: localhost\r\n{extra}Connection: close\r\n\r\n"
			),
		);
		assert_eq!(head.0, get.0, "Range {range:?}: status line");
		assert!(
			head.2.is_empty(),
			"Range {range:?}: HEAD must not send content"
		);
		assert_eq!(
			head.1.len(),
			get.1.len(),
			"Range {range:?}: same header set\nGET: {:?}\nHEAD: {:?}",
			get.1,
			head.1
		);
		for (k, v) in &get.1 {
			assert_eq!(
				header_value(&head.1, k),
				Some(v.as_str()),
				"Range {range:?}: header {k}"
			);
		}
	}
}

/// RFC 9112 §6.3(3) and §6.3(5): Transfer-Encoding together with
/// Content-Length, and an invalid Content-Length, are unrecoverable framing
/// errors — 400 and close, never a header silently ignored (which would leave
/// unread bytes to be parsed as the next request).
#[test]
fn webdav_request_framing_errors_are_rejected() {
	let fixture = spec_fixture("rcrm_webdav_spec_framing");
	let cases: &[(&str, u16)] = &[
		("Content-Length: abc\r\n", 400),
		("Content-Length: -1\r\n", 400),
		("Content-Length: 1, 1\r\n", 400),
		("Content-Length: 1.5\r\n", 400),
		("Content-Length: \r\n", 400),
		("Content-Length: 1\r\nTransfer-Encoding: chunked\r\n", 400),
		("Transfer-Encoding: gzip\r\n", 400),
		("Transfer-Encoding: chunked, gzip\r\n", 400),
	];
	for (hdr, expected) in cases {
		let (line, headers, body) = http_response_raw(
			fixture.addr,
			&format!("GET /data.bin HTTP/1.1\r\nHost: localhost\r\n{hdr}Connection: close\r\n\r\n"),
		);
		assert!(
			line.contains(&expected.to_string()),
			"headers {hdr:?}: {line}"
		);
		assert_eq!(
			header_value(&headers, "connection"),
			Some("close"),
			"headers {hdr:?}: an unrecoverable framing error must close"
		);
		let cl = header_value(&headers, "content-length").and_then(|v| v.parse::<usize>().ok());
		assert_eq!(cl, Some(body.len()), "headers {hdr:?}: §8.6 Content-Length");
	}
}

/// RFC 9112 §7.1 and RFC 9110 §9.3.2: a chunked request body, and content on
/// a HEAD request (which clients SHOULD NOT send), must still be consumed.
/// The second request on the same connection is the detector.
#[test]
fn webdav_chunked_and_head_bodies_are_consumed() {
	let fixture = spec_fixture("rcrm_webdav_spec_chunked");
	let data = deterministic_content(1024, 7);
	let sequences: &[(&str, &str)] = &[
		(
			"chunked with extensions and a trailer",
			concat!(
				"GET /data.bin HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n",
				"5;ext=1\r\nhello\r\n",
				"6\r\n world\r\n",
				"0\r\nX-Trailer: ok\r\n\r\n",
				"GET /data.bin HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
			),
		),
		(
			"HEAD carrying a Content-Length body",
			concat!(
				"HEAD /data.bin HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\n",
				"xxxxx",
				"GET /data.bin HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
			),
		),
	];
	for (label, raw) in sequences {
		let buf = http_pipeline(fixture.addr, raw);
		let text = String::from_utf8_lossy(&buf);
		assert_eq!(
			text.matches("HTTP/1.1 200").count(),
			2,
			"{label}: expected two intact 200 responses: {text}"
		);
		assert!(
			buf.windows(data.len()).any(|w| w == data.as_slice()),
			"{label}: final GET must still return the whole representation"
		);
	}
}

/// RFC 9110 §11.6.1: the auth-scheme is case-insensitive and one or more
/// spaces may separate it from the token. A different scheme or a wrong
/// password still gets 401 with a challenge.
#[test]
fn webdav_basic_auth_scheme_is_case_insensitive() {
	let dir = std::env::temp_dir().join("rcrm_webdav_spec_auth");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();
	std::fs::write(dir.join("a.txt"), b"hello").unwrap();
	let key = deterministic_content(32, 59);
	let fixture = start_webdav_server_with_auth(
		dir,
		&key,
		false,
		AuthConfig::with_credentials("alice".to_string(), "secret123"),
	);
	let correct = base64::engine::general_purpose::STANDARD.encode(b"alice:secret123");
	let wrong = base64::engine::general_purpose::STANDARD.encode(b"alice:wrong");

	for scheme in ["Basic ", "basic ", "BASIC ", "bAsIc ", "Basic   "] {
		let (line, _, body) = http_response_raw(
			fixture.addr,
			&format!(
				"GET /a.txt HTTP/1.1\r\nHost: localhost\r\nAuthorization: {scheme}{correct}\r\nConnection: close\r\n\r\n"
			),
		);
		assert!(line.contains("200"), "scheme {scheme:?}: {line}");
		assert_eq!(body, b"hello", "scheme {scheme:?}");
	}
	for (scheme, cred) in [("Bearer ", correct.as_str()), ("Basic ", wrong.as_str())] {
		let (line, headers, _) = http_response_raw(
			fixture.addr,
			&format!(
				"GET /a.txt HTTP/1.1\r\nHost: localhost\r\nAuthorization: {scheme}{cred}\r\nConnection: close\r\n\r\n"
			),
		);
		assert!(line.contains("401"), "scheme {scheme:?}: {line}");
		assert!(
			header_value(&headers, "www-authenticate").is_some(),
			"401 must carry WWW-Authenticate"
		);
	}
}

/// RFC 9110 §8.6 / RFC 9112 §6.3: every response (including empty-body 200,
/// 400, 403, 416, 501 and OPTIONS) declares a correct Content-Length, so a
/// keep-alive client can always delimit it. HEAD declares the GET length while
/// sending no bytes.
#[test]
fn webdav_every_response_declares_content_length() {
	let fixture = spec_fixture("rcrm_webdav_spec_cl");
	let cases: &[(&str, &str)] = &[
		("GET", "/data.bin"),
		("HEAD", "/data.bin"),
		("GET", "/missing"),
		("HEAD", "/missing"),
		("GET", "/"),
		("HEAD", "/"),
		("OPTIONS", "/"),
		("PROPFIND", "/"),
		("PUT", "/x"),
		("BREW", "/"),
	];
	for (method, path) in cases {
		let (line, headers, body) = http_response_raw(
			fixture.addr,
			&format!(
				"{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
			),
		);
		let cl = header_value(&headers, "content-length").and_then(|v| v.parse::<usize>().ok());
		assert!(
			cl.is_some(),
			"{method} {path} ({line}) must declare Content-Length"
		);
		if *method == "HEAD" {
			assert!(
				body.is_empty(),
				"{method} {path}: HEAD must not send content"
			);
		} else {
			assert_eq!(
				cl,
				Some(body.len()),
				"{method} {path}: Content-Length must equal the body"
			);
		}
	}
}

/// Request-body cap boundary: exactly 1 MiB is accepted, one byte more is
/// refused with 413 and a closed connection (no unbounded buffering).
#[test]
fn webdav_request_body_limit_boundary() {
	let fixture = spec_fixture("rcrm_webdav_spec_body_limit");
	let at_limit = "x".repeat(1024 * 1024);
	let (line, _, _) = http_response_raw(
		fixture.addr,
		&format!(
			"GET /data.bin HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
			at_limit.len(),
			at_limit
		),
	);
	assert!(line.contains("200"), "exactly 1 MiB is accepted: {line}");

	let over = format!(
		"GET /data.bin HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
		at_limit.len() + 1
	);
	let (line, headers, _) = http_response_raw(fixture.addr, &over);
	assert!(
		line.contains("413"),
		"one byte over the cap is refused: {line}"
	);
	assert_eq!(header_value(&headers, "connection"), Some("close"));
}

/// RFC 9110 §7.6.1: "Connection" carries a comma-separated token LIST, so a
/// `close` token anywhere in it ends the connection after this response. The
/// second pipelined request is the detector — if the first one was (wrongly)
/// treated as keep-alive, two responses come back.
#[test]
fn webdav_connection_token_list_is_parsed() {
	let fixture = spec_fixture("rcrm_webdav_spec_conn");
	for hdr in ["keep-alive, close", "CLOSE", "close, keep-alive"] {
		let raw = format!(
			"GET /data.bin HTTP/1.1\r\nHost: localhost\r\nConnection: {hdr}\r\n\r\n{}",
			"GET /data.bin HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
		);
		let buf = http_pipeline(fixture.addr, &raw);
		let text = String::from_utf8_lossy(&buf);
		assert_eq!(
			text.matches("HTTP/1.1 200").count(),
			1,
			"Connection: {hdr} must close after the first response: {text}"
		);
	}
}

/// RFC 9110 §14.2 on a zero-length representation: no range is satisfiable,
/// and computing `content_length - 1` while clamping must not underflow.
#[test]
fn webdav_empty_file_ranges_do_not_underflow() {
	let dir = std::env::temp_dir().join("rcrm_webdav_spec_empty");
	let fixture = spec_fixture("rcrm_webdav_spec_empty");
	std::fs::write(dir.join("empty.bin"), b"").unwrap();
	for range in ["bytes=0-", "bytes=-1", "bytes=0-0", "bytes=1-2"] {
		let (line, headers, body) = http_response_raw(
			fixture.addr,
			&format!(
				"GET /empty.bin HTTP/1.1\r\nHost: localhost\r\nRange: {range}\r\nConnection: close\r\n\r\n"
			),
		);
		assert!(line.contains("416"), "empty file, Range {range}: {line}");
		assert_eq!(
			header_value(&headers, "content-range"),
			Some("bytes */0"),
			"empty file, Range {range}"
		);
		assert!(body.is_empty(), "empty file, Range {range}: no content");
	}
}

/// RFC 9112 §7.1: malformed chunk framing is unrecoverable, and a chunk larger
/// than the 1 MiB cap is refused before any buffering.
#[test]
fn webdav_chunked_framing_errors_are_rejected() {
	let fixture = spec_fixture("rcrm_webdav_spec_chunk_err");
	let cases: &[(&str, u16)] = &[
		("ZZ\r\n", 400),
		("5\r\nhelloXX", 400),
		("FFFFFFFFFFFFFFFF\r\n", 413),
	];
	for (body, expected) in cases {
		let (line, headers, _) = http_response_raw(
			fixture.addr,
			&format!(
				"GET /data.bin HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{body}"
			),
		);
		assert!(
			line.contains(&expected.to_string()),
			"chunked body {body:?}: {line}"
		);
		assert_eq!(
			header_value(&headers, "connection"),
			Some("close"),
			"chunked body {body:?}: framing errors must close"
		);
	}
}

#[test]
fn webdav_range_request_partial_content() {
	let dir = std::env::temp_dir().join("rcrm_webdav_test_range");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	let path = dir.join("resume.mp4");
	let original = deterministic_content(32 * 1024, 5);
	std::fs::write(&path, &original).unwrap();

	let key = deterministic_content(32, 13);
	let manager = Manager::new(true, true, 2048, is_supported_file, 6, Some(&key));
	let _ = manager.encrypt_file(&path).unwrap();
	drop(manager);

	let fixture = start_webdav_server(dir.clone(), &key, false);
	let (status, headers, body) = http_request_split(
		fixture.addr,
		"GET /resume.mp4 HTTP/1.1\r\nHost: localhost\r\nRange: bytes=10000-20000\r\nConnection: close\r\n\r\n",
	);
	assert!(status.contains("206"), "expected 206, got: {}", status);
	assert_eq!(body.len(), 10001);
	assert_eq!(&body[..], &original[10000..=20000]);

	let cr = headers
		.iter()
		.find(|(k, _)| k.eq_ignore_ascii_case("content-range"))
		.map(|(_, v)| v.as_str())
		.unwrap();
	assert!(cr.contains("bytes 10000-20000/"), "Content-Range: {}", cr);
}

#[test]
fn webdav_path_traversal_with_windows_separators_contained() {
	// The secret lives OUTSIDE the served root.
	let base = std::env::temp_dir().join("rcrm_webdav_test_traversal_win");
	let _ = std::fs::remove_dir_all(&base);
	let root = base.join("root");
	std::fs::create_dir_all(&root).unwrap();
	std::fs::write(base.join("secret.txt"), b"TOP-SECRET-CONTENT").unwrap();

	let key = deterministic_content(32, 29);
	let fixture = start_webdav_server(root.clone(), &key, false);

	for probe in [
		r"/..\secret.txt",
		r"/..\..\secret.txt",
		r"/..\.secret.txt",
		r"/..%5Csecret.txt",
		r"/..%5C..%5Csecret.txt",
		"/C:%5Csecret.txt",
		r"/..%2Fsecret.txt",
	] {
		let response = http_request(
			fixture.addr,
			&format!("GET {probe} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
		);
		assert!(
			!response.contains("TOP-SECRET-CONTENT"),
			"GET {probe} leaked a file outside the root:\n{}",
			response
		);
	}

	// Positive control: a file inside the root is still served.
	std::fs::write(root.join("ok.txt"), b"public").unwrap();
	let response = http_request(
		fixture.addr,
		"GET /ok.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
	);
	assert!(response.contains("200"), "expected 200:\n{}", response);
	assert!(
		response.contains("public"),
		"expected the body:\n{}",
		response
	);
}

#[test]
fn webdav_write_methods_rejected_403() {
	let dir = std::env::temp_dir().join("rcrm_webdav_test_write");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	let key = deterministic_content(32, 11);
	let fixture = start_webdav_server(dir.clone(), &key, false);

	for method in &["PUT", "DELETE", "MKCOL", "MOVE", "COPY"] {
		let response = http_request(
			fixture.addr,
			&format!(
				"{method} /test HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
			),
		);
		assert!(
			response.contains("403"),
			"{} should be 403: {}",
			method,
			response
		);
	}
}

#[test]
fn webdav_plain_file_served_as_is() {
	let dir = std::env::temp_dir().join("rcrm_webdav_test_plain");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	let plain_content = b"plain text for webdav test".to_vec();
	std::fs::write(dir.join("readme.txt"), &plain_content).unwrap();

	let key = deterministic_content(32, 17);
	let fixture = start_webdav_server(dir.clone(), &key, false);
	let (status, _headers, body) = http_request_split(
		fixture.addr,
		"GET /readme.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
	);
	assert!(status.contains("200"));
	assert_eq!(body, plain_content);
}

#[test]
fn webdav_options_advertises_dav() {
	let dir = std::env::temp_dir().join("rcrm_webdav_test_options");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	let key = deterministic_content(32, 19);
	let fixture = start_webdav_server(dir.clone(), &key, false);
	let response = http_request(
		fixture.addr,
		"OPTIONS / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
	);
	assert!(response.contains("200"));
	assert!(response.contains("DAV: 1"), "no DAV header: {}", response);
	assert!(
		response.contains("PROPFIND"),
		"Allow should include PROPFIND: {}",
		response
	);
}

#[test]
fn webdav_https_works() {
	let dir = std::env::temp_dir().join("rcrm_webdav_test_https");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	let path = dir.join("secret.mp4");
	let original = deterministic_content(16 * 1024, 31);
	std::fs::write(&path, &original).unwrap();

	let key = deterministic_content(32, 31);
	let manager = Manager::new(true, true, 2048, is_supported_file, 6, Some(&key));
	let _ = manager.encrypt_file(&path).unwrap();
	drop(manager);

	let fixture = start_webdav_server(dir.clone(), &key, true);

	// Connect with a rustls TLS client.
	let client_config = build_no_verify_client_config();
	let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
	let conn = rustls::ClientConnection::new(client_config, server_name).unwrap();
	let tcp = TcpStream::connect(fixture.addr).unwrap();
	let mut tls = rustls::StreamOwned::new(conn, tcp);

	let request = b"GET /secret.mp4 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
	tls.write_all(request).unwrap();
	tls.flush().unwrap();

	// Read headers (Content-Length tells us the body size).
	let (_status, _headers, body) = read_http_over_tls(&mut tls);
	assert!(_status.contains("200"), "status: {}", _status);
	assert_eq!(&body[..], &original[..]);
}

#[test]
fn webdav_basic_auth_required() {
	let dir = std::env::temp_dir().join("rcrm_webdav_test_auth");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();
	std::fs::write(dir.join("a.txt"), b"hello").unwrap();

	let key = deterministic_content(32, 41);
	let manager = Manager::new(true, true, 2048, is_supported_file, 6, Some(&key));
	let session_key = Arc::new(SessionKey::generate().expect("mlock failed"));
	let ctx = ServerContext {
		mounts: generate_mount_names(std::slice::from_ref(&dir)),
		manager: Arc::new(manager),
		session_key,
		cache: Arc::new(FileCache::new()),
		tls_config: None,
		implicit_tls: false,
		protocol: Protocol::WebDav,
		max_connections: 8,
		auth: AuthConfig::with_credentials("alice".to_string(), "secret123"),
		idle_timeout: Duration::from_secs(60),
	};
	let server = Server::new(ctx, "127.0.0.1:0".parse().unwrap());
	let (listener, addr) = server.bind().expect("bind failed");
	let shutdown = Arc::new(AtomicBool::new(false));
	let shutdown_clone = Arc::clone(&shutdown);
	let _thread = std::thread::spawn(move || server.serve(listener, shutdown_clone));
	std::thread::sleep(Duration::from_millis(150));

	// No auth → 401.
	let response = http_request(
		addr,
		"GET /a.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
	);
	assert!(
		response.contains("401"),
		"no auth should be 401: {}",
		response
	);
	assert!(
		response.contains("WWW-Authenticate"),
		"should have WWW-Authenticate: {}",
		response
	);

	// Wrong password → 401.
	let wrong = base64::engine::general_purpose::STANDARD.encode(b"alice:wrong");
	let response = http_request(
		addr,
		&format!(
			"GET /a.txt HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {wrong}\r\nConnection: close\r\n\r\n"
		),
	);
	assert!(
		response.contains("401"),
		"wrong pass should be 401: {}",
		response
	);

	// Correct → 200.
	let correct = base64::engine::general_purpose::STANDARD.encode(b"alice:secret123");
	let (status, _headers, body) = http_request_split(
		addr,
		&format!(
			"GET /a.txt HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {correct}\r\nConnection: close\r\n\r\n"
		),
	);
	assert!(
		status.contains("200"),
		"correct auth should be 200: {}",
		status
	);
	assert_eq!(body, b"hello");

	shutdown.store(true, Ordering::Relaxed);
}

/// Simulate a browser flow: GET / to load HTML index → click an encrypted
/// file's virtual name → GET /virtual_name.jpg should resolve correctly.
/// This tests both the HTML listing generation AND virtual name resolution
/// through the name_index cache populated during listing.
#[test]
fn webdav_html_listing_then_get_virtual_name() {
	let dir = std::env::temp_dir().join("rcrm_webdav_test_browse");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	let path = dir.join("car.jpg");
	let original = deterministic_content(16 * 1024, 77);
	std::fs::write(&path, &original).unwrap();

	let key = deterministic_content(32, 77);
	let manager = Manager::new(true, true, 2048, is_supported_file, 6, Some(&key));
	let enc_name = manager.encrypt_file(&path).unwrap();
	drop(manager);
	assert!(rcrm::is_valid_encrypted_file_name(&enc_name));

	let fixture = start_webdav_server(dir.clone(), &key, false);

	// Step 1: Browser-style GET / to load HTML index.
	// This populates the name_index cache for encrypted files.
	let html = http_request(
		fixture.addr,
		"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
	);
	assert!(html.contains("200"), "HTML index should be 200: {}", html);
	assert!(
		html.contains("car.jpg"),
		"HTML index should list virtual name: {}",
		html
	);
	assert!(
		!html.contains(&enc_name),
		"HTML index must not show .b72 hash: {}",
		html
	);

	// Step 2: Click the link — GET /car.jpg via virtual name.
	// Must resolve through name_index (populated in step 1).
	let (status, _headers, body) = http_request_split(
		fixture.addr,
		"GET /car.jpg HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
	);
	assert!(
		status.contains("200"),
		"GET virtual name should resolve: {}",
		status
	);
	assert_eq!(&body[..], &original[..]);
}

// =======================
// TLS client helper (self-signed cert, no verification)
// =======================

fn build_no_verify_client_config() -> Arc<rustls::ClientConfig> {
	use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};

	#[derive(Debug)]
	struct NoVerifier;

	impl ServerCertVerifier for NoVerifier {
		fn verify_server_cert(
			&self,
			_: &rustls::pki_types::CertificateDer,
			_: &[rustls::pki_types::CertificateDer],
			_: &rustls::pki_types::ServerName,
			_: &[u8],
			_: rustls::pki_types::UnixTime,
		) -> Result<ServerCertVerified, rustls::Error> {
			Ok(ServerCertVerified::assertion())
		}
		fn verify_tls12_signature(
			&self,
			_: &[u8],
			_: &rustls::pki_types::CertificateDer,
			_: &rustls::DigitallySignedStruct,
		) -> Result<HandshakeSignatureValid, rustls::Error> {
			Ok(HandshakeSignatureValid::assertion())
		}
		fn verify_tls13_signature(
			&self,
			_: &[u8],
			_: &rustls::pki_types::CertificateDer,
			_: &rustls::DigitallySignedStruct,
		) -> Result<HandshakeSignatureValid, rustls::Error> {
			Ok(HandshakeSignatureValid::assertion())
		}
		fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
			vec![
				rustls::SignatureScheme::RSA_PKCS1_SHA256,
				rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
				rustls::SignatureScheme::RSA_PSS_SHA256,
				rustls::SignatureScheme::ED25519,
				rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
				rustls::SignatureScheme::RSA_PSS_SHA384,
				rustls::SignatureScheme::RSA_PKCS1_SHA384,
				rustls::SignatureScheme::RSA_PKCS1_SHA512,
				rustls::SignatureScheme::RSA_PSS_SHA512,
			]
		}
	}

	let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
	let config = rustls::ClientConfig::builder_with_provider(provider)
		.with_safe_default_protocol_versions()
		.unwrap()
		.dangerous()
		.with_custom_certificate_verifier(Arc::new(NoVerifier))
		.with_no_client_auth();
	Arc::new(config)
}

/// Read an HTTP response over a TLS stream, using Content-Length for the
/// body (so we don't rely on EOF, which fails when the server doesn't send
/// a TLS close_notify before TCP shutdown).
fn read_http_over_tls(
	tls: &mut rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
) -> (String, Vec<(String, String)>, Vec<u8>) {
	let mut head = Vec::new();
	let mut buf = [0u8; 1];
	loop {
		let n = tls.read(&mut buf).unwrap();
		if n == 0 {
			break;
		}
		head.push(buf[0]);
		if head.len() >= 4 && &head[head.len() - 4..] == b"\r\n\r\n" {
			break;
		}
	}
	let head_str = String::from_utf8_lossy(&head);
	let mut lines = head_str.lines();
	let status_line = lines.next().unwrap_or("").to_string();
	let mut headers = Vec::new();
	for line in lines {
		if let Some((k, v)) = line.split_once(':') {
			headers.push((k.trim().to_string(), v.trim().to_string()));
		}
	}
	let content_length: usize = headers
		.iter()
		.find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
		.and_then(|(_, v)| v.parse().ok())
		.unwrap_or(0);
	let mut body = vec![0u8; content_length];
	if content_length > 0 {
		tls.read_exact(&mut body).unwrap();
	}
	(status_line, headers, body)
}

// =======================
// Regressions: path confinement, framing, short bodies
// =======================

/// A symlink inside the mount pointing OUT of it must not expose the target:
/// path resolution resolves each component and refuses anything that leaves
/// the canonical mount root (complete mediation).
#[test]
#[cfg(windows)]
fn webdav_symlink_outside_mount_is_refused() {
	let base = std::env::temp_dir().join("rcrm_webdav_symlink_escape");
	let _ = std::fs::remove_dir_all(&base);
	let mount = base.join("mount");
	std::fs::create_dir_all(&mount).unwrap();
	std::fs::write(base.join("outside.mp4"), b"SECRET-OUTSIDE").unwrap();
	let link = mount.join("leak.mp4");
	if std::os::windows::fs::symlink_file(base.join("outside.mp4"), &link).is_err() {
		eprintln!("skipping: no privilege to create a symlink here");
		return;
	}
	let key = deterministic_content(32, 53);
	let fixture = start_webdav_server(mount, &key, false);
	let resp = http_request(
		fixture.addr,
		"GET /leak.mp4 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
	);
	assert!(
		!resp.contains("SECRET-OUTSIDE"),
		"a symlink must not expose a file outside the mount: {resp}"
	);
	let _ = std::fs::remove_dir_all(&base);
}

/// Two `Content-Length` or two `Transfer-Encoding` field lines are the CL.CL /
/// TE.TE smuggling shapes; RFC 9112 §6.3 requires 400 + close, not framing on
/// the first value.
#[test]
fn webdav_duplicate_framing_headers_are_rejected() {
	let fixture = spec_fixture("rcrm_webdav_dup_framing");
	let cases: &[&str] = &[
		"Content-Length: 1\r\nContent-Length: 2\r\n",
		"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
	];
	for hdr in cases {
		let (line, headers, _) = http_response_raw(
			fixture.addr,
			&format!("GET /data.bin HTTP/1.1\r\nHost: localhost\r\n{hdr}Connection: close\r\n\r\n"),
		);
		assert!(line.contains("400"), "duplicate framing {hdr:?}: {line}");
		assert_eq!(
			header_value(&headers, "connection"),
			Some("close"),
			"duplicate framing {hdr:?} must close"
		);
	}
}
