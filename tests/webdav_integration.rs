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
use rcrm::serve::{AuthConfig, FileCache, Protocol, Server, ServerContext};
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
	let manager = Manager::new(true, true, 2048, is_supported_file, 6, Some(key));
	let session_key = Arc::new(SessionKey::generate());
	let tls_cfg = if https {
		Some(tls_config::build_ephemeral_config().expect("TLS config"))
	} else {
		None
	};
	let ctx = ServerContext {
		root,
		manager: Arc::new(manager),
		session_key,
		cache: Arc::new(FileCache::new()),
		tls_config: tls_cfg,
		require_tls: false,
		implicit_tls: https,
		protocol: if https {
			Protocol::WebDavHttps
		} else {
			Protocol::WebDav
		},
		max_connections: 8,
		auth: AuthConfig::no_auth(),
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
	std::fs::write(&path, &deterministic_content(8192, 1)).unwrap();

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
	let session_key = Arc::new(SessionKey::generate());
	let ctx = ServerContext {
		root: dir.clone(),
		manager: Arc::new(manager),
		session_key,
		cache: Arc::new(FileCache::new()),
		tls_config: None,
		require_tls: false,
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

	let provider = Arc::new(rustls::crypto::ring::default_provider());
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
