// tests/ftps_integration.rs
// End-to-end test for FTPS (FTP over TLS).
//
// Starts the server with an auto-generated ephemeral self-signed
// certificate, connects with a rustls TLS client (with certificate
// verification disabled — the cert is self-signed and ephemeral),
// upgrades via AUTH TLS, and verifies that RETR over an encrypted
// control+data connection still projects the original plaintext.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct};

use rcrm::serve::tls as tls_config;
use rcrm::serve::{AuthConfig, FileCache, Server, ServerContext};
use rcrm::{Manager, SessionKey, is_supported_file};

// =======================
// No-op certificate verifier (self-signed ephemeral cert)
// =======================

#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
	fn verify_server_cert(
		&self,
		_end_entity: &CertificateDer<'_>,
		_intermediates: &[CertificateDer<'_>],
		_server_name: &ServerName<'_>,
		_ocsp_response: &[u8],
		_now: UnixTime,
	) -> Result<ServerCertVerified, rustls::Error> {
		Ok(ServerCertVerified::assertion())
	}

	fn verify_tls12_signature(
		&self,
		_message: &[u8],
		_cert: &CertificateDer<'_>,
		_dss: &DigitallySignedStruct,
	) -> Result<HandshakeSignatureValid, rustls::Error> {
		Ok(HandshakeSignatureValid::assertion())
	}

	fn verify_tls13_signature(
		&self,
		_message: &[u8],
		_cert: &CertificateDer<'_>,
		_dss: &DigitallySignedStruct,
	) -> Result<HandshakeSignatureValid, rustls::Error> {
		Ok(HandshakeSignatureValid::assertion())
	}

	fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
		vec![
			rustls::SignatureScheme::RSA_PKCS1_SHA256,
			rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
			rustls::SignatureScheme::RSA_PSS_SHA256,
			rustls::SignatureScheme::RSA_PKCS1_SHA384,
			rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
			rustls::SignatureScheme::RSA_PSS_SHA384,
			rustls::SignatureScheme::RSA_PKCS1_SHA512,
			rustls::SignatureScheme::RSA_PSS_SHA512,
			rustls::SignatureScheme::ED25519,
			rustls::SignatureScheme::ED448,
		]
	}
}

fn build_client_config() -> Arc<ClientConfig> {
	let provider = Arc::new(rustls::crypto::ring::default_provider());
	let config = ClientConfig::builder_with_provider(provider)
		.with_safe_default_protocol_versions()
		.expect("safe default versions")
		.dangerous()
		.with_custom_certificate_verifier(Arc::new(NoVerifier))
		.with_no_client_auth();
	Arc::new(config)
}

// =======================
// Test helpers
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
	thread: Option<std::thread::JoinHandle<std::io::Result<()>>>,
}

impl Drop for ServerFixture {
	fn drop(&mut self) {
		self.shutdown.store(true, Ordering::Relaxed);
		if let Some(t) = self.thread.take() {
			let _ = t.join();
		}
	}
}

fn start_tls_server(root: std::path::PathBuf, key: &[u8]) -> ServerFixture {
	start_server_with_mode(root, key, false)
}

fn start_implicit_tls_server(root: std::path::PathBuf, key: &[u8]) -> ServerFixture {
	start_server_with_mode(root, key, true)
}

fn start_server_with_mode(root: std::path::PathBuf, key: &[u8], implicit: bool) -> ServerFixture {
	let manager = Manager::new(true, true, 2048, is_supported_file, 6, Some(key));
	let session_key = Arc::new(SessionKey::generate());
	let tls_cfg = tls_config::build_ephemeral_config().expect("ephemeral cert failed");
	let ctx = ServerContext {
		root,
		manager: Arc::new(manager),
		session_key,
		cache: Arc::new(FileCache::new()),
		tls_config: Some(tls_cfg),
		require_tls: false,
		implicit_tls: implicit,
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
		thread: Some(thread),
	}
}

// =======================
// Helpers
// =======================

/// Read a single CRLF-terminated line from a Read.
fn read_line(stream: &mut impl Read) -> std::io::Result<String> {
	let mut buf = Vec::new();
	let mut byte = [0u8; 1];
	loop {
		let n = stream.read(&mut byte)?;
		if n == 0 {
			return Err(std::io::Error::new(
				std::io::ErrorKind::UnexpectedEof,
				"connection closed mid-line",
			));
		}
		if byte[0] == b'\n' {
			break;
		}
		buf.push(byte[0]);
	}
	if buf.ends_with(b"\r") {
		buf.pop();
	}
	Ok(String::from_utf8_lossy(&buf).into_owned())
}

#[test]
fn ftps_retr_over_tls() {
	let dir = std::env::temp_dir().join("rcrm_ftps_test");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	let path = dir.join("secret.mp4");
	let original = deterministic_content(32 * 1024, 31);
	std::fs::write(&path, &original).unwrap();

	let key = deterministic_content(32, 31);
	let manager = Manager::new(true, true, 2048, is_supported_file, 6, Some(&key));
	let _ = manager.encrypt_file(&path).unwrap();
	drop(manager);

	let fixture = start_tls_server(dir.clone(), &key);

	// --- Connect plaintext, read welcome, AUTH TLS ---
	let mut tcp = TcpStream::connect(fixture.addr).expect("connect failed");
	tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
	tcp.set_write_timeout(Some(Duration::from_secs(10)))
		.unwrap();
	let mut tcp_read = tcp.try_clone().unwrap();

	let welcome = read_line(&mut tcp_read).unwrap();
	assert!(welcome.starts_with("220"), "welcome: {}", welcome);

	tcp.write_all(b"AUTH TLS\r\n").unwrap();
	tcp.flush().unwrap();
	let auth_resp = read_line(&mut tcp_read).unwrap();
	assert!(auth_resp.starts_with("234"), "AUTH TLS: {}", auth_resp);

	// --- Upgrade to TLS (client side) ---
	let client_config = build_client_config();
	let server_name = ServerName::try_from("localhost").unwrap();
	let client_conn = rustls::ClientConnection::new(client_config, server_name)
		.map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
		.unwrap();
	let mut tls = rustls::StreamOwned::new(client_conn, tcp);

	// --- Continue FTP commands over TLS ---
	// FEAT over TLS — verify standard multi-line format (each feature on
	// its own line with `211-` prefix) and that AUTH TLS is advertised.
	tls.write_all(b"FEAT\r\n").unwrap();
	tls.flush().unwrap();
	let mut feat_lines = Vec::new();
	loop {
		let line = read_line(&mut tls).unwrap();
		let is_end = line.starts_with("211 ");
		feat_lines.push(line);
		if is_end {
			break;
		}
	}
	let all_feat = feat_lines.join("\n");
	assert!(
		all_feat.contains("AUTH TLS"),
		"explicit FTPES FEAT should advertise AUTH TLS: {}",
		all_feat
	);
	// Verify multi-line format: first line "211-...", last line "211 ...".
	assert!(
		feat_lines[0].starts_with("211-"),
		"first FEAT line should start with 211-: {}",
		feat_lines[0]
	);
	assert!(
		feat_lines[feat_lines.len() - 1].starts_with("211 "),
		"last FEAT line should start with '211 ': {}",
		feat_lines[feat_lines.len() - 1]
	);

	let user_resp = read_line_after_cmd(&mut tls, "USER anonymous").unwrap();
	assert!(user_resp.starts_with("230"), "USER: {}", user_resp);

	let pbsz_resp = read_line_after_cmd(&mut tls, "PBSZ 0").unwrap();
	assert!(pbsz_resp.starts_with("200"), "PBSZ: {}", pbsz_resp);

	let prot_resp = read_line_after_cmd(&mut tls, "PROT P").unwrap();
	assert!(prot_resp.starts_with("200"), "PROT: {}", prot_resp);

	let type_resp = read_line_after_cmd(&mut tls, "TYPE I").unwrap();
	assert!(type_resp.starts_with("200"), "TYPE: {}", type_resp);

	// SIZE over TLS.
	let size_resp = read_line_after_cmd(&mut tls, "SIZE secret.mp4").unwrap();
	assert!(size_resp.starts_with("213"), "SIZE: {}", size_resp);
	assert!(size_resp.contains(&format!("{}", original.len())));

	// PASV over TLS — the *data* connection will also be TLS (PROT P).
	let pasv_resp = read_line_after_cmd(&mut tls, "PASV").unwrap();
	assert!(pasv_resp.starts_with("227"), "PASV: {}", pasv_resp);
	let port = parse_pasv_port(&pasv_resp).expect("parse PASV port");

	// Connect data socket (plain TCP first; server will upgrade it to TLS
	// because PROT P is set).
	let data_tcp = TcpStream::connect(("127.0.0.1", port)).expect("data connect");
	data_tcp
		.set_read_timeout(Some(Duration::from_secs(30)))
		.unwrap();

	// Send RETR over the (TLS) control connection.
	tls.write_all(b"RETR secret.mp4\r\n").unwrap();
	tls.flush().unwrap();
	let retr_resp = read_line(&mut tls).unwrap();
	assert!(retr_resp.starts_with("150"), "RETR: {}", retr_resp);

	// Wrap the data socket in TLS (client side).
	let data_client_config = build_client_config();
	let data_server_name = ServerName::try_from("localhost").unwrap();
	let data_conn = rustls::ClientConnection::new(data_client_config, data_server_name)
		.map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
		.unwrap();
	let mut data_tls = rustls::StreamOwned::new(data_conn, data_tcp);

	// Read the projected plaintext.
	let mut received = Vec::with_capacity(original.len());
	let n = data_tls.read_to_end(&mut received).expect("read data");
	assert_eq!(n, original.len(), "data length mismatch");
	assert_eq!(received, original, "data content mismatch");

	// Expect 226 on the control connection.
	let done = read_line(&mut tls).unwrap();
	assert!(done.starts_with("226"), "226: {}", done);
}

fn read_line_after_cmd(
	tls: &mut rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
	cmd: &str,
) -> std::io::Result<String> {
	tls.write_all(cmd.as_bytes())?;
	tls.write_all(b"\r\n")?;
	tls.flush()?;
	read_full_response(tls)
}

/// Read a complete FTP response, handling multi-line (continuation) replies.
/// Returns the final (single-line) response. Multi-line replies are
/// consumed and discarded — the last line is returned.
fn read_full_response(stream: &mut impl Read) -> std::io::Result<String> {
	let first = read_line(stream)?;
	// Multi-line if 4th char is '-'.
	let bytes = first.as_bytes();
	if bytes.len() >= 4 && bytes[3] == b'-' {
		let code_bytes = &bytes[..3];
		loop {
			let line = read_line(stream)?;
			let line_bytes = line.as_bytes();
			// Final line: "<code> ..." (4th char is space).
			if line_bytes.len() >= 4 && &line_bytes[..3] == code_bytes && line_bytes[3] == b' ' {
				return Ok(line);
			}
		}
	} else {
		Ok(first)
	}
}

fn parse_pasv_port(resp: &str) -> Option<u16> {
	let open = resp.find('(')?;
	let close = resp.find(')')?;
	let nums: Vec<u16> = resp[open + 1..close]
		.split(',')
		.filter_map(|s| s.trim().parse().ok())
		.collect();
	if nums.len() != 6 {
		return None;
	}
	Some(nums[4] * 256 + nums[5])
}

/// Implicit FTPS: the control connection is TLS from the very first byte.
/// No AUTH TLS negotiation — the client wraps in TLS immediately on
/// connect. This tests the `implicit_tls: true` path in FtpSession::new.
#[test]
fn implicit_ftps_retr() {
	let dir = std::env::temp_dir().join("rcrm_implicit_ftps_test");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	let path = dir.join("secret.mp4");
	let original = deterministic_content(32 * 1024, 57);
	std::fs::write(&path, &original).unwrap();

	let key = deterministic_content(32, 57);
	let manager = Manager::new(true, true, 2048, is_supported_file, 6, Some(&key));
	let _ = manager.encrypt_file(&path).unwrap();
	drop(manager);

	let fixture = start_implicit_tls_server(dir.clone(), &key);

	// Connect and immediately wrap in TLS (implicit FTPS).
	let tcp = TcpStream::connect(fixture.addr).expect("connect failed");
	tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
	tcp.set_write_timeout(Some(Duration::from_secs(10)))
		.unwrap();

	let client_config = build_client_config();
	let server_name = ServerName::try_from("localhost").unwrap();
	let client_conn = rustls::ClientConnection::new(client_config, server_name)
		.map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
		.unwrap();
	let mut tls = rustls::StreamOwned::new(client_conn, tcp);

	// Read the 220 welcome — it arrives already TLS-encrypted.
	let welcome = read_line(&mut tls).unwrap();
	assert!(welcome.starts_with("220"), "welcome: {}", welcome);

	// FEAT must NOT advertise AUTH TLS (implicit mode, no upgrade possible).
	// Read the full multi-line response and verify no line mentions AUTH.
	let feat_resp = read_line_after_cmd(&mut tls, "FEAT").unwrap();
	assert!(feat_resp.starts_with("211"), "FEAT: {}", feat_resp);
	// The final line is "211 End"; we need to inspect the whole response.
	// Re-send FEAT and capture every line this time.
	tls.write_all(b"FEAT\r\n").unwrap();
	tls.flush().unwrap();
	let mut feat_lines = Vec::new();
	loop {
		let line = read_line(&mut tls).unwrap();
		let is_end = line.starts_with("211 ");
		feat_lines.push(line);
		if is_end {
			break;
		}
	}
	let all_feat = feat_lines.join("\n");
	assert!(
		!all_feat.contains("AUTH TLS"),
		"implicit FTPS FEAT must not advertise AUTH TLS: {}",
		all_feat
	);
	assert!(
		all_feat.contains("UTF8"),
		"FEAT should still advertise UTF8: {}",
		all_feat
	);

	// USER / PASS (anonymous).
	let user_resp = read_line_after_cmd(&mut tls, "USER anonymous").unwrap();
	assert!(user_resp.starts_with("230"), "USER: {}", user_resp);

	// TYPE I.
	let type_resp = read_line_after_cmd(&mut tls, "TYPE I").unwrap();
	assert!(type_resp.starts_with("200"), "TYPE: {}", type_resp);

	// SIZE.
	let size_resp = read_line_after_cmd(&mut tls, "SIZE secret.mp4").unwrap();
	assert!(size_resp.starts_with("213"), "SIZE: {}", size_resp);
	assert!(size_resp.contains(&format!("{}", original.len())));

	// PASV — data connection is also TLS (implicit FTPS defaults to PROT P).
	let pasv_resp = read_line_after_cmd(&mut tls, "PASV").unwrap();
	assert!(pasv_resp.starts_with("227"), "PASV: {}", pasv_resp);
	let port = parse_pasv_port(&pasv_resp).expect("parse PASV port");

	let data_tcp = TcpStream::connect(("127.0.0.1", port)).expect("data connect");
	data_tcp
		.set_read_timeout(Some(Duration::from_secs(30)))
		.unwrap();

	// RETR.
	tls.write_all(b"RETR secret.mp4\r\n").unwrap();
	tls.flush().unwrap();
	let retr_resp = read_line(&mut tls).unwrap();
	assert!(retr_resp.starts_with("150"), "RETR: {}", retr_resp);

	// Wrap data socket in TLS.
	let data_client_config = build_client_config();
	let data_server_name = ServerName::try_from("localhost").unwrap();
	let data_conn = rustls::ClientConnection::new(data_client_config, data_server_name)
		.map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
		.unwrap();
	let mut data_tls = rustls::StreamOwned::new(data_conn, data_tcp);

	let mut received = Vec::with_capacity(original.len());
	let n = data_tls.read_to_end(&mut received).expect("read data");
	assert_eq!(n, original.len(), "data length mismatch");
	assert_eq!(received, original, "data content mismatch");

	let done = read_line(&mut tls).unwrap();
	assert!(done.starts_with("226"), "226: {}", done);
}

/// Implicit FTPS: PROT C (clear data) must be rejected — the whole point
/// of implicit FTPS is end-to-end encryption.
#[test]
fn implicit_ftps_rejects_prot_c() {
	let dir = std::env::temp_dir().join("rcrm_implicit_ftps_protc_test");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	let key = deterministic_content(32, 88);
	let fixture = start_implicit_tls_server(dir.clone(), &key);

	let tcp = TcpStream::connect(fixture.addr).expect("connect failed");
	tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();

	let client_config = build_client_config();
	let server_name = ServerName::try_from("localhost").unwrap();
	let client_conn = rustls::ClientConnection::new(client_config, server_name).unwrap();
	let mut tls = rustls::StreamOwned::new(client_conn, tcp);

	let _ = read_line(&mut tls).unwrap(); // 220
	let _ = read_line_after_cmd(&mut tls, "USER anonymous").unwrap(); // 230

	// PROT C must be rejected with 534.
	let prot_resp = read_line_after_cmd(&mut tls, "PROT C").unwrap();
	assert!(
		prot_resp.starts_with("534"),
		"PROT C should be 534 in implicit FTPS, got: {}",
		prot_resp
	);

	// PROT P must succeed.
	let prot_p_resp = read_line_after_cmd(&mut tls, "PROT P").unwrap();
	assert!(prot_p_resp.starts_with("200"), "PROT P: {}", prot_p_resp);
}

/// Implicit FTPS: AUTH TLS must be rejected (already in TLS).
#[test]
fn implicit_ftps_rejects_auth_tls() {
	let dir = std::env::temp_dir().join("rcrm_implicit_ftps_authtls_test");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	let key = deterministic_content(32, 99);
	let fixture = start_implicit_tls_server(dir.clone(), &key);

	let tcp = TcpStream::connect(fixture.addr).expect("connect failed");
	tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();

	let client_config = build_client_config();
	let server_name = ServerName::try_from("localhost").unwrap();
	let client_conn = rustls::ClientConnection::new(client_config, server_name).unwrap();
	let mut tls = rustls::StreamOwned::new(client_conn, tcp);

	let _ = read_line(&mut tls).unwrap(); // 220

	let auth_resp = read_line_after_cmd(&mut tls, "AUTH TLS").unwrap();
	assert!(
		auth_resp.starts_with("503"),
		"AUTH TLS should be 503 in implicit FTPS, got: {}",
		auth_resp
	);
}
