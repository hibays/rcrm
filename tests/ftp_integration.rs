// tests/ftp_integration.rs
// End-to-end tests for the projection FTP server.
//
// These tests start a real FTP server on an ephemeral loopback port,
// connect with a minimal hand-rolled FTP client, and verify:
//   * LIST shows decrypted virtual names (not .b72 hash names)
//   * SIZE returns the virtual (original) size, not the on-disk size
//   * RETR streams the original plaintext byte-for-byte
//   * REST + RETR resumes from the given offset
//   * Write commands (STOR/DELE/MKD) are rejected with 550
//   * Plain (non-encrypted) files are served as-is
//   * Path traversal (..) is contained within the root

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rcrm::serve::{AuthConfig, FileCache, Server, ServerContext};
use rcrm::{Manager, SessionKey, is_supported_file};

// =======================
// Minimal FTP client
// =======================

struct FtpClient {
	control: TcpStream,
	reader: BufReader<TcpStream>,
}

impl FtpClient {
	fn connect(addr: SocketAddr) -> std::io::Result<Self> {
		let control = TcpStream::connect(addr)?;
		control.set_read_timeout(Some(Duration::from_secs(10)))?;
		control.set_write_timeout(Some(Duration::from_secs(10)))?;
		let reader_stream = control.try_clone()?;
		Ok(FtpClient {
			control,
			reader: BufReader::new(reader_stream),
		})
	}

	/// Read one FTP response line and return (code, message).
	fn read_response(&mut self) -> std::io::Result<(u16, String)> {
		let mut line = String::new();
		self.reader.read_line(&mut line)?;
		let line = line.trim_end_matches(['\r', '\n']);
		if line.len() < 4 {
			return Err(std::io::Error::new(
				std::io::ErrorKind::InvalidData,
				format!("short response: {:?}", line),
			));
		}
		// Multi-line responses use "code-" prefix; we only handle single-line
		// responses here (sufficient for our test commands).
		let code: u16 = line[..3].parse().map_err(|_| {
			std::io::Error::new(
				std::io::ErrorKind::InvalidData,
				format!("bad code in: {:?}", line),
			)
		})?;
		let msg = line[4..].to_string();
		Ok((code, msg))
	}

	fn cmd(&mut self, line: &str) -> std::io::Result<(u16, String)> {
		self.control.write_all(line.as_bytes())?;
		self.control.write_all(b"\r\n")?;
		self.control.flush()?;
		self.read_response()
	}

	/// Send PASV and connect to the returned data port. Returns the data
	/// stream.
	fn pasv_connect(&mut self) -> std::io::Result<TcpStream> {
		let (code, msg) = self.cmd("PASV")?;
		assert_eq!(code, 227, "PASV failed: {}", msg);
		// Parse "(h1,h2,h3,h4,p1,p2)"
		let open = msg.find('(').ok_or_else(|| {
			std::io::Error::new(
				std::io::ErrorKind::InvalidData,
				format!("no '(' in PASV: {}", msg),
			)
		})?;
		let close = msg.find(')').ok_or_else(|| {
			std::io::Error::new(
				std::io::ErrorKind::InvalidData,
				format!("no ')' in PASV: {}", msg),
			)
		})?;
		let nums: Vec<u16> = msg[open + 1..close]
			.split(',')
			.map(|s| s.trim().parse().unwrap())
			.collect();
		assert_eq!(nums.len(), 6, "PASV returned wrong tuple: {:?}", nums);
		let port = nums[4] * 256 + nums[5];
		let data_stream = TcpStream::connect(("127.0.0.1", port))?;
		data_stream.set_read_timeout(Some(Duration::from_secs(30)))?;
		Ok(data_stream)
	}
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
	_root: PathBuf,
}

impl Drop for ServerFixture {
	fn drop(&mut self) {
		self.shutdown.store(true, Ordering::Relaxed);
		if let Some(t) = self.thread.take() {
			let _ = t.join();
		}
	}
}

fn start_server(root: PathBuf, key: &[u8]) -> ServerFixture {
	let manager = Manager::new(true, true, 2048, is_supported_file, 6, Some(key));
	let session_key = Arc::new(SessionKey::generate());
	let ctx = ServerContext {
		root: root.clone(),
		manager: Arc::new(manager),
		session_key,
		cache: Arc::new(FileCache::new()),
		tls_config: None,
		require_tls: false,
		implicit_tls: false,
		protocol: rcrm::serve::Protocol::Ftp,
		max_connections: 8,
		auth: AuthConfig::no_auth(),
		idle_timeout: Duration::from_secs(60),
	};
	let server = Server::new(ctx, "127.0.0.1:0".parse().unwrap());
	let (listener, addr) = server.bind().expect("bind failed");
	let shutdown = Arc::new(AtomicBool::new(false));
	let shutdown_clone = Arc::clone(&shutdown);
	let thread = std::thread::spawn(move || server.serve(listener, shutdown_clone));
	// Give the server a moment to start accepting.
	std::thread::sleep(Duration::from_millis(100));
	ServerFixture {
		addr,
		shutdown,
		thread: Some(thread),
		_root: root,
	}
}

// =======================
// Tests
// =======================

#[test]
fn ftp_retr_projects_decrypted_content() {
	let dir = std::env::temp_dir().join("rcrm_ftp_test_retr");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	let path = dir.join("video.mp4");
	let original = deterministic_content(64 * 1024, 42);
	std::fs::write(&path, &original).unwrap();

	let key = deterministic_content(32, 7);
	let manager = Manager::new(true, true, 2048, is_supported_file, 6, Some(&key));
	let new_name = manager.encrypt_file(&path).expect("encrypt failed");
	drop(manager);
	assert!(rcrm::is_valid_encrypted_file_name(&new_name));

	let fixture = start_server(dir.clone(), &key);
	let mut client = FtpClient::connect(fixture.addr).expect("connect failed");

	// Read welcome.
	let (code, _) = client.read_response().expect("welcome");
	assert_eq!(code, 220);

	// Anonymous login.
	let (code, _) = client.cmd("USER anonymous").unwrap();
	assert_eq!(code, 230);

	// Binary mode.
	let (code, _) = client.cmd("TYPE I").unwrap();
	assert_eq!(code, 200);

	// SIZE should return the virtual (original) size.
	let (code, msg) = client.cmd("SIZE video.mp4").unwrap();
	assert_eq!(code, 213, "SIZE failed: {}", msg);
	assert_eq!(msg.trim(), format!("{}", original.len()));

	// RETR the file via PASV.
	let data_stream = client.pasv_connect().expect("PASV failed");
	let (code, msg) = client.cmd("RETR video.mp4").unwrap();
	assert_eq!(code, 150, "RETR failed: {}", msg);

	let mut data = data_stream;
	let mut received = Vec::with_capacity(original.len());
	let n = data.read_to_end(&mut received).expect("read data");
	assert_eq!(n, original.len());
	assert_eq!(received, original);

	// Expect 226 transfer complete.
	let (code, _) = client.read_response().expect("226");
	assert_eq!(code, 226);
}

#[test]
fn ftp_list_shows_decrypted_names() {
	let dir = std::env::temp_dir().join("rcrm_ftp_test_list");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	let path = dir.join("movie.mp4");
	std::fs::write(&path, deterministic_content(8192, 1)).unwrap();

	let key = deterministic_content(32, 9);
	let manager = Manager::new(true, true, 2048, is_supported_file, 6, Some(&key));
	let enc_name = manager.encrypt_file(&path).expect("encrypt failed");
	drop(manager);

	// The on-disk name should be a .b72 hash, NOT "movie.mp4".
	assert_ne!(enc_name, "movie.mp4");
	assert!(rcrm::is_valid_encrypted_file_name(&enc_name));

	let fixture = start_server(dir.clone(), &key);
	let mut client = FtpClient::connect(fixture.addr).expect("connect failed");
	let _ = client.read_response().unwrap(); // welcome
	let _ = client.cmd("USER anonymous").unwrap();
	let _ = client.cmd("TYPE I").unwrap();

	// LIST via PASV.
	let data_stream = client.pasv_connect().expect("PASV failed");
	let (code, msg) = client.cmd("LIST").unwrap();
	assert_eq!(code, 150, "LIST failed: {}", msg);

	let mut data = data_stream;
	let mut listing = String::new();
	data.read_to_string(&mut listing).expect("read listing");
	let _ = client.read_response(); // 226

	// The listing must contain "movie.mp4" (the decrypted name) and must
	// NOT contain the .b72 hash name.
	assert!(
		listing.contains("movie.mp4"),
		"listing missing decrypted name: {}",
		listing
	);
	assert!(
		!listing.contains(&enc_name),
		"listing should not contain encrypted name {}: {}",
		enc_name,
		listing
	);
}

#[test]
fn ftp_write_commands_rejected() {
	let dir = std::env::temp_dir().join("rcrm_ftp_test_write");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	let key = deterministic_content(32, 11);
	let fixture = start_server(dir.clone(), &key);
	let mut client = FtpClient::connect(fixture.addr).expect("connect failed");
	let _ = client.read_response().unwrap();
	let _ = client.cmd("USER anonymous").unwrap();

	// STOR — must be rejected.
	let (code, _) = client.cmd("STOR test.txt").unwrap();
	assert_eq!(code, 550, "STOR should be rejected with 550");

	// DELE — must be rejected.
	let (code, _) = client.cmd("DELE test.txt").unwrap();
	assert_eq!(code, 550, "DELE should be rejected with 550");

	// MKD — must be rejected.
	let (code, _) = client.cmd("MKD newdir").unwrap();
	assert_eq!(code, 550, "MKD should be rejected with 550");

	// RMD — must be rejected.
	let (code, _) = client.cmd("RMD newdir").unwrap();
	assert_eq!(code, 550, "RMD should be rejected with 550");

	// RNFR — must be rejected.
	let (code, _) = client.cmd("RNFR test.txt").unwrap();
	assert_eq!(code, 550, "RNFR should be rejected with 550");
}

#[test]
fn ftp_rest_resume() {
	let dir = std::env::temp_dir().join("rcrm_ftp_test_rest");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	let path = dir.join("resume.mp4");
	let original = deterministic_content(32 * 1024, 5);
	std::fs::write(&path, &original).unwrap();

	let key = deterministic_content(32, 13);
	let manager = Manager::new(true, true, 2048, is_supported_file, 6, Some(&key));
	let _ = manager.encrypt_file(&path).unwrap();
	drop(manager);

	let fixture = start_server(dir.clone(), &key);
	let mut client = FtpClient::connect(fixture.addr).expect("connect failed");
	let _ = client.read_response().unwrap();
	let _ = client.cmd("USER anonymous").unwrap();
	let _ = client.cmd("TYPE I").unwrap();

	// REST at offset 10000, then RETR.
	let offset: u64 = 10000;
	let (code, _) = client.cmd(&format!("REST {}", offset)).unwrap();
	assert_eq!(code, 350);

	let data_stream = client.pasv_connect().expect("PASV failed");
	let (code, msg) = client.cmd("RETR resume.mp4").unwrap();
	assert_eq!(code, 150, "RETR after REST failed: {}", msg);

	let mut data = data_stream;
	let mut received = Vec::new();
	data.read_to_end(&mut received).expect("read data");
	let _ = client.read_response(); // 226

	// Should receive original[10000..].
	let expected = &original[offset as usize..];
	assert_eq!(received.len(), expected.len());
	assert_eq!(received.as_slice(), expected);
}

#[test]
fn ftp_plain_file_served_as_is() {
	let dir = std::env::temp_dir().join("rcrm_ftp_test_plain");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	// A plain (non-encrypted) file with a non-media extension so it won't
	// be picked up by the encryption rule_fn.
	let plain_path = dir.join("notes.txt");
	let plain_content = b"hello, this is a plain text file\r\n".to_vec();
	std::fs::write(&plain_path, &plain_content).unwrap();

	let key = deterministic_content(32, 17);
	let fixture = start_server(dir.clone(), &key);
	let mut client = FtpClient::connect(fixture.addr).expect("connect failed");
	let _ = client.read_response().unwrap();
	let _ = client.cmd("USER anonymous").unwrap();
	let _ = client.cmd("TYPE I").unwrap();

	// SIZE.
	let (code, msg) = client.cmd("SIZE notes.txt").unwrap();
	assert_eq!(code, 213, "SIZE plain: {}", msg);
	assert_eq!(msg.trim(), format!("{}", plain_content.len()));

	// RETR.
	let data_stream = client.pasv_connect().expect("PASV failed");
	let (code, msg) = client.cmd("RETR notes.txt").unwrap();
	assert_eq!(code, 150, "RETR plain: {}", msg);

	let mut data = data_stream;
	let mut received = Vec::new();
	data.read_to_end(&mut received).expect("read");
	let _ = client.read_response();
	assert_eq!(received, plain_content);
}

#[test]
fn ftp_path_traversal_contained() {
	let dir = std::env::temp_dir().join("rcrm_ftp_test_traversal");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	let key = deterministic_content(32, 19);
	let fixture = start_server(dir.clone(), &key);
	let mut client = FtpClient::connect(fixture.addr).expect("connect failed");
	let _ = client.read_response().unwrap();
	let _ = client.cmd("USER anonymous").unwrap();
	let _ = client.cmd("TYPE I").unwrap();

	// Try to escape the root via CWD ../../../etc and then RETR something.
	let (code, _) = client.cmd("CWD ../../..").unwrap();
	assert_eq!(code, 250); // CWD succeeds but stays at root

	// PWD should show "/" (root), not an escaped path.
	let (code, msg) = client.cmd("PWD").unwrap();
	assert_eq!(code, 257);
	assert!(msg.contains("\"/\""), "PWD should be at root: {}", msg);

	// SIZE on a path that would be outside root — must fail.
	let (code, _) = client.cmd("SIZE ../../../etc/passwd").unwrap();
	assert_eq!(code, 550, "traversal SIZE should be 550");
}

#[test]
fn ftp_size_returns_virtual_size_not_disk_size() {
	let dir = std::env::temp_dir().join("rcrm_ftp_test_size");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	let path = dir.join("sized.mp4");
	let original = deterministic_content(64 * 1024, 23);
	std::fs::write(&path, &original).unwrap();

	let key = deterministic_content(32, 23);
	let manager = Manager::new(true, true, 2048, is_supported_file, 6, Some(&key));
	let enc_name = manager.encrypt_file(&path).expect("encrypt failed");
	drop(manager);

	let enc_path = dir.join(&enc_name);
	let disk_size = std::fs::metadata(&enc_path).unwrap().len();
	// On-disk size is larger than virtual (original) size due to the header.
	assert!(disk_size > original.len() as u64);

	let fixture = start_server(dir.clone(), &key);
	let mut client = FtpClient::connect(fixture.addr).expect("connect failed");
	let _ = client.read_response().unwrap();
	let _ = client.cmd("USER anonymous").unwrap();

	// SIZE on the virtual name should return the original size, not disk size.
	let (code, msg) = client.cmd("SIZE sized.mp4").unwrap();
	assert_eq!(code, 213, "SIZE: {}", msg);
	assert_eq!(
		msg.trim(),
		format!("{}", original.len()),
		"SIZE should return virtual size {}, got {}",
		original.len(),
		msg.trim()
	);
}

#[test]
fn ftp_quit_disconnects() {
	let dir = std::env::temp_dir().join("rcrm_ftp_test_quit");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	let key = deterministic_content(32, 29);
	let fixture = start_server(dir.clone(), &key);
	let mut client = FtpClient::connect(fixture.addr).expect("connect failed");
	let _ = client.read_response().unwrap();
	let _ = client.cmd("USER anonymous").unwrap();

	let (code, _) = client.cmd("QUIT").unwrap();
	assert_eq!(code, 221);

	// Connection should be closed by the server.
	let mut buf = [0u8; 1];
	let result = client.reader.read(&mut buf);
	assert!(
		result.is_err() || result.unwrap() == 0,
		"server should close after QUIT"
	);
}

/// When the directory has NO encrypted files, the server should start
/// without any encryption password and serve plain files normally.
/// This tests the "no encrypted files → no password needed" branch of
/// run_serve (simulated here by building the context with a keyless
/// manager, exactly as run_serve does).
#[test]
fn ftp_serves_plain_files_without_encryption_password() {
	let dir = std::env::temp_dir().join("rcrm_ftp_test_nopass");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	// Only a plain text file — no encrypted files at all.
	let plain_content = b"plain content -- no password needed".to_vec();
	std::fs::write(dir.join("readme.txt"), &plain_content).unwrap();

	// Build a manager with NO key, exactly as run_serve does when
	// enc_files.is_empty().
	let manager = Manager::new(true, true, 2048, is_supported_file, 6, None);
	let session_key = Arc::new(SessionKey::generate());
	let ctx = ServerContext {
		root: dir.clone(),
		manager: Arc::new(manager),
		session_key,
		cache: Arc::new(FileCache::new()),
		tls_config: None,
		require_tls: false,
		implicit_tls: false,
		protocol: rcrm::serve::Protocol::Ftp,
		max_connections: 8,
		auth: AuthConfig::no_auth(),
		idle_timeout: Duration::from_secs(60),
	};
	let server = Server::new(ctx, "127.0.0.1:0".parse().unwrap());
	let (listener, addr) = server.bind().expect("bind failed");
	let shutdown = Arc::new(AtomicBool::new(false));
	let shutdown_clone = Arc::clone(&shutdown);
	let _thread = std::thread::spawn(move || server.serve(listener, shutdown_clone));
	std::thread::sleep(Duration::from_millis(100));

	let mut client = FtpClient::connect(addr).expect("connect failed");
	let _ = client.read_response().unwrap(); // welcome
	let _ = client.cmd("USER anonymous").unwrap();
	let _ = client.cmd("TYPE I").unwrap();

	// LIST should show the plain file.
	let data_stream = client.pasv_connect().expect("PASV failed");
	let (code, _) = client.cmd("LIST").unwrap();
	assert_eq!(code, 150);
	let mut data = data_stream;
	let mut listing = String::new();
	data.read_to_string(&mut listing).expect("read listing");
	let _ = client.read_response(); // 226
	assert!(listing.contains("readme.txt"), "listing: {}", listing);

	// RETR should return the plain content.
	let data_stream = client.pasv_connect().expect("PASV failed");
	let (code, _) = client.cmd("RETR readme.txt").unwrap();
	assert_eq!(code, 150);
	let mut data = data_stream;
	let mut received = Vec::new();
	data.read_to_end(&mut received).expect("read");
	let _ = client.read_response(); // 226
	assert_eq!(received, plain_content);

	shutdown.store(true, Ordering::Relaxed);
	std::fs::remove_dir_all(&dir).unwrap();
}

// Silence unused import warnings.
#[allow(dead_code)]
fn _to_socket_addrs(host: &str) -> Vec<SocketAddr> {
	host.to_socket_addrs().unwrap().collect()
}

/// Regression test for the PASV bind-address bug. Previously PASV/EPSV
/// bound the data listener to `self.addr.ip()` (the *client's* IP), which
/// fails with WSAEADDRNOTAVAIL (10049) when the client is on another host.
///
/// This test binds the server to `0.0.0.0` and connects via the loopback
/// alias `127.0.0.2` (on Windows/Unix the entire 127/8 range is loopback).
/// The PASV 227 response must advertise the server-side local IP
/// (127.0.0.2, the address the client actually used) and the data
/// connection must succeed — proving the listener was bound to the right
/// address. Before the fix, binding to the client IP happened to work on
/// 127.0.0.1 (because client == server IP) but failed on any other IP.
#[test]
fn ftp_pasv_advertises_correct_ip_on_non_default_loopback() {
	let dir = std::env::temp_dir().join("rcrm_ftp_test_pasv_ip");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();
	std::fs::write(dir.join("a.txt"), b"hello").unwrap();

	let key = deterministic_content(32, 71);
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
		protocol: rcrm::serve::Protocol::Ftp,
		max_connections: 8,
		auth: AuthConfig::no_auth(),
		idle_timeout: Duration::from_secs(60),
	};
	// Bind to 0.0.0.0 so the client can connect via 127.0.0.2.
	let server = Server::new(ctx, "0.0.0.0:0".parse().unwrap());
	let (listener, _) = server.bind().expect("bind failed");
	let bound_port = listener.local_addr().unwrap().port();
	let shutdown = Arc::new(AtomicBool::new(false));
	let shutdown_clone = Arc::clone(&shutdown);
	let _thread = std::thread::spawn(move || server.serve(listener, shutdown_clone));
	std::thread::sleep(Duration::from_millis(100));

	// Connect via the 127.0.0.2 loopback alias.
	let client_addr: SocketAddr = format!("127.0.0.2:{}", bound_port).parse().unwrap();
	let mut client = FtpClient::connect(client_addr).expect("connect failed");
	let _ = client.read_response().unwrap(); // welcome
	let _ = client.cmd("USER anonymous").unwrap();
	let _ = client.cmd("TYPE I").unwrap();

	// PASV — the 227 response must advertise 127.0.0.2 (the server-side
	// local IP of the control connection), NOT 127.0.0.1.
	let (code, msg) = client.cmd("PASV").unwrap();
	assert_eq!(code, 227, "PASV: {}", msg);
	// Parse "(h1,h2,h3,h4,p1,p2)"
	let open = msg.find('(').expect("no ( in PASV");
	let close = msg.find(')').expect("no ) in PASV");
	let nums: Vec<u8> = msg[open + 1..close]
		.split(',')
		.filter_map(|s| s.trim().parse().ok())
		.collect();
	assert_eq!(nums.len(), 6, "PASV tuple: {:?}", nums);
	assert_eq!(
		&nums[..4],
		&[127, 0, 0, 2],
		"PASV must advertise the server-side local IP 127.0.0.2, got {}.{}.{}.{}",
		nums[0],
		nums[1],
		nums[2],
		nums[3]
	);
	let data_port = (nums[4] as u16) * 256 + nums[5] as u16;

	// Data connection to 127.0.0.2:data_port must succeed — this is what
	// failed with 10049 before the fix when client and server IPs differed.
	let mut data = TcpStream::connect(("127.0.0.2", data_port)).expect("data connect");
	let (code, _) = client.cmd("RETR a.txt").unwrap();
	assert_eq!(code, 150);
	let mut received = Vec::new();
	data.read_to_end(&mut received).expect("read data");
	let _ = client.read_response(); // 226
	assert_eq!(received, b"hello");

	shutdown.store(true, Ordering::Relaxed);
	std::fs::remove_dir_all(&dir).unwrap();
}
