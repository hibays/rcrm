// RFC 2577 peer checks for the passive data channel.
// Test patterns adapted from Cloudinvoke/libunftp tests/common.rs,
// tests/list.rs and crates/unftp-sbe-fs/tests/main.rs (parse_pasv, "connect
// the data socket after the 150 reply"). libunftp implements the same-host
// rule in src/server/datachan.rs:631-658 but has no test for it.
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rcrm::serve::{AuthConfig, FileCache, Server, ServerContext, generate_mount_names};
use rcrm::{Manager, SessionKey, is_supported_file};

#[cfg(windows)]
mod source_bind {
	use std::mem::size_of;
	use std::net::{SocketAddrV4, TcpStream};
	use std::os::windows::io::FromRawSocket;

	#[repr(C)]
	struct SockAddrIn {
		sin_family: u16,
		sin_port: u16,
		sin_addr: u32,
		sin_zero: [u8; 8],
	}

	#[link(name = "Ws2_32")]
	unsafe extern "system" {
		#[link_name = "socket"]
		fn ws_socket(af: i32, ty: i32, protocol: i32) -> usize;
		#[link_name = "bind"]
		fn ws_bind(s: usize, addr: *const SockAddrIn, len: i32) -> i32;
		#[link_name = "connect"]
		fn ws_connect(s: usize, addr: *const SockAddrIn, len: i32) -> i32;
		#[link_name = "closesocket"]
		fn ws_closesocket(s: usize) -> i32;
	}

	fn sockaddr(addr: SocketAddrV4) -> SockAddrIn {
		SockAddrIn {
			sin_family: 2, // AF_INET
			sin_port: addr.port().to_be(),
			sin_addr: u32::from_ne_bytes(addr.ip().octets()),
			sin_zero: [0; 8],
		}
	}

	/// Open a TCP connection with a chosen local source address.
	pub fn connect_from(source: SocketAddrV4, target: SocketAddrV4) -> Option<TcpStream> {
		unsafe {
			let s = ws_socket(2, 1, 6); // AF_INET, SOCK_STREAM, IPPROTO_TCP
			if s == usize::MAX {
				return None;
			}
			let local = sockaddr(source);
			if ws_bind(s, &local, size_of::<SockAddrIn>() as i32) != 0 {
				ws_closesocket(s);
				return None;
			}
			let remote = sockaddr(target);
			if ws_connect(s, &remote, size_of::<SockAddrIn>() as i32) != 0 {
				ws_closesocket(s);
				return None;
			}
			Some(TcpStream::from_raw_socket(s as u64))
		}
	}
}

struct FtpClient {
	control: TcpStream,
	reader: BufReader<TcpStream>,
}

impl FtpClient {
	fn connect(addr: SocketAddr) -> Self {
		let control = TcpStream::connect(addr).unwrap();
		control
			.set_read_timeout(Some(Duration::from_secs(10)))
			.unwrap();
		let reader = BufReader::new(control.try_clone().unwrap());
		FtpClient { control, reader }
	}

	fn read_response(&mut self) -> (u16, String) {
		let mut line = String::new();
		self.reader.read_line(&mut line).unwrap();
		let line = line.trim_end_matches(['\r', '\n']);
		assert!(line.len() >= 4, "short response: {line:?}");
		(line[..3].parse().unwrap(), line[4..].to_string())
	}

	fn cmd(&mut self, line: &str) -> (u16, String) {
		self.control.write_all(line.as_bytes()).unwrap();
		self.control.write_all(b"\r\n").unwrap();
		self.control.flush().unwrap();
		self.read_response()
	}

	/// Adapted from libunftp's parse_pasv helper.
	fn pasv_addr(&mut self) -> SocketAddrV4 {
		let (code, msg) = self.cmd("PASV");
		assert_eq!(code, 227, "PASV failed: {msg}");
		let body = msg
			.split_once('(')
			.and_then(|(_, r)| r.split_once(')'))
			.unwrap()
			.0;
		let nums: Vec<u16> = body.split(',').map(|s| s.trim().parse().unwrap()).collect();
		assert_eq!(nums.len(), 6, "PASV tuple: {nums:?}");
		let ip =
			std::net::Ipv4Addr::new(nums[0] as u8, nums[1] as u8, nums[2] as u8, nums[3] as u8);
		SocketAddrV4::new(ip, nums[4] * 256 + nums[5])
	}
}

struct Fixture {
	addr: SocketAddr,
	shutdown: Arc<AtomicBool>,
	thread: Option<std::thread::JoinHandle<std::io::Result<()>>>,
	_root: PathBuf,
}

impl Drop for Fixture {
	fn drop(&mut self) {
		self.shutdown.store(true, Ordering::Relaxed);
		if let Some(t) = self.thread.take() {
			let _ = t.join();
		}
	}
}

fn start_server(root: PathBuf) -> Fixture {
	let manager = Manager::new(true, true, 2048, is_supported_file, 6, Some(b"key"));
	let ctx = ServerContext {
		mounts: generate_mount_names(std::slice::from_ref(&root)),
		manager: Arc::new(manager),
		session_key: Arc::new(SessionKey::generate().expect("mlock failed")),
		cache: Arc::new(FileCache::new()),
		tls_config: None,
		implicit_tls: false,
		protocol: rcrm::serve::Protocol::Ftp,
		max_connections: 8,
		auth: AuthConfig::no_auth(),
		idle_timeout: Duration::from_secs(30),
	};
	let server = Server::new(ctx, "0.0.0.0:0".parse().unwrap());
	let (listener, addr) = server.bind().unwrap();
	let shutdown = Arc::new(AtomicBool::new(false));
	let thread = std::thread::spawn({
		let shutdown = Arc::clone(&shutdown);
		move || server.serve(listener, shutdown)
	});
	std::thread::sleep(Duration::from_millis(100));
	Fixture {
		addr,
		shutdown,
		thread: Some(thread),
		_root: root,
	}
}

fn tmp(name: &str) -> PathBuf {
	let dir = std::env::temp_dir().join(format!("rcrm_ftp_peer_{}_{}", std::process::id(), name));
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();
	dir
}

#[test]
fn ftp_same_host_other_port_data_connection_is_accepted() {
	let dir = tmp("same_host");
	std::fs::write(dir.join("a.txt"), b"HELLO-SAME-HOST").unwrap();
	let fixture = start_server(dir);
	let mut client = FtpClient::connect(SocketAddr::from(([127, 0, 0, 1], fixture.addr.port())));
	let _ = client.read_response(); // 220
	client.cmd("USER anonymous");
	client.cmd("TYPE I");
	let data_addr = client.pasv_addr();
	assert_eq!(client.cmd("LIST"), (150, "Opening data connection".into()));
	let mut data = TcpStream::connect(data_addr).unwrap();
	data.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
	let mut bytes = Vec::new();
	data.read_to_end(&mut bytes).unwrap();
	assert!(
		String::from_utf8_lossy(&bytes).contains("a.txt"),
		"{:?}",
		String::from_utf8_lossy(&bytes)
	);
	assert_eq!(client.read_response().0, 226);
}

#[test]
#[cfg(windows)]
fn ftp_foreign_source_ip_data_connection_is_refused() {
	use source_bind::connect_from;

	let dir = tmp("foreign_ip");
	std::fs::write(dir.join("a.txt"), b"HELLO-FOREIGN").unwrap();
	let fixture = start_server(dir);
	let mut client = FtpClient::connect(SocketAddr::from(([127, 0, 0, 1], fixture.addr.port())));
	let _ = client.read_response(); // 220
	client.cmd("USER anonymous");
	client.cmd("TYPE I");
	let data_addr = client.pasv_addr();
	assert_eq!(client.cmd("LIST").0, 150);

	// Data peer from 127.0.0.2 while the control peer is 127.0.0.1.
	let mut foreign = connect_from(SocketAddrV4::new([127, 0, 0, 2].into(), 0), data_addr)
		.expect("bind data socket to 127.0.0.2 (loopback aliases must exist)");
	foreign
		.set_read_timeout(Some(Duration::from_secs(2)))
		.unwrap();
	let mut buf = [0u8; 128];
	let n = foreign.read(&mut buf).unwrap_or(0);
	assert_eq!(
		n, 0,
		"a foreign data peer must be dropped without any listing bytes"
	);

	// The server must still serve the legitimate client afterwards.
	let mut data = TcpStream::connect(data_addr).unwrap();
	data.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
	let mut bytes = Vec::new();
	data.read_to_end(&mut bytes).unwrap();
	assert!(
		String::from_utf8_lossy(&bytes).contains("a.txt"),
		"{:?}",
		String::from_utf8_lossy(&bytes)
	);
	assert_eq!(client.read_response().0, 226);
}
