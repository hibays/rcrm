// tests/perf_probe.rs
// Performance probes for the Rust side.
//
// These are NOT part of the normal gate — every probe is `#[ignore]`d so
// `cargo test` skips it. Run them explicitly:
//
//     cargo test --release --test perf_probe -- --ignored --nocapture
//
// Each probe prints one "PROBE <name>: <value>" line so the numbers can be
// diffed across runs. Keep them allocation-light and wall-clock based; the
// point is to catch regressions in the cold-launch path (KDF + scan +
// header verification) and in the streaming path (I/O + ChaCha20).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

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

fn scratch(name: &str) -> PathBuf {
	let dir = std::env::temp_dir().join(format!("rcrm_perf_{}", name));
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();
	dir
}

/// The KDF cost of one password — Argon2id(m=32MiB, t=7, p=4).
fn measure_kdf() {
	let key = deterministic_content(32, 7);
	let mut runs = Vec::new();
	for _ in 0..3 {
		let t0 = Instant::now();
		let m = Manager::new(true, true, 2048, is_supported_file, 6, Some(&key));
		let dt = t0.elapsed();
		drop(m);
		runs.push(dt);
	}
	let best = runs.iter().min().unwrap();
	let mean: Duration = runs.iter().sum::<Duration>() / runs.len() as u32;
	println!(
		"PROBE kdf_argon2id: best={:.1}ms mean={:.1}ms (m=32MiB t=7 p=4)",
		best.as_secs_f64() * 1000.0,
		mean.as_secs_f64() * 1000.0
	);
}

/// Cold launch, step 2 + step 3 of the bridge's `start()`: two `build_manager`
/// calls, each of which re-derives every key from scratch.
fn measure_double_manager() {
	let key = deterministic_content(32, 7);
	let t0 = Instant::now();
	let m1 = Manager::new(true, true, 2048, is_supported_file, 6, Some(&key));
	let t1 = t0.elapsed();
	drop(m1);
	let t0 = Instant::now();
	let m2 = Manager::new(true, true, 2048, is_supported_file, 6, Some(&key));
	let t2 = t0.elapsed();
	drop(m2);
	println!(
		"PROBE build_manager_x2: first={:.1}ms second={:.1}ms total={:.1}ms",
		t1.as_secs_f64() * 1000.0,
		t2.as_secs_f64() * 1000.0,
		(t1 + t2).as_secs_f64() * 1000.0
	);
}

/// The bridge's startup verification pass: open every encrypted file and
/// check its header against every registered key.
fn measure_verify_pass(file_count: usize) {
	let dir = scratch("verify");
	let key = deterministic_content(32, 11);
	let manager = Manager::new(true, true, 2048, is_supported_file, 6, Some(&key));
	for i in 0..file_count {
		let p = dir.join(format!("clip{:05}.mp4", i));
		std::fs::write(&p, deterministic_content(4096, i as u8)).unwrap();
		manager.encrypt_file(&p).unwrap();
	}
	let paths: Vec<PathBuf> = std::fs::read_dir(&dir)
		.unwrap()
		.flatten()
		.map(|e| e.path())
		.collect();

	let t0 = Instant::now();
	let mut ok = 0usize;
	for fp in &paths {
		let hit = std::fs::File::open(fp)
			.ok()
			.and_then(|mut f| manager.read_file_header_any_key(&mut f).ok())
			.is_some();
		if hit {
			ok += 1;
		}
	}
	let dt = t0.elapsed();
	println!(
		"PROBE verify_headers: {} files in {:.1}ms ({:.2}ms/file, ok={})",
		paths.len(),
		dt.as_secs_f64() * 1000.0,
		dt.as_secs_f64() * 1000.0 / paths.len().max(1) as f64,
		ok
	);
}

/// Projected read throughput: `read_at_with` in 64 KiB chunks, which is what
/// both the WebDAV and FTP transfer loops do.
fn measure_projected_read(label: &str, calibration: i32, size: usize) {
	let dir = scratch(label);
	let path = dir.join("movie.mp4");
	std::fs::write(&path, deterministic_content(size, 3)).unwrap();
	let key = deterministic_content(32, 13);
	let manager = Manager::new(true, true, calibration, is_supported_file, 6, Some(&key));
	manager.encrypt_file(&path).unwrap();
	drop(manager);

	let manager = Manager::new(true, true, calibration, is_supported_file, 6, Some(&key));
	let session_key = SessionKey::generate().unwrap();
	let enc_path = std::fs::read_dir(&dir)
		.unwrap()
		.flatten()
		.map(|e| e.path())
		.find(|p| {
			p.file_name()
				.and_then(|n| n.to_str())
				.map(rcrm::is_valid_encrypted_file_name)
				.unwrap_or(false)
		})
		.expect("encrypted file");

	let pf = rcrm::ProjectedFile::open(&enc_path, &manager, &session_key).unwrap();
	let mut f = std::fs::File::open(&enc_path).unwrap();

	// Warm the cache so we measure steady-state, not first-touch disk I/O.
	let mut warm = vec![0u8; 64 * 1024];
	pf.read_at_with(&mut f, 0, &mut warm, &session_key).unwrap();

	let mut buf = vec![0u8; 64 * 1024];
	let mut sent = 0u64;
	let t0 = Instant::now();
	while sent < size as u64 {
		let want = std::cmp::min(buf.len() as u64, size as u64 - sent) as usize;
		let n = pf
			.read_at_with(&mut f, sent, &mut buf[..want], &session_key)
			.unwrap();
		if n == 0 {
			break;
		}
		sent += n as u64;
	}
	let dt = t0.elapsed();
	let secs = dt.as_secs_f64();
	println!(
		"PROBE projected_read[{label}]: {} MiB in {:.1}ms = {:.0} MiB/s ({:.2} GB/s)",
		size as f64 / (1024.0 * 1024.0),
		secs * 1000.0,
		(size as f64 / (1024.0 * 1024.0)) / secs,
		(size as f64 / 1e9) / secs
	);
}

/// The same loop over a PLAIN file — the I/O-only baseline, so the difference
/// against `projected_read` is the crypto + projection overhead.
fn measure_plain_read(size: usize) {
	let dir = scratch("plain");
	let path = dir.join("movie.mp4");
	std::fs::write(&path, deterministic_content(size, 3)).unwrap();
	let mut f = std::fs::File::open(&path).unwrap();
	let mut buf = vec![0u8; 64 * 1024];
	let mut sent = 0u64;
	let t0 = Instant::now();
	while sent < size as u64 {
		let want = std::cmp::min(buf.len() as u64, size as u64 - sent) as usize;
		let n = f.read(&mut buf[..want]).unwrap();
		if n == 0 {
			break;
		}
		sent += n as u64;
	}
	let dt = t0.elapsed();
	let secs = dt.as_secs_f64();
	println!(
		"PROBE plain_read: {} MiB in {:.1}ms = {:.0} MiB/s",
		size as f64 / (1024.0 * 1024.0),
		secs * 1000.0,
		(size as f64 / (1024.0 * 1024.0)) / secs
	);
}

struct ServerFixture {
	addr: SocketAddr,
	shutdown: Arc<AtomicBool>,
}

impl Drop for ServerFixture {
	fn drop(&mut self) {
		self.shutdown.store(true, Ordering::Relaxed);
	}
}

fn start_webdav_server(root: PathBuf, key: &[u8]) -> ServerFixture {
	let manager = Manager::new(true, true, 2048, is_supported_file, 6, Some(key));
	let session_key = Arc::new(SessionKey::generate().expect("mlock failed"));
	let ctx = ServerContext {
		mounts: generate_mount_names(&[root]),
		manager: Arc::new(manager),
		session_key,
		cache: Arc::new(FileCache::new()),
		tls_config: None,
		implicit_tls: false,
		protocol: Protocol::WebDav,
		max_connections: 16,
		auth: AuthConfig::no_auth(),
		idle_timeout: Duration::from_secs(60),
	};
	let server = Server::new(ctx, "127.0.0.1:0".parse().unwrap());
	let (listener, addr) = server.bind().expect("bind failed");
	let shutdown = Arc::new(AtomicBool::new(false));
	let shutdown_clone = Arc::clone(&shutdown);
	std::thread::spawn(move || server.serve(listener, shutdown_clone));
	std::thread::sleep(Duration::from_millis(150));
	ServerFixture { addr, shutdown }
}

/// Round-trip latency of one small WebDAV request, with `pad` extra header
/// bytes. The server reads the request head ONE BYTE AT A TIME
/// (`read_until_double_crlf`), so latency should grow linearly with the
/// header size — this probe quantifies that slope.
fn measure_webdav_latency(pad: usize, iters: usize) {
	let dir = scratch("latency");
	std::fs::write(dir.join("a.mp4"), deterministic_content(1024, 1)).unwrap();
	let key = deterministic_content(32, 17);
	let fixture = start_webdav_server(dir.clone(), &key);

	let padding = "x".repeat(pad);
	let req = format!(
		"PROPFIND / HTTP/1.1\r\nHost: localhost\r\nX-Pad: {}\r\nConnection: close\r\n\r\n",
		padding
	);

	// Warm up (accept path, DNS-less connect, first-touch of the mount).
	for _ in 0..3 {
		let mut s = TcpStream::connect(fixture.addr).unwrap();
		s.write_all(req.as_bytes()).unwrap();
		let mut sink = Vec::new();
		let _ = s.read_to_end(&mut sink);
	}

	let mut total = Duration::ZERO;
	for _ in 0..iters {
		let t0 = Instant::now();
		let mut s = TcpStream::connect(fixture.addr).unwrap();
		s.write_all(req.as_bytes()).unwrap();
		let mut sink = Vec::new();
		let _ = s.read_to_end(&mut sink);
		total += t0.elapsed();
	}
	let mean = total.as_secs_f64() * 1000.0 / iters as f64;
	println!(
		"PROBE webdav_latency[pad={pad}]: mean={:.3}ms over {iters} requests",
		mean
	);
}

/// Same request, but over ONE keep-alive connection: the second and later
/// requests skip the accept path entirely. The difference between this and
/// `webdav_latency` is the cost of the server's accept poll.
fn measure_webdav_latency_keepalive(pad: usize, iters: usize) {
	let dir = scratch("latency_ka");
	std::fs::write(dir.join("a.mp4"), deterministic_content(1024, 1)).unwrap();
	let key = deterministic_content(32, 17);
	let fixture = start_webdav_server(dir.clone(), &key);

	let padding = "x".repeat(pad);
	let req = format!(
		"PROPFIND / HTTP/1.1\r\nHost: localhost\r\nX-Pad: {}\r\nContent-Length: 0\r\n\r\n",
		padding
	);

	let mut s = TcpStream::connect(fixture.addr).unwrap();
	s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();

	let mut total = Duration::ZERO;
	for _ in 0..iters {
		let t0 = Instant::now();
		s.write_all(req.as_bytes()).unwrap();
		// Read one response: headers + Content-Length body.
		let mut head = Vec::new();
		let mut b = [0u8; 1];
		loop {
			let n = s.read(&mut b).unwrap();
			if n == 0 {
				break;
			}
			head.push(b[0]);
			if head.len() >= 4 && &head[head.len() - 4..] == b"\r\n\r\n" {
				break;
			}
		}
		let head_str = String::from_utf8_lossy(&head);
		let cl: usize = head_str
			.lines()
			.find_map(|l| {
				l.split_once(':').and_then(|(k, v)| {
					if k.eq_ignore_ascii_case("content-length") {
						v.trim().parse().ok()
					} else {
						None
					}
				})
			})
			.unwrap_or(0);
		if cl > 0 {
			let mut body = vec![0u8; cl];
			s.read_exact(&mut body).unwrap();
		}
		total += t0.elapsed();
	}
	let mean = total.as_secs_f64() * 1000.0 / iters as f64;
	println!(
		"PROBE webdav_latency_keepalive[pad={pad}]: mean={:.3}ms over {iters} requests",
		mean
	);
}

/// Full GET throughput over loopback TCP for a projected file.
fn measure_webdav_get(size: usize) {
	let dir = scratch("get");
	let path = dir.join("movie.mp4");
	std::fs::write(&path, deterministic_content(size, 5)).unwrap();
	let key = deterministic_content(32, 19);
	let manager = Manager::new(true, true, 2048, is_supported_file, 6, Some(&key));
	manager.encrypt_file(&path).unwrap();
	drop(manager);

	let fixture = start_webdav_server(dir.clone(), &key);
	let mut s = TcpStream::connect(fixture.addr).unwrap();
	s.set_read_timeout(Some(Duration::from_secs(120))).unwrap();
	let req = "GET /movie.mp4 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
	let t0 = Instant::now();
	s.write_all(req.as_bytes()).unwrap();
	let mut got = 0usize;
	let mut buf = vec![0u8; 256 * 1024];
	loop {
		let n = s.read(&mut buf).unwrap();
		if n == 0 {
			break;
		}
		got += n;
	}
	let dt = t0.elapsed();
	let secs = dt.as_secs_f64();
	println!(
		"PROBE webdav_get: {} MiB wire in {:.1}ms = {:.0} MiB/s ({} bytes received)",
		size as f64 / (1024.0 * 1024.0),
		secs * 1000.0,
		(size as f64 / (1024.0 * 1024.0)) / secs,
		got
	);
}

/// The directory scan that a cold start does first: walk the tree and
/// classify every entry.
fn measure_scan(file_count: usize) {
	let dir = scratch("scan");
	// A two-level tree: 10 sub-dirs x (file_count/10) files.
	let per_dir = (file_count / 10).max(1);
	for d in 0..10 {
		let sub = dir.join(format!("d{:02}", d));
		std::fs::create_dir_all(&sub).unwrap();
		for i in 0..per_dir {
			std::fs::write(sub.join(format!("clip{:05}.mp4", i)), b"x").unwrap();
		}
	}
	// Warm the directory cache first, then take the best of three — the
	// first pass would otherwise measure cold-cache metadata fetches.
	for _ in 0..2 {
		let _ = rcrm::resolve_ne_path_from_dir_with_progress(&dir, |_| {});
	}
	let mut best = f64::MAX;
	for _ in 0..3 {
		let t0 = Instant::now();
		let (nor, enc) = rcrm::resolve_ne_path_from_dir_with_progress(&dir, |_| {});
		let dt = t0.elapsed().as_secs_f64() * 1000.0;
		best = best.min(dt);
		println!(
			"PROBE dir_scan: {} files in {:.1}ms ({:.3}ms/file, plain={} enc={})",
			per_dir * 10,
			dt,
			dt / (per_dir * 10) as f64,
			nor.len(),
			enc.len()
		);
	}
	println!("PROBE dir_scan_best: {:.1}ms", best);
}

// =======================
// Probes
// =======================

#[test]
#[ignore = "perf probe — run explicitly with --ignored"]
fn probe_cold_launch() {
	println!("--- cold launch ---");
	measure_kdf();
	measure_double_manager();
	measure_scan(2000);
	measure_verify_pass(200);
}

#[test]
#[ignore = "perf probe — run explicitly with --ignored"]
fn probe_streaming() {
	println!("--- streaming ---");
	let size = 64 * 1024 * 1024;
	measure_plain_read(size);
	measure_projected_read("partial", 2048, size);
	measure_projected_read("full", -1, size);
}

#[test]
#[ignore = "perf probe — run explicitly with --ignored"]
fn probe_webdav() {
	println!("--- webdav ---");
	measure_webdav_latency(0, 100);
	measure_webdav_latency(4096, 100);
	measure_webdav_latency_keepalive(0, 200);
	measure_webdav_latency_keepalive(4096, 200);
	measure_webdav_get(64 * 1024 * 1024);
}

// Keep the unused-import lint quiet for Path (used by helper signatures).
#[allow(dead_code)]
fn _unused(_p: &Path) {}
