// examples/manual_serve.rs
// Manual end-to-end test helper: creates test files, encrypts one, and
// starts the projection FTP server on 127.0.0.1:22121 so you can connect
// with curl / FileZilla / lftp to verify the projection.
//
// Run with:  cargo run --release --example manual_serve
// Then:      curl ftp://127.0.0.1:22121/
//            curl ftp://127.0.0.1:22121/sample.mp4 -o out.mp4
//
// Ctrl+C to stop.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rcrm::serve::tls as tls_config;
use rcrm::serve::{AuthConfig, FileCache, Server, ServerContext, generate_mount_names};
use rcrm::{Manager, SessionKey, is_supported_file};

fn main() {
	let dir = std::env::temp_dir().join("rcrm_manual_serve");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	// Create a fake media file (8 KB, will be partially encrypted).
	let mut content = vec![0u8; 8192];
	for (i, b) in content.iter_mut().enumerate() {
		*b = (i % 251) as u8; // deterministic non-trivial content
	}
	std::fs::write(dir.join("sample.mp4"), &content).unwrap();

	// A plain text file (non-encrypted, served as-is).
	std::fs::write(dir.join("readme.txt"), b"plain readme -- served as-is").unwrap();

	// A small file that will be FULL-encrypted (< 2048 bytes).
	let small = vec![0xABu8; 512];
	std::fs::write(dir.join("tiny.mp3"), &small).unwrap();

	// Encrypt with a known password.
	let password = b"testpass123";
	let manager = Manager::new(true, true, 2048, is_supported_file, 6, Some(password));

	for entry in std::fs::read_dir(&dir).unwrap().flatten() {
		let path = entry.path();
		if rcrm::is_supported_file(&path) {
			match manager.encrypt_file(&path) {
				Ok(new_name) => eprintln!("encrypted: {} -> {}", path.display(), new_name),
				Err(e) => eprintln!("encrypt {} failed: {}", path.display(), e),
			}
		}
	}
	drop(manager);

	// Re-create the manager for serving (read-only).
	let manager = Manager::new(true, true, 2048, is_supported_file, 6, Some(password));
	let session_key = Arc::new(SessionKey::generate());
	let tls_cfg = tls_config::build_ephemeral_config().expect("TLS config");

	let ctx = ServerContext {
		mounts: generate_mount_names(&[dir.clone()]),
		manager: Arc::new(manager),
		session_key,
		cache: Arc::new(FileCache::new()),
		tls_config: Some(tls_cfg),
		require_tls: false,
		implicit_tls: false,
		protocol: rcrm::serve::Protocol::Ftp,
		max_connections: 8,
		auth: AuthConfig::no_auth(),
		idle_timeout: Duration::from_secs(300),
	};

	let server = Server::new(ctx, "127.0.0.1:22121".parse().unwrap());
	let (listener, addr) = server.bind().expect("bind failed");

	let shutdown = Arc::new(AtomicBool::new(false));
	let shutdown_clone = Arc::clone(&shutdown);
	ctrlc::set_handler(move || {
		if !shutdown_clone.swap(true, Ordering::SeqCst) {
			eprintln!("\n[manual_serve] shutting down...");
		} else {
			std::process::exit(130);
		}
	})
	.expect("ctrlc");

	eprintln!("[manual_serve] root: {}", dir.display());
	eprintln!("[manual_serve] listening on {}", addr);
	eprintln!("[manual_serve] FTPS enabled (AUTH TLS)");
	eprintln!("[manual_serve] try:");
	eprintln!("    curl ftp://127.0.0.1:22121/");
	eprintln!("    curl ftp://127.0.0.1:22121/sample.mp4 -o out.mp4");
	eprintln!("    curl ftp://127.0.0.1:22121/readme.txt -o out.txt");
	eprintln!("    curl ftp://127.0.0.1:22121/tiny.mp3 -o out.mp3");
	eprintln!(
		"    curl --ftp-ssl-control --ftp-ssl -k ftp://127.0.0.1:22121/sample.mp4 -o out_tls.mp4"
	);
	eprintln!("[manual_serve] Ctrl+C to stop");

	server.serve(listener, shutdown).expect("serve");
}
