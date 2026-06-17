// examples/implicit_serve.rs
// Manual end-to-end test helper for Implicit FTPS (port 990 style).
// The control connection is TLS-wrapped immediately on connect — no
// AUTH TLS negotiation.
//
// Run with:  cargo run --release --example implicit_serve
// Then:      curl --ftp-ssl -k ftp://127.0.0.1:22122/
//            curl --ftp-ssl -k ftp://127.0.0.1:22122/sample.mp4 -o out.mp4
//
// Ctrl+C to stop.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rcrm::serve::tls as tls_config;
use rcrm::serve::{AuthConfig, FileCache, Server, ServerContext};
use rcrm::{Manager, SessionKey, is_supported_file};

fn main() {
	let dir = PathBuf::from(std::env::temp_dir()).join("rcrm_implicit_serve");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	let mut content = vec![0u8; 8192];
	for (i, b) in content.iter_mut().enumerate() {
		*b = (i % 251) as u8;
	}
	std::fs::write(dir.join("sample.mp4"), &content).unwrap();
	std::fs::write(dir.join("readme.txt"), b"plain readme -- served as-is").unwrap();
	let small = vec![0xABu8; 512];
	std::fs::write(dir.join("tiny.mp3"), &small).unwrap();

	let password = b"testpass123";
	let manager = Manager::new(true, true, 2048, is_supported_file, 6, Some(password));
	for entry in std::fs::read_dir(&dir).unwrap().flatten() {
		let path = entry.path();
		if rcrm::is_supported_file(&path) {
			let _ = manager.encrypt_file(&path);
		}
	}
	drop(manager);

	let manager = Manager::new(true, true, 2048, is_supported_file, 6, Some(password));
	let session_key = Arc::new(SessionKey::generate());
	let tls_cfg = tls_config::build_ephemeral_config().expect("TLS config");

	let ctx = ServerContext {
		root: dir.clone(),
		manager: Arc::new(manager),
		session_key,
		cache: Arc::new(FileCache::new()),
		tls_config: Some(tls_cfg),
		require_tls: false,
		implicit_tls: true,
		max_connections: 8,
		auth: AuthConfig::no_auth(),
		idle_timeout: Duration::from_secs(300),
	};

	let server = Server::new(ctx, "0.0.0.0:22122".parse().unwrap());
	let (listener, addr) = server.bind().expect("bind failed");

	let shutdown = Arc::new(AtomicBool::new(false));
	let shutdown_clone = Arc::clone(&shutdown);
	ctrlc::set_handler(move || {
		if !shutdown_clone.swap(true, Ordering::SeqCst) {
			eprintln!("\n[implicit_serve] shutting down...");
		} else {
			std::process::exit(130);
		}
	})
	.expect("ctrlc");

	eprintln!("[implicit_serve] root: {}", dir.display());
	eprintln!(
		"[implicit_serve] listening on {} (implicit FTPS — TLS from byte 0)",
		addr
	);
	eprintln!("[implicit_serve] try:");
	eprintln!("    curl --ftp-ssl -k ftp://127.0.0.1:22122/");
	eprintln!("    curl --ftp-ssl -k ftp://127.0.0.1:22122/sample.mp4 -o out.mp4");
	eprintln!("    curl --ftp-ssl -k ftp://127.0.0.1:22122/tiny.mp3 -o out.mp3");
	eprintln!("[implicit_serve] Ctrl+C to stop");

	server.serve(listener, shutdown).expect("serve");
}
