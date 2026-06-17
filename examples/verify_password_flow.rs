// examples/verify_password_flow.rs
// Demonstrates the password verification flow that `rcrm serve` uses.
//
// This example simulates the non-interactive core of
// `verify_encryption_passwords`: it creates files encrypted with password
// "correctpass", then shows that a manager with the wrong password fails
// to verify all files, and a manager with the right password succeeds.
//
// Run with: cargo run --release --example verify_password_flow

use std::path::PathBuf;

use rcrm::{Manager, is_supported_file};

fn main() {
	let dir = PathBuf::from(std::env::temp_dir()).join("rcrm_verify_flow");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	// Create and encrypt files with "correctpass".
	let correctpass = b"correctpass";
	let wrongpass = b"wrongpass";

	for i in 0..5u8 {
		let path = dir.join(format!("file{}.mp4", i));
		let content: Vec<u8> = (0..4096).map(|x| (x + i as usize) as u8).collect();
		std::fs::write(&path, &content).unwrap();
	}

	let enc_manager = Manager::new(true, true, 2048, is_supported_file, 6, Some(correctpass));
	let mut enc_files = Vec::new();
	for entry in std::fs::read_dir(&dir).unwrap().flatten() {
		let path = entry.path();
		if rcrm::is_supported_file(&path) {
			let name = enc_manager.encrypt_file(&path).unwrap();
			enc_files.push(dir.join(name));
		}
	}
	drop(enc_manager);

	println!(
		"Created {} encrypted files in {}",
		enc_files.len(),
		dir.display()
	);

	// Simulate: user enters WRONG password first.
	println!("\n--- Simulating wrong password ---");
	let mut manager = Manager::new(true, true, 2048, is_supported_file, 6, Some(wrongpass));
	let failed = verify_all(&enc_files, &mut manager);
	println!(
		"Wrong password: {} of {} files failed",
		failed.len(),
		enc_files.len()
	);
	assert!(!failed.is_empty(), "wrong password should fail some files");

	// Simulate: user enters CORRECT password (added to keyring).
	println!("\n--- Simulating correct password added ---");
	manager.use_added_key(correctpass);
	let failed = verify_all(&enc_files, &mut manager);
	println!(
		"After adding correct pass: {} of {} files failed",
		failed.len(),
		enc_files.len()
	);
	assert!(
		failed.is_empty(),
		"all files should pass with correct password"
	);

	// Simulate: no encrypted files → no password needed.
	println!("\n--- Simulating no encrypted files ---");
	let empty_dir = dir.join("empty");
	std::fs::create_dir_all(&empty_dir).unwrap();
	let (nor, enc) = rcrm::resolve_ne_path_from_dir(&empty_dir);
	println!("Empty dir: {} normal, {} encrypted", nor.len(), enc.len());
	assert!(enc.is_empty(), "empty dir should have no encrypted files");
	println!("No password needed (enc_files.is_empty() == true)");

	std::fs::remove_dir_all(&dir).unwrap();
	println!("\nAll verification flow tests passed!");
}

/// Core of `verify_encryption_passwords` — returns the list of files that
/// could NOT be opened with any registered key.
fn verify_all(enc_files: &[PathBuf], manager: &mut Manager) -> Vec<PathBuf> {
	let mut failed = Vec::new();
	for p in enc_files {
		match std::fs::File::open(p) {
			Ok(mut f) => match manager.read_file_header_any_key(&mut f) {
				Ok(_) => {}
				Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
					failed.push(p.clone());
				}
				Err(_) => {}
			},
			Err(_) => {}
		}
	}
	failed
}
