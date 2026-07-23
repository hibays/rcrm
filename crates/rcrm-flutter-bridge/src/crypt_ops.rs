// src/crypt_ops.rs
// rcrm-flutter-bridge — crypt folder operations
//
// Exposes encrypt/decrypt folder operations for the Flutter GUI.

use std::path::Path;

use rcrm_core::Manager;

use crate::server;

/// Encrypt or decrypt a folder in-place.
///
/// Returns 0 on success, -1 on failure (error is stored via `set_error`).
pub fn crypt_folder(path: &str, password: &str, is_encrypt: bool) -> i32 {
	let dir = Path::new(path);
	if !dir.exists() {
		server::set_error(format!("Directory does not exist: {path}"));
		return -1;
	}
	if !dir.is_dir() {
		server::set_error(format!("Path is not a directory: {path}"));
		return -1;
	}

	let password_bytes = password.as_bytes();
	let manager = Manager::new(
		true, // dir_name_crypt
		true, // file_name_crypt
		2048, // calibration_amount
		rcrm_core::is_supported_file,
		4, // works
		Some(password_bytes),
	);

	// Scan all supported files in the directory
	let (normal_files, encrypted_files) =
		rcrm_core::resolve_ne_path_from_dir_with_progress(dir, |_| {});

	// Combine both vectors — we operate on all files
	let files: Vec<std::path::PathBuf> = normal_files.into_iter().chain(encrypted_files).collect();

	if files.is_empty() {
		server::set_error("No supported files found in directory");
		return -1;
	}

	let action = if is_encrypt {
		"Encrypting"
	} else {
		"Decrypting"
	};

	let mut failures = 0usize;
	for file_path in &files {
		let result = if is_encrypt {
			manager.encrypt_file(file_path)
		} else {
			manager.decrypt_file(file_path)
		};

		if let Err(e) = result {
			rcrm_core::log_error!("[bridge] {action} failed for {}: {e}", file_path.display());
			failures += 1;
		}
	}

	if failures == files.len() {
		server::set_error(format!(
			"All {} file(s) failed to {}",
			files.len(),
			if is_encrypt { "encrypt" } else { "decrypt" },
		));
		return -1;
	}

	0
}
