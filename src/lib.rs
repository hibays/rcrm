// src/lib.rs
// rcrm - A simple file encryption/decryption tool
// Copyleft (©) 2024-2025 hibays

// A drop-in global allocator wrapper around the [mimalloc](https://github.com/microsoft/mimalloc)
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod base72;
pub use base72::b72_decode_rust as b72decode;

mod crypt;
pub use crypt::Manager;

// =======================
// MIME 类型判断（简化版）
// =======================

pub fn is_supported_file(path: &std::path::Path) -> bool {
	if path.is_dir() {
		return false;
	}

	let ext = path
		.extension()
		.and_then(std::ffi::OsStr::to_str)
		.unwrap_or("")
		.to_lowercase();

	const SUPPORTED_EXTS: &[&str] = &[
		"mp4", "avi", "wmv", "mov", "m4v", "rm", "rmvb", "mkv", "jpg", "jpeg", "png", "webp",
		"ppm", "raw", "avif", "mp3", "wav", "flac", "aac", "ogg",
	];

	SUPPORTED_EXTS.contains(&ext.as_str())
}

// =======================
// 判断是否为加密文件名
// =======================

pub fn is_valid_encrypted_file_name(name: &str) -> bool {
	if !name.starts_with('.') {
		return false;
	}
	if let Ok(decoded) = b72decode(&name.as_bytes()[1..]) {
		return decoded.len() == 32;
	}
	false
}
