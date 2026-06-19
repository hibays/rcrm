// crates/rcrm-core/src/file_util.rs
// rcrm - File scanning and MIME type helpers.
// Copyleft (©) 2024-2025 hibays

use std::{
	fs,
	path::{Path, PathBuf},
};

use crate::base72::b72_decode_rust as b72decode;

// =======================
// MIME 类型判断（简化版）
// =======================

pub fn is_supported_file(path: &Path) -> bool {
	if path.is_dir() {
		return false;
	}

	let ext = path
		.extension()
		.and_then(std::ffi::OsStr::to_str)
		.unwrap_or("")
		.to_lowercase();

	if let Some(mime) = mime_guess::from_ext(&ext).first()
		&& (mime.type_() == "video" || mime.type_() == "image" || mime.type_() == "audio")
	{
		return true;
	};

	const SUPPORTED_EXTS: &[&str] = &[
		"mp4", "avi", "wmv", "mov", "m4v", "rm", "rmvb", "mkv", "webm", // Video
		"jpg", "jpeg", "png", "webp", "ppm", "raw", "avif", // Image
		"mp3", "wav", "flac", "aac", "ogg", // Audio
		"zip", "rar", "7z", // Archive
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

// =======================
// Helper: 递归获取目录下的所有视频文件/加密文件
// =======================

pub fn resolve_ne_path_from_dir(path: &Path) -> (Vec<PathBuf>, Vec<PathBuf>) {
	let mut queue = vec![path.to_path_buf()];
	let mut nor_videos = Vec::new();
	let mut enc_videos = Vec::new();

	while let Some(file) = queue.pop() {
		if file.is_file() {
			if is_supported_file(&file) {
				nor_videos.push(file);
			} else if let Some(name) = file.file_name().and_then(|s| s.to_str())
				&& is_valid_encrypted_file_name(name)
			{
				enc_videos.push(file);
			}
		} else if file.is_dir()
			&& let Ok(entries) = fs::read_dir(&file)
		{
			for entry in entries.flatten() {
				queue.push(entry.path());
			}
		}
	}

	(nor_videos, enc_videos)
}

// =======================
// Helper: 递归获取目录下的所有视频文件/加密文件（带进度条）
// =======================

pub fn resolve_ne_path_from_dir_with_progress(
	path: &Path,
	progress_cb: impl Fn(usize),
) -> (Vec<PathBuf>, Vec<PathBuf>) {
	let mut queue = vec![path.to_path_buf()];
	let mut nor_videos = Vec::new();
	let mut enc_videos = Vec::new();
	let mut scanned_count = 0;

	while let Some(file) = queue.pop() {
		scanned_count += 1;
		progress_cb(scanned_count);

		if file.is_file() {
			if is_supported_file(&file) {
				nor_videos.push(file);
			} else if let Some(name) = file.file_name().and_then(|s| s.to_str())
				&& is_valid_encrypted_file_name(name)
			{
				enc_videos.push(file);
			}
		} else if file.is_dir()
			&& let Ok(entries) = fs::read_dir(&file)
		{
			for entry in entries.flatten() {
				queue.push(entry.path());
			}
		}
	}

	(nor_videos, enc_videos)
}
