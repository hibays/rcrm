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

	is_supported_file_name(path)
}

/// Extension check only — the caller already knows the path is a regular
/// file, so it skips the `is_dir()` probe.
fn is_supported_file_name(path: &Path) -> bool {
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
	let mut nor_videos = Vec::new();
	let mut enc_videos = Vec::new();
	let mut queue: Vec<PathBuf> = Vec::new();

	// The root may itself be a file — keep the old behaviour of accepting
	// it, then walk it as a directory.
	match fs::metadata(path).map(|m| m.is_file()) {
		Ok(true) => {
			classify_file(path, &mut nor_videos, &mut enc_videos);
			return (nor_videos, enc_videos);
		}
		Ok(false) => queue.push(path.to_path_buf()),
		Err(_) => return (nor_videos, enc_videos),
	}

	while let Some(dir) = queue.pop() {
		let Ok(rd) = fs::read_dir(&dir) else {
			continue;
		};
		for entry in rd.flatten() {
			let p = entry.path();
			// `file_type()` reuses the type the OS reported with the
			// directory entry; `is_file()` + `is_dir()` cost two stats per
			// entry, and on Windows each one opens the file.
			let Ok(ft) = entry.file_type() else {
				continue;
			};
			if ft.is_dir() {
				queue.push(p);
			} else if ft.is_file() {
				classify_file(&p, &mut nor_videos, &mut enc_videos);
			}
		}
	}

	(nor_videos, enc_videos)
}

/// Sort one regular file into the plain / encrypted buckets.
fn classify_file(path: &Path, nor_videos: &mut Vec<PathBuf>, enc_videos: &mut Vec<PathBuf>) {
	if is_supported_file_name(path) {
		nor_videos.push(path.to_path_buf());
	} else if let Some(name) = path.file_name().and_then(|s| s.to_str())
		&& is_valid_encrypted_file_name(name)
	{
		enc_videos.push(path.to_path_buf());
	}
}

// =======================
// Helper: 递归获取目录下的所有视频文件/加密文件（带进度条）
// =======================

pub fn resolve_ne_path_from_dir_with_progress(
	path: &Path,
	progress_cb: impl Fn(usize),
) -> (Vec<PathBuf>, Vec<PathBuf>) {
	let mut nor_videos = Vec::new();
	let mut enc_videos = Vec::new();
	let mut scanned_count = 0;
	let mut queue: Vec<PathBuf> = Vec::new();

	match fs::metadata(path).map(|m| m.is_file()) {
		Ok(true) => {
			scanned_count += 1;
			progress_cb(scanned_count);
			classify_file(path, &mut nor_videos, &mut enc_videos);
			return (nor_videos, enc_videos);
		}
		Ok(false) => queue.push(path.to_path_buf()),
		Err(_) => return (nor_videos, enc_videos),
	}

	while let Some(dir) = queue.pop() {
		let Ok(rd) = fs::read_dir(&dir) else {
			continue;
		};
		for entry in rd.flatten() {
			let p = entry.path();
			scanned_count += 1;
			progress_cb(scanned_count);

			let Ok(ft) = entry.file_type() else {
				continue;
			};
			if ft.is_dir() {
				queue.push(p);
			} else if ft.is_file() {
				classify_file(&p, &mut nor_videos, &mut enc_videos);
			}
		}
	}

	(nor_videos, enc_videos)
}
