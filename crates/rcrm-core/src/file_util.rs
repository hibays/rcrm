// crates/rcrm-core/src/file_util.rs
// rcrm - File scanning and MIME type helpers.
// Copyleft (©) 2024-2025 hibays

use std::{
	collections::HashSet,
	fs,
	path::{Path, PathBuf},
};

use crate::base72::b72_decode_rust as b72decode;

// Directory identity for symlink-cycle detection. Unix uses dev+ino from
// metadata already read; other platforms fall back to the canonical path.
#[cfg(unix)]
type DirId = (u64, u64);
#[cfg(not(unix))]
type DirId = PathBuf;

/// Derive a directory's identity from its path and already-fetched metadata.
///
/// Unix uses `(dev, ino)` from `meta` — the same metadata the caller read to
/// learn the entry type, so this is free. Other platforms ignore `meta` and
/// canonicalise the path, since a stable file index is not generally available.
#[cfg(unix)]
fn dir_id(_path: &Path, meta: &fs::Metadata) -> Option<DirId> {
	use std::os::unix::fs::MetadataExt;
	Some((meta.dev(), meta.ino()))
}

#[cfg(not(unix))]
fn dir_id(path: &Path, _meta: &fs::Metadata) -> Option<DirId> {
	fs::canonicalize(path).ok()
}

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

/// Classify a directory entry, returning what the walker should do with it.
enum Step {
	Push(PathBuf),               // real directory — always walk
	PushSymlink(PathBuf, DirId), // symlinked directory — walk once by identity
	File(PathBuf),               // regular file (or symlink to one) — classify
	Skip,
}

fn classify(entry: &fs::DirEntry) -> Step {
	let path = entry.path();
	let Ok(ft) = entry.file_type() else {
		return Step::Skip;
	};
	if !ft.is_symlink() {
		return if ft.is_dir() {
			Step::Push(path)
		} else if ft.is_file() {
			Step::File(path)
		} else {
			Step::Skip
		};
	}
	let Ok(meta) = fs::metadata(&path) else {
		return Step::Skip;
	};
	let target = meta.file_type();
	if target.is_dir() {
		match dir_id(&path, &meta) {
			Some(id) => Step::PushSymlink(path, id),
			None => Step::Skip,
		}
	} else if target.is_file() {
		Step::File(path)
	} else {
		Step::Skip
	}
}

/// `on_entry` runs per entry (for progress); `on_file` per file to classify.
fn walk(path: &Path, mut on_entry: impl FnMut(), mut on_file: impl FnMut(&Path)) {
	let mut queue: Vec<PathBuf> = Vec::new();
	let mut visited: HashSet<DirId> = HashSet::new();

	match fs::metadata(path) {
		Ok(m) if m.is_file() => {
			on_entry();
			on_file(path);
			return;
		}
		Ok(m) => {
			// Include root so a symlink back to it is refused.
			if let Some(id) = dir_id(path, &m) {
				visited.insert(id);
			}
			queue.push(path.to_path_buf());
		}
		Err(_) => return,
	}

	while let Some(dir) = queue.pop() {
		let Ok(rd) = fs::read_dir(&dir) else {
			continue;
		};
		for entry in rd.flatten() {
			on_entry();
			match classify(&entry) {
				Step::Push(p) => queue.push(p),
				Step::PushSymlink(p, id) => {
					if visited.insert(id) {
						queue.push(p);
					}
				}
				Step::File(p) => on_file(&p),
				Step::Skip => {}
			}
		}
	}
}

pub fn resolve_ne_path_from_dir(path: &Path) -> (Vec<PathBuf>, Vec<PathBuf>) {
	let mut nor_videos = Vec::new();
	let mut enc_videos = Vec::new();
	walk(
		path,
		|| {},
		|p| classify_file(p, &mut nor_videos, &mut enc_videos),
	);
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
	let mut scanned = 0;
	walk(
		path,
		|| {
			scanned += 1;
			progress_cb(scanned);
		},
		|p| classify_file(p, &mut nor_videos, &mut enc_videos),
	);
	(nor_videos, enc_videos)
}
