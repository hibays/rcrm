// tests/regression_core.rs
// Regressions for empirically-confirmed core bugs fixed in the current tree:
//   * the directory scan dropped symlinked media files,
//   * encrypt_file corrupted its source when the calibration was too small,
//   * init_head failures discarded the real io::Error.

use std::io;
use std::path::PathBuf;

use rcrm::{Manager, is_supported_file, resolve_ne_path_from_dir};

fn tmp(name: &str) -> PathBuf {
	let p = std::env::temp_dir().join(format!("rcrm_regression_{}_{}", std::process::id(), name));
	let _ = std::fs::remove_dir_all(&p);
	std::fs::create_dir_all(&p).unwrap();
	p
}

/// The perf refactor switched from `Path::is_file` (follows symlinks) to
/// `DirEntry::file_type` (does NOT), silently dropping symlinked media. The
/// scan must follow a symlink to a real media file.
#[test]
fn scan_includes_symlinked_media_file() {
	let dir = tmp("symlink_scan");
	let real = dir.join("real.mp4");
	std::fs::write(&real, b"x").unwrap();
	let link = dir.join("link.mp4");
	#[cfg(windows)]
	let made = std::os::windows::fs::symlink_file(&real, &link).is_ok();
	#[cfg(unix)]
	let made = std::os::unix::fs::symlink(&real, &link).is_ok();
	if !made {
		eprintln!("skipping: no privilege to create a symlink here");
		return;
	}
	let (normal, encrypted) = resolve_ne_path_from_dir(&dir);
	assert!(
		normal.iter().any(|p| p == &link),
		"a symlinked media file must be scanned: {normal:?} / {encrypted:?}"
	);
	let _ = std::fs::remove_dir_all(&dir);
}

/// A symlink that forms a directory cycle must not hang the walk, and must not
/// duplicate the subtree. Visit-once by directory identity keeps it finite on
/// both platforms (canonical path on Windows, dev+ino on Unix).
#[test]
fn scan_does_not_loop_on_symlink_cycle() {
	let dir = tmp("symlink_cycle");
	std::fs::write(dir.join("clip.mp4"), b"x").unwrap();
	let link = dir.join("loop");
	#[cfg(windows)]
	let made = std::os::windows::fs::symlink_dir(&dir, &link).is_ok();
	#[cfg(unix)]
	let made = std::os::unix::fs::symlink(&dir, &link).is_ok();
	if !made {
		eprintln!("skipping: no privilege to create a symlink here");
		return;
	}
	// Must terminate; if it loops, the test process hangs and the harness times out.
	let (normal, _) = resolve_ne_path_from_dir(&dir);
	assert_eq!(
		normal.len(),
		1,
		"a symlink back to the root must not duplicate the subtree: {normal:?}"
	);
	let _ = std::fs::remove_dir_all(&dir);
}

/// When `calibration_amount` is smaller than the header, encrypt_file returns
/// InvalidInput — but it MUST NOT have overwritten the source's first bytes
/// before discovering that. (Found empirically: calibration=1 left the header
/// written into the source file on the error path.)
#[test]
fn encrypt_file_error_does_not_corrupt_source() {
	let dir = tmp("encrypt_cal");
	let file = dir.join("clip.mp4");
	let original = b"ORIGINAL-CONTENT-THAT-MUST-SURVIVE-1234567890";
	std::fs::write(&file, original).unwrap();

	// calibration=1 is below the header size; Manager maps <=0 to u32::MAX,
	// so pass a positive-but-too-small value directly.
	let mgr = Manager::new(false, false, 1, is_supported_file, 1, Some(b"pw"));
	let result = mgr.encrypt_file(&file);
	assert!(result.is_err(), "a too-small calibration must be rejected");
	assert_eq!(
		result.unwrap_err().kind(),
		io::ErrorKind::InvalidInput,
		"the failure is a validation error"
	);
	assert_eq!(
		std::fs::read(&file).unwrap(),
		original,
		"the error path must not touch the source file"
	);
	let _ = std::fs::remove_dir_all(&dir);
}
