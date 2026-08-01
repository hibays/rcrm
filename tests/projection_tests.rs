// tests/projection_tests.rs
// Tests for the read-only projection layer (ProjectedFile + SessionKey).
//
// These tests verify that:
//   1. A partially-encrypted file can be read back byte-for-byte identical
//      to its original plaintext via ProjectedFile::read_at, across
//      head/tail/spanning offsets, without ever writing to disk.
//   2. A fully-encrypted file (smaller than calibration_amount) also
//      projects correctly.
//   3. SessionKey encrypt/decrypt round-trips and the ciphertext differs
//      from the plaintext.

use std::io::Read;
use std::path::PathBuf;

use rcrm::{Manager, ProjectedFile, SessionKey, is_supported_file};

fn make_manager(key: &[u8]) -> Manager {
	Manager::new(true, true, 2048, is_supported_file, 6, Some(key))
}

/// Build deterministic pseudo-random content of `len` bytes so tests are
/// reproducible (OsRng would also work, but determinism makes debugging
/// easier when a test fails).
fn deterministic_content(len: usize, seed: u8) -> Vec<u8> {
	let mut out = Vec::with_capacity(len);
	let mut state = seed as u32;
	for _ in 0..len {
		// xorshift32
		state ^= state << 13;
		state ^= state >> 17;
		state ^= state << 5;
		out.push((state & 0xff) as u8);
	}
	out
}

#[test]
fn session_key_roundtrip() {
	let sk = SessionKey::generate().expect("mlock failed");
	let plaintext = deterministic_content(4096, 42);
	let nonce: [u8; 12] = rand::random();
	let ciphertext = sk.encrypt(&plaintext, &nonce).unwrap();
	// Ciphertext must differ from plaintext (extremely high probability).
	assert_ne!(&ciphertext[..], &plaintext[..]);
	// Round-trip recovers plaintext.
	let recovered = sk.decrypt(&ciphertext, &nonce).unwrap();
	assert_eq!(&recovered[..], &plaintext[..]);
}

#[test]
fn session_key_distinct_nonces_produce_distinct_ciphertexts() {
	let sk = SessionKey::generate().expect("mlock failed");
	let plaintext = deterministic_content(256, 7);
	let n1: [u8; 12] = rand::random();
	let n2: [u8; 12] = rand::random();
	let c1 = sk.encrypt(&plaintext, &n1).unwrap();
	let c2 = sk.encrypt(&plaintext, &n2).unwrap();
	assert_ne!(c1, c2);
}

/// Partially encrypt a file and verify that ProjectedFile reads back the
/// original content at every offset and length combination we try.
#[test]
fn partial_projection_reads_original_content() {
	let dir = std::env::temp_dir().join("rcrm_proj_test_partial");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	// Use a "supported" extension so the Manager's rule_fn accepts it.
	let path = dir.join("test_video.mp4");
	// 64 KiB — well above calibration_amount (2048), so Partial mode.
	let original = deterministic_content(64 * 1024, 123);
	std::fs::write(&path, &original).unwrap();

	let key = deterministic_content(32, 99);
	let manager = make_manager(&key);
	let new_name = manager.encrypt_file(&path).expect("encrypt failed");
	let enc_path = dir.join(&new_name);

	// Sanity: the file was renamed to a .b72 hash.
	assert!(rcrm::is_valid_encrypted_file_name(&new_name));

	let session_key = SessionKey::generate().expect("mlock failed");
	let pf = ProjectedFile::open(&enc_path, &manager, &session_key).expect("open failed");

	// Virtual size must equal the original plaintext size.
	assert_eq!(pf.virtual_size(), original.len() as u64);

	// Virtual name must be the original filename (decrypted from header).
	assert_eq!(pf.virtual_name(), "test_video.mp4");

	// Read back the whole file via read_at and compare.
	let mut reconstructed = Vec::with_capacity(original.len());
	let mut buf = vec![0u8; 4096];
	let mut offset = 0u64;
	while offset < pf.virtual_size() {
		let n = pf.read_at(offset, &mut buf, &session_key).unwrap();
		assert!(n > 0, "read_at returned 0 at offset {}", offset);
		reconstructed.extend_from_slice(&buf[..n]);
		offset += n as u64;
	}
	assert_eq!(reconstructed, original);

	// Test spanning read (head + tail boundary at calibration_amount=2048).
	let mut span_buf = [0u8; 4096]; // 2048 from head + 2048 from tail
	let n = pf.read_at(1024, &mut span_buf, &session_key).unwrap();
	assert_eq!(n, 4096);
	assert_eq!(&span_buf[..], &original[1024..1024 + 4096]);

	// Test read entirely within the head.
	let mut head_buf = [0u8; 100];
	let n = pf.read_at(100, &mut head_buf, &session_key).unwrap();
	assert_eq!(n, 100);
	assert_eq!(&head_buf[..], &original[100..200]);

	// Test read entirely within the tail.
	let mut tail_buf = [0u8; 100];
	let n = pf.read_at(40_000, &mut tail_buf, &session_key).unwrap();
	assert_eq!(n, 100);
	assert_eq!(&tail_buf[..], &original[40_000..40_100]);

	// Test read at EOF.
	let mut eof_buf = [0u8; 10];
	let n = pf
		.read_at(original.len() as u64, &mut eof_buf, &session_key)
		.unwrap();
	assert_eq!(n, 0);

	// Test read past EOF.
	let n = pf
		.read_at(original.len() as u64 + 100, &mut eof_buf, &session_key)
		.unwrap();
	assert_eq!(n, 0);

	std::fs::remove_dir_all(&dir).unwrap();
}

/// Fully encrypt a small file (< calibration_amount) and verify projection.
#[test]
fn full_projection_reads_original_content() {
	let dir = std::env::temp_dir().join("rcrm_proj_test_full");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	let path = dir.join("small.mp3");
	// 512 bytes — below calibration_amount (2048), so Full mode.
	let original = deterministic_content(512, 200);
	std::fs::write(&path, &original).unwrap();

	let key = deterministic_content(32, 55);
	let manager = make_manager(&key);
	let new_name = manager.encrypt_file(&path).expect("encrypt failed");
	let enc_path = dir.join(&new_name);

	let session_key = SessionKey::generate().expect("mlock failed");
	let pf = ProjectedFile::open(&enc_path, &manager, &session_key).expect("open failed");

	assert_eq!(pf.virtual_size(), original.len() as u64);
	assert_eq!(pf.virtual_name(), "small.mp3");
	assert!(pf.is_full_encrypted());

	// Full read.
	let mut reconstructed = Vec::with_capacity(original.len());
	let mut buf = vec![0u8; 128];
	let mut offset = 0u64;
	while offset < pf.virtual_size() {
		let n = pf.read_at(offset, &mut buf, &session_key).unwrap();
		assert!(n > 0);
		reconstructed.extend_from_slice(&buf[..n]);
		offset += n as u64;
	}
	assert_eq!(reconstructed, original);

	std::fs::remove_dir_all(&dir).unwrap();
}

/// Wrong key must fail to open a projected file.
#[test]
fn wrong_key_rejected() {
	let dir = std::env::temp_dir().join("rcrm_proj_test_wrongkey");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	let path = dir.join("file.mp4");
	std::fs::write(&path, deterministic_content(4096, 1)).unwrap();

	let key1 = deterministic_content(32, 1);
	let key2 = deterministic_content(32, 2);
	let manager1 = make_manager(&key1);
	let manager2 = make_manager(&key2);

	let new_name = manager1.encrypt_file(&path).unwrap();
	let enc_path = dir.join(&new_name);

	let session_key = SessionKey::generate().expect("mlock failed");
	let result = ProjectedFile::open(&enc_path, &manager2, &session_key);
	assert!(result.is_err(), "open with wrong key should fail");

	std::fs::remove_dir_all(&dir).unwrap();
}

/// Multi-key: two files encrypted with different passwords, both
/// projectable through one Manager holding both keys.
#[test]
fn multi_key_projection() {
	let dir = std::env::temp_dir().join("rcrm_proj_test_multikey");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	let path1 = dir.join("a.mp4");
	let path2 = dir.join("b.mp4");
	let content1 = deterministic_content(8192, 10);
	let content2 = deterministic_content(8192, 20);
	std::fs::write(&path1, &content1).unwrap();
	std::fs::write(&path2, &content2).unwrap();

	let key1 = deterministic_content(32, 1);
	let key2 = deterministic_content(32, 2);

	// Encrypt file1 with key1, file2 with key2.
	let mgr1 = make_manager(&key1);
	let name1 = mgr1.encrypt_file(&path1).unwrap();
	let mgr2 = make_manager(&key2);
	let name2 = mgr2.encrypt_file(&path2).unwrap();

	let enc1 = dir.join(&name1);
	let enc2 = dir.join(&name2);

	// Build a manager with both keys.
	let mut manager = make_manager(&key1);
	manager.use_added_key(&key2);

	let session_key = SessionKey::generate().expect("mlock failed");
	let pf1 = ProjectedFile::open(&enc1, &manager, &session_key).expect("open enc1");
	let pf2 = ProjectedFile::open(&enc2, &manager, &session_key).expect("open enc2");

	// Verify both project correctly.
	let mut buf = vec![0u8; content1.len()];
	let n = pf1.read_at(0, &mut buf, &session_key).unwrap();
	assert_eq!(&buf[..n], &content1[..]);

	let mut buf = vec![0u8; content2.len()];
	let n = pf2.read_at(0, &mut buf, &session_key).unwrap();
	assert_eq!(&buf[..n], &content2[..]);

	std::fs::remove_dir_all(&dir).unwrap();
}

/// Verify that the on-disk encrypted file is NOT modified by opening it
/// as a ProjectedFile (read-only contract).
#[test]
fn projection_does_not_modify_disk() {
	let dir = std::env::temp_dir().join("rcrm_proj_test_nomodify");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	let path = dir.join("file.mp4");
	std::fs::write(&path, deterministic_content(8192, 77)).unwrap();

	let key = deterministic_content(32, 33);
	let manager = make_manager(&key);
	let new_name = manager.encrypt_file(&path).unwrap();
	let enc_path = dir.join(&new_name);

	// Snapshot the on-disk bytes.
	let before = std::fs::read(&enc_path).unwrap();

	// Open and read through the projection.
	let session_key = SessionKey::generate().expect("mlock failed");
	let pf = ProjectedFile::open(&enc_path, &manager, &session_key).unwrap();
	let mut buf = vec![0u8; 4096];
	let _ = pf.read_at(0, &mut buf, &session_key).unwrap();
	let _ = pf.read_at(2048, &mut buf, &session_key).unwrap();
	let _ = pf.read_at(4096, &mut buf, &session_key).unwrap();
	drop(pf);

	// Re-snapshot — must be byte-identical.
	let after = std::fs::read(&enc_path).unwrap();
	assert_eq!(before, after, "on-disk file was modified by projection");

	std::fs::remove_dir_all(&dir).unwrap();
}

/// Test `read_file_header_any_key` directly — the mechanism that powers
/// `verify_encryption_passwords` in main.rs. Files encrypted with different
/// keys must be openable by a manager holding all keys. The returned key
/// index is one of the registered keys that matches (possibly
/// `MAGIC_KEY_USING` if it holds a copy of the matching derived key).
#[test]
fn read_header_any_key_finds_matching_key() {
	let dir = std::env::temp_dir().join("rcrm_proj_test_anykey");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	let path1 = dir.join("a.mp4");
	let path2 = dir.join("b.mp4");
	std::fs::write(&path1, deterministic_content(4096, 1)).unwrap();
	std::fs::write(&path2, deterministic_content(4096, 2)).unwrap();

	let key1 = deterministic_content(32, 1);
	let key2 = deterministic_content(32, 2);

	// Encrypt file1 with key1, file2 with key2.
	let mgr1 = make_manager(&key1);
	let name1 = mgr1.encrypt_file(&path1).unwrap();
	let mgr2 = make_manager(&key2);
	let name2 = mgr2.encrypt_file(&path2).unwrap();

	let enc1 = dir.join(&name1);
	let enc2 = dir.join(&name2);

	// Build a manager with both keys.
	let mut manager = make_manager(&key1);
	manager.use_added_key(&key2);

	// Both files must be openable (that's the core invariant — the
	// verification loop only cares that SOME key works, not which index).
	let mut f1 = std::fs::File::open(&enc1).unwrap();
	let (header1, _idx1) = manager
		.read_file_header_any_key(&mut f1)
		.expect("file1 should open with multi-key manager");
	assert!(header1.file_size > 0);

	let mut f2 = std::fs::File::open(&enc2).unwrap();
	let (header2, _idx2) = manager
		.read_file_header_any_key(&mut f2)
		.expect("file2 should open with multi-key manager");
	assert!(header2.file_size > 0);

	// Now test with a manager that only has key1 — file2 must fail.
	let mgr_only1 = make_manager(&key1);
	let mut f2b = std::fs::File::open(&enc2).unwrap();
	assert!(
		mgr_only1.read_file_header_any_key(&mut f2b).is_err(),
		"file2 should fail with only key1"
	);

	// And vice versa: manager with only key2 — file1 must fail.
	let mgr_only2 = make_manager(&key2);
	let mut f1b = std::fs::File::open(&enc1).unwrap();
	assert!(
		mgr_only2.read_file_header_any_key(&mut f1b).is_err(),
		"file1 should fail with only key2"
	);

	std::fs::remove_dir_all(&dir).unwrap();
}

/// Test that `read_file_header_any_key` returns InvalidData (not some other
/// error) when no key matches — this is the error kind that
/// `verify_encryption_passwords` checks to decide whether to prompt for
/// another password.
#[test]
fn read_header_any_key_returns_invalid_data_on_wrong_key() {
	let dir = std::env::temp_dir().join("rcrm_proj_test_invaliddata");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	let path = dir.join("file.mp4");
	std::fs::write(&path, deterministic_content(4096, 1)).unwrap();

	let key1 = deterministic_content(32, 1);
	let key2 = deterministic_content(32, 2);

	let mgr1 = make_manager(&key1);
	let name = mgr1.encrypt_file(&path).unwrap();
	let enc = dir.join(&name);

	// Manager with only key2 → must fail with InvalidData.
	let mgr2 = make_manager(&key2);
	let mut f = std::fs::File::open(&enc).unwrap();
	match mgr2.read_file_header_any_key(&mut f) {
		Ok(_) => panic!("wrong key should fail"),
		Err(ref err) => {
			assert_eq!(
				err.kind(),
				std::io::ErrorKind::InvalidData,
				"wrong key must return InvalidData, got {:?}: {}",
				err.kind(),
				err
			);
		}
	}

	std::fs::remove_dir_all(&dir).unwrap();
}

// Keep PathBuf import used (for future test expansions).
#[allow(dead_code)]
fn _path() -> PathBuf {
	PathBuf::from(".")
}

// Silence unused Read import if all usages are removed in future edits.
#[allow(dead_code)]
fn _read<R: Read>(_: R) {}

/// `read_at_with` (caller-provided handle) must produce byte-identical
/// results to `read_at` (self-opened handle) for every offset/len
/// combination, including the head/tail boundary, EOF and out-of-order
/// offsets through a single reused handle.
#[test]
fn read_at_with_matches_read_at_across_offsets() {
	let dir = std::env::temp_dir().join("rcrm_proj_test_readatwith");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	let path = dir.join("test_video.mp4");
	// 128 KiB, well above calibration_amount (2048) → Partial mode.
	let original = deterministic_content(128 * 1024, 5);
	std::fs::write(&path, &original).unwrap();

	let key = deterministic_content(32, 6);
	let manager = make_manager(&key);
	let new_name = manager.encrypt_file(&path).expect("encrypt failed");
	let enc_path = dir.join(&new_name);

	let session_key = SessionKey::generate().expect("mlock failed");
	let pf = ProjectedFile::open(&enc_path, &manager, &session_key).expect("open failed");

	// One handle reused across ALL reads (the transfer-loop pattern).
	let mut f = std::fs::File::open(&enc_path).unwrap();

	// Deterministic (offset, len) pairs covering:
	//   - start of file, middle of head, head/tail boundary (2048)
	//   - middle of tail, EOF, past EOF, zero-length, huge len
	let cases: &[(u64, usize)] = &[
		(0, 1),
		(0, 4096),
		(100, 100),
		(1024, 2048),           // spans head/tail boundary at 2048
		(2048, 4096),           // exactly at boundary
		(3000, 500),            // straddles boundary
		(40_000, 100),          // tail
		(128 * 1024 - 10, 10),  // tail near EOF
		(128 * 1024, 10),       // at EOF → 0
		(128 * 1024 + 100, 10), // past EOF → 0
		(0, 0),                 // empty buffer → 0
		(0, 1 << 20),           // huge len → clamped to file size
	];

	for &(off, len) in cases {
		let mut a = vec![0xAAu8; len];
		let mut b = vec![0xBBu8; len];
		let n_a = pf.read_at(off, &mut a, &session_key).unwrap();
		let n_b = pf.read_at_with(&mut f, off, &mut b, &session_key).unwrap();
		assert_eq!(n_a, n_b, "count mismatch at offset {} len {}", off, len);
		assert_eq!(
			&a[..n_a],
			&b[..n_b],
			"content mismatch at offset {} len {}",
			off,
			len
		);
	}

	// Out-of-order offsets through the same handle (seek correctness).
	let mut buf = vec![0u8; 64];
	let n = pf
		.read_at_with(&mut f, 40_000, &mut buf, &session_key)
		.unwrap();
	assert_eq!(&buf[..n], &original[40_000..40_000 + n]);
	let n = pf
		.read_at_with(&mut f, 100, &mut buf, &session_key)
		.unwrap();
	assert_eq!(&buf[..n], &original[100..100 + n]);
	let n = pf
		.read_at_with(&mut f, 1024, &mut buf, &session_key)
		.unwrap();
	assert_eq!(&buf[..n], &original[1024..1024 + n]);

	drop(f);
	std::fs::remove_dir_all(&dir).unwrap();
}

/// `read_at_with` on a FULL-encrypted file must match `read_at` too.
#[test]
fn read_at_with_matches_read_at_full_encrypted() {
	let dir = std::env::temp_dir().join("rcrm_proj_test_readatwith_full");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	let path = dir.join("small.mp3");
	// 512 bytes — below calibration_amount (2048) → Full mode.
	let original = deterministic_content(512, 9);
	std::fs::write(&path, &original).unwrap();

	let key = deterministic_content(32, 8);
	let manager = make_manager(&key);
	let new_name = manager.encrypt_file(&path).expect("encrypt failed");
	let enc_path = dir.join(&new_name);

	let session_key = SessionKey::generate().expect("mlock failed");
	let pf = ProjectedFile::open(&enc_path, &manager, &session_key).expect("open failed");
	assert!(pf.is_full_encrypted());

	let mut f = std::fs::File::open(&enc_path).unwrap();
	for off in [0u64, 1, 100, 511, 512, 1000] {
		let mut a = vec![0u8; 64];
		let mut b = vec![0xCCu8; 64];
		let n_a = pf.read_at(off, &mut a, &session_key).unwrap();
		let n_b = pf.read_at_with(&mut f, off, &mut b, &session_key).unwrap();
		assert_eq!(n_a, n_b);
		assert_eq!(&a[..n_a], &b[..n_b], "mismatch at offset {}", off);
	}
	drop(f);
	std::fs::remove_dir_all(&dir).unwrap();
}

/// O3: the head is materialized lazily. A file whose part2 fragment (the
/// last `header_len` bytes, at disk offset `file_size`) has been truncated
/// away still OPENS successfully (only the header + adjacent part1 are read
/// at open time), the unencrypted tail still reads fine, and only a read
/// overlapping the head region fails (on the deferred part2 read).
#[test]
fn lazy_head_defers_part2_read_until_head_access() {
	let dir = std::env::temp_dir().join("rcrm_proj_test_lazyhead");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	let path = dir.join("test_video.mp4");
	let original = deterministic_content(64 * 1024, 21);
	std::fs::write(&path, &original).unwrap();

	let key = deterministic_content(32, 22);
	let manager = make_manager(&key);
	let new_name = manager.encrypt_file(&path).expect("encrypt failed");
	let enc_path = dir.join(&new_name);

	// Disk layout: [header H][part1 C-H][plain tail C..file_size][part2 H].
	// Truncate away the final H bytes (the part2 fragment) by setting the
	// length to the virtual (plaintext) size.
	let file_size = original.len() as u64;
	let f = std::fs::OpenOptions::new()
		.write(true)
		.open(&enc_path)
		.unwrap();
	f.set_len(file_size).unwrap();
	drop(f);

	let session_key = SessionKey::generate().expect("mlock failed");
	let pf = ProjectedFile::open(&enc_path, &manager, &session_key).expect("open must succeed");

	// Tail reads (offset >= calibration_amount) still work without the head.
	let mut buf = vec![0u8; 100];
	let n = pf.read_at(40_000, &mut buf, &session_key).unwrap();
	assert_eq!(n, 100);
	assert_eq!(&buf[..], &original[40_000..40_100]);

	// Head-overlapping reads now fail on the deferred part2 read.
	let mut head_buf = vec![0u8; 100];
	assert!(
		pf.read_at(100, &mut head_buf, &session_key).is_err(),
		"head read should fail on truncated part2"
	);

	// And the failure is cached: a second head read fails the same way.
	assert!(pf.read_at(100, &mut head_buf, &session_key).is_err());

	std::fs::remove_dir_all(&dir).unwrap();
}
