// tests/kdf_guard.rs
// Guards for the key derivation.
//
// The Argon2id parameters are part of the ON-DISK format: the header stores
// `BLAKE2b(derived_key ‖ file_size ‖ calibration ‖ salt)`, so the derived
// key must stay reproducible for every file ever encrypted.
//
// Changing the parameters IS allowed — it is a breaking change and every
// existing library has to be re-encrypted. What is guarded here:
//   * the derivation is deterministic,
//   * the parameters do not accidentally get WEAKER (raising them is fine),
//   * a file written by an older build still decrypts — the canary that
//     tells you "you just broke every existing library",
//   * and registering the same key twice still panics.

use rcrm::{KDF_M_COST, KDF_P_COST, KDF_T_COST, Manager, is_supported_file, key_index};

/// The password is a test fixture, not a secret.
const TEST_PASSWORD: &[u8] = b"rcrm-kdf-guard-test";
/// calibration_amount — also part of the salt derivation.
const CALIBRATION: i32 = 2048;

/// The plaintext behind `tests/testdata/kdf_v1.bin` — the canary file that
/// stands in for "a library encrypted by an older build". It contains a
/// multi-byte character on purpose: the projection has to reproduce the
/// bytes exactly.
const FIXTURE_PLAINTEXT: &str = "rcrm kdf fixture v1 \u{2014} payload that must stay readable\n";
/// The original (pre-encryption) file name recorded in the fixture's header.
const FIXTURE_NAME: &str = "fixture-v1.mp4";

fn manager_with(key: Option<&[u8]>) -> Manager {
	Manager::new(true, true, CALIBRATION, is_supported_file, 6, key)
}

fn derived_key_hex(m: &Manager) -> String {
	m.using_key()
		.expect("a key is selected")
		.as_bytes()
		.iter()
		.map(|b| format!("{:02x}", b))
		.collect()
}

/// The derivation must be a pure function of (password, calibration).
#[test]
fn derivation_is_deterministic() {
	let a = manager_with(Some(TEST_PASSWORD));
	let b = manager_with(Some(TEST_PASSWORD));
	assert_eq!(derived_key_hex(&a), derived_key_hex(&b));
}

/// Different passwords must not collide.
#[test]
fn different_passwords_derive_different_keys() {
	let a = manager_with(Some(TEST_PASSWORD));
	let b = manager_with(Some(b"a different password"));
	assert_ne!(derived_key_hex(&a), derived_key_hex(&b));
}

/// Raising the cost is a security upgrade and is allowed; dropping below
/// the floor by accident is not.
#[test]
fn kdf_parameters_meet_the_security_floor() {
	// Checked at compile time: a build that drops below the floor does not link.
	const {
		assert!(
			KDF_M_COST >= (1 << 15),
			"memory cost dropped below the 32768 KiB floor"
		)
	};
	const { assert!(KDF_T_COST >= 7, "pass count dropped below the floor of 7") };
	const { assert!(KDF_P_COST >= 1, "parallelism dropped below the floor of 1") };
}

/// The canary: a file encrypted by an older build must still decrypt.
///
/// If this fails, the on-disk format changed and EVERY existing library
/// needs re-encrypting. Regenerate the fixture on purpose with
/// `RCRC_EMIT_KDF_FIXTURE=1 cargo test -p rcrm --test kdf_guard -- --ignored`.
#[test]
fn a_fixture_encrypted_by_an_older_build_still_decrypts() {
	let bytes = std::fs::read(fixture_path()).expect("fixture file must exist");
	let dir = std::env::temp_dir().join("rcrm_kdf_fixture");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();
	let path = dir.join(".fixture-v1");
	std::fs::write(&path, &bytes).unwrap();

	let manager = manager_with(Some(TEST_PASSWORD));
	let mut f = std::fs::File::open(&path).unwrap();
	let (header, _) = manager
		.read_file_header_any_key(&mut f)
		.expect("the fixture must still decrypt");
	assert_eq!(
		header.file_size,
		FIXTURE_PLAINTEXT.len() as u64,
		"the fixture's recorded size changed"
	);
	assert_eq!(
		header.orig_file_name.as_deref(),
		Some(FIXTURE_NAME),
		"the fixture's original file name changed"
	);

	// And the projected content must be the original plaintext.
	let session_key = rcrm::SessionKey::generate().unwrap();
	let pf = rcrm::ProjectedFile::open(&path, &manager, &session_key).unwrap();
	let mut out = vec![0u8; FIXTURE_PLAINTEXT.len()];
	pf.read_at(0, &mut out, &session_key).unwrap();
	assert_eq!(out, FIXTURE_PLAINTEXT.as_bytes());

	let _ = std::fs::remove_dir_all(&dir);
}

/// Regenerate the canary fixture — only when the format changed on purpose:
/// `RCRC_EMIT_KDF_FIXTURE=1 cargo test -p rcrm --test kdf_guard -- --ignored`
#[test]
#[ignore = "fixture generator — run explicitly with --ignored"]
fn emit_fixture() {
	if std::env::var("RCRC_EMIT_KDF_FIXTURE").is_err() {
		return;
	}
	let dir = std::env::temp_dir().join("rcrm_kdf_fixture_emit");
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();

	let path = dir.join(FIXTURE_NAME);
	std::fs::write(&path, FIXTURE_PLAINTEXT.as_bytes()).unwrap();
	let encrypted = manager_with(Some(TEST_PASSWORD))
		.encrypt_file(&path)
		.unwrap();

	let bytes = std::fs::read(dir.join(&encrypted)).unwrap();
	let out = fixture_path();
	std::fs::create_dir_all(out.parent().unwrap()).unwrap();
	std::fs::write(&out, &bytes).unwrap();
	println!("wrote {} bytes to {}", bytes.len(), out.display());
}

fn fixture_path() -> std::path::PathBuf {
	std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
		.join("tests")
		.join("testdata")
		.join("kdf_v1.bin")
}

/// Registering the same key index twice is a programming error and
/// `Manager` panics on it: a silently-ignored registration looks to the
/// user like "the password does not work".
#[test]
#[should_panic(expected = "of key exists!")]
fn registering_the_same_key_twice_panics() {
	let mut manager = manager_with(Some(TEST_PASSWORD));
	// The same password again → the same key index → must fail loudly.
	manager.use_added_key(TEST_PASSWORD);
}

#[test]
fn key_index_is_the_identity_of_a_registered_key() {
	let manager = manager_with(Some(TEST_PASSWORD));
	// The caller's duplicate check: the registered password's index is
	// taken, an unrelated one is not.
	assert!(manager.has_key_index(key_index(TEST_PASSWORD)));
	assert!(!manager.has_key_index(key_index(b"a different password")));
}
