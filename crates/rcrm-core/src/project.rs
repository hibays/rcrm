// src/project.rs
// rcrm - Read-only projection of encrypted files for the FTP(S) server.
// Copyleft (©) 2024-2025 hibays
//
// This module provides:
//   * `SessionKey`    — an ephemeral ChaCha20 key used to encrypt cached
//                       decrypted heads at rest in memory, to resist
//                       cold-boot / memory-dump side-channel attacks.
//   * `ProjectedFile` — a read-only virtual view of an encrypted file that
//                       presents the original plaintext to callers without
//                       ever writing it back to disk. Partially-encrypted
//                       files keep only their head (calibration_amount
//                       bytes) cached in memory; the unencrypted tail is
//                       streamed directly from disk on demand.

use std::fs::OpenOptions;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use zeroize::Zeroizing;

use crate::crypt::{FileHeader, Manager};

// =======================
// SessionKey: encrypts cached plaintext heads in memory
// =======================

/// Ephemeral symmetric key generated once at server startup and held in a
/// `Zeroizing` wrapper. Used to encrypt every cached decrypted head so that
/// a memory dump does not reveal plaintext file content. The key itself is
/// not derivable from anything on disk — it lives only in process memory
/// and is wiped on drop.
pub struct SessionKey {
	key: Zeroizing<[u8; 32]>,
}

impl SessionKey {
	pub fn generate() -> Self {
		let mut key = Zeroizing::new([0u8; 32]);
		rand::TryRngCore::try_fill_bytes(&mut rand::rngs::OsRng, key.as_mut())
			.expect("OsRng failed");
		SessionKey { key }
	}

	/// Encrypt `plaintext` with a fresh per-entry `nonce`. The ciphertext is
	/// the same length as the plaintext (ChaCha20 is a stream cipher).
	pub fn encrypt(&self, plaintext: &[u8], nonce: &[u8; 12]) -> Vec<u8> {
		let mut cipher = ChaCha20::new_from_slices(self.key.as_ref(), nonce).unwrap();
		let mut out = plaintext.to_vec();
		cipher.apply_keystream(&mut out);
		out
	}

	/// Decrypt `ciphertext` into a `Zeroizing` buffer so the plaintext is
	/// wiped from memory as soon as the caller drops it.
	pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8; 12]) -> io::Result<Zeroizing<Vec<u8>>> {
		let mut cipher = ChaCha20::new_from_slices(self.key.as_ref(), nonce)
			.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
		let mut out = Zeroizing::new(ciphertext.to_vec());
		cipher.apply_keystream(out.as_mut());
		Ok(out)
	}
}

// =======================
// ProjectedFile: read-only virtual view of an encrypted file
// =======================

pub struct ProjectedFile {
	path: PathBuf,
	header: FileHeader,
	kind: ProjectedKind,
}

enum ProjectedKind {
	/// Entire file body is encrypted. No head caching — stream-decrypt on
	/// each read using ChaCha20's seekable keystream. The matching manager
	/// key is cloned here so `read_at` is self-contained (does not need a
	/// `&Manager` reference).
	Full { key: Zeroizing<[u8; 32]> },
	/// Only the first `calibration_amount` bytes are encrypted. The
	/// decrypted head is cached here, encrypted at rest with the session
	/// key. The remainder of the file is read directly from disk (it was
	/// never modified on disk).
	Partial {
		encrypted_head: Vec<u8>,
		head_nonce: [u8; 12],
	},
}

impl ProjectedFile {
	/// Open an encrypted file, verify its header (trying every key
	/// registered in `manager`), and (for partial files) decrypt + cache
	/// the head. Returns `Err(InvalidData)` if no key matches.
	pub fn open(path: &Path, manager: &Manager, session_key: &SessionKey) -> io::Result<Self> {
		let mut file = OpenOptions::new().read(true).open(path)?;
		let (header, key_idx) = manager.read_file_header_any_key(&mut file)?;

		let kind = if header.is_full_encrypted() {
			// Clone the matching key for self-contained reads.
			let key = manager
				.key_by_idx(key_idx)
				.ok_or_else(|| io::Error::other("key vanished"))?
				.clone();
			ProjectedKind::Full { key }
		} else {
			// Partial: decrypt the head with the matching key, then
			// re-encrypt it with the session key for in-memory storage.
			let key = manager
				.key_by_idx(key_idx)
				.ok_or_else(|| io::Error::other("key vanished"))?;
			let head = header.decrypt_head(&mut file, key.as_ref())?;
			let head_nonce: [u8; 12] = rand::random();
			let encrypted_head = session_key.encrypt(head.as_ref(), &head_nonce);
			ProjectedKind::Partial {
				encrypted_head,
				head_nonce,
			}
		};

		// Drop the file handle — its internal buffers are not sensitive
		// (encrypted data only), but releasing it promptly is good hygiene.
		drop(file);

		Ok(ProjectedFile {
			path: path.to_path_buf(),
			header,
			kind,
		})
	}

	pub fn virtual_size(&self) -> u64 {
		self.header.file_size
	}

	pub fn virtual_name(&self) -> &str {
		self.header
			.orig_file_name
			.as_deref()
			.unwrap_or_else(|| self.path.file_name().and_then(|s| s.to_str()).unwrap_or(""))
	}

	pub fn disk_path(&self) -> &std::path::Path {
		&self.path
	}

	pub fn is_full_encrypted(&self) -> bool {
		matches!(self.kind, ProjectedKind::Full { .. })
	}

	/// Read `buf.len()` bytes starting at virtual offset `offset` from the
	/// projected (decrypted) file. Returns the number of bytes read (may be
	/// less than `buf.len()` at EOF).
	///
	/// For `Partial` files, the cached head is decrypted on-the-fly into a
	/// temporary `Zeroizing` buffer for the portion that overlaps the head
	/// region; the tail is streamed directly from disk. For `Full` files,
	/// the entire read is streamed from disk with on-the-fly decryption
	/// using ChaCha20's seekable keystream — nothing is cached.
	pub fn read_at(
		&self,
		offset: u64,
		buf: &mut [u8],
		session_key: &SessionKey,
	) -> io::Result<usize> {
		let vsize = self.header.file_size;
		if offset >= vsize || buf.is_empty() {
			return Ok(0);
		}
		let to_read = std::cmp::min(buf.len() as u64, vsize - offset) as usize;
		let buf = &mut buf[..to_read];

		match &self.kind {
			ProjectedKind::Full { key } => {
				// On-disk layout: [header (H)][encrypted_data (file_size)]
				// Virtual byte i lives at disk byte (H + i), encrypted with
				// keystream[keystream_offset + i].
				let mut file = OpenOptions::new().read(true).open(&self.path)?;
				file.seek(SeekFrom::Start(self.header.header_len as u64 + offset))?;
				file.read_exact(buf)?;

				let mut cipher = ChaCha20::new_from_slices(key.as_ref(), &self.header.nonce)
					.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
				cipher.seek(self.header.keystream_offset + offset);
				cipher.apply_keystream(buf);
			}
			ProjectedKind::Partial {
				encrypted_head,
				head_nonce,
			} => {
				let c = self.header.calibration_amount as u64;

				if offset >= c {
					// Entirely in the unencrypted tail region — read from disk.
					// (disk[C..file_size] == original[C..file_size], unchanged.)
					let mut file = OpenOptions::new().read(true).open(&self.path)?;
					file.seek(SeekFrom::Start(offset))?;
					file.read_exact(buf)?;
				} else if offset + to_read as u64 <= c {
					// Entirely within the decrypted head — decrypt the cached
					// head on-the-fly and copy out the requested slice.
					let head = session_key.decrypt(encrypted_head, head_nonce)?;
					let start = offset as usize;
					buf.copy_from_slice(&head[start..start + to_read]);
				} else {
					// Spans the head/tail boundary: head[offset..C] from
					// memory, then disk[C..offset+to_read] from disk.
					let head = session_key.decrypt(encrypted_head, head_nonce)?;
					let head_part_len = (c - offset) as usize;
					buf[..head_part_len].copy_from_slice(&head[offset as usize..c as usize]);

					let mut file = OpenOptions::new().read(true).open(&self.path)?;
					file.seek(SeekFrom::Start(c))?;
					file.read_exact(&mut buf[head_part_len..])?;
				}
			}
		}

		Ok(to_read)
	}
}
