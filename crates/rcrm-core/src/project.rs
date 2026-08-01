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

use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};

use crate::locked_page::LockedKey;
use rand::TryRng;
use zeroize::Zeroizing;

use crate::crypt::{FileHeader, Manager};

// =======================
// SessionKey: encrypts cached plaintext heads in memory
// =======================

/// Ephemeral symmetric key generated once at server startup, held in
/// page-locked memory so it cannot be swapped to disk.
pub struct SessionKey {
	key: LockedKey<32>,
}

impl SessionKey {
	pub fn generate() -> io::Result<Self> {
		let mut key = LockedKey::<32>::zeroed()?;
		rand::rngs::SysRng
			.try_fill_bytes(key.as_mut_bytes())
			.expect("SysRng failed");
		Ok(SessionKey { key })
	}

	/// Encrypt `plaintext` with a fresh per-entry `nonce`. The ciphertext is
	/// the same length as the plaintext (ChaCha20 is a stream cipher).
	pub fn encrypt(&self, plaintext: &[u8], nonce: &[u8; 12]) -> io::Result<Vec<u8>> {
		let mut cipher = ChaCha20::new_from_slices(self.key.as_bytes(), nonce)
			.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
		let mut out = plaintext.to_vec();
		cipher.apply_keystream(&mut out);
		Ok(out)
	}

	/// Decrypt `ciphertext` into a `Zeroizing` buffer so the plaintext is
	/// wiped from memory as soon as the caller drops it.
	pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8; 12]) -> io::Result<Zeroizing<Vec<u8>>> {
		let mut cipher = ChaCha20::new_from_slices(self.key.as_bytes(), nonce)
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
	/// key is shared (Arc) here so `read_at` is self-contained (does not
	/// need a `&Manager` reference) without cloning the locked page.
	Full { key: Arc<LockedKey<32>> },
	/// Only the first `calibration_amount` bytes are encrypted. The
	/// decrypted head is cached lazily: the on-disk part2 tail of the head
	/// ciphertext (header_len bytes at disk offset `file_size`) is only
	/// read + decrypted on the first read that overlaps the head region.
	/// The cached head is encrypted at rest with the session key. The
	/// remainder of the file is read directly from disk (it was never
	/// modified on disk).
	Partial {
		key: Arc<LockedKey<32>>,
		/// First (calibration - header_len) ciphertext bytes of the head —
		/// physically adjacent to the header, read during open.
		part1: Vec<u8>,
		/// Lazily computed (encrypted_head, head_nonce). `Err` if the
		/// deferred part2 read/decrypt failed; cached so a permanently
		/// broken file fails consistently.
		head: OnceLock<io::Result<(Vec<u8>, [u8; 12])>>,
	},
}

impl ProjectedFile {
	/// Open an encrypted file, verify its header (trying every key
	/// registered in `manager`), and (for partial files) read the part of
	/// the head adjacent to the header. The second head fragment on disk
	/// and the head decryption itself are deferred to the first read that
	/// overlaps the head region (see [`Self::init_head`]). Returns
	/// `Err(InvalidData)` if no key matches.
	pub fn open(path: &Path, manager: &Manager, _session_key: &SessionKey) -> io::Result<Self> {
		let file = OpenOptions::new().read(true).open(path)?;
		// Buffer the header read: the 94-byte fixed header is followed
		// immediately by part1 of the head ciphertext, so one underlying
		// read syscall serves both (the 64 KiB buffer absorbs the adjacent
		// bytes; part1 is then copied from memory).
		let mut reader = BufReader::with_capacity(64 * 1024, file);
		let (header, key_idx) = manager.read_file_header_any_key(&mut reader)?;

		let kind = if header.is_full_encrypted() {
			// Share the matching key; no per-file locked-page clone.
			let key = manager
				.key_by_idx(key_idx)
				.ok_or_else(|| io::Error::other("key vanished"))?;
			ProjectedKind::Full { key }
		} else {
			let key = manager
				.key_by_idx(key_idx)
				.ok_or_else(|| io::Error::other("key vanished"))?;
			// part1 = the (calibration - header_len) ciphertext bytes
			// physically adjacent to the header (disk[H..C]).
			let c = header.calibration_amount as usize;
			let part1_len = c.saturating_sub(header.header_len);
			let mut part1 = vec![0u8; part1_len];
			reader.read_exact(&mut part1)?;
			ProjectedKind::Partial {
				key,
				part1,
				head: OnceLock::new(),
			}
		};

		// Drop the file handle — its internal buffers are not sensitive
		// (encrypted data only), but releasing it promptly is good hygiene.
		drop(reader);

		Ok(ProjectedFile {
			path: path.to_path_buf(),
			header,
			kind,
		})
	}

	/// Lazily materialize the decrypted head: read the second head
	/// fragment (the last `header_len` ciphertext bytes, stored at disk
	/// offset `file_size`), decrypt the assembled head with the file key,
	/// then re-encrypt it with the session key for in-memory storage.
	///
	/// Called at most once per `ProjectedFile` (via `OnceLock`); on
	/// failure the error is cached so later reads fail consistently
	/// instead of re-reading the disk.
	fn init_head(
		&self,
		file: &mut File,
		session_key: &SessionKey,
	) -> io::Result<(Vec<u8>, [u8; 12])> {
		let ProjectedKind::Partial { key, part1, .. } = &self.kind else {
			return Err(io::Error::other("init_head on non-partial file"));
		};
		let c = self.header.calibration_amount as usize;
		let h = self.header.header_len;

		// part1_len + part2_len must equal c — the same split as
		// FileHeader::decrypt_head. Using `c - part1_len` (instead of h)
		// keeps this mathematically identical to the original even in the
		// degenerate c < header_len case (unreachable via encrypt_file,
		// which panics on that underflow, but a hand-crafted header with a
		// valid key_hash could still reach it).
		let part1_len = c.saturating_sub(h);
		let mut enc = Zeroizing::new(Vec::with_capacity(c));
		enc.extend_from_slice(part1);
		// part2: the remaining (c - part1_len) ciphertext bytes live at
		// disk [file_size..file_size + (c - part1_len)] (see encrypt_file's
		// write sequence).
		file.seek(SeekFrom::Start(self.header.file_size))?;
		let part2_len = c - part1_len;
		let mut part2 = vec![0u8; part2_len];
		file.read_exact(&mut part2)?;
		enc.extend_from_slice(&part2);

		// Decrypt: seek the cipher to `keystream_offset` and apply
		// keystream (same math as FileHeader::decrypt_head).
		let mut cipher = ChaCha20::new_from_slices(key.as_bytes(), &self.header.nonce)
			.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
		cipher.seek(self.header.keystream_offset);
		cipher.apply_keystream(&mut enc);

		let head_nonce: [u8; 12] = rand::random();
		let encrypted_head = session_key.encrypt(enc.as_ref(), &head_nonce)?;
		Ok((encrypted_head, head_nonce))
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
	///
	/// This variant opens the file for every call. Hot loops (e.g. the
	/// WebDAV/FTP transfer loops that read one 64 KiB chunk per call)
	/// should instead open the file once and use [`Self::read_at_with`].
	pub fn read_at(
		&self,
		offset: u64,
		buf: &mut [u8],
		session_key: &SessionKey,
	) -> io::Result<usize> {
		let mut file = OpenOptions::new().read(true).open(&self.path)?;
		self.read_at_with(&mut file, offset, buf, session_key)
	}

	/// Like [`Self::read_at`], but reads through a caller-provided file
	/// handle opened once before the loop. The handle is opened read-only
	/// and its cursor position is irrelevant: every read seeks to the
	/// absolute virtual offset first, so out-of-order offsets and multiple
	/// concurrent callers (each with their own handle) are safe.
	///
	/// The caller owns the handle and is responsible for closing it
	/// (dropping it) after the transfer; this method never stores it.
	pub fn read_at_with(
		&self,
		file: &mut File,
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
				file.seek(SeekFrom::Start(self.header.header_len as u64 + offset))?;
				file.read_exact(buf)?;

				let mut cipher = ChaCha20::new_from_slices(key.as_bytes(), &self.header.nonce)
					.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
				cipher.seek(self.header.keystream_offset + offset);
				cipher.apply_keystream(buf);
			}
			ProjectedKind::Partial { head, .. } => {
				let c = self.header.calibration_amount as u64;

				if offset >= c {
					// Entirely in the unencrypted tail region — read from disk.
					// (disk[C..file_size] == original[C..file_size], unchanged.)
					file.seek(SeekFrom::Start(offset))?;
					file.read_exact(buf)?;
				} else {
					// Overlaps the head region. Materialize the decrypted
					// head on first use (reads the deferred part2 fragment,
					// decrypts, re-encrypts at rest with the session key),
					// then decrypt it on-the-fly into a temporary Zeroizing
					// buffer and copy out the requested slice.
					let cached = head.get_or_init(|| self.init_head(file, session_key));
					let (encrypted_head, head_nonce) = cached
						.as_ref()
						.map_err(|e| io::Error::new(e.kind(), e.to_string()))?;
					let head = session_key.decrypt(encrypted_head, head_nonce)?;
					if offset + to_read as u64 <= c {
						let start = offset as usize;
						buf.copy_from_slice(&head[start..start + to_read]);
					} else {
						// Spans the head/tail boundary: head[offset..C] from
						// memory, then disk[C..offset+to_read] from disk.
						let head_part_len = (c - offset) as usize;
						buf[..head_part_len].copy_from_slice(&head[offset as usize..c as usize]);
						file.seek(SeekFrom::Start(c))?;
						file.read_exact(&mut buf[head_part_len..])?;
					}
				}
			}
		}

		Ok(to_read)
	}
}
