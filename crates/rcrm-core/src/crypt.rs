// src/crypt.rs
// rcrm - A simple file encryption/decryption tool
// Copyleft (©) 2024-2025 hibays

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Version};
use blake2::{Blake2b512, Blake2s256, Digest};

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};

use zeroize::{Zeroize, Zeroizing};

use crate::base72::b72_encode_rust as b72encode;

// =======================
// Xorshift RNGs
// =======================

// See https://gist.github.com/AbsoluteVirtue/82a1913196fe0922262930ee81c327cb
fn xorshift32(state: &mut u32) -> u32 {
	// Algorithm "xor" from p. 4 of Marsaglia, "Xorshift RNGs"
	*state ^= *state << 13;
	*state ^= *state >> 17;
	*state ^= *state << 5;
	*state
}

fn xorshift64s(state: u64) -> u64 {
	// Xorshift64s, variant A_1(12,25,27) with multiplier M_32 from line 3 of table 5
	let mut n = state;
	n ^= n << 12;
	n ^= n >> 25;
	n ^= n << 27;
	n * 0x2545f4914f6cdd1d
}

// =======================
// Manager Struct
// =======================

pub struct Manager {
	pub dir_name_crypt: bool,
	pub file_name_crypt: bool,
	pub calibration_amount: u32,
	pub rule_fn: fn(&Path) -> bool,
	pub works: usize,
	pub keys: HashMap<u32, Zeroizing<[u8; 32]>>,
}

impl Manager {
	pub const MAGIC_KEY_USING: u32 = 0;

	pub fn new(
		dir_name_crypt: bool,
		file_name_crypt: bool,
		calibration_amount: i32,
		rule_fn: fn(&Path) -> bool,
		works: usize,
		key: Option<&[u8]>,
	) -> Self {
		let cal_amount = if calibration_amount <= 0 {
			u32::MAX
		} else {
			calibration_amount as u32
		};

		let mut manager = Manager {
			dir_name_crypt,
			file_name_crypt,
			calibration_amount: cal_amount,
			rule_fn,
			works,
			keys: HashMap::new(),
		};

		if let Some(k) = key {
			manager.use_added_key(k);
		}

		manager
	}

	fn derive_key(&self, key: &[u8]) -> Zeroizing<[u8; 32]> {
		let mut state = self.calibration_amount;
		let salt_val = xorshift64s(xorshift32(&mut state) as u64) ^ self.calibration_amount as u64;
		let salt = &salt_val.to_le_bytes()[..8];

		let argon2 = Argon2::new(
			Algorithm::Argon2id,
			Version::V0x13,
			argon2::Params::new(1 << 15, 7, 4, Some(32)).unwrap(),
		);

		let mut hash = Zeroizing::new([0u8; 32]);
		argon2.hash_password_into(key, salt, hash.as_mut()).unwrap();
		hash
	}

	fn add_key(&mut self, key: &[u8], idx: Option<u32>) -> u32 {
		let derived = self.derive_key(key);
		let idx = idx.unwrap_or_else(|| crc32fast::hash(key));

		if self.keys.contains_key(&idx) {
			panic!("Index ({}) of key exists!", idx);
		}

		if !self.keys.values().any(|v| v == &derived) {
			self.keys.insert(idx, derived);
		}

		idx
	}

	pub fn use_key(&mut self, idx: &u32) {
		// use_key will clone the key to MAGIC_KEY_USING
		// and won't drop the original key
		if !self.keys.contains_key(idx) {
			panic!("The indexed key index '{}' does not exist.", idx);
		}
		self.keys
			.insert(Manager::MAGIC_KEY_USING, self.keys[idx].to_owned()); // Note: clone will copy the key
	}

	pub fn drop_key(&mut self, idx: &u32) -> Option<Zeroizing<[u8; 32]>> {
		if let Some(val) = self.keys.get_mut(idx) {
			val.zeroize();
		};
		self.keys.remove(idx)
	}

	pub fn drop_all_keys(&mut self) {
		if let Some(idxs) = self.list_key_idxs() {
			for idx in idxs {
				self.drop_key(&idx);
			}
		}
	}

	pub fn use_added_key(&mut self, key: &[u8]) -> u32 {
		let idx = self.add_key(key, None);
		self.use_key(&idx);
		idx
	}

	pub fn use_provided_key(&mut self, key: &[u8]) {
		self.keys
			.insert(Manager::MAGIC_KEY_USING, self.derive_key(key));
	}

	pub fn list_key_idxs(&self) -> Option<Vec<u32>> {
		let v: Vec<u32> = self.keys.keys().cloned().collect();
		if v.is_empty() { None } else { Some(v) }
	}

	fn get_using_key(&self) -> &Zeroizing<[u8; 32]> {
		self.keys
			.get(&Manager::MAGIC_KEY_USING)
			.expect("No current key")
	}

	/// Public accessor for the currently-active derived key.
	/// Used by the projection layer to decrypt file heads / streams on demand.
	pub fn using_key(&self) -> &Zeroizing<[u8; 32]> {
		self.get_using_key()
	}

	/// Read and verify the header of an encrypted file. Returns the parsed
	/// header without touching the file body. The file cursor is left
	/// positioned at the first byte after the header (i.e. at the start of
	/// the encrypted head part 1 for partial files, or the start of the
	/// encrypted data for full files).
	pub fn read_file_header(&self, file: &mut File) -> io::Result<FileHeader> {
		FileHeader::read_and_verify(file, self.get_using_key().as_ref())
	}

	/// Decrypt the head (the first `calibration_amount` bytes of the
	/// original plaintext) of a partially-encrypted file. The file cursor
	/// must be positioned at the first byte after the header (use
	/// [`Manager::read_file_header`] first).
	pub fn decrypt_head(
		&self,
		file: &mut File,
		header: &FileHeader,
	) -> io::Result<Zeroizing<Vec<u8>>> {
		header.decrypt_head(file, self.get_using_key().as_ref())
	}

	/// Try to detect whether `file` is an rcrm-encrypted file by reading and
	/// verifying its header. Returns `Ok(Some(header))` if encrypted with the
	/// current key, `Ok(None)` if not encrypted (or wrong key), or `Err` on
	/// I/O failure. The file cursor is rewound to the start on the `None`
	/// path so the caller can fall back to plain serving.
	pub fn try_read_header(&self, file: &mut File) -> io::Result<Option<FileHeader>> {
		match FileHeader::read_and_verify(file, self.get_using_key().as_ref()) {
			Ok(h) => Ok(Some(h)),
			Err(e) if e.kind() == io::ErrorKind::InvalidData => {
				// Either too small for a header, or key_hash mismatch → not encrypted with our key.
				// Rewind so the caller can serve the file as plain.
				let _ = file.seek(SeekFrom::Start(0));
				Ok(None)
			}
			Err(e) => Err(e),
		}
	}

	/// Try every key registered in this manager until one verifies the
	/// file's header. Returns the header and the index of the matching key.
	/// On success the file cursor is positioned at the first byte after the
	/// header. If no key matches, returns `InvalidData`.
	pub fn read_file_header_any_key(&self, file: &mut File) -> io::Result<(FileHeader, u32)> {
		let mut last_err: Option<io::Error> = None;
		for (&idx, key) in &self.keys {
			// Rewind before each attempt.
			file.seek(SeekFrom::Start(0))?;
			match FileHeader::read_and_verify(file, key.as_ref()) {
				Ok(h) => return Ok((h, idx)),
				Err(e) if e.kind() == io::ErrorKind::InvalidData => {
					last_err = Some(e);
					continue;
				}
				Err(e) => return Err(e),
			}
		}
		Err(last_err.unwrap_or_else(|| {
			io::Error::new(
				io::ErrorKind::InvalidData,
				"No key registered — cannot open encrypted file",
			)
		}))
	}

	/// Look up a registered key by its index. Used by projection to
	/// retrieve the matching key for a file after `read_file_header_any_key`.
	pub fn key_by_idx(&self, idx: u32) -> Option<&Zeroizing<[u8; 32]>> {
		self.keys.get(&idx)
	}

	#[allow(dead_code)]
	fn filter(&self, paths: &[PathBuf]) -> Vec<PathBuf> {
		paths
			.iter()
			.filter(|p| (self.rule_fn)(p))
			.cloned()
			.collect()
	}

	pub fn encrypt_file(&self, file: &Path) -> io::Result<String> {
		let mut f = File::options().read(true).write(true).open(file)?;
		let file_size = f.metadata()?.len();

		// 生成随机盐和 nonce
		let key_hash_salt: [u8; 4] = rand::random();
		let nonce: [u8; 12] = rand::random();

		// 计算 key_hash = BLAKE2b(key + file_size + ca + salt)
		let mut hasher = Blake2b512::new();
		hasher.update(self.get_using_key());
		hasher.update(file_size.to_le_bytes());
		hasher.update(self.calibration_amount.to_le_bytes());
		hasher.update(key_hash_salt);
		let key_hash: [u8; 64] = hasher.finalize().into();

		/* 构造 header:
		(04 bytes <I) calibration_amount
		(08 bytes <Q) file_size
		(04 bytes   ) key_hash_salt
		(64 bytes   ) key_hash
		(12 bytes   ) nonce
		(02 bytes <H) file_name_crypt(in final bit) && original_file_name_length(in bytes)
		(?? bytes   ) original_file_name(encrypted)  */
		let mut header = Vec::new();
		header.extend_from_slice(&self.calibration_amount.to_le_bytes()); // 4
		header.extend_from_slice(&file_size.to_le_bytes()); // 8
		header.extend_from_slice(&key_hash_salt); // 4
		header.extend_from_slice(key_hash.as_slice()); // 64
		header.extend_from_slice(&nonce); // 12

		// 生成密钥流（基于密钥和 nonce）
		let mut cipher = ChaCha20::new_from_slices(self.get_using_key().as_ref(), &nonce).unwrap();

		// 处理文件名加密
		// Note: 文件名加密时，会原地修改文件名
		let file_name_b = if self.file_name_crypt {
			let mut file_name_b = file
				.file_name()
				.unwrap()
				.to_string_lossy()
				.into_owned()
				.into_bytes();
			header.extend_from_slice(&(((file_name_b.len() as u16) << 1) | 1).to_le_bytes()); // 2
			cipher.apply_keystream(&mut file_name_b); // Inplace encrypt file name
			header.extend(&file_name_b);
			file_name_b
		} else {
			header.extend([0u8, 0u8]); // 2
			Vec::new() // Note: 未启用文件名加密时，file_name_b 不会被使用，故为空
		};

		// 加密后数据（根据 calibration_amount）
		if self.calibration_amount == u32::MAX || file_size < self.calibration_amount as u64 {
			// 全加密
			let mut enc_data = Vec::new();
			// 读取原文件数据
			f.read_to_end(&mut enc_data)?;

			cipher.apply_keystream(&mut enc_data);

			f.seek(SeekFrom::Start(0))?;
			// 写入：header + 加密数据
			f.write_all(&header)?;
			f.write_all(&enc_data)?;
		} else {
			// 部分加密
			// 读取原文件数据进行加密
			/*
			let mut enc_data = Vec::with_capacity(self.calibration_amount as usize);
			Read::by_ref(&mut f)
				.take(self.calibration_amount as u64)
				.read_to_end(&mut enc_data)
				.unwrap();*/
			let mut enc_data = vec![0u8; self.calibration_amount as usize];
			f.read_exact(&mut enc_data)?;
			cipher.apply_keystream(&mut enc_data);

			// 写入：header + 加密数据
			f.seek(SeekFrom::Start(0))?;
			f.write_all(&header)?;
			f.write_all(&enc_data[..self.calibration_amount as usize - header.len()])?;
			f.seek(SeekFrom::End(0))?;
			f.write_all(&enc_data[self.calibration_amount as usize - header.len()..])?;
		};

		drop(f);

		if self.file_name_crypt {
			// 对文件名进行加密
			let hash = Blake2s256::digest(&file_name_b);
			let encoded = b72encode(&hash);
			let new_path = file.with_file_name(format!(".{}", String::from_utf8_lossy(&encoded)));

			fs::rename(file, &new_path)?;
			Ok(new_path.file_name().unwrap().to_string_lossy().into_owned())
		} else {
			// 文件名未加密，保持原名
			Ok(file.file_name().unwrap().to_string_lossy().into_owned())
		}
	}

	pub fn decrypt_file(&self, file: &Path) -> io::Result<String> {
		let mut f = File::options().read(true).open(file)?;

		let header_rd = &mut [0u8; 4 + 8 + 4 + 64 + 12 + 2];
		let read = f.read(header_rd)?;
		if read < 4 + 8 + 4 + 64 + 12 + 2 {
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				"File too small for header",
			));
		}

		// 假设 header 未加密，提取关键字段
		let ca_b = &header_rd[0..4];
		let file_size_b = &header_rd[4..12];
		let key_hash_salt = &header_rd[12..16];
		let key_hash = &header_rd[16..80];

		// Verify key_hash before nonce
		let mut hasher = Blake2b512::new();
		hasher.update(self.get_using_key());
		hasher.update(file_size_b);
		hasher.update(ca_b);
		hasher.update(key_hash_salt);
		if key_hash != hasher.finalize()[..64].as_ref() {
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				"Uncorrected key!",
			));
		}

		let nonce = &header_rd[80..92];
		let mut cipher = ChaCha20::new_from_slices(self.get_using_key().as_ref(), nonce).unwrap();

		// 读取文件名标志和长度
		let ff = u16::from_le_bytes([header_rd[92], header_rd[93]]);
		let file_name_crypt = (ff & 1) != 0;
		let original_file_name_length = (ff >> 1) as usize;

		// 解密文件名（如果加密）
		let orig_file_name = if file_name_crypt && original_file_name_length > 0 {
			let mut enc_name = vec![0u8; original_file_name_length];
			f.read_exact(&mut enc_name)?;

			cipher.apply_keystream(&mut enc_name);

			String::from_utf8(enc_name).map_err(|_| {
				io::Error::new(io::ErrorKind::InvalidData, "Invalid filename encoding")
			})?
		} else {
			String::new()
		};

		let calibration_amount = u32::from_le_bytes(ca_b.try_into().unwrap());
		let file_size = u64::from_le_bytes(file_size_b.try_into().unwrap());

		// 读取并解密数据部分
		let dec_data = if calibration_amount == u32::MAX || file_size < calibration_amount as u64 {
			// 全解密
			// Support too small file encrypt in decrypt level
			let mut data = Vec::new();
			f.read_to_end(&mut data)?;

			cipher.apply_keystream(&mut data);
			data
		} else {
			// 部分解密
			/*
			let mut data = Vec::with_capacity(calibration_amount as usize);
			// Note: 这里有一个 Debug 很久的问题，导致解密失败的，即初始化时使用vec![0u8; calibration_amount as usize]
			// 而不是 Vec::with_capacity(calibration_amount as usize) 时，使用 read_to_end 读取数据
			// 会导致数据是 [0000... + read_data]（即数据前有 calibration_amount 个 0）
			// 而不是纯粹的 read_data，从而导致解密失败
			let curpos = f.stream_position()?;
			Read::by_ref(&mut &f)
				.take(calibration_amount as u64 - curpos)
				.read_to_end(&mut data)?;*/
			let curpos = f.stream_position()? as usize;
			let mut data = vec![0u8; calibration_amount as usize - curpos];
			f.read_exact(&mut data)?;
			f.seek(SeekFrom::Start(file_size))?;

			let mut tail = vec![0u8; curpos];
			f.read_exact(&mut tail)?;

			data.extend(tail);

			cipher.apply_keystream(&mut data);
			data
		};
		drop(f);

		// 重写文件为解密后的原始内容
		let mut wf = File::options().write(true).truncate(false).open(file)?;
		wf.write_all(&dec_data)?;
		wf.set_len(file_size)?;
		wf.flush()?;
		drop(wf);

		if file_name_crypt {
			// 文件名解密回原名
			let new_path = file.with_file_name(&orig_file_name);
			fs::rename(file, &new_path)?;
			Ok(orig_file_name)
		} else {
			// 文件名未加密，保持原名
			Ok(file.file_name().unwrap().to_string_lossy().into_owned())
		}
	}
}

// =======================
// FileHeader: parsed and verified header of an encrypted file
// =======================

/// Parsed header of an rcrm-encrypted file, with the key_hash already
/// verified against the supplied manager key.
///
/// Layout on disk (little-endian where applicable):
/// ```text
/// (04 bytes <I) calibration_amount
/// (08 bytes <Q) file_size            ← original (plaintext) size
/// (04 bytes   ) key_hash_salt
/// (64 bytes   ) key_hash             ← BLAKE2b(key || file_size || ca || salt)
/// (12 bytes   ) nonce                ← ChaCha20 nonce
/// (02 bytes <H) file_name_crypt(bit0) || original_file_name_length(bits1..15)
/// (?? bytes   ) original_file_name(encrypted with the same ChaCha20 keystream)
/// ```
#[derive(Clone)]
pub struct FileHeader {
	pub calibration_amount: u32,
	/// Original (plaintext) file size — the virtual size seen by FTP clients.
	pub file_size: u64,
	pub key_hash_salt: [u8; 4],
	pub key_hash: [u8; 64],
	pub nonce: [u8; 12],
	pub file_name_crypt: bool,
	/// Decrypted original filename, if `file_name_crypt` was enabled.
	pub orig_file_name: Option<String>,
	/// Total header length in bytes (fixed 94 + variable filename).
	pub header_len: usize,
	/// Byte offset into the ChaCha20 keystream where the file *body*
	/// (the encrypted head) begins. Equals the encrypted filename length
	/// when name-cryption is enabled (the cipher advances past the
	/// filename bytes before encrypting the body), otherwise 0.
	pub keystream_offset: u64,
}

impl FileHeader {
	/// Fixed prefix length: ca(4) + file_size(8) + salt(4) + key_hash(64) +
	/// nonce(12) + flags(2) = 94 bytes.
	pub const FIXED_LEN: usize = 4 + 8 + 4 + 64 + 12 + 2;

	/// Read the header from `file` and verify `key_hash` against `manager_key`.
	/// On success the file cursor is positioned at the first byte after the
	/// header. On `InvalidData` error the cursor position is unspecified.
	pub fn read_and_verify(file: &mut File, manager_key: &[u8]) -> io::Result<Self> {
		let mut header_rd = [0u8; Self::FIXED_LEN];
		let read = file.read(&mut header_rd)?;
		if read < Self::FIXED_LEN {
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				"File too small for header",
			));
		}

		let ca_b = &header_rd[0..4];
		let file_size_b = &header_rd[4..12];
		let key_hash_salt: [u8; 4] = header_rd[12..16].try_into().unwrap();
		let key_hash: [u8; 64] = header_rd[16..80].try_into().unwrap();

		// Verify key_hash = BLAKE2b(manager_key || file_size || ca || salt)
		let mut hasher = Blake2b512::new();
		hasher.update(manager_key);
		hasher.update(file_size_b);
		hasher.update(ca_b);
		hasher.update(key_hash_salt);
		if key_hash != hasher.finalize()[..64].as_ref() {
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				"Uncorrected key!",
			));
		}

		let nonce: [u8; 12] = header_rd[80..92].try_into().unwrap();
		let ff = u16::from_le_bytes([header_rd[92], header_rd[93]]);
		let file_name_crypt = (ff & 1) != 0;
		let original_file_name_length = (ff >> 1) as usize;

		let mut cipher = ChaCha20::new_from_slices(manager_key, &nonce)
			.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

		let (orig_file_name, keystream_offset, name_len) =
			if file_name_crypt && original_file_name_length > 0 {
				let mut enc_name = vec![0u8; original_file_name_length];
				file.read_exact(&mut enc_name)?;
				cipher.apply_keystream(&mut enc_name);
				let name = String::from_utf8(enc_name).map_err(|_| {
					io::Error::new(io::ErrorKind::InvalidData, "Invalid filename encoding")
				})?;
				(
					Some(name),
					original_file_name_length as u64,
					original_file_name_length,
				)
			} else {
				(None, 0u64, 0)
			};

		let header_len = Self::FIXED_LEN + name_len;

		Ok(FileHeader {
			calibration_amount: u32::from_le_bytes(ca_b.try_into().unwrap()),
			file_size: u64::from_le_bytes(file_size_b.try_into().unwrap()),
			key_hash_salt,
			key_hash,
			nonce,
			file_name_crypt,
			orig_file_name,
			header_len,
			keystream_offset,
		})
	}

	/// `true` if the entire file body is encrypted (calibration_amount ==
	/// u32::MAX, or the file is smaller than calibration_amount).
	pub fn is_full_encrypted(&self) -> bool {
		self.calibration_amount == u32::MAX || self.file_size < self.calibration_amount as u64
	}

	/// Decrypt the head (the first `calibration_amount` bytes of the original
	/// plaintext) of a partially-encrypted file.
	///
	/// `file` must be positioned at the first byte after the header (use
	/// [`FileHeader::read_and_verify`] first). On return, the cursor is left
	/// at an unspecified position.
	pub fn decrypt_head(
		&self,
		file: &mut File,
		manager_key: &[u8],
	) -> io::Result<Zeroizing<Vec<u8>>> {
		let c = self.calibration_amount as usize;
		let h = self.header_len;
		let vsize = self.file_size;

		// The encrypted head (calibration_amount bytes of the original
		// plaintext, encrypted with the ChaCha20 keystream starting at
		// `keystream_offset`) is split on disk into two contiguous regions:
		//   part1 (C-H bytes) at disk[H..C]
		//   part2 (H bytes)   at disk[file_size..file_size+H]
		// (See Manager::encrypt_file for the write sequence.)
		let part1_len = c.saturating_sub(h);
		let mut enc_data = Zeroizing::new(vec![0u8; c]);

		// Read part1: currently positioned right after the header.
		file.read_exact(&mut enc_data[..part1_len])?;

		// Read part2: jump to disk offset `file_size`.
		file.seek(SeekFrom::Start(vsize))?;
		file.read_exact(&mut enc_data[part1_len..])?;

		// Decrypt: seek the cipher to `keystream_offset` and apply keystream.
		let mut cipher = ChaCha20::new_from_slices(manager_key, &self.nonce)
			.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
		// Advance the cipher past the filename bytes (if any) to reach the
		// body portion of the keystream.
		if self.keystream_offset > 0 {
			// Generate-and-discard `keystream_offset` bytes to advance the
			// cipher state. apply_keystream on a zero buffer XORs in the
			// keystream, leaving us with the raw keystream — but we only
			// care about advancing the position, so use StreamCipherSeek.
			use chacha20::cipher::StreamCipherSeek;
			cipher.seek(self.keystream_offset);
		}
		cipher.apply_keystream(enc_data.as_mut());

		Ok(enc_data)
	}
}
