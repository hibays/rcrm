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
	pub keys: HashMap<u32, Vec<u8>>,
}

#[allow(dead_code)]
impl Manager {
	pub const MAGIC_KEY_USING: &u32 = &0;

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

	fn derive_key(&self, key: &[u8]) -> Vec<u8> {
		let mut state = self.calibration_amount;
		let salt_val = xorshift64s(xorshift32(&mut state) as u64) ^ self.calibration_amount as u64;
		let salt = &salt_val.to_le_bytes()[..8];

		let argon2 = Argon2::new(
			Algorithm::Argon2id,
			Version::V0x13,
			argon2::Params::new(1 << 15, 7, 4, Some(32)).unwrap(),
		);

		let mut hash = vec![0u8; 32];
		argon2.hash_password_into(key, salt, &mut hash).unwrap();
		hash
	}

	fn add_key(&mut self, key: &[u8], index: Option<u32>) -> u32 {
		let derived = self.derive_key(key);
		let idx = index.unwrap_or_else(|| crc32fast::hash(key));

		if self.keys.contains_key(&idx) {
			panic!("Index ({}) of key exists!", idx);
		}

		if !self.keys.values().any(|v| v == &derived) {
			self.keys.insert(idx, derived);
		}

		idx
	}

	fn use_key(&mut self, index: &u32) {
		if !self.keys.contains_key(index) {
			panic!("The key indexed '{}' does not exist.", index);
		}
		self.keys
			.insert(*Self::MAGIC_KEY_USING, self.keys[index].clone());
	}

	fn pop_key(&mut self, index: &u32) -> Option<Vec<u8>> {
		self.keys.remove(index)
	}

	fn use_added_key(&mut self, key: &[u8]) {
		let idx = self.add_key(key, None);
		self.use_key(&idx);
	}

	fn _using_key(&self) -> &[u8] {
		self.keys
			.get(Self::MAGIC_KEY_USING)
			.expect("No current key")
	}

	fn filter(&self, paths: &[PathBuf]) -> Vec<PathBuf> {
		paths
			.iter()
			.filter(|p| (self.rule_fn)(p))
			.cloned()
			.collect()
	}

	pub fn encrypt_file(&self, file: &Path) -> io::Result<String> {
		let file_name_b = file
			.file_name()
			.unwrap()
			.to_string_lossy()
			.into_owned()
			.into_bytes();
		let mut f = File::options().read(true).write(true).open(file)?;
		let file_size = f.metadata()?.len();

		// 生成随机盐和 nonce
		let key_hash_salt: [u8; 4] = rand::random();
		let nonce: [u8; 12] = rand::random();

		// 生成密钥流（基于密钥和 nonce）
		let mut cipher = ChaCha20::new_from_slices(self._using_key(), &nonce).unwrap();

		// 计算 key_hash = BLAKE2b(key + file_size + ca + salt)
		let mut hasher = Blake2b512::new();
		hasher.update(self._using_key());
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

		// 文件名加密标志和内容
		if self.file_name_crypt {
			header.extend_from_slice(&(((file_name_b.len() as u16) << 1) | 1).to_le_bytes()); // 2
		} else {
			header.extend([0u8, 0u8]); // 2
		}

		let mut file_name_b_crypt = file_name_b.clone();
		// 加密文件名
		cipher.apply_keystream(&mut file_name_b_crypt);

		header.extend(file_name_b_crypt);

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
			// 读取原文件数据
			let mut enc_data = Vec::with_capacity(self.calibration_amount as usize);
			//f.read(&mut data)?;
			Read::by_ref(&mut f)
				.take(self.calibration_amount as u64)
				.read_to_end(&mut enc_data)
				.unwrap();
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
		let mut f = File::options().read(true).write(true).open(file)?;

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
		hasher.update(self._using_key());
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
		let mut cipher = ChaCha20::new_from_slices(self._using_key(), nonce).unwrap();

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
			let mut data = vec![0u8; calibration_amount as usize];
			Read::by_ref(&mut &f)
				.take(calibration_amount as u64 - (&f).stream_position()?)
				.read_to_end(&mut data)?;
			f.seek(SeekFrom::Start(file_size))?;

			let mut tail = Vec::new();
			f.read_to_end(&mut tail)?;

			data.extend(tail);

			cipher.apply_keystream(&mut data);
			data
		};

		// 写回文件（从头开始）
		f.seek(SeekFrom::Start(0))?;
		f.write_all(&dec_data)?;
		f.set_len(file_size)?;

		drop(f);

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
