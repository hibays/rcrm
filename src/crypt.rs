// src/crypt.rs
// rcrm - A simple file encryption/decryption tool
// Copyleft (©) 2024-2025 hibays

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Version};
use blake2::{Blake2b512, Blake2s256, Digest};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::{ChaCha20, Key, Nonce};

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
	n.wrapping_mul(0x2545f4914f6cdd1d)
}

// =======================
// Manager Struct
// =======================

#[allow(dead_code)]
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

	pub fn encrypt_file(&mut self, file: &Path) -> io::Result<String> {
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
		let mut cipher = ChaCha20::new(
			Key::from_slice(self._using_key()),
			Nonce::from_slice(&nonce),
		);

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
		let enc_data =
			if self.calibration_amount == u32::MAX || file_size < self.calibration_amount as u64 {
				// 全加密
				// 读取原文件数据
				let mut data = Vec::new();
				f.read_to_end(&mut data)?;
				cipher.apply_keystream(&mut data);
				data
			} else {
				// 部分加密
				// 读取原文件数据
				let mut data = Vec::with_capacity(self.calibration_amount as usize);
				//f.read(&mut data)?;
				Read::by_ref(&mut f)
					.take(self.calibration_amount as u64)
					.read_to_end(&mut data)
					.unwrap();
				cipher.apply_keystream(&mut data);
				data
			};

		// 写入：header + 加密数据
		f.seek(SeekFrom::Start(0))?;
		f.write_all(&header)?;
		f.write_all(&enc_data)?;
		f.set_len((header.len() + enc_data.len()) as u64)?;

		drop(f);

		// 重命名文件（加密文件名）
		let new_name = if self.file_name_crypt {
			let hash = Blake2s256::digest(&file_name_b);
			let encoded = b72encode(&hash);
			file.with_file_name(format!(".{}", String::from_utf8_lossy(&encoded)))
		} else {
			file.with_file_name(file.file_name().unwrap())
		};

		fs::rename(file, &new_name)?;
		Ok(new_name.file_name().unwrap().to_string_lossy().into_owned())
	}

	pub fn decrypt_file(&mut self, file: &Path) -> io::Result<String> {
		let mut f = File::options().read(true).write(true).open(file)?;
		let file_size = f.metadata()?.len();

		// 读取前 128 字节尝试解析 header 长度（先不加密）
		let mut header_probe = vec![0u8; 128];
		let read = f.read(&mut header_probe)?;
		if read < 94 {
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				"File too small for header",
			));
		}

		// 提取 header_len：我们固定 header 至少 94 字节，但支持对齐到 16 字节
		// 先尝试从前 94 字节中恢复 key_hash_salt 和 nonce
		let mut fake_nonce = [0u8; 12];
		let mut fake_salt = [0u8; 4];

		// 假设 header 未加密，提取关键字段
		let ca_bytes = &header_probe[0..4];
		let orig_size_bytes = &header_probe[4..12];
		let key_hash_salt = &header_probe[12..16];
		let nonce = &header_probe[80..92];

		// 检查是否加密：我们尝试用当前 key 解密前 header_len 字节
		let calibration_amount = u32::from_le_bytes(ca_bytes.try_into().unwrap());
		let original_size = u64::from_le_bytes(orig_size_bytes.try_into().unwrap());

		// 重新读取整个可能的 header（我们写入时对齐到 16 字节）
		let mut header = vec![0u8; 256]; // 最大 header 预估
		f.seek(SeekFrom::Start(0))?;
		f.read_exact(&mut header[..256])?;

		// 找到实际 header 结束：flag 在 92 字节处
		let mut header_len = 94;
		if header[92] == 1 {
			let name_len = u16::from_le_bytes([header[93], header[94]]) as usize;
			header_len = 95 + name_len;
		}
		// 对齐到 16 字节
		header_len = (header_len + 15) & !15;

		if header_len > 256 || header_len as u64 > file_size {
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				"Invalid header length",
			));
		}

		// 截取 header
		let mut header = header[..header_len].to_vec();

		// 用当前密钥生成 keystream 解密 header
		let mut cipher =
			ChaCha20::new(Key::from_slice(self._using_key()), Nonce::from_slice(nonce));
		let mut keystream = vec![0u8; 1024];
		cipher.apply_keystream(&mut keystream);

		for i in 0..header_len {
			header[i] ^= keystream[i % keystream.len()];
		}

		// 验证 key_hash
		let mut hasher = Blake2b512::new();
		hasher.update(self._using_key());
		hasher.update(orig_size_bytes);
		hasher.update(ca_bytes);
		hasher.update(key_hash_salt);
		let computed_hash = hasher.finalize();

		let stored_hash = &header[16..80];
		if computed_hash[..] != stored_hash[..64] {
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				"Uncorrected key!",
			));
		}

		// 解密文件名（如果加密）
		let mut orig_file_name = String::new();
		if header[92] == 1 {
			let name_len = u16::from_le_bytes([header[93], header[94]]) as usize;
			let name_start = 95;
			let mut dec_name = Vec::with_capacity(name_len);
			for i in 0..name_len {
				dec_name
					.push(header[name_start + i] ^ keystream[(header_len + i) % keystream.len()]);
			}
			orig_file_name = String::from_utf8(dec_name).map_err(|_| {
				io::Error::new(io::ErrorKind::InvalidData, "Invalid filename encoding")
			})?;
		}

		// 读取并解密数据部分
		let mut data = Vec::new();
		f.read_to_end(&mut data)?;

		for i in 0..data.len() {
			data[i] ^= keystream[(header_len + i) % keystream.len()];
		}

		// 截断为原始大小
		data.truncate(original_size as usize);

		// 写回文件（从头开始）
		f.seek(SeekFrom::Start(0))?;
		f.write_all(&data)?;
		f.set_len(original_size)?;

		drop(f);

		// 重命名回原名
		let new_path = if orig_file_name.is_empty() {
			file.with_file_name(file.file_name().unwrap())
		} else {
			file.with_file_name(&orig_file_name)
		};

		fs::rename(file, &new_path)?;
		Ok(orig_file_name)
	}
}
