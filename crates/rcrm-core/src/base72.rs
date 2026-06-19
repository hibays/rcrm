// base72.rs
// Implementation of Base72 encode and decode in Rust for Python 3.
//
// THE GPLv3 LICENSE
// Copyleft (©) 2025 hibays
//

use lazy_static::lazy_static;

lazy_static! {
	// Base72 字母表
	static ref B72_ENCODE_TAB: [u8; 72] = [
		b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9',
		b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j',
		b'k', b'm', b'n', b'o', b'p', b'q', b'r', b's', b't', b'u',
		b'v', b'w', b'x', b'y', b'z', b'A', b'B', b'C', b'D', b'E',
		b'F', b'G', b'H', b'J', b'K', b'L', b'M', b'N', b'P', b'Q',
		b'R', b'S', b'T', b'U', b'V', b'W', b'X', b'Y', b'Z', b'_',
		b'-', b'+', b'=', b'(', b')', b'[', b']', b'{', b'}', b'@',
		b',', b';'
	];

	// 快速解码表（256 长度数组，直接通过 ASCII 值索引）
	static ref B72_DECODE_TAB: [u8; 256] = {
		let mut tab = [0xFF; 256];
		for (i, &c) in B72_ENCODE_TAB.iter().enumerate() {
			tab[c as usize] = i as u8;
		}
		tab
	};

	// 预生成双字符编码表（72x72 组合）
	static ref B72_ENCODE_TAB2: [[u8; 2]; 72*72] = {
		let mut tab: [[u8; 2]; 72*72] = [[0; 2]; 72*72];
		let mut index = 0;
		for &c1 in B72_ENCODE_TAB.iter() {
			for &c2 in B72_ENCODE_TAB.iter() {
				tab[index] = [c1, c2];
				index += 1;
			}
		}
		tab
	};
}

/// Base72 编码（Rust 加速版）：10 bytes → 13 chars
pub fn b72_encode_rust(data: &[u8]) -> Vec<u8> {
	let orig_len = data.len();
	let padding = (10 - (orig_len % 10)) % 10;
	let data = if padding > 0 {
		let mut padded = data.to_vec();
		padded.extend(vec![0u8; padding]);
		padded
	} else {
		data.to_vec()
	};

	let mut output = Vec::with_capacity((data.len() / 10) * 13);

	for chunk in data.chunks(10) {
		// 10 bytes → u80，用 u128 存储（高位补0）
		let mut n_bytes = [0u8; 16];
		n_bytes[6..16].copy_from_slice(chunk); // 16-10=6，高位6字节为0
		let mut n = u128::from_be_bytes(n_bytes);

		// 提取13个Base72数字（从高位到低位）
		let mut digits = [0u8; 13];
		for i in (0..13).rev() {
			digits[i] = (n % 72) as u8;
			n /= 72;
		}

		// 使用双字符表加速输出（6组双字符 + 1单字符）
		for i in 0..6 {
			let idx = (digits[2 * i] as usize) * 72 + digits[2 * i + 1] as usize;
			output.extend_from_slice(&B72_ENCODE_TAB2[idx]);
		}
		output.push(B72_ENCODE_TAB[digits[12] as usize]);
	}

	// 移除填充字符（填充字节对应的是末尾的0值编码）
	if padding > 0 {
		let len = output.len();
		output.truncate(len - padding);
	}
	output
}

/// Base72 解码（Rust 加速版）：13 chars → 10 bytes
pub fn b72_decode_rust(data: &[u8]) -> Result<Vec<u8>, String> {
	let orig_len = data.len();
	let padding = (13 - (orig_len % 13)) % 13;
	let data = if padding > 0 {
		let mut padded = data.to_vec();
		padded.extend(vec![B72_ENCODE_TAB[71]; padding]);
		padded
	} else {
		data.to_vec()
	};

	let mut output = Vec::with_capacity((data.len() / 13) * 10);

	for chunk in data.chunks(13) {
		// 13个字符 → 合成一个 u80 数值（用 u128 存储）
		let mut num = 0u128;
		for &c in chunk {
			let digit = B72_DECODE_TAB[c as usize];
			if digit == 0xFF {
				return Err(format!("Invalid Base72 character: '{}'", c as char));
			}
			num = num * 72 + digit as u128;
		}

		// 转换回10字节（大端，取低10字节）
		let bytes = num.to_be_bytes();
		output.extend_from_slice(&bytes[6..16]); // 高6字节是填充0
	}

	// 移除填充字节
	if padding > 0 {
		let len = output.len();
		output.truncate(len - padding);
	}
	Ok(output)
}
