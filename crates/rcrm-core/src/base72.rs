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

/// Minimal base72 char count for a partial chunk of k bytes (k = 0..=10):
/// ceil(8*k / log2(72)). Full 10-byte chunks use 13 (the k=10 entry).
const CHARS_FOR_BYTES: [usize; 11] = [0, 2, 3, 4, 6, 7, 8, 10, 11, 12, 13];

/// Base72 编码（Rust 加速版，最小编码）。
/// 满 10 字节块 → 13 字符；末块 k 字节 → CHARS_FOR_BYTES[k] 字符。
pub fn b72_encode_rust(data: &[u8]) -> Vec<u8> {
	let mut output = Vec::with_capacity(data.len() * 13 / 10 + 13);

	let mut chunks = data.chunks_exact(10);
	for chunk in &mut chunks {
		// 10 bytes → u80（用 u128 存储，高 6 字节为 0）→ 13 个 base72 位（大端）。
		let mut n_bytes = [0u8; 16];
		n_bytes[6..16].copy_from_slice(chunk);
		let mut n = u128::from_be_bytes(n_bytes);

		let mut digits = [0u8; 13];
		for i in (0..13).rev() {
			digits[i] = (n % 72) as u8;
			n /= 72;
		}
		// 6 组双字符 + 1 单字符。
		for i in 0..6 {
			let idx = (digits[2 * i] as usize) * 72 + digits[2 * i + 1] as usize;
			output.extend_from_slice(&B72_ENCODE_TAB2[idx]);
		}
		output.push(B72_ENCODE_TAB[digits[12] as usize]);
	}

	// 末块（1..=9 字节）→ 最小数量的 base72 字符，无填充。
	let rem = chunks.remainder();
	if !rem.is_empty() {
		let k = rem.len();
		let c = CHARS_FOR_BYTES[k];
		let mut n_bytes = [0u8; 16];
		n_bytes[16 - k..16].copy_from_slice(rem); // 低 k 字节
		let mut n = u128::from_be_bytes(n_bytes);

		let mut digits = [0u8; 13];
		for i in (0..c).rev() {
			digits[i] = (n % 72) as u8;
			n /= 72;
		}
		for d in digits.iter().take(c) {
			output.push(B72_ENCODE_TAB[*d as usize]);
		}
	}
	output
}

/// Base72 解码（Rust 加速版，最小编码）。
/// 满块 13 字符 → 10 字节；末块字符数（L mod 13）唯一确定末块字节数。
pub fn b72_decode_rust(data: &[u8]) -> Result<Vec<u8>, String> {
	let rem = data.len() % 13;
	// L mod 13 → 末块字节数。{1,5,9} 不可能由合法编码产生 → 拒绝（也避免下溢 panic）。
	let partial_bytes: usize = match rem {
		0 => 0,
		2 => 1,
		3 => 2,
		4 => 3,
		6 => 4,
		7 => 5,
		8 => 6,
		10 => 7,
		11 => 8,
		12 => 9,
		_ => return Err(format!("Invalid Base72 length: {}", data.len())),
	};

	let full_len = data.len() - rem;
	let mut output = Vec::with_capacity(full_len / 13 * 10 + partial_bytes);

	// 解码一组字符为 u128。
	let decode_group = |chunk: &[u8]| -> Result<u128, String> {
		let mut num = 0u128;
		for &c in chunk {
			let digit = B72_DECODE_TAB[c as usize];
			if digit == 0xFF {
				return Err(format!("Invalid Base72 character: '{}'", c as char));
			}
			num = num * 72 + digit as u128;
		}
		Ok(num)
	};

	// 满 13 字符块 → 10 字节（大端低 10 字节）。
	let mut i = 0;
	while i < full_len {
		let num = decode_group(&data[i..i + 13])?;
		let bytes = num.to_be_bytes();
		output.extend_from_slice(&bytes[6..16]);
		i += 13;
	}

	// 末块 → partial_bytes 个字节（大端低位）。
	if partial_bytes > 0 {
		let num = decode_group(&data[full_len..])?;
		let bytes = num.to_be_bytes();
		output.extend_from_slice(&bytes[16 - partial_bytes..16]);
	}

	Ok(output)
}

#[cfg(test)]
mod tests {
	use super::*;

	// Deterministic LCG so the test needs no rand dependency.
	fn fill(seed: &mut u64, buf: &mut [u8]) {
		for b in buf.iter_mut() {
			*seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
			*b = (*seed >> 33) as u8;
		}
	}

	#[test]
	fn roundtrip_all_lengths_and_values() {
		let mut seed = 0x1234_5678_9abc_def0u64;
		// Every length 0..=40 crosses chunk + every possible padding (0..9).
		for len in 0..=40usize {
			// A few random samples per length plus all-0x00 and all-0xFF edges.
			let mut samples: Vec<Vec<u8>> = vec![vec![0u8; len], vec![0xFFu8; len]];
			for _ in 0..8 {
				let mut v = vec![0u8; len];
				fill(&mut seed, &mut v);
				samples.push(v);
			}
			for original in samples {
				let enc = b72_encode_rust(&original);
				let dec = b72_decode_rust(&enc)
					.unwrap_or_else(|e| panic!("decode failed for len {len}: {e}"));
				assert_eq!(
					dec, original,
					"round-trip mismatch at len {len}: enc={:?}",
					String::from_utf8_lossy(&enc)
				);
				// Minimal encoding: full 10-byte chunks emit 13 chars; the partial
				// final chunk of k bytes emits CHARS_FOR_BYTES[k] (ceil(8k/log2 72)).
				if len > 0 {
					let expect = 13 * (len / 10) + CHARS_FOR_BYTES[len % 10];
					assert_eq!(enc.len(), expect, "char count wrong at len {len}");
				}
			}
		}
	}

	#[test]
	fn alphabet_is_72_distinct() {
		let mut seen = std::collections::HashSet::new();
		for &c in B72_ENCODE_TAB.iter() {
			assert!(seen.insert(c), "duplicate alphabet char {}", c as char);
		}
		assert_eq!(seen.len(), 72);
		// Ambiguous characters must be absent.
		for bad in [b'l', b'I', b'O'] {
			assert!(!seen.contains(&bad), "ambiguous char {} present", bad as char);
		}
	}

	#[test]
	fn decode_rejects_invalid_char() {
		// Use VALID lengths so it's the character (not the length) that's rejected.
		assert!(b72_decode_rust(b"000000000000.").is_err()); // len 13, '.' invalid
		assert!(b72_decode_rust(b"00.").is_err()); // len 3 (valid len), '.' invalid
	}

	#[test]
	fn decode_rejects_invalid_length() {
		// L mod 13 in {1,5,9} can never be produced by a valid encoding.
		for &bad_len in &[1usize, 5, 9, 14, 18, 22] {
			let s = vec![b'0'; bad_len];
			assert!(
				b72_decode_rust(&s).is_err(),
				"len {bad_len} (mod13={}) should be rejected",
				bad_len % 13
			);
		}
	}

	#[test]
	fn hash_32_bytes_is_42_chars() {
		// The real use case: a 32-byte Blake2s filename hash.
		let mut seed = 0xdead_beef_cafe_1234u64;
		let mut hash = [0u8; 32];
		fill(&mut seed, &mut hash);
		let enc = b72_encode_rust(&hash);
		assert_eq!(enc.len(), 42, "32-byte hash must encode to 42 chars");
		let dec = b72_decode_rust(&enc).unwrap();
		assert_eq!(dec, hash);
		assert_eq!(dec.len(), 32); // matches is_valid_encrypted_file_name
	}

	#[test]
	fn roundtrip_many_random_lengths() {
		let mut seed = 0xa5a5_5a5a_0f0f_f0f0u64;
		fn next(seed: &mut u64) -> u64 {
			*seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
			*seed
		}
		// 5000 random variable-length payloads (length 0..=300).
		for _ in 0..5000 {
			let len = (next(&mut seed) % 301) as usize;
			let mut v = vec![0u8; len];
			fill(&mut seed, &mut v);
			let enc = b72_encode_rust(&v);
			let dec = b72_decode_rust(&enc)
				.unwrap_or_else(|e| panic!("decode failed (len {len}): {e}"));
			assert_eq!(dec, v, "round-trip mismatch at random len {len}");
			let expect = 13 * (len / 10) + CHARS_FOR_BYTES[len % 10];
			assert_eq!(enc.len(), expect, "char count wrong at random len {len}");
		}
	}

	#[test]
	fn roundtrip_1_to_1000_bytes_1000_each() {
		// For every length 1..=1000, 1000 random payloads: encode then decode
		// must reproduce the original byte-for-byte (1,000,000 checks).
		let mut seed = 0x0123_4567_89ab_cdefu64;
		let mut buf = vec![0u8; 1000];
		for len in 1..=1000usize {
			let slice = &mut buf[..len];
			for _ in 0..1000 {
				fill(&mut seed, slice);
				let enc = b72_encode_rust(slice);
				let dec = b72_decode_rust(&enc)
					.unwrap_or_else(|e| panic!("decode failed (len {len}): {e}"));
				assert_eq!(dec.as_slice(), &*slice, "round-trip mismatch at len {len}");
			}
		}
	}
}
