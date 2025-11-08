use rcrm::{Manager, is_supported_file, is_valid_encrypted_file_name};

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn 加解密一致性() {
		let manager = Manager::new(true, true, 2048, is_supported_file, 6, Some(&[0u8; 16]));
	}
}
