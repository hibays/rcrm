#[cfg(test)]
mod tests {
	use rcrm::{
		Manager, is_supported_file, is_valid_encrypted_file_name, resolve_ne_path_from_dir,
	};
	use std::fs;
	use std::path::PathBuf;

	#[test]
	fn 文件加解密一致性() {
		//生成16bytes的key
		let mut key = [0u8; 16];
		let _ = rand::TryRngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut key);
		let manager = Manager::new(false, true, 2048, is_supported_file, 6, Some(&key));

		let assets_name = "tests/assets/resources.zip";
		let tests_res_dir = PathBuf::from("tests/assets/testres");

		// Step 0: 测试目录存在时，先删除
		if tests_res_dir.exists() {
			fs::remove_dir_all(&tests_res_dir).unwrap();
		}

		// Step 0: 解压测试资源包到测试目录
		let file = fs::File::open(assets_name).unwrap();
		let mut archive = zip::ZipArchive::new(file).unwrap();
		archive.extract("tests/assets/").unwrap();

		// Step 1: 遍历出所有文件
		let (nor_videos, _enc_videos) = resolve_ne_path_from_dir(&tests_res_dir);

		for file in &nor_videos {
			// Step 1: 计算文件 crc32 hash
			let crc32_orig = crc32fast::hash(&fs::read(file).unwrap());

			// Step 2: 加密文件
			let new_name = match manager.encrypt_file(file) {
				Ok(new_name) => {
					let fname = file.file_name().unwrap().to_string_lossy();
					println!(" 成功: \"{}\" -> \"{}\"", fname, new_name);
					&file.with_file_name(new_name)
				}
				Err(e) => {
					let fname = file.file_name().unwrap().to_string_lossy();
					let fsize = file.metadata().map(|m| m.len()).unwrap_or(0);
					println!(" 失败: \"{}\" ({}b)", fname, fsize);
					println!(" 错误: {:?}", e);
					file
				}
			};

			//Step 2: 验证加密文件名格式
			assert!(is_valid_encrypted_file_name(
				&new_name.file_name().unwrap().to_string_lossy()
			));

			// Step 3: 解密文件
			let decrypted_name = match manager.decrypt_file(new_name) {
				Ok(orig_name) => {
					let fname = new_name.file_name().unwrap().to_string_lossy();
					println!(" 成功: \"{}\" -> \"{}\"", fname, orig_name);
					&file.with_file_name(orig_name)
				}
				Err(e) => {
					let fname = new_name.file_name().unwrap().to_string_lossy();
					let fsize = new_name.metadata().map(|m| m.len()).unwrap_or(0);
					println!(" 失败: \"{}\" ({}b)", fname, fsize);
					println!(" 错误: {:?}", e);
					new_name
				}
			};

			// Step 4: 验证解密后文件名格式
			assert!(is_supported_file(decrypted_name));

			// Step 5: 验证解密后文件 crc32 hash
			let crc32_decrypted = crc32fast::hash(&fs::read(decrypted_name).unwrap());
			assert_eq!(crc32_orig, crc32_decrypted);
		}

		// Step Final: 清理测试目录
		if tests_res_dir.exists() {
			fs::remove_dir_all(&tests_res_dir).unwrap();
		}
	}
}
