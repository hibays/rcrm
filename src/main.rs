// src/main.rs
// rcrm - A simple file encryption/decryption tool
// Copyleft (©) 2024-2025 hibays

use std::cell::Cell;
use std::path::PathBuf;
use std::{fs, io};

use clap::Parser;
use dialoguer::Password;
use indicatif::{ProgressBar, ProgressStyle};

use zeroize::Zeroizing;

use rcrm::{Manager, is_supported_file, resolve_ne_path_from_dir_with_progress};

// =======================
// CLI Args
// =======================

#[derive(Parser)]
#[command(author, version, about)]
struct Args {
	#[arg(short('d'), long, default_value_t = String::from(".."))]
	dir: String,
}

// =======================
// Helper: 获取密码
// =======================

fn get_user_password(prompt: &str, twofa: bool) -> io::Result<Zeroizing<String>> {
	let pwd = Password::new().with_prompt(prompt);
	if twofa {
		Ok(Zeroizing::new(
			pwd.with_confirmation("       CONFIRM", "Passwords do not match")
				.interact()?,
		))
	} else {
		Ok(Zeroizing::new(pwd.interact()?))
	}
}

// =======================
// String padding helper
// =======================

trait PadToWidth {
	fn pad_to_width(&self, width: usize) -> String;
}

impl PadToWidth for String {
	fn pad_to_width(&self, width: usize) -> String {
		let len = self.chars().count();
		let padding = " ".repeat(width.saturating_sub(len));
		format!("{}{}", self, padding)
	}
}

impl PadToWidth for &str {
	fn pad_to_width(&self, width: usize) -> String {
		self.to_string().pad_to_width(width)
	}
}

impl PadToWidth for std::borrow::Cow<'_, str> {
	fn pad_to_width(&self, width: usize) -> String {
		self.as_ref().pad_to_width(width)
	}
}

// =======================
// Main Function
// =======================

fn main() -> io::Result<()> {
	let args = Args::parse();
	let dir = PathBuf::from(args.dir).canonicalize()?;

	println!("* Scanning: {}", dunce::canonicalize(&dir)?.display());

	// 创建不确定进度的进度条用于扫描
	let scan_pb = ProgressBar::new_spinner();
	scan_pb.set_style(
		ProgressStyle::default_spinner()
			.template("{spinner:.green} Scanning... {pos} files scanned. {decimal_bytes_per_sec}")
			.unwrap(),
	);
	scan_pb.enable_steady_tick(std::time::Duration::from_millis(100));

	let scanned_files = Cell::new(0);
	let (nor_videos, enc_videos) = resolve_ne_path_from_dir_with_progress(&dir, |count| {
		scan_pb.set_position(count as u64);
		scanned_files.set(count);
	});

	scan_pb.finish_with_message(format!(
		"Scan complete: {} files found",
		scanned_files.get()
	));

	if nor_videos.is_empty() && enc_videos.is_empty() {
		eprintln!("No valid files found.");
		return Ok(());
	}

	let (is_encode, op_videos) = if !nor_videos.is_empty() {
		if enc_videos.is_empty() {
			(true, nor_videos)
		} else {
			let encode = dialoguer::Confirm::new()
				.with_prompt("Want to encode?")
				.default(true)
				.interact()?;
			(encode, if encode { nor_videos } else { enc_videos })
		}
	} else {
		(false, enc_videos)
	};

	println!(
		"{}",
		if is_encode {
			"<--- Encoding --->"
		} else {
			"<--- Decoding --->"
		}
	);

	let maxsize = op_videos
		.iter()
		.map(|p| p.file_name().unwrap().to_string_lossy().chars().count())
		.max()
		.unwrap_or(0);

	let password = get_user_password("INPUT PASSWORD", is_encode)?;
	let mut manager = Manager::new(
		true,
		true,
		2048,
		is_supported_file,
		6,
		Some(password.as_bytes()),
	);
	drop(password);

	let pb = ProgressBar::new(op_videos.len() as u64);
	pb.set_style(
		ProgressStyle::default_bar()
			.template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} {percent}% ({eta})")
			.unwrap(),
	);

	for file in &op_videos {
		let result = if is_encode {
			manager.encrypt_file(file)
		} else {
			manager.decrypt_file(file)
		};

		match result {
			Ok(new_name) => {
				let fname = file.file_name().unwrap().to_string_lossy();
				pb.println(format!(
					" 成功: \"{}\" -> \"{}\"",
					fname.pad_to_width(maxsize),
					new_name
				));
			}
			Err(e) => {
				let fname = file.file_name().unwrap().to_string_lossy();
				let fsize = file.metadata().map(|m| m.len()).unwrap_or(0);
				pb.println(format!(
					" 失败: \"{}\" ({}b)",
					fname.pad_to_width(maxsize),
					fsize
				));

				if e.kind() == io::ErrorKind::InvalidData && e.to_string() == "Uncorrected key!" {
					pb.println("\t↑ 密码错误!");

					let mut key_matched_in_prelist = false;
					for idx in manager.list_key_idxs().unwrap() {
						if idx == Manager::MAGIC_KEY_USING {
							continue;
						}
						pb.println(format!("\t↑ 尝试中: `{:}`", idx));
						manager.use_key(&idx);
						if let Ok(name) = manager.decrypt_file(file) {
							pb.println(format!("\t↑ 成功: -> \"{}\"", name));
							key_matched_in_prelist = true;
							break;
						} else {
							pb.println("\t↑ 密码错误!");
						}
					}
					if !key_matched_in_prelist {
						while let Ok(pwd) = pb.suspend(|| get_user_password("\t↑ 请重试-> ", false))
						{
							manager.use_added_key(pwd.as_bytes());
							drop(pwd);
							match manager.decrypt_file(file) {
								Ok(name) => {
									pb.println(format!("\t↑ 成功: -> \"{}\"", name));
									break;
								}
								Err(_) => {
									pb.println("\t↑ 密码错误!");
									if pb.suspend(|| {
										!dialoguer::Confirm::new()
											.with_prompt("\t↑ Proceed trying?")
											.interact()
											.unwrap_or(false)
									}) {
										pb.println("\t↑ Canceled!");
										break;
									}
								}
							}
						}
					}
				} else {
					pb.println(format!("\t↑ {} -> {}", e.kind(), e));
					if pb.suspend(|| {
						dialoguer::Confirm::new()
							.with_prompt("\t↑ Would you like to delete it?")
							.interact()
							.unwrap_or(false) && dialoguer::Confirm::new()
							.with_prompt("\t↑ Proceed?")
							.interact()
							.unwrap_or(false)
					}) {
						let _ = fs::remove_file(file);
						pb.println("\t↑ Deleted!");
					} else {
						pb.println("\t↑ Canceled!");
					}
				}
			}
		}

		pb.inc(1);
	}

	manager.drop_all_keys();
	pb.finish_with_message("ALL DONE");
	Ok(())
}
