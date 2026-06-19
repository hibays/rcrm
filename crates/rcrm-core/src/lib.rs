// crates/rcrm-core/src/lib.rs
// rcrm-core — Core encryption, projection, and file utilities.
// Copyleft (©) 2024-2025 hibays

mod base72;
pub mod crypt;
mod file_util;
pub mod project;

pub use base72::b72_decode_rust as b72decode;
pub use crypt::{FileHeader, Manager};
pub use file_util::{
	is_supported_file, is_valid_encrypted_file_name, resolve_ne_path_from_dir,
	resolve_ne_path_from_dir_with_progress,
};
pub use project::{ProjectedFile, SessionKey};
