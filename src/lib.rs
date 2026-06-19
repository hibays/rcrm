// src/lib.rs
// rcrm - A simple file encryption/decryption tool
// Copyleft (©) 2024-2025 hibays

// A drop-in global allocator wrapper around the [mimalloc](https://github.com/microsoft/mimalloc)
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

// Re-export core functionality from sub-crates for convenience.
// The binary crate (main.rs) and examples import through `rcrm::*`.
pub use rcrm_core::*;
pub use rcrm_server::serve;
