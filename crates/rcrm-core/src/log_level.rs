// log_level.rs
// Runtime log level for rcrm Rust libraries.
// Thread-safe, settable via FFI from the Flutter GUI.

use std::sync::atomic::{AtomicU8, Ordering};

/// 0 = silent, 1 = errors only, 2 = info, 3 = debug
static LEVEL: AtomicU8 = AtomicU8::new(2); // default: info

/// Set the global log level.
pub fn set(level: u8) {
	LEVEL.store(level.min(3), Ordering::Relaxed);
}

/// Returns true if messages at this level should be printed.
/// Levels: 0 = silent, 1 = error, 2 = info, 3 = debug
pub fn enabled(level: u8) -> bool {
	LEVEL.load(Ordering::Relaxed) >= level
}

/// Convenience: log an info message.
#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        if $crate::log_level::enabled(2) {
            eprintln!($($arg)*);
        }
    };
}

/// Convenience: log an error message.
#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        if $crate::log_level::enabled(1) {
            eprintln!($($arg)*);
        }
    };
}

/// Convenience: log a debug message.
#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        if $crate::log_level::enabled(3) {
            eprintln!($($arg)*);
        }
    };
}
