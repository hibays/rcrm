// build.rs
// rcrm-flutter-bridge — build script
//
// Detects the target platform and sets cfg flags for conditional compilation.
// On Android, sets up the NDK toolchain integration.

fn main() {
	let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

	match target_os.as_str() {
		"android" => {
			// Android needs to be built as a shared library (.so)
			// The Flutter Android build system (Gradle + CMake) will handle
			// the actual linking.
			println!("cargo:rustc-cfg=target_os_android");
			// Non-PIC relocations in rav1d ARM .S asm for .so builds.
			println!("cargo:rustc-link-arg=-Wl,-Bsymbolic");
		}
		"windows" => {
			println!("cargo:rustc-cfg=target_os_windows");
		}
		"linux" => {
			println!("cargo:rustc-cfg=target_os_linux");
		}
		"macos" | "ios" => {
			println!("cargo:rustc-cfg=target_os_apple");
		}
		_ => {}
	}

	// Rebuild if any source in the bridge changes
	println!("cargo:rerun-if-changed=src/");
}
