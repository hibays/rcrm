# RCrm FFI API Reference

All C-ABI functions are exposed via `dart:ffi` through `RustBridge` in `ffi/rust_bridge.dart`.

## Memory Ownership

- Strings **returned** by Rust are malloc'd — Dart must call `rcrm_free_string` after use
- Strings **passed** to Rust are borrowed — Rust copies them immediately
- `DecodeBuf` **returned** by async decode — Rust owns the buffer; Dart reads then frees via `rcrm_free_decode_buf`

## Server Lifecycle

| Function | Signature | Returns |
|----------|-----------|---------|
| `rcrm_start_server` | `(dirs_json, password, bind_addr, port)` | handle (≥0) or -1 |
| `rcrm_stop_server` | `(handle)` | 0 OK, -1 invalid |
| `rcrm_get_server_url` | `(handle)` | malloc'd URL string |
| `rcrm_get_server_status` | `(handle)` | 1 running, 0 stopped, -1 invalid |
| `rcrm_get_auth_credentials` | `(handle)` | JSON `{"username":"…","password":"…"}` |

## Crypt

| Function | Signature | Returns |
|----------|-----------|---------|
| `rcrm_crypt_folder` | `(path, password, is_encrypt)` | 0 success |

## Blank Frame Detection

| Function | Signature | Returns |
|----------|-----------|---------|
| `rcrm_is_blank_frame` | `(data, len)` | 1 blank, 0 content, -1 decode error |

Decodes JPEG via `zune_jpeg` (YCbCr, channel 0 = luminance). Threshold: avg luminance < 20 (near-black) or > 235 (near-white) = blank. Thread-safe, reentrant.

## Mobile Image Decode (`#[cfg(feature = "mobile-decode")]`)

| Function | Signature | Returns |
|----------|-----------|---------|
| `rcrm_decode_avif_async` | `(data, len, target_width, callback, ctx)` | void (result via callback) |
| `rcrm_decode_jxl_async` | `(data, len, target_width, callback, ctx)` | void (result via callback) |
| `rcrm_free_decode_buf` | `(ptr)` | void |

**Async decode flow**: Rust copies `data` synchronously, spawns `std::thread::spawn` for decode, calls `callback(result, ctx)` when done. Dart uses `NativeCallable.listener` for the callback — it lands on the main isolate's event loop. **Zero-copy**: Rust takes ownership of the Dart `calloc` buffer via `Vec::from_raw_parts` — Dart must NOT `calloc.free`. `DecodeBuf` output: `{width, height, channels(4), data_len, data}` (raw RGBA pixels).

## Utility

| Function | Signature | Returns |
|----------|-----------|---------|
| `rcrm_free_string` | `(ptr)` | void (safe with null) |
| `rcrm_last_error` | `()` | malloc'd error string or null |
| `rcrm_last_verify` | `()` | JSON `{"encrypted":N,"locked":M}` |
| `rcrm_version` | `()` | malloc'd version string |
| `rcrm_set_log_level` | `(level)` | void (0=silent…3=debug) |

## Dart Usage

```dart
final bridge = RustBridge();
bridge.load();

// Start server
final handle = bridge.startWebDavServer(
  directories: ['/path/to/media'],
  password: 'mypassword',
  bindAddress: '127.0.0.1',
  port: 8080,
);

// Get credentials
final creds = bridge.getAuthCredentials(handle);
// {'username': 'abc123', 'password': 'xyz456'}
```

## See Also

- `ffi/rust_bridge.dart` — all extern "C" bindings with null/pointer safety
- `crates/rcrm-flutter-bridge/src/lib.rs` — extern "C" implementations with `# Safety` docs
- AGENTS.md — architecture, conventions, and development workflow
