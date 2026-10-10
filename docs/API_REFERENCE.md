# RCrm FFI API Reference

All C-ABI functions are exposed via `dart:ffi` through `RustBridge` in
`ffi/rust_bridge.dart`. Symbols marked *mobile-decode* are compiled only when
the `mobile-decode` Cargo feature is on (Android/iOS builds; desktop omits it).

## Memory Ownership

Four shapes exist; picking the wrong one is a leak, a double free or worse.

| Shape | Who allocates | Who frees | Used by |
|---|---|---|---|
| **Returned string** | Rust (`str_to_cstring`) | Dart, via `rcrm_free_string` | `rcrm_get_server_url`, `rcrm_last_error`, `rcrm_version`, `rcrm_media_metadata_async`'s reply |
| **Passed string** | Dart | Dart — Rust copies immediately | `rcrm_start_server`, `rcrm_crypt_folder` |
| **Owned buffer** (`DecodeBuf`) | Dart (`calloc`, or a copy-free native fetch) | **Rust**, when the decode finishes | `rcrm_decode_avif_async` / `_jxl_async` / `_heic_async` |
| **Borrowed buffer** | Dart | Dart, after the call returns | `rcrm_encode_thumb_webp`, `rcrm_generate_thumb_webp_from_image` |

Rules that follow from the table:

- An **owned** buffer must be exactly the payload: the ABI rebuilds its `Vec`
  from the **length alone**, so Dart either `calloc`s exactly (one copy) or
  fetches into native memory already sized to the body (`services/native_bytes.dart`
  — no copy). Never `calloc.free` it, and never touch it after the call — including
  on the timeout path. No export takes a caller-supplied capacity: a wrong one
  would free a wrong layout and could not be checked in Rust. Dart enforces the
  "exactly `len` bytes" half by type instead — `NativeTransfer` can only be
  obtained from a whole-file `NativeBytes`, and `transferIfWhole()` returns null
  for a partly filled allocation, which callers treat as retryable.
- A **borrowed** buffer stays Dart's: the call only reads it, so a failure costs
  nothing and the caller frees it afterwards.
- Every buffer Rust hands back (`DecodeBuf`, `WebpBuf`) is read **in place**:
  Dart wraps it with `asTypedList` / an `ImageDescriptor` and frees it through
  the matching `rcrm_free_*` (or a `NativeFinalizer` for `WebpBuf`).

## Server Lifecycle

| Function | Signature | Returns |
|----------|-----------|---------|
| `rcrm_start_server` | `(dirs_json, passwords_json, bind_addr, port, tls_json?)` | handle (≥0) or -1 |
| `rcrm_stop_server` | `(handle)` | 0 OK, -1 invalid |
| `rcrm_get_server_url` | `(handle)` | malloc'd URL string |
| `rcrm_get_server_status` | `(handle)` | 1 running, 0 stopped, -1 invalid |
| `rcrm_get_auth_credentials` | `(handle)` | JSON `{"username":"…","password":"…"}` |

## Crypt

| Function | Signature | Returns |
|----------|-----------|---------|
| `rcrm_crypt_folder` | `(path, password, is_encrypt)` | 0 success |
| `rcrm_last_verify` | `()` | JSON `{"encrypted":N,"locked":M}` |

## Blank Frame Detection

| Function | Signature | Returns |
|----------|-----------|---------|
| `rcrm_is_blank_frame` | `(data, len)` | 1 blank, 0 content, -1 decode error |

Decodes JPEG via `zune_jpeg` (YCbCr, channel 0 = luminance). Threshold: avg
luminance < 20 (near-black) or > 235 (near-white) = blank. Thread-safe,
reentrant. Takes a borrowed buffer.

## Media Metadata — EXIF / track *(all platforms)*

| Function | Signature | Returns |
|----------|-----------|---------|
| `rcrm_media_metadata_async` | `(data, len, kind_hint, callback, ctx)` | void (JSON via callback) |
| `rcrm_free_string` | `(ptr)` | void (safe with null) |

Parses EXIF (images) or container track info (video/audio) with `nom-exif`,
in memory only. `kind_hint`: 0 = auto (sniff the container), 1 = image,
2 = track.

**Ownership:** Rust takes the buffer and frees it when the parse finishes — so
Dart never frees it, not even after a timeout (the Rust thread may still be
reading). The transfer is `(data, len)` only and the buffer must have been
allocated with **exactly `len`** bytes: this side never sends a capacity, because
a wrong one would free a wrong layout. Dart guarantees the size by type —
`NativeTransfer` (`services/native_bytes.dart`) is only obtainable from a
whole-file `NativeBytes`, so a partly filled 4 MiB head cannot be handed over at
all (the metadata service then reports a retryable non-answer). The callback
fires **exactly once** on every path (null buffer, empty input, parser panic,
failed thread spawn); Dart's `MediaMetadataService` turns a missing callback into
a timeout and does not cache the result.

JSON shape (only fields that were actually found are present):

```json
{
  "kind": "image" | "track" | "unknown",
  "exif":  { "make", "model", "lens", "software", "capturedAt", "capturedOffset",
             "iso", "fNumber", "exposureTime", "focalLength", "focalLength35mm",
             "exposureBias", "flash", "orientation", "pixelWidth", "pixelHeight",
             "gps": { "lat", "lon", "altitude" }, "embeddedTrack" },
  "track": { "make", "model", "software", "author", "durationMs", "width",
             "height", "createdAt", "gpsIso6709" },
  "error": "…"
}
```

`error` means the bytes were identified but could not be parsed — the UI must
stay silent rather than claim "no camera information" (see
`MediaMetadata.parsed`).


## Mobile Image Decode *(`mobile-decode`: AVIF / JXL / HEIC)*

| Function | Signature | Returns |
|----------|-----------|---------|
| `rcrm_decode_avif_async` | `(data, len, target_width, callback, ctx)` | void (result via callback) |
| `rcrm_decode_jxl_async` | `(data, len, target_width, callback, ctx)` | void (result via callback) |
| `rcrm_decode_heic_async` | `(data, len, target_width, callback, ctx)` | void (result via callback) |
| `rcrm_free_decode_buf` | `(ptr)` | void |

**Async decode flow**: Dart hands over the buffer (native fetch → no copy, or
one `calloc` copy), Rust spawns `std::thread::spawn`, decodes at
`target_width` (0 = full size) and calls `callback(result, ctx)`. Dart uses a
persistent `NativeCallable.listener`, so the callback lands on the main
isolate's event loop.

`DecodeBuf` (RGBA8, read in place):

```c
struct DecodeBuf { uint32_t width, height; uint8_t channels; /* =4 */
                   size_t data_len; size_t cap; uint8_t *data; };
```

`cap` is the allocation size — a decoder that hands back a `Vec` may have spare
capacity, and `rcrm_free_decode_buf` rebuilds the allocation with it. The Dart
mirror is `_DB` in `services/mobile_image_decoder.dart` (pinned by a test).

## WebP Thumbnails

Two generators, differing only in what they take. Both return a `WebpBuf`
(`{data_len, data}`) that Dart views in place and frees with
`rcrm_free_webp_buf` (or a `NativeFinalizer`).

| Function | Input | Available on | Used by |
|---|---|---|---|
| `rcrm_encode_thumb_webp` | **raw RGBA** (`width*height*4`) | every platform | the engine-decoded path: all of desktop, and JPEG/PNG/WebP/HEIC-that-Rust-cannot-take on mobile |
| `rcrm_generate_thumb_webp_from_image` | **an encoded image** (AVIF/JXL/HEIC) | *mobile-decode* | the on-disk thumbnail cache for software-decoded formats: Rust decodes → downscales → encodes, so no pixels enter Dart |

| Function | Signature |
|---|---|
| `rcrm_encode_thumb_webp` | `(data, len, width, height, quality)` → `WebpBuf*` |
| `rcrm_generate_thumb_webp_from_image` | `(data, len, target_width, quality, kind_hint)` → `WebpBuf*` |
| `rcrm_free_webp_buf` | `(ptr)` → void |

`kind_hint` for the from-image generator: 1 = AVIF, 2 = JXL, 3 = HEIC/HEIF,
anything else sniffs the container header. Both inputs are **borrowed**.

Dart callers: `ThumbWebpWorker.encodeRgba` / `.generateThumbFromImage`
(`services/thumb_webp_worker.dart`), driven by `DiskThumbImage`
(`widgets/disk_thumb_image.dart`).

## QR / Cast

| Function | Signature | Returns |
|----------|-----------|---------|
| `rcrm_generate_qr_webp` | `(data, len)` | `WebpBuf*` with the QR as WebP |
| `rcrm_decode_qr` / `rcrm_decode_qr_bgra` / `rcrm_decode_qr_luma` | `(data, len[, stride, width, height])` | malloc'd payload string or null |
| `rcrm_generate_tv_cert` | `()` | JSON with the TV's cert/key paths |

## Utility

| Function | Signature | Returns |
|----------|-----------|---------|
| `rcrm_free_string` | `(ptr)` | void (safe with null) |
| `rcrm_last_error` | `()` | malloc'd error string or null |
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
- `services/native_bytes.dart` — the copy-free fetch these paths feed from
- `docs/ARCHITECTURE.md` — how the pieces fit together
- AGENTS.md — conventions, feature gates, and development workflow
