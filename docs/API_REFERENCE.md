# RCrm FFI API Reference

All C-ABI functions are exposed via `dart:ffi` through `RustBridge` in
`ffi/rust_bridge.dart`. Symbols marked *mobile-decode* are compiled only when
the `mobile-decode` Cargo feature is on (Android/iOS builds; desktop omits it).
Symbols marked *libmpv-poster* use the `libmpv-poster` feature — the direct
libmpv renderer, enabled on EVERY platform including iOS (media_kit ships libmpv
there as an embedded, code-signed `Mpv.framework`). It does not require
`mobile-decode`.

## Memory Ownership

Five shapes exist; picking the wrong one is a leak, a double free or worse.

| Shape | Who allocates | Who frees | Used by |
|---|---|---|---|
| **Returned string** | Rust (`str_to_cstring`) | Dart, via `rcrm_free_string` | `rcrm_get_server_url`, `rcrm_last_error`, `rcrm_version`, `rcrm_media_metadata_async`'s reply |
| **Passed string** | Dart | Dart — Rust copies immediately | `rcrm_start_server`'s `dirs_json`/`bind_addr`, `rcrm_crypt_folder` |
| **Password buffer** | Rust (`rcrm_password_buffer`) | Rust, in `rcrm_start_server` | the password pointer passed to `rcrm_start_server` |
| **Owned buffer** (`DecodeBuf`) | Rust (`rcrm_alloc_bytes`, filled by Dart in place) | **Rust**, when the decode finishes | `rcrm_decode_avif_async` / `_jxl_async` / `_heic_async` |
| **Borrowed buffer** | Rust (`rcrm_alloc_bytes`), or calloc before the bridge loads | Dart via `rcrm_free_bytes` (or calloc), after the call returns | `rcrm_encode_thumb_webp`, `rcrm_generate_thumb_webp_from_image` |
| **Returned buffer** (`WebpBuf`) | Rust | Dart, via `rcrm_free_webp_buf` (or a `NativeFinalizer`) | every WebP producer, including `rcrm_generate_poster_async`'s callback |

Rules that follow from the table:

- An **owned** buffer is allocated by `rcrm_alloc_bytes(len)` and filled by Dart
  in place — a `calloc` copy for a Dart list, or straight from the network for a
  native fetch (`services/native_bytes.dart`, no copy). Rust owns the allocation
  from the first byte and rebuilds its `Vec` from the **length alone**, so the
  same global allocator performs both the allocation and the free. This is what
  makes the global allocator swappable without any FFI change: no buffer is ever
  allocated on one side and freed on the other. Dart never frees an owned buffer
  and never touches it after the call — including on the timeout path. No export
  takes a caller-supplied capacity: a wrong one would free a wrong layout and
  could not be checked in Rust. Dart enforces the "exactly `len` bytes" half by
  type — `NativeTransfer` can only be obtained from a whole-file `NativeBytes`,
  and `transferIfWhole()` returns null for a partly filled allocation, which
  callers treat as retryable. `NativeBytes` carries its matched deallocator, so a
  test that constructs a `calloc` buffer directly always frees it with calloc.
- A **borrowed** buffer stays Dart's: the call only reads it, so a failure costs
  nothing and the caller frees it afterwards.
- Every buffer Rust hands back (`DecodeBuf`, `WebpBuf`) is read **in place**:
  Dart wraps it with `asTypedList` / an `ImageDescriptor` and frees it through
  the matching `rcrm_free_*` (or a `NativeFinalizer` for `WebpBuf`).

### Verifying the unsafe hand-off

The allocation → Dart fill → `Box<[u8]>` reconstruction path is the only unsafe
memory contract in the bridge. The ordinary Rust tests cover it; on a host with
the tooling, validate the layout and initialization invariants under a memory
checker too:

```bash
MIRIFLAGS=-Zmiri-permissive-provenance \
  cargo +nightly miri test -p rcrm-flutter-bridge -- native_buffer_tests metadata_ffi_tests
valgrind --leak-check=full target/debug/deps/rcrm_flutter_bridge-*
```

`-Zmiri-permissive-provenance` is required because Dart sends the callback
`ctx` as an integer request id (Rust passes it back verbatim and never
dereferences it); the test harness's `Box<Sender>` round-trip through `ctx`
relies on it too. Strict provenance would flag a pattern that is intentional
here. Miri found and we fixed two test-harness bugs while validating this path:
a `&Sender` borrowed through a raw pointer across threads (now an owned
`Box<Sender>` clone), and a deliberately contract-violating `len == 0` test
that leaked its original allocation (now reclaimed explicitly).

Valgrind is unavailable on the Windows development host; Miri is available via
`cargo +nightly miri`, but neither is part of the default build/test gate.
"whoever allocates, frees" is the rule these checks guard; do not replace the
Rust-owned buffer with a Dart `calloc` buffer on a path that hands ownership to
an export.

## Server Lifecycle

| Function | Signature | Returns |
|----------|-----------|---------|
| `rcrm_password_buffer` | `(len)` | `*mut u8` — Rust-allocated zeroed buffer of exactly `len` bytes (null when `len==0`); Dart writes UTF-8 into it, then `rcrm_start_server` takes it back |
| `rcrm_start_server` | `(dirs_json, password, bind_addr, port)` | always `1` (request accepted — watch `rcrm_register_server_event` for the outcome); `password` must be the pointer from `rcrm_password_buffer()`, or null for plaintext folders |
| `rcrm_register_server_event` | `(cb)` | void — registers `(code,a,b,c)` listener; all-int payload, nothing to free |
| `rcrm_stop_server` | `(handle)` | 0 OK, -1 invalid |
| `rcrm_get_server_url` | `(handle)` | malloc'd URL string |
| `rcrm_get_auth_credentials` | `(handle)` | JSON `{"username":"…","password":"…"}` |

Rust owns all decryption keys **and the password buffer**. Dart never keeps a
password list: it writes the one newly typed UTF-8 password into a Rust-
allocated buffer and hands it to `rcrm_start_server`; Rust frees it with the
same allocator (no cross-allocator free) and derives that single key into a
persistent keyring (one Argon2id per password, never N). Progress and the
verdict are pushed through the event callback: `code=1` progress (`a`=0 scan /
1 verify, `b`/`c`=done/total), `code=-2` locked (`a`/`b`/`c` =
encrypted/locked/unlocked), `code=2` running, `-1` error, `0` stopped.

## Crypt

| Function | Signature | Returns |
|----------|-----------|---------|
| `rcrm_crypt_folder` | `(path, password, is_encrypt)` | 0 success |

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
one copy into a Rust-allocated buffer), Rust spawns `std::thread::spawn`, decodes at
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
| `rcrm_generate_poster_async` | `(url, headers, positions, target_width, quality, callback, ctx)` → void (see below) |
| `rcrm_free_webp_buf` | `(ptr)` → void |

`kind_hint` for the from-image generator: 1 = AVIF, 2 = JXL, 3 = HEIC/HEIF,
anything else sniffs the container header. All inputs are **borrowed**.

Dart callers: `ThumbWebpWorker.encodeRgba` / `.generateThumbFromImage`
(`services/thumb_webp_worker.dart`), driven by `DiskThumbImage`
(`widgets/disk_thumb_image.dart`). Every WebP result is read through
`RustBridge.webpBufBytes`, the one place that wraps a `WebpBuf*` in a Dart view
with a freeing finalizer.

## libmpv Posters

`rcrm_generate_poster_async` (`libmpv-poster`, every platform including iOS)
loads the process's libmpv — on iOS the embedded `Mpv.framework/Mpv` — renders one
frame per candidate position with the software renderer and answers with a
finished WebP. The frame never enters Dart.

```c
typedef void (*RcrmPosterCallback)(WebpBuf *buffer, int32_t status, void *ctx);
void rcrm_generate_poster_async(const char *url,        /* borrowed, copied */
                                const char *headers,    /* CRLF list, copied */
                                const char *positions,  /* "30.000,15.000,…"  */
                                uint32_t target_width,  /* maximum, no upscale */
                                uint8_t quality,
                                RcrmPosterCallback callback,
                                void *ctx);
```

- `headers` is the CRLF-separated header block the Dart side already builds for
  HTTP (`Authorization: Basic …`); Rust turns it into libmpv's
  `http-header-fields` (comma-separated). A value containing a comma cannot be
  expressed — the only header sent is Basic auth, whose alphabet has none.
- `positions` are seconds, most promising first; they come from
  `posterSeekPlan` (`utils/poster_frame.dart`), and libmpv skips any position at
  or past the duration it reads itself.
- `status`: **0** = `buffer` is a finished WebP (`rcrm_free_webp_buf`); **1** =
  libmpv ran but this file produced no usable frame (blank/undecodable — another
  file may work); **2** = this process has no usable libmpv (no shared library, a
  missing symbol, or a client API older than the software renderer) — there is no
  fallback renderer, so Dart answers "no poster" and the failure is cached in Rust.
- The callback arrives on a Rust-spawned thread; Dart routes it through a
  `NativeCallable.listener`. A null callback renders nothing and reports nothing.
- Internally: one mpv client + one `MPV_RENDER_API_TYPE_SW` render context per
  job, created and destroyed on that thread (render.h's rule), reused across the
  candidate positions of that job. Load 25 s, seek 5 s, frame 3 s, whole job
  40 s — every stage answers, so a stuck file cannot hold a poster slot forever.
- The client carries the **poster budgets**, not a player's: `demuxer-max-bytes`
  and `demuxer-max-back-bytes` 4 MiB, `cache-on-disk=no`, `network-timeout=5`,
  `vd-lavc-threads` = min(cores, 8) (4 on Android), `hwdec=no`. A poster needs one frame, so mpv's playback
  defaults (150 + 50 MiB of demux cache, a 60 s network timeout, one decoder
  frame per core) are memory the caller never gets back — on a phone they are
  how a large file's first poster killed the app (2026-11-16).
- Frames the context still holds from before a seek are consumed the render.h way
  — `render` + `report_swap` — so the stale picture is not reported again.
  `MPV_RENDER_PARAM_SKIP_RENDERING` was dropped on 2026-11-16: the SW backend's
  first draw is a one-time warm-up the kept frame pays anyway, so skipping it
  measured the same job total (and depended on a parameter older libmpv need
  not implement).

Caller: `LibMpvPoster.generate` (`services/poster_libmpv.dart`), reached from
`ThumbnailService` (`services/thumbnail_service.dart`) as its only renderer.

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

## Native interop review (Flutter 3.50)

Flutter 3.50 declared **direct native interop stable**: FFIgen for Objective-C
and JNIgen for Java/Kotlin joined FFIgen's *long-standing C support*, and
Pigeon's FFI/JNI mode entered preview. The whole bridge surface was audited
against that announcement. **No runtime binding was migrated**, for concrete
reasons; what changed is the string-based plumbing (below).

### What is already direct interop

All 25 exports in `crates/rcrm-flutter-bridge/src/lib.rs` are handwritten
`extern "C"` functions reached through `dart:ffi` in `ffi/rust_bridge.dart`.
They are synchronous, callable from any isolate (`Isolate.run` calls
`RustBridge.load()`), zero-copy for media bytes (Memory Ownership above), and
already use `NativeCallable.listener` for Rust→Dart callbacks plus a
`NativeFinalizer` for `WebpBuf`. C FFI was stable long before 3.50; this
release added Objective-C bindings and JNIgen, neither of which applies here.

FFIgen 23.0.0 generates **signatures only**. It cannot express the five
ownership shapes above, the address-keyed Rust-owned password buffer, the
"never free on timeout" rule, the runtime probe that treats the five
`mobile-decode` symbols as absent on desktop, or the callback/finalizer
addresses. It also needs a maintained C header (the crate has none) and
LLVM ≥ 18. Replacing the handwritten layer with generated bindings would turn
a checked ownership contract into raw signatures — a downgrade, not an upgrade.

### Why the platform channels stay

Seven `MethodChannel`s / eleven methods remain. They are **lifecycle wrappers**,
not "Dart wants to call a Java class": the native halves own an Activity /
Context, a `BroadcastReceiver` + `ContentObserver`, an `AVAudioSession`, or an
`HWND`.

| Tool | Why not |
|---|---|
| JNIgen 1.0.1 | Generates bindings for Java/Kotlin classes; using it would mean constructing `AudioManager`, `Intent`, `Uri`, `BroadcastReceiver` in Dart and managing registration there. Needs JDK 17–21, CMake and a Gradle stub for Android classpaths; Android SDK stubs after API 28 are documented as incomplete; `package:jni` needs `Jni.spawn` off Android. dart.dev still labels Java interop **experimental** while the 3.50 blog calls it stable — the docs have not caught up. |
| Pigeon native interop | **Preview** (29.0.0 experimental → 29.1.1 Preview → 30.0.0 BREAKING CHANGE), and explicitly **not supported on Windows or Linux**, which rules out `rcrm/window`. Its README lists multi-engine routing, background isolates without an engine id, stale `@FlutterApi` registrations after hot restart, and no macOS detach callback; `rcrm/volume`'s `onChanged` is exactly a `@FlutterApi` push. Data classes, Lists and Maps are still encoded into **one buffer per call** in Pigeon's own comparison table, so "zero serialisation" is not literal. |
| FFI for the Windows runner | `rcrm/window` is one parameterless void command fired on a pointer-down; its serialisation cost is nil. Moving it to FFI would lose the runner's real `HWND` and require guessing the foreground window from the Rust DLL. |

### What was evolved instead: the typed boundary

The part of the 3.50 message that *does* apply here is "string-based plumbing".
`lib/services/platform_bridge.dart` is now the single typed boundary for all
seven channels: `PlatformChannelNames`, `PlatformMethods`, `PlatformArgs`, and
typed call / reply helpers. The seven services no longer contain an
`invokeMethod('…')` string or a hand-built argument map, and untyped codec
replies are normalised to `Map<String, Object?>` in one place. Wire behaviour
is unchanged — same channel names, method names, `StandardMessageCodec`
payloads and exception / fallback policies — so Kotlin, Swift, the Windows
runner and the existing mock tests needed no edits.
`test/platform_bridge_test.dart` pins the contract (7 names, 10+1 methods,
argument keys, reply shape, `onChanged` push).

**Migration path**: if Pigeon native interop reaches stable with Windows/Linux
coverage and a solved `@FlutterApi` lifecycle, replace only
`platform_bridge.dart`. The 25 C-ABI exports stay handwritten regardless; any
generator used there must be a *validator* of the ownership contract, never the
runtime binding.

## See Also

- `ffi/rust_bridge.dart` — all extern "C" bindings with null/pointer safety
- `crates/rcrm-flutter-bridge/src/lib.rs` — extern "C" implementations with `# Safety` docs
- `services/native_bytes.dart` — the copy-free fetch these paths feed from
- `docs/ARCHITECTURE.md` — how the pieces fit together
- AGENTS.md — conventions, feature gates, and development workflow
