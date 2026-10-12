# RCrm — Encrypted Media Library Browser

## Architecture

```
┌──────────────────────────────────────────┐
│  Flutter GUI (rcrm-gui)                  │
│  • VideoCard: poster + hover preview     │
│  • ImageCard: AuthImage (auth header)     │
│  • VideoPlayer: media_kit (libmpv)        │
│  • ImageViewer: zoomable page + filmstrip │
│  • Info sheet: EXIF / track metadata      │
│  • Setup: mount, password, server launch  │
├──────────────────────────────────────────┤
│  dart:ffi → rcrm-flutter-bridge          │
│  • start/stop server (global singleton)   │
│  • folder encrypt/decrypt                 │
│  • blank frame detection (zune_jpeg)      │
│  • WebP thumbnails (RGBA or encoded image)│
│  • media metadata (EXIF / track, nom-exif)│
│  • AVIF/JXL/HEIC software decode *        │
│  • QR generate/scan + TV cast cert        │
├──────────────────────────────────────────┤
│  Rust Server (rcrm-server)                │
│  • Read-only WebDAV + FTP/FTPS            │
│  • HTTP Basic Auth + BLAKE2s-256 hashing  │
│  • TLS (rustls + self-signed cert)        │
│  • per-connection OS threads              │
├──────────────────────────────────────────┤
│  Rust Core (rcrm-core)                    │
│  • ChaCha20 stream cipher                 │
│  • Argon2id key derivation                │
│  • ProjectedFile (read-only decryption)   │
│  • LockedKey (mlock/VirtualLock memory)   │
└──────────────────────────────────────────┘

* mobile only (`mobile-decode` Cargo feature; desktop uses Flutter's engine)
```

## Project Structure

```
crates/
├── rcrm-core/          Encryption engine + file projection
├── rcrm-server/        WebDAV + FTP server, thread-per-connection
├── rcrm-flutter-bridge/ C-ABI FFI shim (cdylib)
│   └── src/
│       ├── avif/       AVIF decode (ISOBMFF + rav1d)     ─┐
│       ├── jxl/        JXL decode (jxl-oxide)             ├ mobile-decode
│       ├── heic/       HEIC/HEIF decode (heic crate)     ─┘
│       ├── decode.rs   DecodeBuf + shared downscaling
│       ├── webp.rs     WebP encoding (zenwebp)
│       ├── metadata.rs EXIF / track parsing (nom-exif)
│       └── server.rs   Server lifecycle for the app
└── rcrm-gui/           Flutter application
    ├── lib/
    │   ├── ffi/         dart:ffi bindings
    │   ├── models/      MediaItem, Album, ServerConfig
    │   ├── providers/   Riverpod state management
    │   ├── screens/     Home, Videos, Images, Player, Viewer, Settings
    │   ├── services/    WebDavClient, native_bytes, thumbnail/metadata services
    │   └── widgets/     VideoCard, ImageCard, player chrome, info sheet
    └── test/            Dart tests
src/                     CLI binary (crypt/serve subcommands)
scripts/                 Build scripts (all platforms)
tests/                   Rust integration tests
docs/                    Documentation
```

## Data Flow

### Scan & Browse

```
Flutter startup → ServerNotifier.start()
  → RustBridge.startWebDavServer() → Rust server thread
  → Ping retry (3×200ms) → OPTIONS check
  → MediaLibrary.scanAll() → WebDAV PROPFIND recursion
    → XML multistatus 207 → MediaItem[] + Album[]
  → Riverpod state → Screen rebuilds
```

### Auth Flow

```
Server start → generate random user:pass
  → store in Rust singleton
  → Dart reads via rcrm_get_auth_credentials()
  → sharedAuthHeaderProvider holds Authorization header
  → All HTTP requests use header (never embedded in URL)
    → WebDavClient: .setHeader('Authorization')
    → AuthImage ImageProvider: header in ImageStreamCompleter
    → ffmpeg CLI: -headers "Authorization: Basic ..."
```

### Video Playback

```
Video tab: two arrangements of ONE list, chosen by `videoClassification`
('none' = the flat grid/list above, the default; 'folder' | 'format' = grouped)
  → the groups are DERIVED, not stored: `videoFoldersProvider` calls the same
    `MediaLibrary.buildAlbums` the photo tab's albums use, with the video tab's
    own classification passed in — so switching arrangements costs no re-scan and
    cannot regroup the photo tab
  → a group opens into its own videos (`video_screen.dart`); Esc, the header's
    back, and the system back key all return to the group list — the key is a
    step out of the tab's SUB-VIEW before it is a step out of the tab, so
    `home_screen` (which owns tab switching and the double-back exit guard)
    defers to the flag the tab publishes: `videoFolderOpenProvider` here, the
    photo tab's `imageAlbumOpenProvider` for an open album
  → the photo tab answers `none` the same way: `ImageScreen` shows every image in
    one flat grid rather than opening its old single "All Images" album
VideoCard tap → Navigator.push(video_player_screen)
  → Player.create() in addPostFrameCallback
  → Media(url, httpHeaders: {Authorization: ...})
  → media_kit (libmpv) plays
  → Custom controls overlay (2s idle fade)
  → Jump (the transport bar's prev/next): open the other video IN the player
    that is already playing (`_playInPlace`) — no new route, so fullscreen,
    picture-in-picture with its dragged geometry, the scroll position behind it,
    the rate, the volume, the screen brightness and the chrome's visibility are
    all untouched by construction; a forward step also pushes the video being
    left onto the jump stack (providers/video_jump_stack.dart, capped at the
    `video_jump_history_limit` setting)
  → Back: pop that stack and play the entry as a ROUTE step, so it carries the
    platform's back-direction transition (that transition is what makes Back a
    different gesture from the transport's prev, which reaches the same video
    with nothing on screen moving); an empty stack leaves the player
  → Related list (utils/related_videos.dart) excludes the stack's entries
  → Player.stop() before Navigator.pop — a route the player REPLACES is stopped
    and disposed by its own `dispose()`, i.e. once its transition has finished,
    which is what keeps its last frame on screen instead of blanking it
```

### Thumbnail Pipeline

> The on-disk `ThumbCache` (mobile by default) is **managed, not evicted**:
> `ThumbCache.manage()` scores every entry — last use (weight 3), generation time
> (weight 1) and size (weight −2), each normalised by the median of this cache —
> and cuts cold / warm / fresh at the TWO LARGEST GAPS in that score order, when
> they are significant against the cache's own median gap (a cache with no shape
> keeps equal thirds), so the coldest third of this cache is cold whatever its
> calendar ages are. Auto trim then spends the lowest-scoring first, only until the
> target is met. The access record is
> a separate log (`<base>/._thumbs_used`, written on a cache hit, throttled),
> because the file's mtime IS the generation time and a read must not rewrite it.
> Nothing is asserted from outside, so a thumbnail generated three years ago and
> opened yesterday outranks one generated last week that nobody has opened, and
> the same rule is right for a library scanned weekly and one opened twice a year.
> The rule is pure (`utils/thumb_cache_policy.dart`); the settings row has one
> entry point (`ThumbCacheDialog`) whose tier rows show size and age in words and
> delete their own tier whole. **Nothing prunes on its own**: `write`
> only writes, and the cache grows until the user opens the cache row: each tier
> row deletes its own tier whole, and Auto trim spends the coldest entries down to
> the target set in that same dialog (platform default 96 MB mobile / 512 MB
> desktop).

Video posters (ffmpeg / media_kit):

```
VideoCard.initState()
  → addPostFrameCallback → _loadPoster()
    → ThumbnailService.generatePoster(url)
      → In-flight dedup: same URL concurrent → reuse Completer
      → 8 seek positions (loop until non-blank)
        → ffmpeg stdout pipe → Uint8List (desktop; zero disk writes)
        → media_kit Player pool → screenshot() (mobile)
          → pool: free-list slots (1 mobile / 11 desktop)
          → destroyed after 30s idle
        → Rust FFI isBlankFrame (zune_jpeg luminance)
        → LRU cache (max 32 mobile / 512 desktop)
      → return bytes
```

Image thumbnails (`DiskThumbImage`, when `ThumbCache.enabled`):

```
grid cell → DiskThumbImage(url, width)
  → disk cache hit? decode the cached small WebP (no network, no gate)
  → miss → ImageLoadGate token
      → software-decoded format (AVIF/JXL/HEIC) on mobile:
          fetchNativeBytes(url)                    ← socket → NATIVE memory
          → ThumbWebpWorker.generateThumbFromImage ← worker isolate
              → rcrm_generate_thumb_webp_from_image
                 (Rust: decode → downscale → WebP; pixels never enter Dart)
      → anything else, desktop, or bytes Rust would not decode:
          HTTP → Dart bytes → engine decode (targetWidth)
          → toByteData(rawRgba) → ThumbWebpWorker.encodeRgba
              → rcrm_encode_thumb_webp (one copy into native memory)
          (a decoder's refusal is not the network's answer: the engine reads
           files our `heic`/`rav1d`/`jxl-oxide` build refuses, so the original is
           fetched again only on this path — otherwise such a file would show in
           the viewer and stay blank in the grid)
  → ThumbCache.write (small WebP only)
```

### Image Display

```
PooledImage(url)                       ImageViewer page
  → AuthImage / DiskThumbImage           → _FullResImageProvider (private cache)
      → software-decoded format (mobile)     → same native-fetch fast path
          fetchNativeBytes → tryDecodeNative   → decode → ui.Image → RawImage
          (compressed bytes never enter Dart)  (RGBA must be copied once into
      → else HTTP → engine codec                Dart: dart:ui builds ui.Image
                                                from Dart buffers only)
```

### Info Sheet (EXIF / track)

```
viewer floating top chrome ⓘ → MediaMetadataService.forUrl(url, kind: image)
  → fetchNativeBytes(url, headBytes: 4 MiB)   ← Range request, native memory
  → rcrm_media_metadata_async (Rust thread, nom-exif)
      → JSON → MediaMetadata (typed model; `parsed` gates absence claims)
  → cache per (url, kind) — successes only, so a failed fetch retries
```

### Live Photo Playback

```
long-press in the viewer → phaseLivePhoto(url) (HTTP Range / ISOBMFF probe)
  → video payload (Android embedded / Samsung mpvd) fetched over Range
  → LiveMediaServer.instance.register(bytes) → loopback URL in RAM
      → media_kit Player plays http://127.0.0.1:<port>/<128-bit token>
      → released when the player is torn down
  (Apple Live Photos skip the server: the companion .mov is played directly)
```

## Key Design Decisions

### Auth via Header (not URL-embedded)

All HTTP requests use `Authorization: Basic …` header via `sharedAuthHeader`. `AuthImage` replaces all `Image.network`/`NetworkImage`. ffmpeg gets `-headers` CLI flag. No credentials in URLs.

### Zero-copy by construction

Every byte that reaches Rust has to live in native memory, so the pipeline is
built to put it there exactly once:

- `services/native_bytes.dart` streams an HTTP response **straight into a
  `calloc` buffer** (sized from `Content-Length`, or a fixed head) and hands the
  pointer over. The naive shape — fetch a Dart `Uint8List`, then `calloc` +
  `setAll` — copies the whole payload for nothing.
- Decode **takes ownership** of that buffer (freed by Rust when the decode
  ends); the RGBA comes back as native memory Dart reads in place.
- Thumbnails for software-decoded formats never materialise pixels at all: Rust
  decodes, downscales and encodes WebP in one call, and the result is viewed in
  place through a `NativeFinalizer`.
- Metadata takes ownership too — with no capacity parameter at all: the export
  frees exactly `len` bytes, and Dart can only hand over a buffer that was
  allocated that way (`NativeTransfer`), so a partly filled head is refused
  rather than described by a number Rust would have to trust.
- Where a copy is unavoidable it is documented in place: `dart:ui` can only
  build a `ui.Image` from a Dart buffer, so viewer pixels are copied once; the
  engine-decoded thumbnail path copies its RGBA once into the encoder's input.

### Video: media_kit (libmpv)

Primary player on all platforms. Supports all major formats via libmpv. Custom overlay controls auto-show/hide on hover (never while a panel or the speed menu is open), density chosen from the window's shortest side, width budget admits optional controls by priority. `Player.stop()` before navigation, `Player.dispose()` in `dispose()`.

### Posters: system ffmpeg CLI (desktop) / media_kit pool (mobile)

Zero disk writes — stdout pipe → `Uint8List` in RAM. Desktop uses `Process.run('ffmpeg', ...)` (up to 11 concurrent), mobile uses `media_kit Player.screenshot()` via a pool (1 serial, free-list slots, 30s idle timeout). In-flight dedup prevents duplicate requests for the same URL. Blank frame detection via Rust FFI `Isolate.run`.

> ffmpeg **≥ 9** verifies TLS peers by default (`tls_verify=1`), so posters from
> an HTTPS server with the app's self-signed certificate fail at the handshake
> unless the ffmpeg invocation opts out or is routed through a loopback relay.
> `-tls_verify` is an option *of the `tls` protocol*, so the poster argv carries
> it for `https://` only: ffmpeg resolves an input option's name against the
> protocol the URL selects and aborts on a name that protocol does not define,
> which would empty every plain-HTTP poster (the desktop app's own server is
> `http://127.0.0.1:<port>`). See `docs/BUILDING.md` → Known toolchain issues.

### Images: AuthImage + in-memory cache

All images load through `AuthImage` ImageProvider (or `DiskThumbImage` when the on-disk cache is on). Grid and viewer share identical `ImageProvider` keys for RAM cache reuse. `_FullResImageProvider` (viewer) has its own private `ImageCache` (`ItemCacheLimit.fullResImageCacheMaxBytes`). Flutter global `imageCache` limit set at startup (`ItemCacheLimit.flutterImageCacheMaxBytes`). The viewport transforms only the photo, never the letterbox, and panning is clamped so no drag can reveal empty space.

### Software decode (mobile) vs engine decode (desktop)

Flutter's engine cannot decode AVIF/JXL everywhere, and on desktop (Impeller)
not even HEIC — so mobile builds compile tri-format decoders into the bridge
(`mobile-decode`: `rav1d`, `jxl-oxide`, `heic`) and route those formats through
them. Colour handling, downscaling and orientation therefore stay consistent
across the grid, the viewer and the thumbnail cache. Desktop keeps the engine
path and omits the feature (smaller binary, no AGPL/patent-encumbered codecs).

### Live Photo Detection (Pure Dart)

HTTP Range requests for XMP metadata (Apple/Android) or ISOBMFF `mpvd` box (Samsung HEIC). No Rust server changes. `LivePhotoInfo` enum drives badge and play button UI. Playing one no longer writes a temp file: the payload is served from RAM over a loopback-only, token-addressed HTTP server (`LiveMediaServer`), because media_kit's `Media.memory` writes to disk and deletes only on GC.

### Encryption: Partial + Projected

Files smaller than `calibration_amount` (2048 bytes default) are fully encrypted; larger files encrypt only the first N bytes for fast seeking. `ProjectedFile::read_at()` decrypts on-the-fly with ChaCha20 seekable keystream. Cached heads are re-encrypted with ephemeral `SessionKey` (page-locked via `LockedKey`).

### Security

- Loopback-only bind (127.0.0.1) for the media server; the live-photo server binds loopback too and is addressed by a 128-bit random token, and the server credentials are never forwarded to it
- Certificate policy is **pinning, not trust-all**: an untrusted certificate is refused and shown to the user; only that exact SHA-1 is pinned for the session
- Random per-session Basic Auth credentials
- `zeroize::Zeroizing` for plaintext buffers
- `LockedKey` page-locked OS memory (mlock/VirtualLock)
- `SessionKey` re-encrypts cached heads in process memory
- No plaintext on disk: thumbnails and posters live in RAM (the opt-in `ThumbCache` stores small WebP thumbnails only), and live-photo payloads are served from RAM
- All `extern "C"` functions have `# Safety` docs; every buffer handed to Rust has one documented owner (see `docs/API_REFERENCE.md`)
- Release builds compile out `server_log!`/`server_error!` (no stderr leaks)
