# RCrm — Encrypted Media Library Browser

## Architecture

```
┌──────────────────────────────────────────┐
│  Flutter GUI (rcrm-gui)                  │
│  • VideoCard: poster + hover preview     │
│  • ImageCard: AuthImage (auth header)     │
│  • VideoPlayer: media_kit (libmpv)        │
│  • ImageViewer: PageView + pinch-zoom     │
│  • Setup: mount, password, server launch  │
├──────────────────────────────────────────┤
│  dart:ffi → rcrm-flutter-bridge          │
│  • start/stop server (global singleton)   │
│  • folder encrypt/decrypt                 │
│  • blank frame detection (zune_jpeg)      │
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
```

## Project Structure

```
crates/
├── rcrm-core/          Encryption engine + file projection
├── rcrm-server/        WebDAV + FTP server, thread-per-connection
├── rcrm-flutter-bridge/ C-ABI FFI shim (cdylib)
└── rcrm-gui/           Flutter application
    ├── lib/
    │   ├── ffi/         dart:ffi bindings
    │   ├── models/      MediaItem, Album, ServerConfig
    │   ├── providers/   Riverpod state management
    │   ├── screens/     Home, Videos, Images, Player, Viewer, Settings
    │   ├── services/    WebDavClient, ThumbnailService, MediaLibrary
    │   └── widgets/     VideoCard, ImageCard, PlayerControls
    └── test/            Dart unit tests (19+)
src/                     CLI binary (crypt/serve subcommands)
scripts/                 Build scripts (all platforms)
tests/                   Rust integration tests (34+)
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
VideoCard tap → Navigator.push(video_player_screen)
  → Player.create() in addPostFrameCallback
  → Media(url, httpHeaders: {Authorization: ...})
  → media_kit (libmpv) plays
  → Custom controls overlay (2s idle fade)
  → Player.stop() before Navigator.pop
```

### Thumbnail Pipeline

```
VideoCard.initState()
  → addPostFrameCallback → _loadPoster()
    → ThumbnailService.generatePoster(url)
      → In-flight dedup: same URL concurrent → reuse Completer
      → 8 seek positions (loop until non-blank)
        → ffmpeg stdout pipe → Uint8List (desktop)
        → media_kit Player pool → screenshot() (mobile)
          → pool: free-list slots (1 mobile / 11 desktop)
          → destroyed after 30s idle
        → Rust FFI isBlankFrame (zune_jpeg luminance)
        → LRU cache (max 32 mobile / 512 desktop)
      → return bytes
```

## Key Design Decisions

### Auth via Header (not URL-embedded)

All HTTP requests use `Authorization: Basic …` header via `sharedAuthHeader`. `AuthImage` replaces all `Image.network`/`NetworkImage`. ffmpeg gets `-headers` CLI flag. No credentials in URLs.

### Video: media_kit (libmpv)

Primary player on all platforms. Supports all major formats via libmpv. Custom overlay controls auto-show/hide on hover. `Player.stop()` before navigation, `Player.dispose()` in `dispose()`.

### Posters: system ffmpeg CLI (desktop) / media_kit pool (mobile)

Zero disk writes — stdout pipe → `Uint8List` in RAM. Desktop uses `Process.run('ffmpeg', ...)` (up to 11 concurrent), mobile uses `media_kit Player.screenshot()` via a pool (1 serial, free-list slots, 30s idle timeout). In-flight dedup prevents duplicate requests for the same URL. Blank frame detection via Rust FFI `Isolate.run`.

### Images: AuthImage + in-memory cache

All images load through `AuthImage` ImageProvider. Grid and viewer share identical `ImageProvider` keys for RAM cache reuse. `_FullResImageProvider` (viewer) has its own private `ImageCache` (`ItemCacheLimit.fullResImageCacheMaxBytes`). Flutter global `imageCache` limit set at startup (`ItemCacheLimit.flutterImageCacheMaxBytes`).

### Live Photo Detection (Pure Dart)

HTTP Range requests for XMP metadata (Apple/Android) or ISOBMFF `mpvd` box (Samsung HEIC). No Rust server changes. `LivePhotoInfo` enum drives badge and play button UI.

### Encryption: Partial + Projected

Files smaller than `calibration_amount` (2048 bytes default) are fully encrypted; larger files encrypt only the first N bytes for fast seeking. `ProjectedFile::read_at()` decrypts on-the-fly with ChaCha20 seekable keystream. Cached heads are re-encrypted with ephemeral `SessionKey` (page-locked via `LockedKey`).

### Security

- Loopback-only bind (127.0.0.1)
- Random per-session Basic Auth credentials
- `zeroize::Zeroizing` for plaintext buffers
- `LockedKey` page-locked OS memory (mlock/VirtualLock)
- `SessionKey` re-encrypts cached heads in process memory
- All `extern "C"` functions have `# Safety` docs
- Release builds compile out `server_log!`/`server_error!` (no stderr leaks)
