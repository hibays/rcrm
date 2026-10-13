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
  → Custom controls overlay (2s idle fade): a scrub bar with no thumb at rest that
    grows under the pointer (and shows the time under it), a tap-to-swap
    elapsed/remaining readout, and a settings panel carrying the mode, the facts
    the player reported about the file, and the keyboard map
  → a stall longer than 300ms raises a spinner over the picture (media_kit reports
    `buffering` for the frames a seek spends refilling, so the grace is what keeps
    it from firing at something that was never a wait)
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
  → end of file in `Loop All`: the next video is OFFERED (an up-next card, 8s,
    refusable) instead of taken — the card's ring and its countdown are one
    controller, so the time it shows is the time it waits
  → Player.stop() before Navigator.pop — a route the player REPLACES is stopped
    and disposed by its own `dispose()`, i.e. once its transition has finished,
    which is what keeps its last frame on screen instead of blanking it
```

### Storage Access (Android)

```
Every other flow here assumes the local server can OPEN the chosen folders by
their real paths — which is a permission, and on Android it is three different
permissions depending on the version.

library_setup_screen / settings_screen → StorageAccess.watch() + refresh()
  → MethodChannel 'rcrm/storage' → StorageAccessChannel (Kotlin, `MainActivity`)
  → API >= 30 (11+): Environment.isExternalStorageManager(); action "settings"
      — MANAGE_EXTERNAL_STORAGE is an APP-OP: declaring it grants nothing, there
        is no runtime dialog, and the ask is the system settings screen
        (ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, then the all-files screen,
        then the app's details page — the platform documents that the first two
        may not exist on a given device)
  → API 23..29 (6-10): READ_EXTERNAL_STORAGE; action "dialog"
      — Android 10 additionally needs `android:requestLegacyExternalStorage`
        (scoped storage is the default there and all-files access does not exist
        yet); a refusal Android will not repeat sends the user to the app's own
        settings page instead of a dialog that would be auto-denied
  → API < 23: granted at install. Nothing to ask, and nothing offered
  → the answer is RE-READ ON EVERY RESUME. The settings screen belongs to another
    app, the platform sends no result for it, so coming back to the foreground is
    the only signal — `request` starts the flow and returns immediately rather
    than holding a MethodChannel.Result across the trip (which would pin a dead
    Activity)
  → one notifier (`StorageAccess.state`) feeds both surfaces: the setup screen's
    ask card (the app is unusable without it) and the Settings → Server row
  → the wording is a pure function of the reported status (`storageAccessCopy`),
    so it can only ever say what the Android version in front of the user will
    really do; the row uses its one-line `note`, the card its full `body`
```

### System Volume (mobile)

```
The player has always scaled its own gain (`Player.setVolume`), which is what a
desktop app does: the OS mixer is the user's business and the app's slider is a
second, app-local volume stacked on top of it. A PHONE is the other way round —
its hardware keys, its volume panel and every other media app move ONE stream —
so on mobile the player's volume control moves the device's instead, and the
player itself is pinned wide open. There is only one number, so the two cannot
disagree.

Settings → Display → System Volume (mobile only; ON by default on mobile, OFF
and not offered on desktop — `useSystemVolumeDefault`)
  → video_player_screen._seedVolume (at player open):
      read the stream → the bar STARTS at the phone's current level, never at a
      remembered app volume (that is what "bound to the system" means), and the
      read is taken again before binding so the level is the one NOW
  → the whole decision is one value: `utils/player_volume.dart` (`PlayerVolume`)
    holds which volume the screen drives, the level the bar shows and the last
    level the device was AUDIBLE at, and every transition is pure — the screen
    cannot be mounted in a test (its first frame builds a real media_kit
    `Player`), and the two defects review found in its routing were both in
    exactly that state:
      · the audible memory starts at 0 — and the level a session is SEEDED with
        counts as audible — so an unmute on a session that opened with the phone
        already silent (or on the app's own stored level) reaches the device's
        own last level instead of jumping to full scale
      · the seed path runs twice (what was already known, then the platform's
        answer) and the second pass only CONFIRMS the decision: its reading was
        already in flight when a volume-key press in the opening moments arrived
        as a push, and re-adopting its level would rewind the bar to a level the
        phone is no longer at
      · the device's answer is applied to the bar EXPLICITLY, not only through
        `SystemVolume.state`: a quantised reply can equal the reading the
        notifier already holds, and an unchanged `ValueNotifier` notifies nobody
      · a reading that says the output has become FIXED (an HDMI/USB sink
        appearing mid-session) hands the volume back to the app at the level on
        screen — the same refusal the seed makes, on the runtime path
  → every volume path (slider, wheel, arrow keys, swipe, gesture chip, mute)
    goes through the screen's one `_setVolume`:
      bound   → SystemVolume.setPercent → MethodChannel 'rcrm/volume'
                → Android: AudioManager.setStreamVolume(STREAM_MUSIC, index, 0)
                  (no FLAG_SHOW_UI: the app's own bar is the readout)
                → iOS: the UISlider inside an offscreen MPVolumeView
                → the reply is where the stream LANDED, and it is what the bar
                  shows: a 15-step phone cannot be at 43%, only at 6/15 = 40%
                → a request for a step the app has ALREADY asked for (or the
                  device has confirmed) is not sent: a drag repeats it on most
                  frames, and the confirmation is a round trip away — while a
                  MUTED stream is always written, because the write is what
                  clears the mute
                → a level that is not a number is refused at the entry point:
                  a gesture area with no height yet produces one, and `clamp`
                  passes NaN through while `round()` throws on it
      unbound → Player.setVolume (the app's own gain, persisted as before)
  → a change made ANYWHERE ELSE reaches the bar too: the platform pushes
    `onChanged` on the same channel
      (Android: TWO mechanisms, because neither is promised — a runtime
       receiver for the @hide broadcast android.media.VOLUME_CHANGED_ACTION,
       filtered to STREAM_MUSIC, AND a ContentObserver on Settings.System
       filtered to volume keys, since the app writes SCREEN_BRIGHTNESS per
       frame during a brightness swipe; both collapse into one push. iOS: KVO
       on AVAudioSession.outputVolume)
  → the arithmetic lives in ONE place, `services/system_volume.dart`, as pure
    functions the platform never sees: the platform answers with raw stream
    numbers (`index`, `min`, `max`) and applies an index, so the percentage
    both directions agree on — including the quantisation — is unit-tested
    rather than re-implemented per platform
  → binding needs four things at once (`shouldBindSystemVolume`): a mobile
    platform, the setting, a reading, and an output that is not fixed-volume
    (`isVolumeFixed` on Android; on iOS there is no such call, so the app reports
    "fixed" when its own `MPVolumeView` yields no slider — a route with no volume
    control, where the failure is asymmetric: a wrong "fixed" costs the binding,
    a wrong "settable" would cost the user every volume control there is).
    Without all four the player keeps its own volume rather than showing a
    slider that cannot act — and the Settings row's subtitle is a pure function
    of the switch, whether a reading exists and that `fixed` flag, so it says
    which of the three it is looking at rather than promising device control the
    player will not perform
  → iOS reads through the SAME control it writes through (the volume view's
    slider, falling back to `AVAudioSession.outputVolume` only when there is no
    slider): `outputVolume` is only meaningful on an ACTIVE session, and this app
    must not force one (activating it interrupts whatever else is playing, and a
    video that has not started yet has no session of its own)
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
