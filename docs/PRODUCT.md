# Product

<!-- impeccable:product-schema 1 -->

## Platform

adaptive

Flutter native on Windows / Linux / macOS (primary) with Android and iOS as secondary platforms. One design language across all of them; platform-specific behavior is confined to capabilities the OS actually provides (screenshots, volume binding, fullscreen orientation, all-files storage access).

## Users

Adult content collectors who manage large encrypted local media libraries. Privacy-focused power users, desktop-first with Android as secondary. They historically operated in personal/dim environments — late-night browsing, private spaces — and that remains the product's center of gravity. With a light appearance now in scope, the library must also be readable in bright daylight. They value speed, smoothness, and discretion.

The job to be done: browse, preview, and play a personal encrypted media collection with zero friction and zero plaintext disk writes.

## Product Purpose

RCrm lets people with encrypted media libraries browse them as fluidly as a streaming service. Encrypted ChaCha20+Argon2id folders are served through a local read-only WebDAV server, decrypted on-the-fly, and rendered through a Flutter GUI. No plaintext ever touches disk. The experience should feel like a premium streaming platform — not a file manager.

Success looks like: a user opens the app, enters their password, and instantly sees a beautiful media library they can browse, play, and enjoy — without ever thinking about encryption.

## Positioning

The mechanism a neighboring product could not copy by restyling: the library stays encrypted at rest, a local read-only WebDAV server decrypts on demand, and the GUI never writes plaintext media to disk. Security is invisible by design — no warning icons, no "encrypted!" badges. When the user opts into the thumbnail cache, only small WebP/JPEG derivatives are stored in the app-private cache directory, which the OS may reclaim.

## Operating Context

- Desktop windows and Android/iOS devices; personal libraries that can reach tens of thousands of items.
- Dim rooms by default, and now also daylight / bright environments.
- A per-session local server with randomly generated credentials; certificate pinning rather than trust-all; auth by header, never credentials in URLs.
- Playback via media_kit/libmpv; posters rendered by libmpv itself on every platform but iOS, where media_kit screenshots stand in (no ffmpeg on PATH, no subprocess).
- Cast-to-TV and a TV receiver screen browse and play the same library.

## Capabilities and Constraints

- ChaCha20 + Argon2id encrypted folders with partial/projected encryption, decrypted on the fly.
- Read-only, loopback-only WebDAV server; Basic auth via headers.
- Flutter GUI: video posters, WebP image thumbnails, hover previews, gesture-driven player controls, cast, PiP, live photos, an opt-in disk thumbnail cache.
- Library browsing: every video and image item has a context menu (long press on touch, right-click on desktop) with play/open, a facts panel, copy name/path, and — for videos — reveal-in-folder. Two fingers resize the photo and video grids; the video list is one row per line or two, automatic on wide windows and overridable by pinch or Settings. The library is read-only, so the menu offers no rename/delete/move/share.
- No plaintext media on disk. The thumbnail cache holds only small derivatives in the app-private cache dir.
- Appearance (confirmed 2026-11-07): System / Day / Night modes with **System as default**; five brand accent presets plus a Material You option on Android 12+, with Marquee Orange as default. Both values persist across launches and apply immediately without restart. The video player's PAGE follows the appearance — letterbox, the large file title, its meta row and the Related list. Its floating controls above and below the picture (header gradient, transport bar, speed/mode menus, playback-settings panel, episode sheet) keep the original fixed dark treatment in both appearances, with no extra gradient length or width added; `playerAccent` still carries the chosen theme colour's bright variant. Those gradients end at the same colour with zero alpha, never black-transparent. The image viewer's top bar and the cast QR page stay dark-on-photo: they float on a black scrim above an image that is always the subject, so white is the honest colour there in both appearances. A dark ink layer over a bare placeholder is not an overlay either: when no poster exists, the card's info strip uses the page's semantic colours instead.
- Android 12+ Material You (`dynamic_color`) reads the wallpaper primary at runtime and offers it as a sixth swatch named "Device"; `onPrimary` is measured from its luminance. The swatch is hidden outright on any platform or OS version that reports no dynamic scheme — a control that cannot act is not shown.
- Explicitly out of scope: free-form color picking, full preset theme packs.
- Undecided: none recorded for this feature.

## Brand Commitments

Bold, unapologetic, smooth. Three words.

The warm orange accent on deep dark is the original, deliberate identity — "The Midnight Gallery" — not an accident to be corrected. A light appearance extends that world with a warm cream canvas (the app icon's `#F6F1E9`) and the same tonal layering; it does **not** replace the dark world, which remains the Night appearance and the reference every accent is checked against. Accent colors are a small preset set of saturated, confident hues — no apologetic pastels, no safe neutrals, no gradient-text decor. If it feels like it belongs on a different product, it doesn't belong here.

Voice: direct, no euphemisms. Tone: smooth and confident, not brash or crude.

Anti-references:

- Generic SaaS/enterprise UI — no clean white/blue, no admin-panel tropes, no corporate minimalism
- Sterile media players (VLC, Plex default) — no boring playback chrome
- Overdesigned "dark luxury" that forgets it's a browsing tool

## Evidence on Hand

- `docs/DESIGN.md` — the committed design system and its Do/Don't.
- `brands/design/logo.svg`, `brands/banner.svg`, `brands/build_icons.py` — the shield mark on cream and the generator for every platform icon.
- `crates/rcrm-gui/` — the Flutter GUI; `crates/rcrm-core/`, `crates/rcrm-server/`, `crates/rcrm-flutter-bridge/` — encryption, WebDAV server, native codecs.
- `CHANGELOG.md` — per-batch implementation reports, including measured findings and unverified items.
- No customer testimonials, pricing, licensing claims, third-party benchmarks, or press coverage are on hand. Do not invent them.

## Product Principles

1. **Content is king.** The media is the star. Chrome fades away — auto-hiding controls, quiet surfaces, no visual noise competing with videos and images.
2. **Daring and unapologetic.** Own the saturated accent and the tonal layering. A control that quietly means something else is worse than no control; say what the platform will really do.
3. **Zero friction browsing.** Fast scanning, hover previews, gesture-driven controls, instant transitions. Latency is designed, not tolerated.
4. **Privacy obsessiveness.** Encryption is the reason the product exists. Convey security through confidence, not paranoia. On mobile the library is not capturable by default, and the setting that lifts it states plainly what each OS can and cannot do.
5. **One setting, one door.** A choice belongs where the user is looking when they make it; two controls for one setting is one too many. Color is never the only carrier of state.

## Accessibility & Inclusion

WCAG AA is the baseline (4.5:1 text contrast, focus indicators); the practical goal is readability in both dim rooms and bright daylight, so each accent ships with a contrast-checked variant per appearance. Reduced-motion support via platform reduced-motion settings. Accent swatches carry text labels. No screen-reader-specific accommodations at this stage; standard platform semantics where they are free.
