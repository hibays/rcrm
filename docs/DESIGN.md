---
name: RCrm Media Library
description: Encrypted media library browser — bold dark UI with orange accent
colors:
  primary: "#FF6B00"
  primary-warm: "#FF9900"
  bg-pitch: "#0E0E0E"
  surface-ash: "#1A1A1A"
  card-char: "#222222"
  placeholder-coal: "#2A2A2A"
  shimmer-highlight: "#3A3A3A"
  text-white: "#FFFFFF"
  text-silver: "#AAAAAA"
typography:
  display:
    fontFamily: "Roboto, system-ui, sans-serif"
    fontSize: "clamp(1.5rem, 4vw, 2.5rem)"
    fontWeight: 700
    lineHeight: 1.2
  headline:
    fontFamily: "Roboto, system-ui, sans-serif"
    fontSize: "clamp(1.25rem, 3vw, 1.75rem)"
    fontWeight: 600
    lineHeight: 1.3
  title:
    fontFamily: "Roboto, system-ui, sans-serif"
    fontSize: "1rem"
    fontWeight: 600
    lineHeight: 1.4
  body:
    fontFamily: "Roboto, system-ui, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 400
    lineHeight: 1.5
  label:
    fontFamily: "Roboto, system-ui, sans-serif"
    fontSize: "0.75rem"
    fontWeight: 600
    lineHeight: 1.3
    letterSpacing: "0.02em"
rounded:
  sm: "4px"
  md: "8px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "16px"
  lg: "24px"
components:
  card:
    backgroundColor: "{colors.card-char}"
    rounded: "{rounded.md}"
    padding: "0px"
    shadow: "0 1px 3px rgba(0,0,0,0.3)"
  card-hover:
    backgroundColor: "{colors.card-char}"
    rounded: "{rounded.md}"
    shadow: "0 4px 12px rgba(0,0,0,0.4)"
  bottom-nav:
    backgroundColor: "{colors.surface-ash}"
    textColor: "{colors.text-silver}"
    selectedColor: "{colors.primary-warm}"
  appbar:
    backgroundColor: "{colors.surface-ash}"
    foregroundColor: "{colors.text-white}"
  button-segmented-selected:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.bg-pitch}"
  slider-active:
    trackColor: "{colors.primary}"
    thumbColor: "{colors.primary}"
  slider-inactive:
    trackColor: "rgba(255,255,255,0.20)"
  placeholder:
    backgroundColor: "{colors.placeholder-coal}"
---

# Design System: RCrm Media Library

## 1. Overview

**Creative North Star: "The Midnight Gallery"**

The interface is a dark room where media hangs on the wall, illuminated by a single warm orange glow — the marquee of a theater at night. Everything recedes so the content commands attention. The chrome is dark, flat, and silent; the accent is warm, rare, and confident.

This system has no use for shadows, gradient text, glass blurs, or side-stripe borders. Depth is expressed through tonal layering — card (`#222`) on surface (`#1A1A1A`) on pitch (`#0E0E0E`). Interactive elements earn a subtle lift on hover, but surfaces at rest are flat. The orange accent is never decorative — it leads the eye to what matters (play buttons, progress, selected state).

The design rejects SaaS minimalism, sterile media-player chrome, and any palette that apologises for what this product is. It is unapologetic, smooth, and built for late-night browsing in dim environments.

**Key Characteristics:**

- Dark tonal layering, not shadows
- One warm accent (Marquee Orange), used on ≤10% of any screen
- Surfaces recede; content glows
- Chrome auto-hides on playback — the media is the star
- Bold by choice, not by accident

## 2. Colors: The Marquee Palette

A warm orange on deep, warm-tinted black. The palette is deliberately narrow — one accent, five neutral steps from pitch to white.

### Primary

- **Marquee Orange** (`#FF6B00` / oklch(0.62 0.22 40)): The single accent. Used for play buttons, progress indicators, slider thumbs/tracks, selected segment fills, loading spinners, and nothing else. Its rarity is the point — when orange appears, something is happening.

### Primary Variant

- **Warm Glow** (`#FF9900` / oklch(0.72 0.18 60)): A warmer, slightly lighter orange used exclusively for selected bottom-nav items. Sits just behind Marquee Orange in visual weight.

### Neutral

- **Pitch** (`#0E0E0E` / oklch(0.035 0.005 60)): The canvas. Scaffold background. Near-black with a trace of warmth from a hint of orange hue.
- **Ash** (`#1A1A1A` / oklch(0.13 0.005 60)): Surface layer. App bars, bottom nav, section backgrounds.
- **Char** (`#222222` / oklch(0.18 0.005 60)): Cards, containers. The main content surface.
- **Coal** (`#2A2A2A` / oklch(0.22 0.005 60)): Image placeholders, shimmer base, album empty state fill.
- **Dim Highlight** (`#3A3A3A` / oklch(0.28 0.005 60)): Shimmer highlight, subtle divider.

### Text

- **White** (`#FFFFFF`): Primary text, headlines, icon default.
- **Silver** (`#AAAAAA` / oklch(0.72 0.008 60)): Secondary text, unselected nav labels, metadata.
- **Silver Transparent** (`rgba(255,255,255,0.20)`): Slider inactive track, disabled elements.

### The Rarity Rule

Marquee Orange is used on ≤10% of any given screen. When orange appears, it means *action* or *focus*. Overuse dilutes its signal; the default state of every element is neutral.

## 3. Typography

**Display Font:** Roboto / system-ui (platform default)
**Body Font:** Roboto / system-ui (platform default)

The system uses the platform's native sans-serif. No custom fonts — the media is the typography. Roboto (Android/desktop) and the system UI font (Windows Segoe UI, macOS SF) provide clean readability in dim light without drawing attention to themselves.

### Hierarchy

- **Display** (Bold 700, clamp(1.5rem, 4vw, 2.5rem), 1.2): Screen titles, hero headlines on the home tab. One per screen maximum.
- **Headline** (Semi-Bold 600, clamp(1.25rem, 3vw, 1.75rem), 1.3): Section headers, album titles.
- **Title** (Semi-Bold 600, 1rem, 1.4): Card titles, video names, list item titles.
- **Body** (Regular 400, 0.875rem, 1.5): Descriptive text, metadata, settings labels.
- **Label** (Semi-Bold 600, 0.75rem, 0.02em letter-spacing): Badge text, format labels, small metadata. Not uppercase by default — let the content decide.

Body text is set at a comfortable 65–75ch max line length on desktop. All text is white-primary or silver-secondary against the dark background — no light gray "for elegance" that fails contrast.

### The No-Light-Gray Rule

Secondary text is `#AAAAAA` (contrast 8:1 against pitch), not the washed-out `#666666` or `#888888` that passes AA but hurts readability in dim rooms. Silver is silver, not ash.

## 4. Elevation

The system uses **tonal layering, not shadows** as its primary depth mechanism. Pitch → Ash → Char → Coal creates clear container hierarchy through lightness alone.

Interactive elements earn a subtle shadow lift on hover (`0 4px 12px rgba(0,0,0,0.40)`), but surfaces at rest are flat. App bars have zero elevation — they're distinguished by color, not shadow. Cards have a minimal `0 1px 3px rgba(0,0,0,0.30)` at rest for structural separation, but it is the lightest possible touch.

### The Flat-By-Default Rule

Surfaces are flat at rest. Shadows appear only as a response to state — hover, focus, interactive elevation. A screen should look equally structured with all shadows removed, because the tonal layers carry the hierarchy.

## 5. Components

### Cards

- **Shape:** Gently rounded corners (8px radius)
- **Background:** Char (`#222222`)
- **Shadow:** `0 1px 3px rgba(0,0,0,0.30)` at rest; `0 4px 12px rgba(0,0,0,0.40)` on hover
- **No border.** Cards are distinguished from the surface by their lighter tone, not by strokes.
- **Internal padding:** Component-dependent (video cards: 0 for poster fill; album cards: variable)

### Bottom Navigation

- **Background:** Ash (`#1A1A1A`), full width, fixed type (no shifting)
- **Selected label:** Warm Glow (`#FF9900`) — the warmer, lighter variant of Marquee Orange
- **Unselected label:** Silver (`#AAAAAA`)
- **Icons:** Same color rules as labels
- **No indicator line.** The selected state is color-only.

### App Bar

- **Background:** Ash (`#1A1A1A`), zero elevation
- **Text:** White (`#FFFFFF`)
- **Actions:** White icons
- **Centering:** Left-aligned title (not centered)
- **Back button:** White, no background shape

### Buttons

- **Text style:** Material default with brand color scheme
- **Primary action buttons:** Use Marquee Orange fill where actionable significance demands it
- **Text/outlined buttons:** Silver/white on transparent, no border
- **Segmented buttons:** Selected state fills with Marquee Orange, text becomes black for readability. Unselected: transparent with white secondary text.

### Sliders

- **Active track/thumb:** Marquee Orange (`#FF6B00`)
- **Inactive track:** Silver Transparent (`rgba(255,255,255,0.20)`)
- **Secondary active:** `rgba(255,255,255,0.35)` for buffer display
- **Volume slider (player controls):** White active track, same transparent inactive. Subdued orange is reserved for media progress, not volume.
- **A player's bar is not a settings slider** (`widgets/player_scrub_bar.dart`): no thumb at rest, a thumb and a thicker track while the pointer is on it (or a finger is down, or it holds the keyboard), and a time (or percentage) tooltip that follows the pointer with a 1px guide line through the bar — the one question a progress bar cannot answer by itself is "what is at this x?". The tooltip arrives in 120ms and leaves in 220ms, so a pointer skimming across does not strobe; the entrance is 150ms ease-out. `disableAnimations` turns all of it into an instant state change.
- **Pin the geometry, animate the paint:** Flutter lays a Slider's track out inset by `max(thumbWidth, overlayWidth)/2`, and both of those are what this widget animates — so the halo's SIZE is fixed (`kScrubOverlayRatio`, 1.6× the thumb radius) and only its alpha animates. The track's ends then never move, the pointer-to-value mapping is exact at every frame of the hover, and `ScrubBarGeometry` is a pure function that unit-tests it. video.js hit the same trap and fixed it with pixel margins on the holder for the same reason ("with the default em-based margins, this means it gets narrower and causes issues with mouseover behaviors/math")
- **A bar that cannot be dragged never grows:** no duration means no growth, no tooltip, no halo. An enlarged track under the cursor is a promise of interactivity (video.js: `.vjs-progress-holder.disabled { font-size: 1em }`)

### Progress Bars (Video Player)

- **Buffered:** white 35% (`0x59FFFFFF`)
- **Played:** Marquee Orange (`#FF6B00`)
- **Remaining:** white 20% (`RCrmColors.silverDim`) — the three bands are the same thickness (Material's default fattens the played segment by 2dp, which on a 3dp track is the whole personality of the control)
- **Background:** Transparent
- **Mini progress bar (controls hidden):** Same orange on transparent, thin (2px), buffered band at white 25%. No blanket opacity over it — the bands carry their own alpha, and halving it again made a readout nobody could see

### Loading States

- **Shimmer:** Base Coal (`#2A2A2A`), highlight Dim Highlight (`#3A3A3A`), infinite sweep
- **Image placeholders:** Coal (`#2A2A2A`) background with centered broken-image icon in white24
- **Spinner:** CircularProgressIndicator with Marquee Orange value color

### Image/Video Placeholders

- **Background:** Coal (`#2A2A2A`)
- **Icon (on failure):** broken-image icon, 28px, white24
- **Loading spinner:** 18px CircularProgressIndicator, orange

### Navigation Tabs (Home/Videos/Images)

- **Fixed** `BottomNavigationBarType.fixed` — no shifting on selection
- **3 items:** Home, Videos, Images
- **Icons:** Material defaults
- **Back key hierarchy:** back undoes the innermost thing that is open. An open video folder or photo album is a step INSIDE its tab — back closes it to the list, on either tab by the same rule, and the shell defers to the tab that owns it — and only then does back leave the tab for Home. On Home itself, Android guards the exit with a second press. One press, one step: the header's back arrow and the system gesture are never two different answers

### Controls Overlay (Video Player)

- **Gradient:** Vertical `0x80000000` to `0x00000000` — from opaque black at bottom to transparent
- **Auto-hide:** After 2s idle on desktop (reappears on mouse move or tap). Never while a panel is open — settings, episodes, or the speed menu; that panel's own button is the way out
- **Controls bar:** Transparent background (the gradient IS the background)
- **Fullscreen top bar:** Back (left), title, playback-settings gear (right) — present on every platform, fades with the controls, and respects notch/camera-cutout insets. Back retraces one step (the jump history first, then the route behind the player); Home sits beside it and leaves the whole player chain for the library, but only while there IS a history — with an empty stack Back already leaves the player, and two buttons for one action is one too many. The gear belongs at the top right, never in the transport bar
- **Width budget:** The transport bar admits optional controls by priority (time → skip → rate → episodes) and gives the volume slider whatever width is left; below ~64dp of travel the slider hides, and if the bar still does not fit, whole controls are dropped in a fixed order — fullscreen first (below ~108dp), then mute (below ~74dp), then the rate chip (the play/pause button and elapsed time are never dropped). Controls are never squeezed or shrunk to fit, and width is budgeted only for what will really be painted: a skip button with nowhere to skip to is not planned at all. The app does not bind F11: fullscreen is the `F` shortcut and the title-bar button
- **Skip pair:** Previous and Next switch video inside the player that is already playing — nothing on screen moves, and fullscreen, picture-in-picture, the speed and the volume stay the ones you set. Previous walks the jump history back one step; Back (the top bar, the system gesture) reaches the same video as a route step, with the platform's back-direction animation — which is the difference between leaving a video and skipping to another one. A step is two pages, and both play the platform's back: the video arriving enters the way a pop reveals a page, and the one being left exits the way a pop sends the page it pops away — off the opposite edge, on the platform's own curve, whether the history behind it is empty (a real pop) or not (a replacement). With only the arriving half fixed, both pages travelled the same way at once and a step back read as another forward jump. **The length of a step is the platform's** — 450ms on Android, 300ms on the desktop zoom. A 300/240 override was tried and reverted: it was aimed at the exit "dragging", but the exit that felt wrong was playing the wrong animation (see below), and the override shortened the transitions that had never been a problem. **One exit, whichever way you leave it:** Back with an empty history, Back off the last history entry — a video that was itself reached as a return step — and Home (the top-left control) all pop the player, so all three play that same pop. A page's exit is decided by what it is DOING, never by how it was reached or by which control asked: the returning parameterization is asked only while the page is arriving, and Home no longer stops the player first (a stopped player paints no frame, so that exit played as the same step with the picture missing). Home also leaves in that one step when the video was opened from the search results: the search screen is taken out of the chain without animating it, instead of two pages sliding away at once. And the app itself is already the library's when it arrives — the system bars and the orientation on mobile, the window on desktop, are restored as the exit starts, not after it, so a fullscreen landscape video no longer pops first and rotates second with the library re-laying out in between. Each button is painted only when there is somewhere to skip to, so neither is ever a dead control
- **Density:** Chosen from the window's shortest side — compact < 400dp, regular < 600dp, expanded above. Fullscreen alone never inflates the controls. When the bar itself is narrower than the compact tier can afford (140dp), the targets step down once more rather than overflow: no minimum window size is set, so a desktop window can really be dragged that narrow
- **Time readout:** elapsed and the total, in one line, in tabular figures so a running clock cannot shuffle the row it shares with the skip buttons and the volume slider. Tapping it swaps the second number for the time LEFT (`-40:42`) — the question a 90-minute film actually raises — and the choice is remembered (`player_time_mode`). Both readings are budgeted whether or not one is on screen, so the tap can never make the duration disappear at a narrow width; it is plain text, with no tooltip and no tap target, when there is no swap to offer
- **Transport bar:** play/pause is the largest mark in the bar and the only control with no alternative path; the mute button says how loud it is in three states (`volume_off` / `volume_down` under 50 / `volume_up`), because "volume > 0" drew a full speaker at 5% and at 95% alike. Neither is ever a dead control
- **Volume, named:** the bar's volume control moves whichever volume is really the volume where it is running — on mobile the DEVICE's media stream (what the hardware keys and every other media app move), on desktop the player's own gain. One setting decides it (Settings → Display → System Volume: ON by default on mobile, not offered on desktop at all), and a bound bar opens on the phone's current level rather than on what this app last played at. It also shows the level the device LANDED on, not the one the finger asked for: `setStreamVolume` quantises, and 43% is not a level a 15-step stream has. A change made with the hardware keys moves the bar too, because a bar that disagrees with the phone is the whole problem the binding exists to remove. The row says which of the three things is true — bound, unreadable, or a fixed output — because two of them are cases where the switch cannot keep its promise and the player keeps its own volume instead
- **Speed popup:** Ash surface (`#1A1A1A`), no Material tint, 8dp radius, a check against the active rate. The chip is the one control that reports a state rather than offering an action, so it is the one that holds the accent while that state is not the default — 1.25x should be answerable from across the room, 1x should not shout
- **Buffering:** a spinner over the picture (dark disc, orange arc) once a stall has lasted 300ms — media_kit reports `buffering` for the frames a seek spends refilling, and an animation that means "wait" must not fire at something that was never a wait. It disappears the moment the picture moves again. 300ms is the grace video.js gives its own loading spinner. It never fires on a **finished** video: nothing is loading on the last frame, so an animation that means "working on it" would be about nothing
- **Up next:** when a video ends in `Loop All`, the next one arrives through a card (bottom-end, clear of the transport bar) rather than by surprise: the ring drains over 8s, "Play now" agrees, and the ✕ keeps the last frame. The countdown lives on the ring's own controller, so the time shown and the time until it plays cannot disagree. An open panel covers it without cancelling the autoplay it stands for. **Taking the video back withdraws it**: dragging the bar off the end cancels the offer exactly as the ✕ does, because the viewer has said they are staying — and so does pressing play, which restarts *this* one from the beginning rather than moving on. The countdown is also decided **once** per ending — a repeated end-of-file signal (mpv reports it again after every take-back) never re-arms it, which is what stops a second pass from seeking a video the viewer had just dragged back
- **The two vertical swipes are one gesture at two scales:** the left half of the picture drives the brightness (0..1) and the right half the volume (0..100), and both are the SAME shape — one value the finger owns for the length of the swipe, pushed out to whoever applies it, never read back from there (`utils/swipe_value.dart`). The full range takes **0.6 of the gesture area's height** on either scale (`kVerticalSwipeSpanRatio`), the ends clamp rather than wrap, and a 1px wobble moves the value 1px worth. Both numbers were tuned against the finger: a whole height of travel was the original rule and it read as too slow once the swipe started tracking the finger honestly (on a portrait phone in fullscreen that is ~890px of travel for 0..100, about nine pixels per percent), while going much shorter would aim the value in sub-pixel steps — and it is ONE rate for both halves on purpose, because a viewer who learns one has learned the other. That last part is the whole point: the volume half used to re-read the bar every frame, and while the volume is bound to the device the bar holds the STEP the phone landed on — so on a 15-step phone (6.7% per step, ~40px of a 600px screen) a slow swipe moved nothing at all and a wobble across a step boundary walked the volume backwards. A gesture that fights the finger is a gesture nobody trusts. The device's answer is taken the moment the finger lifts, which is when the bar goes back to showing the truth (and which is why it may outrun the device while the swipe lasts)
- **Fullscreen orientation is a strategy, not a switch:** the player's settings panel offers four policies on mobile — **Fit** (the default: a wide video locks landscape, a tall one portrait, so the picture uses the screen), **System** (rotate only as the OS allows, rotation lock included), **Follow** (the phone's real posture, even against the system lock), and **Lock** (with a Portrait/Landscape direction under it). The old "Auto-Rotate" switch is why this is a strategy: it said "ignore system rotation lock; follow device orientation" and made the only call the framework has for it — every orientation — which Android decodes to `FULL_USER`, documented as *"Respect the user's sensor-based rotation preference"*. The one thing it existed for was the one thing it could not do, and on a locked phone it did nothing at all. **Follow** is offered on both mobile platforms because both can really do it, each with its own API — Android's `FULL_SENSOR` (`"Ignores user's setting to turn off sensor-based rotation"`) and, on iOS, the hardware posture (`UIDevice.orientation`, which the rotation lock does not affect) plus an explicit geometry request — so nothing here promises an override a platform refuses, and nothing hides a policy it can honour. The words are the same on both; a platform caveat belongs on the rows where a platform really cannot act (the screenshot policy, the volume binding). Nothing is forced outside fullscreen — leaving the player hands the app back to its own direction — and the strategy re-applies the moment the video's real shape arrives, which is the other half of what was broken: the old code decided once, from a size the player often had not reported yet, and a portrait video then stayed locked landscape for the whole session. **And a video change costs one rotation, not two:** switching video is a moment with no size at all (the next file is loading, no track open yet), and treating that silence as news used to send the screen off the axis the video had fitted it to and back — two rotations for every skip, and between two same-shaped videos two rotations that cancelled out. So **Fit holds the lock it already has** until the new shape actually arrives, and then rotates once (or not at all). The way up a moment before the player can say is the way up it is already at.
- **Settings panel:** three parts — the playback mode with a sentence under it saying what that mode will really do, the facts the player actually reported about this file (resolution with its class name, pixel format, hardware decode, rotation, audio, bitrate, size — a fact the player has nothing to say about is left out rather than printed as "unknown"), and the keyboard map. Rotation is offered on mobile only and the key map on desktop only: a control that cannot act is not shown at all. The gear that opens it sits in the top-right in fullscreen and at the end of the video's own back/home row in the windowed player — the same chrome at two sizes

### Image Viewer

- **The transform is the photo, never the letterbox:** the picture is laid out at fit-contain size and only the picture is scaled. Panning is clamped so a zoomed photo always covers the viewport and a smaller one is locked to the centre — no drag, at any scale, can reveal empty space
- **Zoom:** pinch and wheel zoom about the focal point, double-tap zooms to the tapped point (2.5×) or resets, 1:1 caps at 6× fit. Max zoom is 6× fit
- **Chrome floats over the photo:** round translucent buttons (40dp, `Colors.black` 32% at rest) over a top scrim, plus the file name and its position as the only text — no toolbar, no bar background, no divider
- **Filmstrip:** bottom scrim `0xCC000000` → transparent behind the thumbnail strip; the selected tile keeps the Marquee Orange border
- **Pull-to-dismiss:** vertical travel 1:1 with sideways damping (0.35) and upward resistance; closing takes 12% of the viewport height (clamped 72–132px) **or** a downward flick over 700 px/s. The photo shrinks to 0.6 and the backdrop opens to ~8% as it goes. It only engages at fit (1×): while the picture is zoomed the drag pans it instead — the way out of a zoom is zooming out, never yanking the photo off the screen. **One gesture, one axis:** the finger's first 8px commit it — a sideways lead (over 1.5× the vertical travel) means the pager owns the gesture and the pull contributes nothing at all from then on, however far down the finger later sinks, while a downward lead stays a pull, however far it then drifts sideways
- **Info sheet:** ash sheet, 14px top radius, hairline top border, light scrim (`black` 35%) so the photo stays the subject. Anatomy: drag handle → large date (EXIF capture time when known, else the file timestamp, shown in local time) with the `1:1` chip → file name → location line, or a dimmed "No location information" → camera block (camera · lens · exposure · dimensions) or the honest "No camera information" → labelled rows (folder, position, animated). Marquee Orange appears only on the `1:1` chip
- **Say only what was established:** an absence ("No camera information", "No location information") is stated only after a successful parse of identified bytes; a failed parse, an unreachable file or a pending read stays silent instead of asserting a fact nobody checked. The animated row reports the same verdict the badge uses (extension test plus a container-header probe), so a genuinely animated WebP/AVIF never shows the badge without the row

### Info Dialogs

- **Style:** Standard Material `AlertDialog` with dark theme default
- **Background:** Surface-level gray (inherited from theme)
- **OK button:** Standard text button

### Format Badges (Image Cards)

- **Background:** Semi-transparent black (`Colors.black54`), 4px radius
- **Text:** White70 (`rgba(255,255,255,0.70)`), 9px, semibold (600)
- **Position:** Top-right corner of image card, absolute
- **Animated indicator:** Circle badge bottom-left — `motion_photos_on` icon, 14px, white, on black54 circle

## 6. Do's and Don'ts

### Do

- **Do** use Marquee Orange sparingly — on ≤10% of any screen. When it appears, the user should feel it means something.
- **Do** use tonal layering (pitch → ash → char → coal) for hierarchy instead of shadows or borders.
- **Do** let content breathe — generous spacing in grids (4px), auto-hiding chrome, transparent overlays.
- **Do** use `text-wrap: balance` on headings and `text-wrap: pretty` on body text (when CSS control is available).
- **Do** use Silver (`#AAAAAA`) for secondary text. Higher contrast than the generic gray so it reads in dim light.
- **Do** clip card content with `Clip.antiAlias` for performance — rounded corners on cards are decorative, not structural.
- **Do** say what the platform will really do. A control whose promise differs by OS — `Allow Screenshots` can refuse a capture on Android and cannot on iOS, where the app can only cover itself — carries the wording of the platform it is shown on, and is not offered at all where it could not act (desktop). A control that quietly means something else is worse than no control. The same rule governs the storage ask, where the platform differs by VERSION rather than by OS: Android 11+ has no dialog for all-files access at all (the ask is a system settings screen), Android 6–10 grant it with an ordinary permission dialog, and an Android 5 device was granted it at install — so one pure function (`storageAccessCopy`) turns the reported status into the copy, the card says why the app needs it (a local server that opens the folders by real path, which a per-folder document grant cannot cover), and the ask is not offered anywhere the permission does not exist
- **Do** let a setting that explains itself carry the explanation. A two-word segment cannot say that `Loop All` now offers the next video through a countdown you can refuse — so the mode's own sentence sits under the choice, where the user is looking when they make it

### Don't

- **Don't** use gradient text (`background-clip: text` with a gradient). The accent is a single solid color.
- **Don't** use glassmorphism (blurred backgrounds). This is a dark tonal system, not a frosted-glass one.
- **Don't** use side-stripe borders (`border-left` > 1px as a colored accent). Use full fills or nothing.
- **Don't** use numbered section markers (01/02/03) or tiny uppercase tracked eyebrows above sections — that's AI grammar, not this brand's voice.
- **Don't** lift cards at rest. Flat by default, elevated only on interaction.
- **Don't** use generic SaaS/enterprise colors (blue-primary, white backgrounds, clean corporate minimalism). This is not a dashboard.
- **Don't** embed credentials in URLs. Use the Authorization header pattern — it's a security guarantee, not a convenience choice.
- **Don't** display `"Encrypted!"` badges or security warning icons. The encryption is invisible by design.
- **Don't** use bounce or elastic easing in animations. Use ease-out exponential curves (quart/quint/expo). Respect `prefers-reduced-motion` with crossfade alternatives.
