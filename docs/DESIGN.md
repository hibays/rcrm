---
name: RCrm Media Library
description: Encrypted media library browser — The Midnight Gallery (Night) and its cream Daylight extension, one saturated accent
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
  day-pitch: "#F6F1E9"
  day-surface-ash: "#EDE7DC"
  day-card-char: "#E3DCCD"
  day-placeholder-coal: "#D6CEBE"
  day-shimmer-highlight: "#C4BBA8"
  day-text-ink: "#1A1613"
  day-text-silver: "#5C5348"
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

> **Two appearances, one world.** Night is the dark room described above. Day (added 2026-11-07) keeps the same five-step tonal layering, the same accent family and the same rarity rule, inverted onto the app icon's cream `#F6F1E9` — not a white/blue SaaS reskin. The default is **System**, so a new install follows the OS. Media overlays are the one deliberate exception; see §2A.

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

## 2A. Appearances & Accents

### Two appearances

| | Night (the original) | Day |
|---|---|---|
| Canvas (pitch) | `#0E0E0E` | `#F6F1E9` — the app icon's cream |
| Surface (ash) | `#1A1A1A` | `#EDE7DC` |
| Card (char) | `#222222` | `#E3DCCD` |
| Placeholder (coal) | `#2A2A2A` | `#D6CEBE` |
| Divider / highlight (dim) | `#3A3A3A` | `#C4BBA8` |
| Primary text | `#FFFFFF` | `#1A1613` |
| Secondary text | `#AAAAAA` (8.3:1) | `#5C5348` (6.7:1) |

Both ramps are the **same five tonal steps in the same order**; only the ramp inverts. Depth is still tone, never shadows. "Silver is silver, not ash" applies to Day too — a washed-out gray that merely passes AA is banned, and Day's secondary ink keeps ≥4.8:1 even on the lightest placeholder.

### Seven accents: five brand presets + Material You + Custom

| Preset | Night accent | Day accent (deepened) | Night nav variant |
|---|---|---|---|
| Marquee (default) | `#FF6B00` | `#9E3E00` | `#FF9900` |
| Safelight | `#FF4D4D` | `#B01F1F` | `#FF7070` |
| Projector | `#FFB800` | `#7A4F00` | `#FFC933` |
| Footlight | `#B57BFF` | `#5F30A8` | `#C99BFF` |
| Neon | `#00D9C0` | `#006A61` | `#33E8D6` |
| Device (Android 12+) | wallpaper `darkDynamic.primary` | wallpaper `lightDynamic.primary` | same as primary |
| Custom | picked colour, lifted to ≥4.5:1 on pitch **and** char | picked colour, deepened to ≥4.5:1 on cream **and** char | Night shade, 18% toward white |

Measured with `Color.computeLuminance()` (WCAG): the five Night accents run 5.9–11.1:1 on pitch; the Day accents 4.8–7.6:1 on cream and ≥4.7:1 on the card surface. A saturated accent that cannot be read on cream is **not** used as text there — Day deepens it, and `onPrimary` flips from near-black to white. **The rarity rule is unchanged**: ≤10% of any screen, in either appearance, whichever accent is active.

**Material You** (`dynamic_color`) is a sixth swatch named **Device**, built from the Android 12+ wallpaper primary rather than a constant. Its `onPrimary` is measured from the colour's luminance, not assumed, because a wallpaper hue has no known lightness. It is offered **only** when the platform supplies both dynamic schemes; on desktop, iOS and older Android the swatch is hidden entirely — a control that cannot act is not shown. The preset colours remain the reference even when Device is active.

**Custom** is a seventh swatch that opens a colour picker (`flutter_colorpicker`, HSV panel + hex field). A picked colour is never painted raw — doing so would let a pastel or an almost-black pick break the contrast contract above, so the shade is nudged toward white until it clears 4.5:1 on both the dark canvas and its card step, and toward black until it clears 4.5:1 on cream and its card step — the card is the extreme of each ramp, so the neutral steps between are covered too. `onPrimary` is measured from its luminance; the bottom-nav variant is the Night shade lightened 18%; the player keeps that bright Night variant. The dialog previews both derived shades before committing. The ARGB persists separately from the accent key — switching back to a preset does not forget the pick — and **confirming is the only commit**: cancelling or dismissing changes nothing. Because the picker is a third-party widget built against `package:flutter/material.dart`, the dialog shims a transparent Flutter `Material`, its localizations and a portrait-sized box around it; its label dropdown is disabled because the SmartDialog overlay has no Navigator ancestor.

### Where the choice lives

Settings → **Appearance**, above Display (it changes the whole app, so it outranks per-view options). One three-way segmented row (System / Day / Night) and one row of the five presets, the Device swatch where available, and the Custom picker swatch. Each swatch carries its **name**, and the active one also gets a check plus a border in the current accent — colour is never the only carrier of state. The change applies on the same frame: no restart, no confirmation, no second door to the same setting. The mode and accent persist as whitelisted strings (an unknown value falls back to System / Marquee); the Custom ARGB persists as its own integer, so a preset switch does not erase it.

**Narrow screens:** a segmented row fills the available width and drops the selected-state check icon, whose width used to squeeze "System" into a two-line wrap (or an ellipsis) at 320dp. Labels pin `maxLines: 1`. The selected **fill** is already the state signal, so the icon is redundant. Check icons stay on the accent swatches, where they do not compete with a word.

### The video player: a themed page with fixed dark chrome

**The page follows the appearance; the floating controls do not.** The scaffold/letterbox (`pitch`), the large file title, its meta row, and the Related heading and rows use the page's semantic ink. Everything that floats ON the picture — the two gradients above (fullscreen header) and below (transport bar) the frame, the speed/playback-mode menus, the playback-settings panel and the episode sheet — keeps the **original dark treatment in both appearances**. Those edges are not a page surface; a cream bar over a video frame reads as a UI frame, and that is not what this player is.

They read the fixed `player*` tokens: `playerScrim` `0x80000000`, `playerScrimStrong` `0xB3000000`, `playerSurface` = `darkAsh`, `playerText` / `playerTextSecondary` / `playerTextFaint` = white / silver / dim silver, `playerTrack` = 20% white, `playerHairline` = 8% white. **No cream bars, and nothing added to the gradients' length or width** — the scrims are the same two stops they always were. `playerAccent` still carries the chosen theme colour, but always its bright Night variant, so a deepened Day accent never lands on black.

**One gradient rule.** The end stop must be the SAME colour at zero alpha (`playerScrim.withValues(alpha: 0)`), never `Colors.transparent`: that is black-transparent and would interpolate through a dark band halfway up the bar. No mid stop, no held plateau — the control row simply sits on the dark gradient it always sat on.

**Every word on the player page is page chrome.** `video_player_screen.dart` owns the large file title, its meta row, and the Related heading and rows — all of them sit on the page canvas, not on the picture. They use `textPrimary` / `textSecondary` / `hairline` like any other screen. A white title on cream is the single most obvious way to break Day; the player's own widget files are not the only place to check.

**The photo viewer and the QR page keep white.** The image viewer's top bar floats on a black scrim over a photo, which is always the subject; the QR pairing page is a fixed deep-blue brand world. White icons and text are correct there in both appearances, so those two read `RCrmColors.mediaText` / `mediaTextSecondary`. (There is no `mediaSurface`/`mediaAccent`/`mediaTrack` any more — the player no longer needs them.)

**An ink layer needs media behind it.** A video card with no poster is a bare placeholder, not media: its bottom info strip and duration chip switch to the page's semantic colours (a light tonal wash with ink text in Day) instead of painting a black band over cream. `VideoPoster` reports whether a real poster is being shown; only then does the card draw the dark media overlay.

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
- **List rows:** the thumbnail is the same 16:9 poster at the row's own height (100dp in `VideoListTile`, 90dp in the player's Related list), and it never stretches with the window — a wide window keeps the 16:9 box and gives the extra width to the text. On a narrow phone it may shrink to 42% of the row so the title and metadata keep a column, but it never grows past the poster's own ratio: a 6:1 band is a cropped poster, not a thumbnail.
- **A GlobalKey belongs to a SURFACE, not to a file.** The mobile sticky preview needs a key per card, and two surfaces can show the same file at the same time — the player's Related list beside the picture and the end card floating over it, or the episode sheet opened on top of that card. Handing both the same key makes the framework move the first card's element into the second card's slot, and **the surface that lost it renders BLANK** (not an error: the tree is silently truncated). `FingerPreviewState.surface(name)` is the only way to ask for one; two surfaces on screen together must be two names. Every caller goes through it — list, grid, sheet, end card, both home rows.

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

### App Icon

- **The mark on cream, not on pitch.** The icon is the red shield on `#F6F1E9`, not the UI's near-black: an icon lives on a dock or a home screen, where the library's darkness would disappear, and cream is the one background that keeps the shield's silhouette readable at 16px. The artwork sits at 94% of the square, so the shield lands at ~62% of its width and ~76% of its height (62% of the Android adaptive canvas, inside its 72dp safe circle); the tile's 22.5% corner radius is the macOS grid's own. It is nudged 2% down, because the shield's alpha centroid is 3.8% above its bounding-box centre — bbox-centring it reads as floating high. A smaller mark reads as a stamp in the middle of a blank card, which is exactly what the first pass looked like.
- **Generated, never hand-edited.** `brands/build_icons.py` turns `brands/design/logo.svg` into every platform size; the rules above and the banner are documented in `brands/README.md`. Do not touch the platform PNGs directly — the next run overwrites them.

### Controls Overlay (Video Player)

- **Gradient:** Vertical `0x80000000` to `0x00000000` — from opaque black at bottom to transparent
- **Auto-hide:** After 2s idle on desktop (reappears on mouse move or tap). Never while a panel is open — settings, episodes, or the speed menu; that panel's own button is the way out
- **Controls bar:** Transparent background (the gradient IS the background)
- **Fullscreen top bar:** Back (left), title, playback-settings gear (right) — present on every platform, fades with the controls, and respects notch/camera-cutout insets. Back retraces one step (the jump history first, then the route behind the player); Home sits beside it and leaves the whole player chain for the library, but only while there IS a history — with an empty stack Back already leaves the player, and two buttons for one action is one too many. The gear belongs at the top right, never in the transport bar
- **Width budget:** The transport bar admits optional controls by priority (time → Next → the playback-mode chip → skip Back → rate → episodes) and gives the volume slider whatever width is left; below ~64dp of travel the slider hides, and if the bar still does not fit, whole controls are dropped in a fixed order — fullscreen first (below ~108dp), then mute (below ~74dp), then the rate chip (the play/pause button and elapsed time are never dropped). The admission is a LADDER, not a greedy fill: once a control does not fit, nothing below it is admitted either. A greedy fill would let a cheaper control into a slot the one above it could not use — the rate chip's label is measured, so at 1.25x it is wider than the mode chip, and the bar would swap the two chips as a window was dragged a single dp narrower. The mode chip ranks above the skip Back on doors, not on frequency: Back has the platform's own gesture behind it on mobile and `Esc` on desktop (both retrace the jump history through `_handleBack`), while the mode's only door is this chip — its row left the settings panel when the chip arrived. The chip spends 32dp of width for a 24dp face (or its face, where that is wider): the box is the tap target, the pill is what the eye reads, and the two are deliberately different numbers — see the mode paragraph below. Controls are never squeezed or shrunk to fit, and width is budgeted only for what will really be painted: a skip button with nowhere to skip to is not planned at all. The app does not bind F11: fullscreen is the `F` shortcut and the title-bar button
- **Skip pair:** Previous and Next switch video inside the player that is already playing — nothing on screen moves, and fullscreen, picture-in-picture, the speed and the volume stay the ones you set. Previous walks the jump history back one step; Back (the top bar, the system gesture) reaches the same video as a route step, with the platform's back-direction animation — which is the difference between leaving a video and skipping to another one. A step is two pages, and both play the platform's back: the video arriving enters the way a pop reveals a page, and the one being left exits the way a pop sends the page it pops away — off the opposite edge, on the platform's own curve, whether the history behind it is empty (a real pop) or not (a replacement). With only the arriving half fixed, both pages travelled the same way at once and a step back read as another forward jump. **The length of a step is the platform's** — 450ms on Android, 300ms on the desktop zoom. A 300/240 override was tried and reverted: it was aimed at the exit "dragging", but the exit that felt wrong was playing the wrong animation (see below), and the override shortened the transitions that had never been a problem. **One exit, whichever way you leave it:** Back with an empty history, Back off the last history entry — a video that was itself reached as a return step — and Home (the top-left control) all pop the player, so all three play that same pop. A page's exit is decided by what it is DOING, never by how it was reached or by which control asked: the returning parameterization is asked only while the page is arriving, and Home no longer stops the player first (a stopped player paints no frame, so that exit played as the same step with the picture missing). Home also leaves in that one step when the video was opened from the search results: the search screen is taken out of the chain without animating it, instead of two pages sliding away at once. And the app itself is already the library's wh... (line truncated to 2000 chars)
- **Density:** Chosen from the window's shortest side — compact < 400dp, regular < 600dp, expanded above. Fullscreen alone never inflates the controls. When the bar itself is narrower than the compact tier can afford (140dp), the targets step down once more rather than overflow: no minimum window size is set, so a desktop window can really be dragged that narrow
- **Time readout:** elapsed and the total, in one line, in tabular figures so a running clock cannot shuffle the row it shares with the skip buttons and the volume slider. Tapping it swaps the second number for the time LEFT (`-40:42`) — the question a 90-minute film actually raises — and the choice is remembered (`player_time_mode`). Both readings are budgeted whether or not one is on screen, so the tap can never make the duration disappear at a narrow width; it is plain text, with no tooltip and no tap target, when there is no swap to offer
- **Transport bar:** play/pause is the largest mark in the bar and the only control with no alternative path; the mute button says how loud it is in three states (`volume_off` / `volume_down` under 50 / `volume_up`), because "volume > 0" drew a full speaker at 5% and at 95% alike. Neither is ever a dead control
- **Volume, named:** the bar's volume control moves whichever volume is really the volume where it is running — on mobile the DEVICE's media stream (what the hardware keys and every other media app move), on desktop the player's own gain. One setting decides it (Settings → Display → System Volume: ON by default on mobile, not offered on desktop at all), and a bound bar opens on the phone's current level rather than on what this app last played at. It also shows the level the device LANDED on, not the one the finger asked for: `setStreamVolume` quantises, and 43% is not a level a 15-step stream has. A change made with the hardware keys moves the bar too, because a bar that disagrees with the phone is the whole problem the binding exists to remove. The row says which of the three things is true — bound, unreadable, or a fixed output — because two of them are cases where the switch cannot keep its promise and the player keeps its own volume instead
- **Speed popup:** Ash surface (`#1A1A1A`), no Material tint, 8dp radius, a check against the active rate. The rate chip and the mode chip are the two controls in the bar that report a state rather than offering an action, and both hold the accent while their state is not the ordinary one — 1.25x should be answerable from across the room, 1x should not shout; `pauseAfter` (the app's own default) is the mode's quiet state, and any chosen mode lights its chip
- **Playback mode, on the bar:** what happens when a file ends — Loop All / Shuffle / Loop One / Pause After — is the transport bar's own chip (`utils/player_playback_mode.dart`), not a row in the settings panel any more. A mode is changed while watching, and a control reached by leaving the picture to open a panel is reached at the wrong moment; one setting keeps one door. The chip reports the mode in force (a glyph per mode: `repeat`, `shuffle`, `repeat_one`, and a stopped circle for the default) and opens the same Ash menu as the rate chip. **The pill is not the target**: the face is `chipIcon + 4 gaps` (24×20 compact, 41×21 expanded) inside a box the bar's own height by at least 80% of its width (32×40 compact, 32.5×40 regular, 41×44 expanded). Left as its own child it measured 23×21 — `PopupMenuButton` adds no padding around the child, so the pill WAS the tap target, a third of every other control in that row. 80% and not 100% is the width ladder's price: at the full 40 the chip costs the RATE chip on a 375dp phone (the bar measures 378.6 there) and the rate chip has no other door, while 32×40 is still 2.6× the old face's area (23×21). The tooltip names the state rather than the control — "When the video ends: Loop One" — because a glyph cannot say the sentence a screen reader has to hear. Its rows carry a label and ONE line of note — `Next video in Related, 8s` against `Random video in Related, 8s` — because the pair that is one word apart still has to say which word, and because a menu is scanned: a row is 48dp and the menu 192dp at 1.0x text, 252dp at 1.6x. It spent a round at 78dp rows and four two-line paragraphs (350dp, 480 at 1.6x), which is a settings page over the video, not a menu. Shuffle differs from Loop All in exactly one word, and the sentences say which: Loop All offers the next video in Related, Shuffle offers a random row of that same list — the viewer's list, same directory first, the jump history already excluded — so the surprise stays insi... (line truncated to 2000 chars)
- **Holding the picture runs it at 2x — on the floating window too:** long press is the speed-up gesture (video.js's own), and it belongs to every surface the picture can be on, because a viewer who holds to skim is not going to reopen a panel to do it a second time. The rate the hold started from is put back when the finger lifts, and the gesture cannot strand the file at 2x: once a long press is accepted, Flutter always pairs its end, and moving in between reports a move-update instead of cancelling — so a hold that drifts is still a hold, and (the arena being spent) not also a drag of the window. A drag that starts *before* the hold is the other way round: it moves the window and never touches the rate. The pair only ever comes from the surface that took the hold, though, so **whoever takes that surface down mid-hold ends the hold itself** — scrolling past the video puts the window where the picture was, scrolling back takes the window away, and either swap leaves a finger holding a surface that is gone; a hold that outlived its own recogniser would leave the file running at 2x with the chip still lit and no way to undo it
- **The floating window is a player, not a badge.** It drags to move and scrubs horizontally where there is a track to scrub along — the small window gives up the scrub, not the hold — and it carries the 2x chip itself, because with it up there is no picture on the page to carry one. It deliberately carries **no way back to the library**: ✕ only closes the window and ⛶ returns to the picture, so a viewer who has scrolled past the video dismisses the window and scrolls up. A third button in a 200px window, for a place the viewer left on purpose, is a button that competes with the two that act
- **Buffering:** a spinner over the picture (dark disc, orange arc) once a stall has lasted 300ms — media_kit reports `buffering` for the frames a seek spends refilling, and an animation that means "wait" must not fire at something that was never a wait. It disappears the moment the picture moves again. 300ms is the grace video.js gives its own loading spinner. It never fires on a **finished** video: nothing is loading on the last frame, so an animation that means "working on it" would be about nothing
- **Up next, on the end card:** when a video ends in `Loop All` or `Shuffle`, the next one is the FIRST tile of the end card (see **End card** below), not a second floating card: that tile is dimmed, a ring drains over 8s, and a `Cancel` chip stops the autoplay while leaving the card up. The whole tile is the yes — clicking it plays that video now, and there is no separate "Play next" button. That promise has a footgun in the widget tree: the dim and the ring over the poster are DECORATION, and a bare translucent `ColoredBox` is hit-test OPAQUE — left bare it swallows every tap in the tile, the tap falls out of the card to the picture underneath, and on a finished file that handler REPLAYS the video the viewer is sitting on. So the dim and the ring sit in an `IgnorePointer`, and only the `Cancel` chip keeps its own handler. In Shuffle the card's quiet line says `Random pick` first, because the viewer was not looking at a list and nothing else on screen would account for the video. The countdown lives on the ring's own controller, so the time shown and the time until it plays cannot disagree. An open panel covers it without cancelling the autoplay it stands for. **Taking the video back withdraws it**: dragging the bar off the end cancels the offer exactly as the ✕ does, because the viewer has said they are staying — and so does pressing play, which restarts *this* one from the beginning rather than moving on. The countdown is also decided **once** per ending — a repeated end-of-file signal (mpv reports it again after every take-back) never re-arms it, which is what stops a second pass from seeking a video the viewer had just dragged back
- **End card:** when a file ends and NOTHING is counting down, the last frame is no longer the whole answer. `Pause After` (the default), a `Loop All`/`Shuffle` ending whose Related list is empty, and an ending the viewer refused all used to leave a static frame with fading chrome: no replay, no next video, and no way back without knowing where the controls went. The card names the file that ended and offers `Replay` (this file, from zero), `All N` (the existing episode sheet — one list, one door) and a Related grid of at most two rows; when `Loop All`/`Shuffle` has an offer, its first tile is the autoplay, ringed and cancellable. The grid's COLUMN count follows the card's width and its ROW count follows the card's real height, not the screen's: a second row that has to be scrolled to is a row nobody knows is there. Tiles are the shared `VideoCard` — desktop hover preview, mobile finger preview, and the duration chip compact cards normally drop — read with `mediaSurface: true`, so the card surface, the placeholder and the chip use the FIXED dark tokens and never the page's semantic colours: this surface floats on the picture, and a cream tile in a dark card is a light patch on a video. The countdown tile suppresses hover preview: it is already about to play, and a second moving picture under the ring is noise. **Its label counts down** (`Auto-plays in 5s`), driven by the same controller that drains the ring — a label that said `8s` for the whole eight seconds was a lie from its second second. `All N` is absent in the windowed player — the whole Related list is already beside the picture and the episode sheet is not mounted there, so the button would be a dead control. The ✕ and a backdrop tap are the same refusal, and either one also stops a running countdown: the ✕ has always promised a quiet last frame. The card rises 8px over 200ms, leaves over 140ms, and `disableAnimations` turns both into a state change. It is deliberately NOT a blurred streaming-site end scree... (line truncated to 2000 chars)
- **The two vertical swipes are one gesture at two scales:** the left half of the picture drives the brightness (0..1) and the right half the volume (0..100), and both are the SAME shape — one value the finger owns for the length of the swipe, pushed out to whoever applies it, never read back from there (`utils/swipe_value.dart`). The full range takes **0.6 of the gesture area's height** on either scale (`kVerticalSwipeSpanRatio`), the ends clamp rather than wrap, and a 1px wobble moves the value 1px worth. Both numbers were tuned against the finger: a whole height of travel was the original rule and it read as too slow once the swipe started tracking the finger honestly (on a portrait phone in fullscreen that is ~890px of travel for 0..100, about nine pixels per percent), while going much shorter would aim the value in sub-pixel steps — and it is ONE rate for both halves on purpose, because a viewer who learns one has learned the other. That last part is the whole point: the volume half used to re-read the bar every frame, and while the volume is bound to the device the bar holds the STEP the phone landed on — so on a 15-step phone (6.7% per step, ~40px of a 600px screen) a slow swipe moved nothing at all and a wobble across a step boundary walked the volume backwards. A gesture that fights the finger is a gesture nobody trusts. The device's answer is taken the moment the finger lifts, which is when the bar goes back to showing the truth (and which is why it may outrun the device while the swipe lasts)
- **Fullscreen orientation is a strategy, not a switch:** the player's settings panel offers four policies on mobile — **Fit** (the default: a wide video locks landscape, a tall one portrait, so the picture uses the screen), **System** (rotate only as the OS allows, rotation lock included), **Follow** (the phone's real posture, even against the system lock), and **Lock** (with a Portrait/Landscape direction under it). The old "Auto-Rotate" switch is why this is a strategy: it said "ignore system rotation lock; follow device orientation" and made the only call the framework has for it — every orientation — which Android decodes to `FULL_USER`, documented as *"Respect the user's sensor-based rotation preference"*. The one thing it existed for was the one thing it could not do, and on a locked phone it did nothing at all. **Follow** is offered on both mobile platforms because both can really do it, each with its own API — Android's `FULL_SENSOR` (`"Ignores user's setting to turn off sensor-based rotation"`) and, on iOS, the hardware posture (`UIDevice.orientation`, which the rotation lock does not affect) plus an explicit geometry request — so nothing here promises an override a platform refuses, and nothing hides a policy it can honour. The words are the same on both; a platform caveat belongs on the rows where a platform really cannot act (the screenshot policy, the volume binding). Nothing is forced outside fullscreen — leaving the player hands the app back to its own direction — and the strategy re-applies the moment the video's real shape arrives, which is the other half of what was broken: the old code decided once, from a size the player often had not reported yet, and a portrait video then stayed locked landscape for the whole session. **And a video change costs one rotation, not two:** switching video is a moment with no size at all (the next file is loading, no track open yet), and treating that silence as news used to send the screen off the axis the video h... (line truncated to 2000 chars)
- **Settings panel:** two parts — the fullscreen orientation (mobile only) and what the player can honestly say about the file it is playing (resolution with its class name, pixel format, hardware decode, rotation, audio, bitrate, size — a fact the player has nothing to say about is left out rather than printed as "unknown"), and the keyboard map. Rotation is offered on mobile only and the key map on desktop only: a control that cannot act is not shown at all. The playback mode used to be the first row here and is the transport bar's chip now (see above); a panel row and a bar chip for one setting would be one setting with two doors. The gear that opens it sits in the top-right in fullscreen and at the end of the video's own back/home row in the windowed player — the same chrome at two sizes
- **Everything that appears in the player arrives, and each arrives as itself:** the settings panel scales up from 0.98 over 160ms (a place the viewer went on purpose, so it settles), the up-next card rises 8px over 200ms (a moment that passes), the cast end-card slides 20px over 220ms, the episode sheet slides in **from the edge it is anchored to** — the right in landscape, the bottom in portrait — over 130ms, because it is a sheet and a sheet comes from its edge. It had no entrance at all, which made it the loudest thing in the player: half the screen plus a scrim, snapping into place while everything else in the same panel glided. 130ms rather than the card's 200ms: half the screen is a long way to travel, and at 200ms it read as the sheet hesitating rather than arriving. It also **leaves the way it came** — the scrim fades *in place* (a full-bleed dimming layer that travelled left an uncovered strip along the edge it moved away from) while the sheet fades and slides back out — which needs the screen to hold it mounted for the exit: an unmounted widget cannot be seen leaving. `prefers-reduced-motion` gets the state change instead of the motion, the same as the other two

### Image Viewer

- **The transform is the photo, never the letterbox:** the picture is laid out at fit-contain size and only the picture is scaled. Panning is clamped so a zoomed photo always covers the viewport and a smaller one is locked to the centre — no drag, at any scale, can reveal empty space
- **Zoom:** pinch and wheel zoom about the focal point, double-tap zooms to the tapped point (2.5×) or resets, 1:1 caps at 6× fit. Max zoom is 6× fit
- **Chrome floats over the photo:** round translucent buttons (40dp, `Colors.black` 32% at rest) over a top scrim, plus the file name and its position as the only text — no toolbar, no bar background, no divider
- **Filmstrip:** bottom scrim `0xCC000000` → transparent behind the thumbnail strip; the selected tile keeps the Marquee Orange border
- **Pull-to-dismiss:** vertical travel 1:1 with sideways damping (0.35) and upward resistance; closing takes 12% of the viewport height (clamped 72–132px) **or** a downward flick over 700 px/s. The photo shrinks to 0.6 and the backdrop opens to ~8% as it goes. It only engages at fit (1×): while the picture is zoomed the drag pans it instead — the way out of a zoom is zooming out, never yanking the photo off the screen. **One gesture, one axis:** the finger's first 8px commit it — a sideways lead (over 1.5× the vertical travel) means the pager owns the gesture and the pull contributes nothing at all from then on, however far down the finger later sinks, while a downward lead stays a pull, however far it then drifts sideways
- **Info sheet:** ash sheet, 14px top radius, hairline top border, light scrim (`black` 35%) so the photo stays the subject. Anatomy: drag handle → large date (EXIF capture time when known, else the file timestamp, shown in local time) with the `1:1` chip → file name → location line, or a dimmed "No location information" → camera block (camera · lens · exposure · dimensions) or the honest "No camera information" → labelled rows (folder, position, animated). Marquee Orange appears only on the `1:1` chip
- **Say only what was established:** an absence ("No camera information", "No location information") is stated only after a successful parse of identified bytes; a failed parse, an unreachable file or a pending read stays silent instead of asserting a fact nobody checked. The animated row reports the same verdict the badge uses (extension test plus a container-header probe), so a genuinely animated WebP/AVIF never shows the badge without the row

### Info Dialogs

- **Style:** Standard Material `AlertDialog`, following the current appearance
- **Background:** Ash surface in Night, cream ash in Day (from `dialogTheme`)
- **OK button:** Standard text button

### Overlays (flutter_smart_dialog)

Every transient surface — dialogs, notifications, anchored menus, the viewer's info sheet — is rendered by `flutter_smart_dialog`, not by `showDialog` / `ScaffoldMessenger` / `PopupMenuButton` / `showModalBottomSheet`. The widget look is unchanged; only the overlay and its lifecycle moved, so all of them share one queue, one mask and one back-button policy.

- **Dialogs:** `SmartDialog.show` wrapping the same Material `AlertDialog` / `SimpleDialogOption` content; dismissal is `SmartDialog.dismiss(result:)`, never `Navigator.pop`. A dialog that must not close on an outside tap sets `clickMaskDismiss: false` (the old `barrierDismissible: false`). Route-level back navigation stays `Navigator.pop`.
- **Menus:** `SmartPopupMenu`, anchored with `showAttach` to the trigger's own context. Downward menus use `Alignment.bottomLeft`; the player's menus open upward with `Alignment.topLeft` (`openUpward: true`), so they clear the transport bar instead of covering the chip that opened them. The global `attachAlignmentType` is `inside`, which aligns the menu's left edge to the trigger's — the native `PopupMenuButton` reading. A menu with NO trigger widget — an item's long-press or right-click — opens through `showSmartMenu`, anchored to the POINT pressed with `targetContext: null` + `targetBuilder`. Passing the card's context as well offsets the panel by that card's own height (measured), because `AttachWidget` adds the target's size to the point it is given. **A row delivers its choice on the CLICK, not through the dismissed future.** `showAttach`'s future only resolves after the exit animation — the panel is still on screen for ~200ms — so awaiting it made every filter land a beat after the menu had collapsed, which reads as "the menu has to be gone before the filter applies". The row calls its owner itself and `dismiss(result:)` runs in the same frame; the future's value is only a fallback for a path with no row tap. Because the panel stays hit-testable through that animation (`visible` is never cleared before the widget is swapped out), the delivery is LATCHED: a second tap on the same row is ignored. That is not cosmetic — re-picking the ACTIVE sort field flips the direction (`_SortNotifier.set`), so an unlatched double delivery would flip and flip back and persist both writes.
- **Menu geometry is the native menu's, not the anchor's:** an anchored surface hands its child the whole screen, so the panel is `IntrinsicWidth` (56dp steps) inside the native `112–280dp` bounds, with 8dp of menu padding and 48dp rows — the same numbers `PopupMenuButton` uses. Without that, a menu whose caller passes no width (the player's rate menu, the cast remote's More menu, the toolbar menus) opens as a full-window slab.
- **Menu mask:** transparent, `clickMaskDismiss: true`. A menu does not dim the page the way a dialog does, but an outside tap is still what closes it.
- **A dialog's content cannot use a `Navigator`:** `SmartDialog` renders above the app's `Navigator`, so content with no Navigator ancestor cannot push a route — a `DropdownButton` in a SmartDialog dialog did nothing when tapped (measured: "Navigator operation requested with a context that does not include a Navigator"). Controls that open a popup must use `SmartPopupMenu` (same overlay, no Navigator needed), as the thumbnail-cache dialog's trim target does.
- **Menu selection:** each row is a `SmartPopupMenuItem` (a widget, so tests can find it by type) that calls `SmartDialog.dismiss(result: value)`; `SmartPopupMenu.onSelected` fires only for a real selection, while `onClosed` covers both selection and cancel (the old `onCanceled`). **The choice is delivered on the click, not as the dialog's result**: `showAttach`'s future resolves only after the panel's exit animation, so awaiting it made every filter, sort and grouping change land ~200–300 ms after the click — long enough to read as "nothing happened until the menu closed". The row starts the dismissal and hands its value to the owner through a `_MenuPickScope`, in the same frame; the awaited result is a fallback for a value that arrives without a row tap (guarded so a choice is never delivered twice). This is what `PopupMenuButton` itself does — the action runs while the route animates out.
- **Notifications:** `SmartDialog.showNotify`, with severity carrying meaning — `error` for an action that failed, `warning` for a state the user should notice, `success` for a completed clean-up. The "press back again to exit" hint is `warning` at 1500 ms.
- **Bottom sheets:** the viewer's info sheet is a bottom-anchored `SmartDialog.show` (`bottomCenter`, full width, black 35% scrim) rather than `showModalBottomSheet`.

### Item Context Menu

- **Two gestures, one menu:** a long press on a touch screen and a right-click on a desktop both open the same menu for the item under the pointer. It is anchored at the POINT pressed (the shared menu panel) and opens downward, flipping upward only when the space below cannot hold it (`utils/menu_placement.dart`). A touch long press is confirmed with a haptic; a mouse gesture is not.
- **The rows say what this library can do.** It is a read-only decrypted view: there is no Rename, Delete, Move or Share, so no row pretends otherwise. Video: Play, Details, Show in folder, Copy name, Copy path. Image: Open, Details, Copy name, Copy path. Search results and the Home rows carry the same menu minus **Show in folder** — the folder view belongs to the Video tab, and revealing one from another screen would be a journey, not an action on the card.
- **Details is the facts panel, not a second design:** images open the viewer's `ImageInfoSheet`; videos open `VideoInfoSheet`, which never states an absence (container metadata is a bonus) and only adds rows the parser or the item really has.
- **Copying:** the clipboard write is the action; on desktop a success notification acknowledges it, while Android 13+ draws the system's own confirmation and the app adds nothing.
- **No reveal on photo items.** The video tab's folders are derived from the scanned list, so revealing one costs no re-scan; the photo tab's albums are built inside the scanned library, so the same row would silently start a whole-library scan. A row that changes the state of the whole library is not an action on one item.

### Library Grid Gestures

- **Two fingers resize the thumbnails**, on the photo grid and the video grid — the gesture every gallery app has, and the one a phone needs because the column button is a 32dp target at the top of the screen. The pinch maps from the count the gesture STARTED on (a live count fed back in would compound and run the grid to the end of its range under a still finger); spreading the fingers means fewer, bigger cells.
- **The gesture is read with raw pointers, not a scale recognizer.** A `ScaleGestureRecognizer` loses the gesture arena to the grid's own vertical drag, so the pinch is a `Listener` (`widgets/two_finger_pinch.dart`) and the scrollable is handed `NeverScrollableScrollPhysics` for the duration: a grid must not scroll under the fingers that are sizing it. Letting either finger go ends the gesture; a resting third finger is not part of it; a trackpad pan/zoom whose scale never moves is a scroll and passes through.
- **The video list has two answers, not a slider:** one row per line, or two. A list pinch commits at 20% of span change (`kPinchListStep`), so a two-finger scroll or a wobble cannot flip the layout.

### Video List Width

- **`video_list_columns` = auto | one | two**, default auto. Auto is two columns from 840dp (Material's "expanded" window class): below it a row's title and metadata need the full width; above it a single row is a long line of text with a thumbnail at one end.
- A two-column list keeps the row's OWN height (`mainAxisExtent: 100`) rather than an aspect ratio — a list row does not grow with the window, and an aspect-ratio delegate would turn the 16:9 thumbnail into a band.
- **Two columns need a window, not just a preference:** an explicit Two is honoured from 600dp (Material's "medium" class). Below that the list stays one column whatever the setting says — half a phone leaves the text column under 100dp inside a fixed 100dp row, and the row overflows. A pinch that cannot change the visible count stores nothing, so a gesture on a phone-width list is a no-op rather than a preference with no answer. The grid is where a phone changes columns.
- Settings → Display carries the same three choices, because a pinch can set `one`/`two` but cannot clear them back to `auto`.

### Automatic Keywords & Channels

- **The tags come from the names, not from a service.** `utils/keywords.dart` splits file and folder names, drops release/technical noise (`1080p`, `x264`, `WEB-DL`, `中文字幕`) and keeps the content words. Chinese/Japanese/Korean runs stay whole while short, and fall back to non-overlapping two-character chunks when long; Latin words are lowercased only for comparison, and the first spelling is what the user reads. **A file carries a SET of tags, not one primary tag**: every meaningful word survives as its own tag (up to eight, strongest first), and membership — not equality — is what filters, channels and search use, so one file appears under every tag it carries. A tag becomes a FILTER or a CHANNEL only when at least two files carry it — one file's keyword is a description, not a way to browse.
- **The video tab's keyword row is an OPT-IN multi-select filter, not a second toolbar.** `KeywordFilterBar` sits UNDER `MediaToolbar` but is off by default, so it does not spend 56dp of permanent space: a **Tags** chip on the toolbar's left, beside the sort and format chips, turns it on and the choice persists. When the toolbar itself falls below 600dp but stays at or above 520dp, the chip drops its label entirely (including its padding) and the toolbar's side padding narrows — `LayoutBuilder` measures the bar it was given (as it does for the player transport bar), so a wide window that hands this toolbar a narrow column gets the same compact chip — three labeled chips plus the view icons overflow a phone-width row. Below 520dp, where the chip would otherwise be the bare `#`, it moves into the overflow instead. Below 520dp the row can no longer hold every control (the long "Duration ↑" sort label alone measures ~195dp, and the full row ~508dp), so ALL right-side controls fold into ONE overflow button on the right: sort direction, Organize, the grid/list switch, the column button and the tag toggle. That button takes the ~40dp the compact bare `#` used to occupy — a SWAP, not an addition — so the row never grows, nothing loses its function, and the bar keeps a control at the right edge instead of a lone `#` and an empty gap. Below 380dp the extension-filter chip folds in too, so even the longest sort label fits a 320dp row. The overflow is the same menu geometry as every other popup (`SmartPopupMenu`, right-anchored), rows carry a check for state and the same icons as their inline counterparts, and a control the caller cannot supply (or whose range holds one value) is simply absent — it never offers a dead action. Each overflow row writes through the same callback as the inline control it replaces; the Settings rows and a grid pinch remain the other doors. **ON, the `#` fades to grey and `TagToggleCheck` lays the accent check over it; `FilterChip`'s built-in check stays off because it paints a near-black scrim that hid Day's accent.** **The tag-filter chips' orange fill + white check is a different selected language by rule: a permanent view option never spends a whole chip of accent, a content filter may.** At compact width the name lives in semantics. **The column button also leaves whenever its RANGE holds one value**, whatever the width ladder says: the caller hands it the range this window can display (160dp per cell), and a 350–479dp desktop shows exactly two columns whatever is stored — a cycle button showing the only number available cannot change a pixel, and its tap would still write that number back over the user's stored 5. `ColumnButton` refuses to emit such a write, and `MediaToolbar` does not build it; Settings → Video Grid Columns is the door that survives. The width → controls mapping is a pure function in `utils/media_toolbar_layout.dart` with boundary tests (599/600, 519/520, 379/380); the widget feeds it the width `LayoutBuilder` gave it, divided by the user's text scale so the same boundaries hold at a larger system font. The sort chip is the one always-inline control whose label grows with that font; at iOS accessibility sizes (up to ~3.1x) it would push the overflow button off a small screen, so its label is capped to the room left after the button and ellipsized — at normal sizes the cap sits far above the natural width and changes nothing. The chip is the SAME component family as its sort/format neighbours: It wears the same theme chip shape, surface and `labelLarge` type, but pins that surface explicitly (`color`) instead of inheriting it — see the fill paragraph below — so the three read as one row in BOTH states: the tag glyph is a SIBLING before it is a state — OFF it inherits the chip's own icon colour, the same `colorScheme.primary` its two neighbours' avatars wear, so the third chip does not read as a permanently dimmed control. The accent therefore never leaves that 16dp slot, and there is only ever one coloured thing inside it: the glyph reads as its siblings, the check reads as state, and a permanent view option never spends a whole chip's worth of accent. The chip's outline is pinned explicitly because `FilterChip`'s default `side` goes transparent when selected, which would drop the pill border its two `Chip` siblings keep. `FilterChip`'s default `color` is an M3 `WidgetStateProperty` that resolves to `secondaryContainer` (cyan) when selected and outranks `selectedColor` — both ends are pinned to the SAME neutral the siblings wear, so no toggle flashes cyan mid-fade and the chip face is identical in both states. Its default selected `labelStyle` is also M3 `onSecondaryContainer`, a DARK ink unreadable on this chip's neutral surface; OFF inherits the siblings' muted label and ON switches to the page's primary ink (AA-checked against the unchanged neutral face). A filter in force (from a Home channel or a tag search) shows the row even when the toggle is off, because then it is the only way to clear it; an explicit toggle likewise shows it even in folder view or before any tag repeats — a checked chip with nothing to hide is a dead switch. A small `Icons.tag` marker leads `All tags` and the strongest repeated tags as chips in a horizontal row. A selected chip fills with Marquee Orange and gains a check; unselected chips are Char on the surface — and every one of these chips pins that fill for ALL ink states (`color`), never just through `selectedColor`: `FilterChip`'s default `color` is an M3 `WidgetStateProperty` that resolves to `secondaryContainer` (teal in this palette) and outranks `selectedColor` while the selection and enable animations overlap, which is a visible teal frame between the click and the orange. That fill is not copied into each call site: `widgets/filter_tag_chip.dart` is the ONE widget for this species (Char at rest, Marquee Orange with a check when selected, theme radius, no border), and both tag surfaces — this bar and search's selected-tag chip — are that widget, so a new surface cannot forget one of the six properties by hand-rolling a seventh copy. `test/chip_fill_policy_test.dart` scans `lib/` for a `FilterChip`/`ChoiceChip`/`InputChip` whose own argument list does not pin `color` and fails, so a fourth hand-built chip cannot land. The theme cannot own this: the toolbar's sort/format `Chip`s and its Tags chip must stay on the NEUTRAL surface while a tag filter must turn orange, so a `chipTheme` would have to repaint one of the two species to serve the other. Selection is multi: every chip adds a constraint, so the list shows the files carrying **all** selected tags — adding a tag narrows, it never unions. `All tags` clears the set. Folders with no matching video disappear while tags are selected; the folder header AND the card that opens it both count what the filter leaves — a card saying "12 videos" over a folder that opens with four is the filter's lie, so the card's 2×2 preview is drawn from the same survivors rather than from posters of excluded files.
- **A filtered empty list says which emptiness it is.** One tag: `No videos tagged "X"`. Several: `No videos with all N selected tags`. When the toolbar's FORMAT chip is narrowing too, its name goes in front (`No MP4 videos tagged "X"`) — the tag is not the only reason and saying so would be a half-truth — and the one `Clear filter` button clears both filters, because an empty state whose only action cannot produce a row is a dead end. Never the library's "No videos found / Add folders" copy, which would be a lie about a full library.
- **Home's channels are the library's own sections.** Up to three repeated tags get a row named after the tag (with the `Icons.tag` marker), and `View all` opens that tag's result page — the same page the player's chips and search open. The Recommended row uses the same tags, weighted by Settings → Display's **Keyword Relevance**: 0 keeps the old daily shuffle (folder order only), 100 lets a strong shared tag outrank a folder neighbour. The default 60 leans on tags without throwing folder adjacency away.
- **The player's tags sit under its title, and each is a door.** The windowed player page puts a wrap of `KeywordChip`s between the file title and the duration/size row: one `#tag` ActionChip per tag (up to eight, wrapped so the whole set is visible), quiet Char on Pitch, no accent. Tapping one pauses playback and opens `/tag-search` with that tag already selected; back returns to the player where it stopped. Fullscreen has no tag row — it is chrome over the picture, not a page. A file's several tags are several independent chips, and every one opens its own result set.
- **Search is where tags become a multi-select query.** `SearchScreen.initialTag` opens with `#tag` in the field. Every `#token` in the field is a selected tag, and several tokens mean ALL of them, the same rule as the video tab. The `Tags` section shows the selected tags as filled, checked chips (tap one to REMOVE it) and then the **related tags** as neutral chips with a small `+` (tap one to ADD it). Related tags are co-occurrence suggestions from `KeywordIndex.relatedTags`, not fuzzy matches: under `#amateur`, the files that already carry it also carry `#couple` and `#studio`, so those are offered. A plain word query instead offers tags that fuzzy-match the word; an empty search offers `Browse by tag`. The free text remaining after the `#tokens` is still applied as a normal search, so `#amateur couple` narrows inside the tag. Images are untagged, so the image tab never advertises tags.
- **Tags appear in the facts panel too, not on the library cards.** `VideoInfoSheet` gets a `Keywords` block under the file facts, in Char chips on Ash; the section is absent when the name yielded nothing. Cards keep their poster and two-line strip — a chip on every tile would compete with the content the card exists to show.
- **Search reads the tags too**, so a chip the user saw is a query they can type; the search hints say "name, tag or type".
- **The keyword row is silent at rest.** No counts, no "AI" language, no tag editing: the names are the source of truth, and the row only decides which subset is on screen.

### Format Badges (Image Cards)

- **Background:** Semi-transparent black (`Colors.black54`), 4px radius
- **Text:** White70 (`rgba(255,255,255,0.70)`), 9px, semibold (600)
- **Position:** Top-right corner of image card, absolute
- **Animated indicator:** Circle badge bottom-left — `motion_photos_on` icon, 14px, white, on black54 circle

## 6. Do's and Don'ts
