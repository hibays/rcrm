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
- **Secondary active:** `rgba(255,255,255,0.40)` for buffer display
- **Volume slider (player controls):** White active track, same transparent inactive. Subdued orange is reserved for media progress, not volume.

### Progress Bars (Video Player)

- **Buffered:** Silver Transparent (`rgba(255,255,255,0.20)`) with white-tinted cap
- **Played:** Marquee Orange (`#FF6B00`)
- **Background:** Transparent
- **Mini progress bar (controls hidden):** Same orange on transparent, thin (2px)

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
- **Skip pair:** Previous and Next switch video inside the player that is already playing — nothing on screen moves, and fullscreen, picture-in-picture, the speed and the volume stay the ones you set. Previous walks the jump history back one step; Back (the top bar, the system gesture) reaches the same video as a route step, with the platform's back-direction animation — which is the difference between leaving a video and skipping to another one. Each button is painted only when there is somewhere to skip to, so neither is ever a dead control
- **Density:** Chosen from the window's shortest side — compact < 400dp, regular < 600dp, expanded above. Fullscreen alone never inflates the controls. When the bar itself is narrower than the compact tier can afford (140dp), the targets step down once more rather than overflow: no minimum window size is set, so a desktop window can really be dragged that narrow
- **Speed popup:** Semi-transparent dark surface with white text

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
