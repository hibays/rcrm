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

### Controls Overlay (Video Player)

- **Gradient:** Vertical `0x80000000` to `0x00000000` — from opaque black at bottom to transparent
- **Auto-hide:** After 2s idle on desktop (reappears on mouse move or tap)
- **Controls bar:** Transparent background (the gradient IS the background)
- **Speed popup:** Semi-transparent dark surface with white text

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
