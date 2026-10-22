# Brand assets

The app's icon, wordmark and banner live here. `design/` is the only
hand-authored artwork; every platform file is regenerated from it, so switching
the logo is a one-file change plus one command.

| File | What it is |
|---|---|
| `design/logo.svg` | The square mark: a shield with the R, on a transparent field (viewBox 512). |
| `design/logo-monochrome.svg` | The same mark with the R knocked out, for Android 13 themed icons (the launcher supplies the tint). |
| `design/banner.svg` | The horizontal lockup: mark + "rcrm" wordmark, transparent, viewBox 1024x512. |
| `build_icons.py` | The generator. |
| `out/` | Generated, committed: the README banner (light/dark), a 1024 preview, and the macOS `.icns`. |

## Regenerate

```bash
python brands/build_icons.py
```

Requires **Python 3.9+** and **ffmpeg**; the script rasterises SVG with ffmpeg's
`librsvg` decoder, or falls back to `rsvg-convert` when the ffmpeg build does
not include it. No Python packages are needed — the two binary containers are
written with `struct`.

Every scale and composite is ffmpeg, and every output is a lossless PNG (or a
PNG/BMP container: `.ico`, `.icns`); nothing is ever re-encoded through a lossy
intermediate.

```bash
python brands/build_icons.py --only android,windows   # one or more targets
python brands/build_icons.py --background 0E0E0E     # re-skin the tile
python brands/build_icons.py --logo path/to/other.svg
```

## What it writes

| Target | Destination | Notes |
|---|---|---|
| Android legacy | `android/.../res/mipmap-*/ic_launcher.png` | 48dp at each density; rounded tile with transparent corners. |
| Android adaptive | `ic_launcher_foreground.png`, `ic_launcher_monochrome.png`, `mipmap-anydpi-v26/ic_launcher.xml`, `values/colors.xml` | 108dp grid, mark at 62% so it stays inside the 72dp safe circle; monochrome is the themed-icon layer. |
| iOS | `ios/.../AppIcon.appiconset/*.png` | Sizes read from Xcode's `Contents.json`; written as RGB (no alpha — the App Store rejects it). |
| macOS | `macos/.../AppIcon.appiconset/*.png` + `out/rcrm.icns` | Art inset to Apple's 824/1024 box, radius 22.5%. The 128px file is also the title-bar asset in `pubspec.yaml`. |
| Windows | `windows/runner/resources/app_icon.ico` | 16–256px, 32-bpp DIB frames (256 is a PNG, as Windows expects). Embedded by `Runner.rc`. |
| Linux | `linux/runner/resources/app_icon.png` | Installed beside the bundle; `my_application.cc` sets it as the GTK window icon. On Wayland the compositor takes the icon from a `.desktop` file instead (this repo bundles no installer), so this route is X11 and taskbar-switcher coverage. |
| Banner | `out/banner.png`, `out/banner-dark.png` | 2x transparent; used at the top of both READMEs. The lockup is centred on its canvas (13.5% margins each side); the source SVG's 9%/18% split read as left-heavy. The wordmark's width is the host font's (the family list falls back to a generic monospace), so the committed PNG is the reference — re-check the margins after regenerating on another machine. |

## Rules the generator encodes

- **The background is cream (`#F6F1E9`), not white.** The artwork is drawn against
  a light surface, and cream keeps it warm beside the app's orange accent while
  still separating the red shield at 16px on a dark dock.
- **The artwork is placed at 94% of the icon's canvas**, which puts the shield
  itself at ~62% of the icon's width and ~76% of its height. It owns the tile
  rather than floating in it -- the first pass at 78% read as a stamp in the
  middle of a blank card -- but it is deliberately not edge-to-edge: the 14%
  above / 10% below quiet zone is what a rounded corner or a launcher mask
  needs.
- **It is optically centred, not bbox-centred.** The shield is wide at the
  shoulders and pointed at the bottom, so its alpha centroid sits 3.8% of the
  canvas ABOVE the bounding-box centre: centring the box reads as floating high.
  The generator nudges the art down by `LOGO_OPTICAL_DY` (2% of the canvas),
  which puts the mass at ~48.4% and leaves the point its air.
- **Adaptive icons are a different canvas.** The foreground is 108dp with a 72dp
  safe circle; the mark is scaled to 62% and the background is the flat colour,
  so no mask can clip the shield.
- **iOS never gets transparency**, even where every pixel is opaque.
- **macOS gets its own art box and shadow-free tile** (no shadow is drawn: the
  system adds its own, and a baked one doubles under it).
- **Linux needs a real file path**, which is why the runner reads
  `/proc/self/exe` and not a Flutter asset.

## Switching the logo

1. Replace `design/logo.svg` with a square-viewBox SVG (and update
   `design/logo-monochrome.svg` — the same paths with the letter in the mask).
2. Run `python brands/build_icons.py`.
3. Commit the regenerated platform files under `crates/rcrm-gui/` and `out/`.

If the new mark's proportions differ, adjust `LOGO_SCALE` and
`ADAPTIVE_SCALE` at the top of the script; both are commented with what they
trade off.

## Not generated

The iOS launch storyboard and Android splash drawables are separate surfaces
(the default Flutter ones are still in place), and there is no web target in this
app, so there are no favicons.
