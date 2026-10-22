#!/usr/bin/env python3
# brands/build_icons.py
# One command turns the artwork in brands/design/ into every app icon this repo
# ships: Android (legacy + adaptive + themed monochrome), iOS, macOS, Windows
# (.ico) and Linux (window icon), plus the README banner.
#
# The pipeline is deliberately ffmpeg-shaped, because the artwork is vector and
# every target is a size of the same square:
#
#   SVG --librsvg (ffmpeg decoder, or rsvg-convert)--> RGBA master at 4096
#        --ffmpeg overlay on the brand background--> the square icon
#        --ffmpeg rounded-rect mask--> the desktop tile / macOS art
#        --ffmpeg scale (lanczos)--> one lossless PNG per platform size
#
# Everything written is PNG (or a PNG/BMP container: .ico, .icns): no JPEG, no
# chroma subsampling, no re-encode of an intermediate. "Lossless" here means the
# only resampling is the one scale down from the master.
#
# Requirements: Python 3.9+ and ffmpeg built with librsvg (ffmpeg -decoders |
# grep rsvg). If ffmpeg lacks librsvg, rsvg-convert (librsvg2-bin) is used for
# the rasterisation and ffmpeg still does every scale and composite.
#
# Switching the logo: replace brands/design/logo.svg (square viewBox), re-run
#     python brands/build_icons.py
# and commit the regenerated platform files. Colours and proportions are the
# constants below; each has a comment explaining what changing it costs.
from __future__ import annotations

import argparse
import json
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / "brands" / "design"
OUT = ROOT / "brands" / "out"
GUI = ROOT / "crates" / "rcrm-gui"

# ── Brand knobs ────────────────────────────────────────────────────
# The cream the mark sits on. The source artwork is transparent; the shield is
# #D64524 and the wordmark #2B2D3A, both designed against a light surface. Cream
# rather than white keeps the icon warm beside the app's orange accent, and it
# is the one tone that still separates the red shield from its background at
# 16px on a dark dock.
BACKGROUND = "F6F1E9"

# Width of the logo canvas as a fraction of the square icon. The shield itself
# is 65.6% wide and 81.25% tall within that canvas, so 0.94 puts the mark at
# ~62% of the icon's width and ~76% of its height: it owns the tile rather than
# floating in it.
LOGO_SCALE = 0.94

# Downward optical nudge, as a fraction of the canvas. The shield is wide at the
# shoulders and pointed at the bottom, so its alpha centroid sits 3.8% of the
# canvas ABOVE the bounding-box centre -- bbox-centring reads as floating high.
# 2% puts the mass back at ~48.4% and leaves 14% above / 10% below; the
# remaining 1.8% is deliberate, because a mark whose mass sits exactly at the
# centre makes the point look like it is about to topple.
LOGO_OPTICAL_DY = 0.02

# Adaptive foregrounds are 108dp and their safe zone is a 72dp circle (36dp
# radius). 0.62 of 108dp leaves the shield's half-diagonal at ~35dp, so even a
# round launcher mask cannot clip it.
ADAPTIVE_SCALE = 0.62

# Desktop tile corner radius, as a fraction of the side. 0.225 is the macOS
# grid's own radius; Windows and Linux read the same tile as one family.
TILE_RADIUS = 0.225

# macOS draws app icons inside an 824x824 rounded rect on a 1024 transparent
# canvas. The tile is inset to that art box; the system adds nothing itself.
MAC_ART_RATIO = 824 / 1024

# Wordmark colour in banner.svg, and the cream it becomes on dark surfaces.
BANNER_TEXT = "#2B2D3A"
BANNER_TEXT_DARK = "#F6F1E9"

# Master resolution. 4096 is 4x the largest platform icon (1024) and 9.5x the
# largest Android density, so every target is a downscale.
MASTER = 4096

# ── Platform tables ────────────────────────────────────────────────
# Android legacy launcher icons: 48dp at mdpi.
ANDROID_DENSITIES = {
    "mdpi": 1.0,
    "hdpi": 1.5,
    "xhdpi": 2.0,
    "xxhdpi": 3.0,
    "xxxhdpi": 4.0,
}
ANDROID_LEGACY_DP = 48
ANDROID_ADAPTIVE_DP = 108

# Windows .ico sizes. 16-48 are the list, taskbar and Alt-Tab; 256 is the large
# shell view. Windows caps ICO frames at 256x256.
WINDOWS_ICO_SIZES = (16, 20, 24, 32, 40, 48, 64, 96, 128, 256)

# macOS AppIcon.appiconset is read from its Contents.json, so Xcode's own list
# stays the source of truth. These are the ICNS chunk types for the .icns copy.
ICNS_TYPES = {
    16: b"icp4",
    32: b"icp5",
    64: b"icp6",
    128: b"ic07",
    256: b"ic08",
    512: b"ic09",
    1024: b"ic10",
}

# ── ffmpeg plumbing ────────────────────────────────────────────────
FFMPEG = shutil.which("ffmpeg")
RSVG = shutil.which("rsvg-convert")
if not FFMPEG:
    sys.exit("error: ffmpeg is not on PATH (needed for every scale and composite)")


def run_tool(cmd: list[str]) -> None:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(" ".join(cmd) + "\n" + proc.stderr[-3000:] + "\n")
        raise SystemExit(1)


def ff(*args: object) -> None:
    cmd = [FFMPEG, "-y", "-nostdin", "-hide_banner", "-loglevel", "error"]
    run_tool([*cmd, *[str(a) for a in args]])


def _probe_svg_decoder() -> bool:
    proc = subprocess.run(
        [FFMPEG, "-hide_banner", "-decoders"], capture_output=True, text=True
    )
    return "librsvg" in proc.stdout


FFMPEG_SVG = _probe_svg_decoder()
if not FFMPEG_SVG and not RSVG:
    sys.exit(
        "error: neither ffmpeg's librsvg decoder nor rsvg-convert is available,\n"
        "so the SVG artwork cannot be rasterised. Install librsvg (or an ffmpeg\n"
        "build with --enable-librsvg)."
    )


def rasterize(svg: Path, width: int, height: int, out: Path) -> None:
    """Render an SVG at an exact pixel size, transparent where it has no paint."""
    if FFMPEG_SVG:
        ff("-width", width, "-height", height, "-i", svg, "-frames:v", "1",
           "-pix_fmt", "rgba", out)
    else:
        run_tool([RSVG, "-w", str(width), "-h", str(height), "-o", str(out), str(svg)])


def solid(size: int, hex_color: str, out: Path) -> None:
    # format=rgba INSIDE the lavfi graph keeps the colour in RGB: letting the
    # colour source negotiate through YUV first shifts #F6F1E9 to #F3EDE6.
    ff("-f", "lavfi", "-i", f"color=c=0x{hex_color}:s={size}x{size},format=rgba",
       "-frames:v", "1", "-pix_fmt", "rgba", out)


def transparent(size: int, out: Path) -> None:
    ff("-f", "lavfi", "-i", f"color=c=black@0.0:s={size}x{size},format=rgba",
       "-frames:v", "1", "-pix_fmt", "rgba", out)


def overlay_center(
    canvas: Path, fg: Path, fg_size: int, out: Path, dy: int = 0
) -> None:
    """Scale a square foreground to fg_size and centre it on canvas, +dy down."""
    ff("-i", canvas, "-i", fg, "-filter_complex",
       f"[1:v]scale={fg_size}:{fg_size}:flags=lanczos[l];"
       f"[0:v][l]overlay=(W-w)/2:(H-h)/2{dy:+d}:format=auto,format=rgba",
       "-frames:v", "1", "-pix_fmt", "rgba", out)


def compose(bg: Path, fg: Path, fg_size: int, out: Path, dy: int = 0) -> None:
    """Overlay a square foreground on an opaque background."""
    overlay_center(bg, fg, fg_size, out, dy)


def rounded_tile(square: Path, radius_fraction: float, out: Path, work: Path) -> None:
    """Apply an antialiased rounded-rect alpha mask to the square master."""
    mask_svg = work / "mask.svg"
    radius = round(MASTER * radius_fraction)
    mask_svg.write_text(
        '<svg xmlns="http://www.w3.org/2000/svg" '
        f'width="{MASTER}" height="{MASTER}" viewBox="0 0 {MASTER} {MASTER}">'
        f'<rect width="{MASTER}" height="{MASTER}" rx="{radius}" fill="#fff"/>'
        "</svg>",
        encoding="utf-8",
    )
    mask = work / "mask.png"
    rasterize(mask_svg, MASTER, MASTER, mask)
    ff("-i", square, "-i", mask, "-filter_complex",
       "[1:v]format=gray[m];[0:v][m]alphamerge,format=rgba",
       "-frames:v", "1", "-pix_fmt", "rgba", out)


def scale(src: Path, size: int, out: Path, pix_fmt: str = "rgba") -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    ff("-i", src, "-vf", f"scale={size}:{size}:flags=lanczos",
       "-frames:v", "1", "-pix_fmt", pix_fmt, out)


def scale_pad(src: Path, art: int, canvas: int, out: Path) -> None:
    """Scale a square to art px and centre it on a transparent canvas px."""
    canvas_png = out.parent / (out.stem + "-canvas.png")
    transparent(canvas, canvas_png)
    ff("-i", canvas_png, "-i", src, "-filter_complex",
       f"[1:v]scale={art}:{art}:flags=lanczos[t];"
       "[0:v][t]overlay=(W-w)/2:(H-h)/2:format=auto,format=rgba",
       "-frames:v", "1", "-pix_fmt", "rgba", out)
    canvas_png.unlink(missing_ok=True)


# ── Containers ─────────────────────────────────────────────────────
def bmp_frame(png: Path, size: int, work: Path) -> bytes:
    """One 32-bpp ICO DIB frame (BITMAPINFOHEADER + XOR + AND mask).

    BMP rather than a PNG frame on purpose: every resource compiler Windows has
    ever shipped reads a 32-bpp DIB, and the icon is generated once, so the few
    hundred KB are cheaper than a build that only works on new rc.exe.
    """
    bmp = work / f"ico-{size}.bmp"
    ff("-i", png, "-frames:v", "1", "-pix_fmt", "bgra", bmp)
    raw = bmp.read_bytes()
    if raw[:2] != b"BM":
        raise SystemExit("error: ffmpeg did not write a BMP for the ICO frame")
    # Read the offsets instead of assuming 14+40: the BMP encoder owns them,
    # and a different ffmpeg build may write a V4/V5 header.
    data_offset = struct.unpack_from("<I", raw, 10)[0]
    dib_size = struct.unpack_from("<I", raw, 14)[0]
    if dib_size < 40:
        raise SystemExit(f"error: unexpected BMP DIB header ({dib_size} bytes)")
    header = bytearray(raw[14:54])  # BITMAPINFOHEADER, 40 bytes
    width, height = struct.unpack_from("<ii", header, 4)
    bpp = struct.unpack_from("<H", header, 14)[0]
    if bpp != 32:
        raise SystemExit(f"error: ffmpeg wrote {bpp}-bpp BMP for the ICO frame")
    xor = raw[data_offset:]
    if len(xor) != width * height * 4:
        raise SystemExit("error: unexpected BMP frame size")
    and_mask = b"\x00" * (((width + 31) // 32) * 4 * height)
    struct.pack_into("<i", header, 8, height * 2)
    struct.pack_into("<I", header, 20, len(xor) + len(and_mask))
    return bytes(header) + xor + and_mask


def write_ico(frames: list[tuple[int, bytes]], out: Path) -> None:
    count = len(frames)
    offset = 6 + 16 * count
    entries = bytearray()
    blobs = bytearray()
    for size, data in frames:
        dim = 0 if size >= 256 else size
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset)
        blobs += data
        offset += len(data)
    out.write_bytes(struct.pack("<HHH", 0, 1, count) + bytes(entries) + bytes(blobs))


def write_icns(art: dict[int, Path], out: Path) -> None:
    """Write an .icns container from PNG art. Not used by the Xcode build (the
    asset catalog is); offered for docs, packaging or a quick dock preview."""
    chunks = bytearray()
    for size in sorted(art):
        kind = ICNS_TYPES.get(size)
        if kind is None:
            continue
        data = art[size].read_bytes()
        chunks += kind + struct.pack(">I", len(data) + 8) + data
    out.write_bytes(b"icns" + struct.pack(">I", len(chunks) + 8) + bytes(chunks))


# ── Text helpers ───────────────────────────────────────────────────
def read_appiconset(path: Path) -> list[tuple[str, int]]:
    """[(filename, pixel size)] from an Xcode Contents.json."""
    data = json.loads(path.read_text(encoding="utf-8"))
    entries: list[tuple[str, int]] = []
    seen: set[str] = set()
    for image in data["images"]:
        # The catalog lists one file per slot, so 20@2x appears for iPhone and
        # iPad alike; the file is the same, so write it once.
        if image["filename"] in seen:
            continue
        seen.add(image["filename"])
        base = float(image["size"].split("x")[0])
        scale = float(image["scale"].rstrip("x"))
        entries.append((image["filename"], round(base * scale)))
    return entries


def recolor(svg_text: str, old: str, new: str) -> str:
    if old.lower() not in svg_text.lower():
        print(f"warning: {old} not found in the banner; dark variant is unchanged")
        return svg_text
    return re.sub(re.escape(old), new, svg_text, flags=re.IGNORECASE)


# ── Build ──────────────────────────────────────────────────────────
def build(
    logo: Path,
    banner: Path | None,
    monochrome: Path,
    background: str,
    only: set[str],
    work: Path,
) -> None:
    all_targets = {"android", "ios", "macos", "windows", "linux", "banner"}
    unknown = only - all_targets
    if unknown:
        sys.exit(f"error: unknown target(s): {', '.join(sorted(unknown))}")

    def want(name: str) -> bool:
        return not only or name in only

    # 1. Masters. One rasterisation of each vector, then every platform size is
    #    a scale of that raster -- so all icons share one antialiasing pass.
    logo_master = work / "logo.png"
    rasterize(logo, MASTER, MASTER, logo_master)
    bg = work / "background.png"
    solid(MASTER, background, bg)

    optical_dy = round(MASTER * LOGO_OPTICAL_DY)
    square = work / "square.png"
    compose(bg, logo_master, round(MASTER * LOGO_SCALE), square, dy=optical_dy)

    tile = work / "tile.png"
    rounded_tile(square, TILE_RADIUS, tile, work)

    # macOS art box: the tile inset to 824/1024 of the canvas.
    mac_master = work / "mac.png"
    scale_pad(tile, round(MASTER * MAC_ART_RATIO), MASTER, mac_master)

    # Adaptive foreground: transparent, mark at the adaptive scale.
    adaptive_size = round(MASTER * ADAPTIVE_SCALE)
    fg_canvas = work / "adaptive-canvas.png"
    transparent(MASTER, fg_canvas)
    fg_master = work / "adaptive-fg.png"
    overlay_center(fg_canvas, logo_master, adaptive_size, fg_master,
                   dy=optical_dy)

    mono_master = work / "mono.png"
    rasterize(monochrome, MASTER, MASTER, mono_master)
    mono_canvas = work / "mono-canvas.png"
    transparent(MASTER, mono_canvas)
    mono_fg = work / "mono-fg.png"
    overlay_center(mono_canvas, mono_master, adaptive_size, mono_fg,
                   dy=optical_dy)

    written: list[Path] = []

    # 2. Android: legacy PNGs (pre-8.0), adaptive foreground + themed monochrome
    #    (8.0+), and the colour the adaptive background layer is.
    if want("android"):
        res = GUI / "android" / "app" / "src" / "main" / "res"
        for density, factor in ANDROID_DENSITIES.items():
            folder = res / f"mipmap-{density}"
            legacy = folder / "ic_launcher.png"
            scale(tile, round(ANDROID_LEGACY_DP * factor), legacy)
            scale(fg_master, round(ANDROID_ADAPTIVE_DP * factor),
                  folder / "ic_launcher_foreground.png")
            scale(mono_fg, round(ANDROID_ADAPTIVE_DP * factor),
                  folder / "ic_launcher_monochrome.png")
            written += [legacy, folder / "ic_launcher_foreground.png",
                        folder / "ic_launcher_monochrome.png"]

        values = res / "values" / "colors.xml"
        values.parent.mkdir(parents=True, exist_ok=True)
        values.write_text(
            '<?xml version="1.0" encoding="utf-8"?>\n'
            "<resources>\n"
            "    <!-- The adaptive icon's background layer, generated by\n"
            "         brands/build_icons.py from BACKGROUND. Change the colour\n"
            "         there and re-run rather than editing this file. -->\n"
            f'    <color name="ic_launcher_background">#{background}</color>\n'
            "</resources>\n",
            encoding="utf-8",
        )
        adaptive = res / "mipmap-anydpi-v26" / "ic_launcher.xml"
        adaptive.parent.mkdir(parents=True, exist_ok=True)
        adaptive.write_text(
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">\n'
            '    <background android:drawable="@color/ic_launcher_background" />\n'
            '    <foreground android:drawable="@mipmap/ic_launcher_foreground" />\n'
            '    <monochrome android:drawable="@mipmap/ic_launcher_monochrome" />\n'
            "</adaptive-icon>\n",
            encoding="utf-8",
        )
        written += [values, adaptive]

    # 3. iOS: opaque squares, RGB (the App Store rejects an alpha channel even
    #    when every pixel is opaque). Sizes come from Xcode's own Contents.json.
    if want("ios"):
        appiconset = GUI / "ios" / "Runner" / "Assets.xcassets" / "AppIcon.appiconset"
        for filename, size in read_appiconset(appiconset / "Contents.json"):
            target = appiconset / filename
            scale(square, size, target, pix_fmt="rgb24")
            written.append(target)

    # 4. macOS: the tile inset to Apple's 824/1024 art box.
    if want("macos"):
        appiconset = GUI / "macos" / "Runner" / "Assets.xcassets" / "AppIcon.appiconset"
        entries = read_appiconset(appiconset / "Contents.json")
        for filename, size in entries:
            target = appiconset / filename
            scale(mac_master, size, target)
            written.append(target)
        write_icns({size: appiconset / name for name, size in entries},
                   OUT / "rcrm.icns")
        written.append(OUT / "rcrm.icns")

    # 5. Windows: one .ico with every shell size. Small frames are 32-bpp DIBs
    #    (readable by every rc.exe there has ever been); the 256 frame is a PNG,
    #    which is what Flutter's own icon does and what Vista+ expects for the
    #    large shell view -- a 256 DIB would triple the file for no benefit.
    if want("windows"):
        frames: list[tuple[int, bytes]] = []
        for size in WINDOWS_ICO_SIZES:
            png = work / f"win-{size}.png"
            scale(tile, size, png)
            data = png.read_bytes() if size >= 256 else bmp_frame(png, size, work)
            frames.append((size, data))
        ico = GUI / "windows" / "runner" / "resources" / "app_icon.ico"
        write_ico(frames, ico)
        written.append(ico)

    # 6. Linux: GTK reads the window icon from a real file at runtime, so the
    #    runner installs it beside the bundle and my_application.cc loads it.
    if want("linux"):
        png = GUI / "linux" / "runner" / "resources" / "app_icon.png"
        scale(tile, 512, png)
        written.append(png)

    # 7. Banner: transparent 2x lockup for the README, light and dark.
    if banner and want("banner"):
        light = OUT / "banner.png"
        rasterize(banner, 2048, 1024, light)
        written.append(light)
        dark_svg = work / "banner-dark.svg"
        dark_svg.write_text(
            recolor(banner.read_text(encoding="utf-8"), BANNER_TEXT, BANNER_TEXT_DARK),
            encoding="utf-8",
        )
        dark = OUT / "banner-dark.png"
        rasterize(dark_svg, 2048, 1024, dark)
        written.append(dark)
        # A square 1024 for docs/social cards, from the same tile master.
        icon = OUT / "icon-1024.png"
        scale(tile, 1024, icon)
        written.append(icon)

    for path in written:
        if not path.exists():
            raise SystemExit(f"error: expected output missing: {path}")
    print(f"wrote {len(written)} files")
    for path in sorted(set(written)):
        print(f"  {path.relative_to(ROOT)}  ({path.stat().st_size:,} bytes)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--logo", type=Path, default=DESIGN / "logo.svg")
    parser.add_argument("--banner", type=Path, default=DESIGN / "banner.svg")
    parser.add_argument("--monochrome", type=Path,
                        default=DESIGN / "logo-monochrome.svg")
    parser.add_argument("--background", default=BACKGROUND,
                        help="hex RGB (no #) behind the mark")
    parser.add_argument("--only", default="",
                        help="comma-separated: android,ios,macos,windows,linux,banner")
    parser.add_argument("--no-banner", action="store_true")
    args = parser.parse_args()

    for path in (args.logo, args.monochrome):
        if not path.exists():
            sys.exit(f"error: missing artwork: {path}")
    if not args.no_banner and not args.banner.exists():
        sys.exit(f"error: missing banner artwork: {args.banner}")

    background = args.background.lstrip("#").upper()
    if not re.fullmatch(r"[0-9A-F]{6}", background):
        sys.exit("error: --background must be six hex digits, e.g. F6F1E9")

    only = {t.strip() for t in args.only.split(",") if t.strip()}
    OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="rcrm-icons-") as tmp:
        build(
            logo=args.logo,
            banner=None if args.no_banner else args.banner,
            monochrome=args.monochrome,
            background=background,
            only=only,
            work=Path(tmp),
        )


if __name__ == "__main__":
    main()
