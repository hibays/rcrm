// services/animated_detector.dart
// Header-based animated image detection using HTTP Range requests.
//
// References nom-exif brand/chunk patterns for ISOBMFF (AVIF/HEIC):
//   - avis = AVIF image sequence (animated)
//   - hevc/hevs/hevm = HEIF image sequence (animated)
//
// For PNG: acTL chunk present → APNG (animated PNG).
// For WebP: ANIM chunk in RIFF container → animated WebP.
//
// Detection fetches only the first 4 KB of each file.
// Results are cached per URL (same pattern as live_photo.dart).

import 'net.dart';
import 'dart:typed_data';

// ── Result type ─────────────────────────────────────────────────

/// Whether a format CAN be animated (container-level support).
/// gif/apng are always animated; webp/avif/heic/heif need header check.
enum AnimatableFormat {
  /// Always animated (gif, apng).
  always,

  /// Potentially animated — needs header check (webp, avif, heic, heif).
  checkable,

  /// Not an animatable format.
  never,
}

/// Returns the [AnimatableFormat] for the given file extension.
AnimatableFormat animatableFormatFor(String ext) {
  switch (ext) {
    case 'gif':
    case 'apng':
      return AnimatableFormat.always;
    case 'png':
    case 'webp':
    case 'avif':
    case 'heic':
    case 'heif':
      return AnimatableFormat.checkable;
    default:
      return AnimatableFormat.never;
  }
}

// ── Caches ──────────────────────────────────────────────────────

final _animatedCache = <String, bool>{};
final _animatedPending = <String, Future<bool>>{};

/// Clear all animated detection caches (e.g. on server restart).
void clearAnimatedCache() {
  _animatedCache.clear();
  _animatedPending.clear();
}

// ── HTTP helper ─────────────────────────────────────────────────

Future<Uint8List> _headerFetch(
  String url,
  int len, {
  Map<String, String>? headers,
}) async {
  final client = createTrustAwareHttpClient();
  try {
    final req = await client.openUrl('GET', Uri.parse(Uri.encodeFull(url)));
    req.headers.set('Range', 'bytes=0-${len - 1}');
    if (headers != null) {
      headers.forEach((k, v) => req.headers.set(k, v));
    }
    final resp = await req.close();
    final bb = BytesBuilder(copy: false);
    await for (final chunk in resp) {
      bb.add(chunk);
    }
    return bb.toBytes();
  } finally {
    client.close();
  }
}

// ── Detection functions ─────────────────────────────────────────

/// Check if a PNG file contains an `acTL` (Animation Control) chunk,
/// which indicates it is an APNG (animated PNG).
///
/// PNG structure: signature (8 bytes) → IHDR → [acTL?] → [fcTL+fdAT] → IDAT → IEND
/// The acTL chunk appears early, immediately after IHDR.
bool _hasAcTL(Uint8List data) {
  if (data.length < 41) return false; // 8 sig + 25 IHDR + 8 acTL header(min)
  // PNG signature check
  const sig = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
  for (int i = 0; i < 8; i++) {
    if (data[i] != sig[i]) return false;
  }
  // Scan chunks after IHDR for acTL
  int pos = 8; // after signature
  while (pos + 8 <= data.length) {
    final len = _readU32BE(data, pos);
    if (pos + 12 + len > data.length) break;
    // Zero-copy: view into the same buffer instead of data.sublist()
    final type = String.fromCharCodes(
      Uint8List.view(data.buffer, data.offsetInBytes + pos + 4, 4),
    );
    if (type == 'acTL') return true;
    if (type == 'IDAT') return false; // IDAT before acTL → not animated
    pos += 12 + len; // length(4) + type(4) + data(len) + crc(4)
  }
  return false;
}

/// Check if a WebP file is animated by looking for the `ANIM` chunk
/// in the RIFF container.
///
/// WebP RIFF structure:
///   'RIFF' (size) 'WEBP' ['VP8X' ... 'ANIM' ...] | ['ANIM' ...]
/// The ANIM chunk appears early, before any frame data.
bool _hasAnimChunk(Uint8List data) {
  if (data.length < 30) return false;
  // RIFF signature
  if (data[0] != 0x52 ||
      data[1] != 0x49 ||
      data[2] != 0x46 ||
      data[3] != 0x46) {
    return false; // not RIFF
  }
  // WEBP form type at offset 8
  if (data[8] != 0x57 ||
      data[9] != 0x45 ||
      data[10] != 0x42 ||
      data[11] != 0x50) {
    return false; // not WEBP
  }
  // Scan chunks starting after 'WEBP' (offset 12)
  int pos = 12;
  while (pos + 8 <= data.length) {
    // Zero-copy: view into the same buffer instead of data.sublist()
    final type = String.fromCharCodes(
      Uint8List.view(data.buffer, data.offsetInBytes + pos, 4),
    );
    final size = _readU32LE(data, pos + 4);
    if (type == 'ANIM') return true;
    if (type == 'VP8 ' || type == 'VP8L' || type == 'ALPH') {
      // VP8/VP8L before ANIM → static WebP
      return false;
    }
    // VP8X is an extended header — ANIM may follow
    pos += 8 + (size % 2 == 1 ? size + 1 : size);
  }
  return false;
}

/// Parse the ISOBMFF ftyp box and check if the major brand or
/// compatible brands indicate an image sequence (animated).
///
/// References nom-exif/src/file.rs:
///   - AVIF: `avis` brand = image sequence
///   - HEIF: `hevc`/`hevs`/`hevm` brands = image sequence
bool _isBmffSequence(Uint8List data) {
  if (data.length < 16) return false;
  // ftyp box: size(4) + 'ftyp'(4) + major_brand(4) + minor_version(4) + [compat brands...]
  final boxSize = _readU32BE(data, 0);
  if (boxSize < 16 || boxSize > data.length) return false;
  // Zero-copy: view instead of data.sublist()
  final boxType = String.fromCharCodes(
    Uint8List.view(data.buffer, data.offsetInBytes + 4, 4),
  );
  if (boxType != 'ftyp') return false;
  final majorBrand = String.fromCharCodes(
    Uint8List.view(data.buffer, data.offsetInBytes + 8, 4),
  );

  // AVIF image sequence brand (nom-exif file.rs:39-40)
  if (majorBrand == 'avis') return true;

  // HEIF image sequence brands (nom-exif file.rs:17,20-21)
  if (majorBrand == 'hevc' || majorBrand == 'hevs' || majorBrand == 'hevm') {
    return true;
  }

  // Check compatible brands (offset 16 onward, 4 bytes each)
  final remaining = boxSize - 16;
  final maxCompat = (remaining ~/ 4).clamp(0, 32); // reasonable cap
  for (int i = 0; i < maxCompat; i++) {
    final off = 16 + i * 4;
    if (off + 4 > boxSize) break;
    // Zero-copy: view instead of data.sublist()
    final compat = String.fromCharCodes(
      Uint8List.view(data.buffer, data.offsetInBytes + off, 4),
    );
    if (compat == 'avis' ||
        compat == 'hevc' ||
        compat == 'hevs' ||
        compat == 'hevm') {
      return true;
    }
  }

  return false;
}

// ── Byte reading helpers ────────────────────────────────────────

int _readU32BE(Uint8List b, int i) =>
    (b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3];

int _readU32LE(Uint8List b, int i) =>
    (b[i + 3] << 24) | (b[i + 2] << 16) | (b[i + 1] << 8) | b[i];

// ── Public API ──────────────────────────────────────────────────

/// Lightweight cached check: is [url] an animated image?
///
/// Fetches only the first 4 KB via HTTP Range.
///   PNG:     acTL chunk detection.
///   WebP:    ANIM chunk in RIFF.
///   AVIF:    ftyp major/compat brand `avis`.
///   HEIC:    ftyp major/compat brand `hevc`/`hevs`/`hevm`.
/// Falls back to false on any error or unsupported format.
Future<bool> isAnimatedUrl(String url, {Map<String, String>? headers}) async {
  // Quick format check — only formats that COULD be animated
  final uri = Uri.parse(url);
  final path = uri.path;
  final ext = path.contains('.') ? path.split('.').last.toLowerCase() : '';
  final fmt = animatableFormatFor(ext);
  if (fmt == AnimatableFormat.always) return true;
  if (fmt == AnimatableFormat.never) return false;

  // Check cache
  if (_animatedCache.containsKey(url)) return _animatedCache[url]!;
  if (_animatedPending.containsKey(url)) return _animatedPending[url]!;

  final f = _detectAnimated(url, ext, headers: headers);
  _animatedPending[url] = f;
  final r = await f;
  _animatedCache[url] = r;
  _animatedPending.remove(url);
  return r;
}

Future<bool> _detectAnimated(
  String url,
  String ext, {
  Map<String, String>? headers,
}) async {
  try {
    // 4 KB is enough for: ftyp box (~100 bytes), PNG IHDR+acTL (~50 bytes),
    // WebP RIFF header+ANIM (~60 bytes). Generous margin for exotic metadata.
    final data = await _headerFetch(url, 4096, headers: headers);
    if (data.length < 16) return false;

    switch (ext) {
      case 'png':
        return _hasAcTL(data);
      case 'webp':
        return _hasAnimChunk(data);
      case 'avif':
      case 'heic':
      case 'heif':
        return _isBmffSequence(data);
      default:
        return false;
    }
  } catch (_) {
    return false;
  }
}
