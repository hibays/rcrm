// services/live_photo.dart
// Live photo / motion photo detection and video extraction.
//
// Essence: it's an IMAGE. Long-press plays briefly, no video controls.
//
// Apple Live Photo:   .heic/.jpg + companion .mov (extension swap)
// Android embedded:   JPEG + appended MP4 trailer.
//   - XMP-based: GCamera:MicroVideoOffset / Container:Item/Item:Length (Google)
//   - EOF scan:   ftyp box at end of file (Xiaomi, other OEMs without XMP)
// Samsung HEIC:       HEIC + embedded MP4 in "mpvd" box
//
// Detection + extraction via HTTP Range (WebDAV server supports 206 Partial).

import 'dart:convert';
import 'dart:typed_data';
import 'net.dart';
import 'package:media_kit/media_kit.dart';

// ── Result types ───────────────────────────────────────────────

enum LivePhotoType { apple, androidEmbedded, samsungHeic, none }

class LivePhotoInfo {
  final LivePhotoType type;

  /// For Apple: the companion .mov URL.
  final String? movUrl;

  /// For Android/Samsung: file size and offset where MP4 data starts.
  final int fileSize;
  final int videoOffset;

  /// For Samsung HEIC mpvd: total size of the mpvd box (header + payload).
  final int mpvdSize;

  const LivePhotoInfo({
    this.type = LivePhotoType.none,
    this.movUrl,
    this.fileSize = 0,
    this.videoOffset = 0,
    this.mpvdSize = 0,
  });

  bool get isLive => type != LivePhotoType.none;
}

// ── Caches ─────────────────────────────────────────────────────

final _resultCache = <String, LivePhotoInfo>{};
final _pending = <String, Future<LivePhotoInfo>>{};

const _kAppleExts = {'heic', 'heif', 'jpg', 'jpeg'};
final _headCache = <String, bool>{};
final _headPending = <String, Future<bool>>{};
// ── HTTP helpers ───────────────────────────────────────────────

Future<Uint8List> _rangeFetch(
  String url,
  int start,
  int end, {
  Map<String, String>? headers,
}) async {
  final client = createTrustAwareHttpClient();
  try {
    final req = await client.openUrl('GET', Uri.parse(Uri.encodeFull(url)));
    req.headers.set('Range', 'bytes=$start-$end');
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

Future<int> _fileSize(String url, {Map<String, String>? headers}) async {
  final client = createTrustAwareHttpClient();
  try {
    final req = await client.openUrl('HEAD', Uri.parse(Uri.encodeFull(url)));
    if (headers != null) {
      headers.forEach((k, v) => req.headers.set(k, v));
    }
    final resp = await req.close();
    final cl = resp.headers.value('content-length');
    if (cl != null) {
      final n = int.tryParse(cl);
      if (n != null && n > 0) return n;
    }
  } finally {
    client.close();
  }
  return 0;
}

// ── Apple Live Photo detection ────────────────────────────────

Future<bool> _hasMovCompanion(
  String url, {
  Map<String, String>? headers,
}) async {
  final uri = Uri.parse(url);
  final path = uri.path;
  final dot = path.lastIndexOf('.');
  if (dot < 0) return false;
  final ext = path.substring(dot + 1).toLowerCase();
  if (!_kAppleExts.contains(ext)) return false;

  final movPath = '${path.substring(0, dot)}.mov';
  final movUrl = uri.replace(path: movPath).toString();

  if (_headCache.containsKey(movUrl)) return _headCache[movUrl]!;
  if (_headPending.containsKey(movUrl)) return _headPending[movUrl]!;

  final f = (() async {
    final client = createTrustAwareHttpClient();
    try {
      final req = await client.openUrl(
        'HEAD',
        Uri.parse(Uri.encodeFull(movUrl)),
      );
      if (headers != null) {
        headers.forEach((k, v) => req.headers.set(k, v));
      }
      final resp = await req.close();
      return resp.statusCode == 200;
    } catch (_) {
      return false;
    } finally {
      client.close();
    }
  })();

  _headPending[movUrl] = f;
  final r = await f;
  _headCache[movUrl] = r;
  _headPending.remove(movUrl);
  return r;
}

// ── XMP / offset parsing ───────────────────────────────────────

int? _parseVideoOffset(String s) {
  // Old: GCamera:MicroVideoOffset="123456"
  final gcam = RegExp(r'GCamera:MicroVideoOffset[=:">]*(\d+)');
  final m1 = gcam.firstMatch(s);
  if (m1 != null) {
    final n = int.tryParse(m1.group(1)!);
    if (n != null && n > 0) return n;
  }
  // New: Item:Length = "123456"
  final container = RegExp(r'Item:Length[=:">\s]*(\d+)');
  final m2 = container.firstMatch(s);
  if (m2 != null) {
    final n = int.tryParse(m2.group(1)!);
    if (n != null && n > 0) return n;
  }
  return null;
}

bool _hasXmpMarkers(Uint8List bytes) {
  final s = String.fromCharCodes(bytes);
  return s.contains('MotionPhoto_Data') ||
      s.contains('MotionPhoto') ||
      s.contains('MicroVideo') ||
      s.contains('Item:Length');
}

// ── ISOBMFF box parser (Samsung HEIC / mpvd) ──────────────────

/// Parse ISOBMFF boxes in [data] to find a box of [targetType].
/// Returns (offset_in_file, box_size) or null.
(int offset, int size)? _findBox(
  Uint8List data,
  String targetType, {
  int fileOffset = 0,
}) {
  int i = 0;
  while (i + 8 <= data.length) {
    final size = _readU32(data, i);
    final type = String.fromCharCodes(
      Uint8List.view(data.buffer, data.offsetInBytes + i + 4, 4),
    );
    final fullSize = size == 0
        ? data.length - i
        : size == 1
        ? (i + 16 <= data.length ? _readU64(data, i + 8) : 0)
        : size;

    if (fullSize < 8 || i + fullSize > data.length) break;

    if (type == targetType) {
      return (fileOffset + i, fullSize);
    }

    // Container boxes: recurse into payload.
    if (_isContainerBox(type)) {
      final payloadOff = size == 1 ? 16 : 8;
      final inner = _findBox(
        Uint8List.view(
          data.buffer,
          data.offsetInBytes + i + payloadOff,
          fullSize - payloadOff,
        ),
        targetType,
        fileOffset: fileOffset + i + payloadOff,
      );
      if (inner != null) return inner;
    }

    i += fullSize;
  }
  return null;
}

int _readU32(Uint8List b, int i) =>
    (b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3];

int _readU64(Uint8List b, int i) => (_readU32(b, i) << 32) | _readU32(b, i + 4);

/// ISOBMFF container box types — these may contain child boxes.
bool _isContainerBox(String type) {
  // Standard HEIF/ISOBMFF container boxes
  const containers = {
    'moov',
    'moof',
    'trak',
    'edts',
    'mdia',
    'minf',
    'stbl',
    'dinf',
    'udta',
    'meta',
    'iprp',
    'iloc',
    'iinf',
    'iref',
    'ipco',
    'meco',
    'schi',
    'pitm',
    'fiin',
    'feal',
    'mere',
    'skip',
    'free',
  };
  // Also recurse into any 4-byte type starting with lowercase letter
  // (ISOBMFF convention for container boxes)
  if (containers.contains(type)) return true;
  if (type.length == 4 &&
      type.codeUnitAt(0) >= 0x61 &&
      type.codeUnitAt(0) <= 0x7a) {
    return true; // lowercase first letter → likely a container
  }
  return false;
}

/// Detect Samsung HEIC "mpvd" box and return its offset and size.
Future<(int offset, int size)?> _findMpvdBox(
  String url, {
  Map<String, String>? headers,
}) async {
  // HEIC headers rarely exceed 512KB (typically ~100KB).
  const headerLen = 512 * 1024;
  final fileSize = await _fileSize(url, headers: headers);
  if (fileSize < 256) return null;

  final len = headerLen < fileSize ? headerLen : fileSize;
  Uint8List data;
  try {
    data = await _rangeFetch(url, 0, len - 1, headers: headers);
  } catch (_) {
    return null;
  }
  if (data.length < 12) return null;
  return _findBox(data, 'mpvd');
}

// ── Bool cache (for grid badges) ─────────────────────────────

final _isLiveCache = <String, bool>{};
final _isLivePending = <String, Future<bool>>{};

/// Lightweight cached check: is [url] a live photo?
///
/// For grid badges only — does NOT fetch 64KB headers.
///   Apple:      HEAD companion .mov (1 request).
///   Android:    512-byte Range GET to peek at XMP markers (1 small request).
///   Samsung:    HEIC only, 512-byte check for "mpvd" (1 small request).
/// Falls back to false — never fetches large payloads.
Future<bool> isLivePhotoUrl(String url, {Map<String, String>? headers}) async {
  if (_isLiveCache.containsKey(url)) return _isLiveCache[url]!;
  if (_isLivePending.containsKey(url)) return _isLivePending[url]!;
  final f = _quickCheck(url, headers);
  _isLivePending[url] = f;
  final r = await f;
  _isLiveCache[url] = r;
  _isLivePending.remove(url);
  return r;
}

Future<bool> _quickCheck(String url, Map<String, String>? headers) async {
  final uri = Uri.parse(url);
  final path = uri.path;
  final dot = path.lastIndexOf('.');
  final ext = dot >= 0 ? path.substring(dot + 1).toLowerCase() : '';

  // ── 1) Apple Live Photo ────────────────────────────────────────
  if (_kAppleExts.contains(ext)) {
    if (await _hasMovCompanion(url, headers: headers)) return true;
  }

  // ── 2) Samsung HEIC (mpvd box) ────────────────────────────────
  if (ext == 'heic' || ext == 'heif') {
    final mpvd = await _findMpvdBox(url, headers: headers);
    if (mpvd != null) return true;
  }

  // ── 3) Android embedded — XMP-based detection (nom-exif approach) ──
  // Fetch 64 KB to find XMP markers (GCamera:MicroVideo/MotionPhoto).
  // This matches nom-exif's scan_motion_photo(): walk JPEG markers
  // looking for XMP APP1 with motion photo signal.
  if (ext != 'jpg' && ext != 'jpeg') return false;

  try {
    final head = await _rangeFetch(url, 0, 65535, headers: headers);
    if (head.length >= 12 && _hasXmpMarkers(head)) return true;
  } catch (_) {
    return false;
  }

  return false;
}

// ── Phase detection (full metadata) ─────────────────────────────

Future<LivePhotoInfo> phaseLivePhoto(
  String url, {
  Map<String, String>? headers,
}) async {
  if (_resultCache.containsKey(url)) return _resultCache[url]!;
  if (_pending.containsKey(url)) return _pending[url]!;

  final f = _phase(url, headers);
  _pending[url] = f;
  final r = await f;
  if (r.isLive) _resultCache[url] = r;
  _pending.remove(url);
  return r;
}

Future<LivePhotoInfo> _phase(String url, Map<String, String>? headers) async {
  final uri = Uri.parse(url);
  final path = uri.path;
  final dot = path.lastIndexOf('.');
  final ext = dot >= 0 ? path.substring(dot + 1).toLowerCase() : '';

  // ── 1) Apple Live Photo ──────────────────────────────────────
  if (_kAppleExts.contains(ext)) {
    final hasMov = await _hasMovCompanion(url, headers: headers);
    if (hasMov) {
      final movPath = '${path.substring(0, dot)}.mov';
      final movUrl = uri.replace(path: movPath).toString();
      return LivePhotoInfo(type: LivePhotoType.apple, movUrl: movUrl);
    }
  }

  // ── 2) Samsung HEIC (mpvd box) ──────────────────────────────
  if (ext == 'heic' || ext == 'heif') {
    final mpvd = await _findMpvdBox(url, headers: headers);
    if (mpvd != null) {
      final (mpvdOff, mpvdSize) = mpvd;
      // Video data starts after 8-byte box header
      return LivePhotoInfo(
        type: LivePhotoType.samsungHeic,
        fileSize: mpvdSize,
        videoOffset: mpvdOff + 8,
        mpvdSize: mpvdSize,
      );
    }
  }

  // ── 3) Android embedded — XMP-based offset detection (nom-exif approach) ──
  // Matches nom-exif's find_motion_photo_offset(): scan JPEG for XMP APP1,
  // parse GCamera:MicroVideoOffset / GCamera:MotionPhotoOffset / Container:Directory.
  final fileSize = await _fileSize(url, headers: headers);
  if (fileSize < 1024) return const LivePhotoInfo();

  final headerEnd = (64 * 1024).clamp(0, fileSize - 1);
  try {
    final header = await _rangeFetch(url, 0, headerEnd, headers: headers);
    if (_hasXmpMarkers(header)) {
      final headerStr = utf8.decode(header, allowMalformed: true);
      final rawOffset = _parseVideoOffset(headerStr);
      if (rawOffset != null && rawOffset > 0) {
        final videoOffset = fileSize - rawOffset;
        if (videoOffset > 0 && videoOffset < fileSize) {
          return LivePhotoInfo(
            type: LivePhotoType.androidEmbedded,
            fileSize: fileSize,
            videoOffset: videoOffset,
          );
        }
      }
    }
  } catch (_) {
    return const LivePhotoInfo();
  }

  return const LivePhotoInfo();
}

// ── Video extraction ──────────────────────────────────────────

/// Extract the video portion from a live photo and create a [Media].
///
/// Apple:          direct .mov URL.
/// AndroidEmbed:   HTTP Range → Media.memory(videoBytes)
/// SamsungHeic:    HTTP Range of mpvd payload → Media.memory(videoBytes)
Future<Media?> createLiveMedia(
  String url, {
  Map<String, String>? headers,
}) async {
  final info = await phaseLivePhoto(url, headers: headers);
  if (!info.isLive) return null;

  // Apple: direct .mov URL.
  if (info.type == LivePhotoType.apple && info.movUrl != null) {
    return Media(info.movUrl!, httpHeaders: headers);
  }

  // Android Embedded: video appended at end of file.
  if (info.type == LivePhotoType.androidEmbedded &&
      info.videoOffset > 0 &&
      info.videoOffset < info.fileSize) {
    try {
      final videoBytes = await _rangeFetch(
        url,
        info.videoOffset,
        info.fileSize - 1,
        headers: headers,
      );
      if (videoBytes.length < 100) return null;
      return Media.memory(videoBytes);
    } catch (_) {
      return null;
    }
  }

  // Samsung HEIC mpvd: payload starts at videoOffset, size = mpvdSize - 8
  if (info.type == LivePhotoType.samsungHeic &&
      info.videoOffset > 0 &&
      info.mpvdSize > 8) {
    try {
      final videoBytes = await _rangeFetch(
        url,
        info.videoOffset,
        info.videoOffset + info.mpvdSize - 9,
        headers: headers,
      );
      if (videoBytes.length < 100) return null;
      return Media.memory(videoBytes);
    } catch (_) {
      return null;
    }
  }

  return null;
}

/// Clear all detection caches (e.g. on server restart).
void clearLivePhotoCache() {
  _resultCache.clear();
  _pending.clear();
  _headCache.clear();
  _headPending.clear();
}
