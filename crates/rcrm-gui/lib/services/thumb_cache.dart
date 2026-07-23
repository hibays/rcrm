// services/thumb_cache.dart
// Optional on-disk thumbnail cache (video posters + small image thumbnails).
//
// Stored in the app's PRIVATE cache directory (getApplicationCacheDirectory) —
// not user-accessible. Gated by [enabled] (mirrored from settings; default ON
// for mobile, OFF for desktop). All ops are best-effort and never throw.

import 'dart:io';
import 'dart:typed_data';
import 'package:path_provider/path_provider.dart';

class ThumbCache {
  ThumbCache._();

  /// Runtime gate, mirrored from the persisted setting. When false, all reads
  /// return null and writes are no-ops.
  static bool enabled = false;

  /// Stable cache id for a media URL: the file PATH only. The WebDAV
  /// host/port/user/password are randomly regenerated each session, so keying
  /// by the full URL would invalidate the cache on every launch.
  static String pathId(String url) {
    try {
      return Uri.parse(url).path;
    } catch (_) {
      return url;
    }
  }

  static Directory? _dir;
  static Future<Directory> _ensureDir() async {
    if (_dir != null) return _dir!;
    final base = await getApplicationCacheDirectory(); // app-private, hidden
    final d = Directory('${base.path}/._thumbs');
    if (!await d.exists()) await d.create(recursive: true);
    _dir = d;
    return d;
  }

  // FNV-1a 64-bit → hex filename (avoids a crypto dependency).
  static String _key(String s) {
    var h = 0xcbf29ce484222325;
    for (final c in s.codeUnits) {
      h ^= c;
      h = (h * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF;
    }
    return h.toRadixString(16);
  }

  static Future<Uint8List?> read(String id) async {
    if (!enabled) return null;
    try {
      final f = File('${(await _ensureDir()).path}/${_key(id)}');
      if (await f.exists()) return await f.readAsBytes();
    } catch (_) {}
    return null;
  }

  static Future<void> write(String id, Uint8List bytes) async {
    if (!enabled) return;
    try {
      final f = File('${(await _ensureDir()).path}/${_key(id)}');
      await f.writeAsBytes(bytes);
    } catch (_) {}
  }

  /// Total size of all cached files, in bytes.
  static Future<int> sizeBytes() async {
    try {
      final d = await _ensureDir();
      var total = 0;
      await for (final e in d.list()) {
        if (e is File) total += await e.length();
      }
      return total;
    } catch (_) {
      return 0;
    }
  }

  static Future<void> clear() async {
    try {
      final d = await _ensureDir();
      await for (final e in d.list()) {
        if (e is File) {
          try {
            await e.delete();
          } catch (_) {}
        }
      }
    } catch (_) {}
  }

  static String human(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
  }
}
