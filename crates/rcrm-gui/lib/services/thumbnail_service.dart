// services/thumbnail_service.dart
// RCrm GUI — video poster generation.
//
// Desktop (Windows/Linux/macOS): system ffmpeg CLI (PATH), stdout pipe → RAM.
// Mobile (Android/iOS): media_kit Player.screenshot → RAM.
// Zero disk writes. In-memory LRU cache. Throttled to [_maxRunning] concurrent.

import 'dart:async';
import 'dart:io' show Process;
import 'dart:isolate';
import 'dart:typed_data';
import 'dart:ffi';
import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart' show visibleForTesting;
import 'package:media_kit/media_kit.dart';
import 'package:media_kit_video/media_kit_video.dart';
import '../ffi/rust_bridge.dart';
import 'item_cache_limit.dart';
import 'thumb_cache.dart';
import 'net.dart';

class ThumbnailService {
  static final _posterCache = <String, Uint8List>{};
  static final _posterInflight = <String, Completer<Uint8List?>>{};

  /// Test hook: when true, generatePoster returns null immediately without
  /// enqueueing work or starting the 30s idle pool timer. Widget tests that
  /// render VideoCards use this to avoid pending-timer failures.
  @visibleForTesting
  static bool suppressPosterGeneration = false;

  /// Poster width in pixels. Mobile constrains the Player surface to this
  /// width (VideoControllerConfiguration); desktop passes it to ffmpeg
  /// (`-vf scale=$_posterWidth:-1`). Both emit 640-wide JPEG.
  static const int _posterWidth = 640;

  /// Throttle: mobile serializes (1) through a single reused Player to bound
  /// memory; desktop runs several ffmpeg processes in parallel.
  static final _posterQ = <void Function()>[];
  static int _posterRunning = 0;
  static final int _maxRunning = ItemCacheLimit.videoPosterConcurrency;

  static void _posterKick() {
    _tnIdleTimer?.cancel();
    while (_posterRunning < _maxRunning && _posterQ.isNotEmpty) {
      _posterRunning++;
      _posterQ.removeAt(0)();
    }
    if (_posterQ.isEmpty && _posterRunning == 0) {
      _tnIdleTimer = Timer(const Duration(seconds: 30), _tnDisposePool);
    }
  }

  // ── Safe URL encoding (desktop ffmpeg) ───────────────────

  /// Encode path segments for ffmpeg URL (auth via -headers, not in URL).
  static String safeUrl(String raw) {
    final uri = Uri.parse(raw);
    final encodedPath = uri.pathSegments
        .map((s) => Uri.encodeComponent(s))
        .join('/');
    final q = uri.query.isNotEmpty ? '?${uri.query}' : '';
    return '${uri.scheme}://${uri.host}:${uri.port}/$encodedPath$q';
  }

  // ── Poster ───────────────────────────────────────────────

  Future<Uint8List?> generatePoster(String videoUrl) async {
    if (suppressPosterGeneration) return null;
    final cached = _cacheGet(videoUrl);
    if (cached != null) return cached;

    // On-disk cache (when enabled): a hit skips ffmpeg/screenshot entirely.
    // Keyed by the stable file path so it survives new server sessions.
    final disk = await ThumbCache.read(ThumbCache.pathId(videoUrl));
    if (disk != null) {
      _posterCache[videoUrl] = disk;
      return disk;
    }

    // Dedup: same URL already in-flight → reuse its completer.
    final existing = _posterInflight[videoUrl];
    if (existing != null) return existing.future;

    final completer = Completer<Uint8List?>();
    _posterInflight[videoUrl] = completer;
    _posterQ.add(() async {
      try {
        final result = isMobile
            ? await _posterMobile(videoUrl)
            : await _posterDesktop(videoUrl);
        if (!completer.isCompleted) completer.complete(result);
      } catch (_) {
        if (!completer.isCompleted) completer.complete(null);
      } finally {
        _posterInflight.remove(videoUrl);
        _posterRunning--;
        _posterKick();
      }
    });
    _posterKick();
    return completer.future;
  }

  /// Desktop: system ffmpeg CLI, stdout pipe → RAM, blank-frame detection.
  Future<Uint8List?> _posterDesktop(String videoUrl) async {
    final cached = _cacheGet(videoUrl);
    if (cached != null) return cached;

    // If auth isn't available yet, don't generate — retry later.
    if (sharedAuthHeader == null) return null;

    final authVal = sharedAuthHeader!['Authorization']!;
    final headerLine = 'Authorization: $authVal';
    final safe = safeUrl(videoUrl); // no creds in URL

    const positions = [0.0, 30.0, 15.0, 0.5, 3.0, 60.0, 120.0, 240.0];
    for (final inputSeek in [true, false]) {
      for (final pos in positions) {
        final ss = pos.toString();
        final args = inputSeek
            ? [
                '-headers',
                headerLine,
                '-ss',
                ss,
                '-an',
                '-i',
                safe,
                '-vframes',
                '1',
                '-q:v',
                '3',
                '-vf',
                'scale=$_posterWidth:-1',
                '-f',
                'image2',
                '-c:v',
                'mjpeg',
                'pipe:1',
              ]
            : [
                '-headers',
                headerLine,
                '-an',
                '-i',
                safe,
                '-ss',
                ss,
                '-vframes',
                '1',
                '-q:v',
                '3',
                '-vf',
                'scale=$_posterWidth:-1',
                '-f',
                'image2',
                '-c:v',
                'mjpeg',
                'pipe:1',
              ];
        Uint8List? bytes;
        try {
          final r = await Process.run(
            'ffmpeg',
            args,
            stdoutEncoding: null,
            stderrEncoding: null,
          );
          bytes = r.exitCode == 0
              ? (r.stdout is Uint8List
                    ? r.stdout as Uint8List
                    : Uint8List.fromList(r.stdout as List<int>))
              : null;
        } catch (_) {
          bytes = null;
        }
        if (bytes != null &&
            bytes.isNotEmpty &&
            bytes.length > 2000 &&
            !(await _isBlank(bytes))) {
          _cache(videoUrl, bytes);
          return bytes;
        }
      }
    }
    return null;
  }

  // ── Mobile: a pool of reused Player+VideoController, one per concurrency slot ─
  // The pool size equals [ItemCacheLimit.videoPosterConcurrency]. Players are
  // created lazily when the first task runs and disposed after 30s idle.
  // [_tnFreeSlots] holds the indices of idle slots; acquiring pops one
  // and releasing pushes it back (O(1), no scanning).
  static final List<Player> _tnPlayers = [];
  static final List<VideoController> _tnControllers = [];
  static final List<int> _tnFreeSlots = [];
  static Timer? _tnIdleTimer;

  static void _tnEnsurePool() {
    final n = ItemCacheLimit.videoPosterConcurrency;
    while (_tnPlayers.length < n) {
      final p = Player();
      p.setVolume(0);
      final c = VideoController(
        p,
        configuration: VideoControllerConfiguration(width: _posterWidth),
      );
      _tnPlayers.add(p);
      _tnControllers.add(c);
      _tnFreeSlots.add(_tnPlayers.length - 1);
    }
  }

  /// Acquire a free slot index, or -1 if none are free (shouldn't happen while
  /// the [_maxRunning] gate holds). Pops the slot off the free stack.
  static int _tnAcquireSlot() =>
      _tnFreeSlots.isEmpty ? -1 : _tnFreeSlots.removeLast();

  static void _tnReleaseSlot(int slot) {
    // Guard against a stale release: if the pool is ever torn down mid-task
    // (_tnDisposePool on the idle timer races an in-flight screenshot), the
    // in-flight task's finally() would push an index that no longer belongs to
    // the (possibly rebuilt) pool — duplicating a slot so two tasks share one
    // Player. Drop out-of-range and already-free slots.
    if (slot < 0 || slot >= _tnPlayers.length) return;
    if (_tnFreeSlots.contains(slot)) return;
    _tnFreeSlots.add(slot);
  }

  static void _tnDisposePool() {
    _tnIdleTimer?.cancel();
    _tnIdleTimer = null;
    for (final p in _tnPlayers) {
      try {
        p.dispose();
      } catch (_) {}
    }
    _tnPlayers.clear();
    _tnControllers.clear();
    _tnFreeSlots.clear();
  }

  /// Wait for the player to actually reach [target] after a seek by listening
  /// to its position stream (no busy polling). Seek completion is asynchronous
  /// and a blind delay either wastes time on fast devices or captures the wrong
  /// frame on slow ones. Tolerance covers the slight undershoot media_kit
  /// reports. A timeout bounds the wait if the stream stalls.
  static Future<void> _waitForSeek(Player player, Duration target) async {
    const tolerance = Duration(milliseconds: 200);
    if ((player.state.position - target).abs() <= tolerance) return;
    final done = Completer<void>();
    final sub = player.stream.position.listen((pos) {
      if ((pos - target).abs() <= tolerance && !done.isCompleted) {
        done.complete();
      }
    });
    try {
      await done.future.timeout(const Duration(seconds: 4));
    } catch (_) {
      // Stream stalled or seek never reported — let the screenshot attempt
      // proceed anyway; isBlank will reject a bad frame and we retry.
    } finally {
      await sub.cancel();
    }
  }

  Future<Uint8List?> _posterMobile(String videoUrl) async {
    final cached = _cacheGet(videoUrl);
    if (cached != null) return cached;

    // If auth isn't available yet, don't generate — retry later.
    if (sharedAuthHeader == null) return null;

    // Lazy pool creation and free-competition slot acquisition.
    _tnEnsurePool();
    final slot = _tnAcquireSlot();
    if (slot < 0) return null;
    final player = _tnPlayers[slot];
    final controller = _tnControllers[slot];
    Uint8List? result;
    try {
      await player
          .open(Media(videoUrl, httpHeaders: sharedAuthHeader), play: true)
          .timeout(const Duration(seconds: 15));
      try {
        await controller.waitUntilFirstFrameRendered.timeout(
          const Duration(seconds: 15),
        );
      } catch (_) {}
      player.pause();

      final dur = player.state.duration;
      const positions = [0.0, 30.0, 15.0, 0.5, 3.0, 60.0, 120.0, 240.0];
      for (final pos in positions) {
        final seekTo = Duration(milliseconds: (pos * 1000).round());
        if (dur > Duration.zero && seekTo > dur) continue;
        try {
          await player.seek(seekTo).timeout(const Duration(seconds: 5));
          await _waitForSeek(player, seekTo);
        } catch (_) {}
        Uint8List? bytes;
        try {
          bytes = await player
              .screenshot(format: 'image/jpeg')
              .timeout(const Duration(seconds: 9));
        } catch (_) {
          bytes = null;
        }
        if (bytes == null || bytes.isEmpty) continue;
        if (bytes.length > 2000 && !(await _isBlank(bytes))) {
          _cache(videoUrl, bytes);
          result = bytes;
          return result;
        }
      }
    } catch (_) {
      try {
        await player.stop();
      } catch (_) {}
    } finally {
      _tnReleaseSlot(slot);
    }
    return result;
  }

  /// Shared LRU read: on hit, move the key to the most-recently-used end.
  static Uint8List? _cacheGet(String key) {
    final v = _posterCache.remove(key);
    if (v != null) _posterCache[key] = v;
    return v;
  }

  void _cache(String key, Uint8List bytes) {
    if (_posterCache.length >= ItemCacheLimit.videoPosterMemoryCacheMax) {
      _posterCache.remove(_posterCache.keys.first);
    }
    _posterCache[key] = bytes;
    ThumbCache.write(ThumbCache.pathId(key), bytes);
  }

  static Future<bool> _isBlank(Uint8List jpgBytes) async {
    return Isolate.run(() {
      final bridge = RustBridge();
      if (!bridge.isLoaded) {
        try {
          bridge.load();
        } catch (_) {
          return false;
        }
      }
      final ptr = malloc<Uint8>(jpgBytes.length);
      ptr.asTypedList(jpgBytes.length).setAll(0, jpgBytes);
      final r = bridge.isBlankFrame(ptr, jpgBytes.length);
      malloc.free(ptr);
      return r == 1;
    });
  }
}
