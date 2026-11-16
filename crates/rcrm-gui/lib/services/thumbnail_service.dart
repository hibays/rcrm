// services/thumbnail_service.dart
// RCrm GUI — video poster generation: one queue, one backend.
//
// Every platform renders the poster inside libmpv itself
// (`poster_libmpv.dart` → `rcrm_generate_poster_async`); this file owns
// everything around that call:
//
//   • an in-memory LRU and the opt-in on-disk ThumbCache (a hit skips the
//     render),
//   • in-flight de-duplication, so one URL is fetched once,
//   • a bounded LIFO stack that starts at most
//     `ItemCacheLimit.videoPosterConcurrency` jobs (`utils/poster_queue.dart`),
//   • a start gate that keeps NEW poster work out of a player route's ENTRANCE
//     (a poster job is a whole decoder; starting one while the player opens
//     competes for the same cores). Running jobs are not interrupted: the
//     libmpv client shares no lock with media_kit's player.
//
// No pixels reach Dart: libmpv renders into a Rust-owned surface and the WebP
// comes back as a buffer Dart views in place. No plaintext reaches the disk
// unless `ThumbCache.enabled`.

import 'dart:async';
import 'dart:typed_data';

import 'package:flutter/foundation.dart' show ChangeNotifier, visibleForTesting;

import '../utils/media_url.dart';
import '../utils/poster_log.dart';
import '../utils/poster_queue.dart';
import 'item_cache_limit.dart';
import 'net.dart';
import 'poster_libmpv.dart';
import 'thumb_cache.dart';

/// Bumped after a poster for a URL has been regenerated, so a mounted
/// `VideoPoster` showing that URL reloads instead of keeping the frame it had.
///
/// A `ChangeNotifier` and not a `ValueNotifier<String?>`: the same URL is
/// refreshed twice in a row often enough ("try again" after a failed decode),
/// and two equal values would notify nobody.
class PosterRefresh extends ChangeNotifier {
  String? lastUrl;

  void bump(String url) {
    lastUrl = url;
    notifyListeners();
  }
}

class ThumbnailService {
  static final _posterCache = <String, Uint8List>{};
  static final _posterInflight = <String, Completer<Uint8List?>>{};

  /// The item menu's "Regenerate thumbnail" writes here; `VideoPoster` listens.
  static final PosterRefresh posterRefresh = PosterRefresh();

  /// Test hook: replaces the body of [generatePoster], so a widget test can drive
  /// a pending / late / null poster without a renderer. The ONE seam: "no
  /// posters" is [noPoster].
  @visibleForTesting
  static Future<Uint8List?> Function(String url)? debugPosterLoader;

  /// The "no poster for anything" answer for [debugPosterLoader].
  @visibleForTesting
  static Future<Uint8List?> noPoster(String url) async => null;

  /// Poster target width. A MAXIMUM: libmpv renders at most this wide (and never
  /// upscales).
  static const int posterWidth = 640;

  /// Throttle: `ItemCacheLimit.videoPosterConcurrency` jobs at a time — one on
  /// a phone, four on a desktop, because a poster job is a whole decoder (its
  /// own libmpv client) either way.
  ///
  /// Waiting jobs, oldest first, so this list IS the stack: index 0 is the
  /// bottom (the entry `admitPosterJob` evicts) and the end is the top (the one
  /// `takePosterJob` runs next). Running jobs are not in here — the runner pops
  /// one as it hands it a slot — so this list is exactly what
  /// `ItemCacheLimit.videoPosterQueueMax` caps.
  static final _posterQ = <PosterJob>[];
  static int _posterRunning = 0;
  static final int _maxRunning = ItemCacheLimit.videoPosterConcurrency;

  // ── Suspension (a player route's ENTRANCE) ──────────────────
  // A poster job decodes on `vd-lavc-threads` (up to 8) threads of its own, and
  // a player route's entrance is opening a file and waiting for its first
  // frame — the moment the user is most likely to notice contention. So no NEW
  // poster job starts while an entrance runs. A job already running is NOT
  // interrupted: it holds no lock the playback player needs, and answering
  // null would become a permanent placeholder. A DEPTH counter, and each route
  // releases ONCE, so it counts "entrances still running".
  static int _posterSuspendDepth = 0;

  /// True while a player route's entrance is still running — i.e. while no new
  /// poster job may start. Test-visible so the depth counter's pairing can be
  /// pinned without a player.
  @visibleForTesting
  static bool get posterSuspended => _posterSuspendDepth > 0;

  /// Stop STARTING poster work. Called by the player route's `install()`, so
  /// the gate closes before that route builds — the playback player is created
  /// inside the push.
  static void suspend() {
    _posterSuspendDepth++;
  }

  /// Let poster work continue. Called by `PosterQuietRoute` once per route: at
  /// the end of its entrance, or from `dispose()` if popped while still
  /// entering.
  static void resume() {
    if (_posterSuspendDepth > 0) _posterSuspendDepth--;
    // Wakes the jobs that were waiting for a slot. A job that was already
    // running keeps running; only the starts were deferred.
    _posterKick();
  }

  static void _posterKick() {
    final plan = planPosterKick(
      queue: _posterQ,
      running: _posterRunning,
      max: _maxRunning,
      suspended: posterSuspended,
    );
    for (var i = 0; i < plan.start; i++) {
      // The TOP of the stack: the newest request is the card on screen now.
      takePosterJob(_posterQ).run();
    }
    // Publish the planned count, not a decrement per start: the jobs handed a
    // slot here are running from this line, whatever a synchronous part of
    // `run` did in between.
    _posterRunning = plan.running;
  }

  // ── Safe URL for the backend ─────────────────────────────────

  /// [raw] without credentials, ready for a backend that authenticates with
  /// headers instead of the URL.
  ///
  /// The input is a canonical `MediaItem.url`; its path was encoded exactly once
  /// by `utils/media_url.dart`. It is carried verbatim — decoding it back into
  /// segments (`uri.pathSegments`) and re-encoding would turn a literal `%20`
  /// filename into a request for a file with a space.
  static String safeUrl(String raw) => withoutUrlCredentials(raw);

  // ── Poster ───────────────────────────────────────────────────

  Future<Uint8List?> generatePoster(
    String videoUrl, {
    bool refresh = false,
    int? durationSeconds,
  }) async {
    final loader = debugPosterLoader;
    if (loader != null) return loader(videoUrl);
    final id = ThumbCache.pathId(videoUrl);
    if (refresh) {
      // A disk entry decoded badly and VideoPoster is asking again. Drop BOTH
      // copies: leaving the bytes in the in-memory LRU would answer every later
      // request with the same bad frame for the rest of the process.
      _posterCache.remove(videoUrl);
      await ThumbCache.remove(id);
    } else {
      final cached = _cacheGet(videoUrl);
      if (cached != null) return cached;
    }

    // On-disk cache (when enabled): a hit skips the render entirely. Keyed by
    // the stable file path so it survives new server sessions.
    //
    // A PURE read: ThumbCache stores opaque bytes — WebP posters and WebP image
    // thumbnails share one directory under different keys — so a reader has no
    // business asserting a format, and a hit must never delete its own entry. A
    // corrupt entry is healed where it is actually detected: just as
    // DiskThumbImage._load removes an entry its codec rejected, VideoPoster's
    // errorBuilder asks for one `refresh` after a decode failure.
    final disk = refresh ? null : await ThumbCache.read(id);
    if (disk != null) {
      _posterCache[videoUrl] = disk;
      return disk;
    }

    // Dedup: same URL already in-flight → reuse its completer.
    final existing = _posterInflight[videoUrl];
    if (existing != null) {
      // Asked for again: take the top of the stack, the poster half of the image
      // gate's `restack`. A job that is already running is not queued, so this
      // is a no-op for it.
      raisePosterJob(_posterQ, videoUrl);
      return existing.future;
    }

    // Where to look is a fraction of the real length, and the libmpv client
    // cannot ask Dart for it, so the plan's input travels with the job.
    final durationHint = durationSeconds == null
        ? Duration.zero
        : Duration(seconds: durationSeconds);

    final completer = Completer<Uint8List?>();
    _posterInflight[videoUrl] = completer;
    final job = PosterJob(
      url: videoUrl,
      completer: completer,
      run: () async {
        Uint8List? result;
        try {
          result = await _runBackend(videoUrl, durationHint);
        } catch (_) {
          result = null;
        }
        try {
          if (result != null && result.isNotEmpty) {
            await _cache(videoUrl, result);
          }
        } catch (_) {
          // Filing the bytes is best-effort: the caller asked for a poster, not
          // for a cache entry, and an answer is still owed either way.
        } finally {
          if (!completer.isCompleted) completer.complete(result);
          _posterInflight.remove(videoUrl);
          _posterRunning--;
          _posterKick();
        }
      },
    );
    // Admission is capped (see `admitPosterJob`): at the limit the oldest
    // *waiting* request is dropped and answered null instead of deferred, so a
    // wall of failing posters cannot grow this queue without bound while every
    // caller keeps a future open. A running job is never the one dropped.
    final evicted = admitPosterJob(
      _posterQ,
      job,
      max: ItemCacheLimit.videoPosterQueueMax,
    );
    if (evicted != null &&
        identical(_posterInflight[evicted.url], evicted.completer)) {
      // No longer in flight. Leaving it in the map would make the next
      // `generatePoster` for that URL reuse an answer already given (null)
      // instead of asking again — the same trap `media_metadata.dart` avoids by
      // caching successes only.
      _posterInflight.remove(evicted.url);
    }
    _posterKick();
    return completer.future;
  }

  /// One run of the libmpv renderer.
  ///
  /// A null answer means "no poster for this file": `VideoCard` paints its
  /// placeholder, and only a `refresh` asks again.
  static Future<Uint8List?> _runBackend(
    String url,
    Duration durationHint,
  ) async {
    final headers = _authHeaders();
    // No auth yet: not a failure, a "later". This returns before the queue is
    // even asked for work, so nothing is retried here — the card asks again on
    // its next mount, which is what the poster cache's real answer will be.
    if (headers == null) return null;

    final result = await LibMpvPoster.generate(
      safeUrl(url),
      headers: headers,
      durationHint: durationHint,
      targetWidth: posterWidth,
    );
    if (result.unavailable) {
      // No renderer in this process: no poster is the honest answer, and the
      // failure is cached in Rust so the next job does not re-probe.
      posterLog('libmpv|unavailable');
      return null;
    }
    return result.bytes;
  }

  /// The server's `Authorization` header as the map the backend takes, or null
  /// when auth is not available yet.
  static Map<String, String>? _authHeaders() {
    final value = sharedAuthHeader?['Authorization'];
    return value == null ? null : {'Authorization': value};
  }

  /// Shared LRU read: on hit, move the key to the most-recently-used end.
  static Uint8List? _cacheGet(String key) {
    final value = _posterCache.remove(key);
    if (value != null) _posterCache[key] = value;
    return value;
  }

  Future<void> _cache(String key, Uint8List bytes) async {
    if (_posterCache.length >= ItemCacheLimit.videoPosterMemoryCacheMax) {
      _posterCache.remove(_posterCache.keys.first);
    }
    _posterCache[key] = bytes;
    // Awaited: the next cell (or the next process) must never meet a file that
    // is still being written. `write` is best-effort and never throws.
    await ThumbCache.write(ThumbCache.pathId(key), bytes);
  }
}
