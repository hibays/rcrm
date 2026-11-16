// services/thumbnail_service.dart
// RCrm GUI — video poster generation: one queue, two backends.
//
// The backend is `utils/poster_backend.dart`'s decision — libmpv renders the
// frame itself on every platform that can load it, media_kit's screenshot
// (`poster_mpv.dart`) on iOS and in builds without the export — and everything
// in this file is backend-agnostic:
//
//   • an in-memory LRU and the opt-in on-disk ThumbCache (a hit skips both),
//   • in-flight de-duplication, so one URL is fetched once,
//   • a bounded queue that starts at most
//     `ItemCacheLimit.videoPosterConcurrency` jobs (`utils/poster_queue.dart`),
//   • a suspension gate that keeps poster work out of a player route's ENTRANCE
//     and parks a running media_kit job (see `PosterParking`); it opens as soon
//     as the step is over, because that route's own Related list needs posters.
//
// No pixels reach Dart on the libmpv path, and no plaintext reaches the disk on
// either path unless `ThumbCache.enabled`.

import 'dart:async';
import 'dart:typed_data';

import 'package:flutter/foundation.dart'
    show ChangeNotifier, visibleForTesting;

import '../utils/media_url.dart';
import '../utils/poster_backend.dart';
import '../utils/poster_log.dart';
import '../utils/poster_queue.dart';
import 'item_cache_limit.dart';
import 'net.dart';
import 'poster_libmpv.dart';
import 'poster_mpv.dart';
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
  /// a pending / late / null poster without a player. The ONE seam: "no posters"
  /// is [noPoster].
  @visibleForTesting
  static Future<Uint8List?> Function(String url)? debugPosterLoader;

  /// The "no poster for anything" answer for [debugPosterLoader].
  @visibleForTesting
  static Future<Uint8List?> noPoster(String url) async => null;

  /// The parking contract handed to the media_kit backend, for tests.
  @visibleForTesting
  static PosterParking get posterParking => _parking;

  /// Poster target width, a MAXIMUM for both backends: libmpv renders at most
  /// this wide (and never upscales), and the media_kit path hands it to the Rust
  /// encoder, which only ever downscales.
  static const int posterWidth = 640;

  /// Throttle: `ItemCacheLimit.videoPosterConcurrency` jobs at a time — one on
  /// a phone, four on a desktop, because a poster job is a whole decoder either
  /// way (an mpv context on the libmpv path, a media_kit Player on the other).
  ///
  /// Waiting jobs, oldest first, so this list IS the stack: index 0 is the
  /// bottom (the entry `admitPosterJob` evicts) and the end is the top (the one
  /// `takePosterJob` runs next). Running jobs are not in here — the runner pops
  /// one as it hands it a slot — so this list is exactly what
  /// `ItemCacheLimit.videoPosterQueueMax` caps.
  static final _posterQ = <PosterJob>[];
  static int _posterRunning = 0;
  static final int _maxRunning = ItemCacheLimit.videoPosterConcurrency;

  /// The queue's side of the parking contract, handed to the media_kit backend.
  static const PosterParking _parking = _ServiceParking();

  // ── Suspension (a player route's ENTRANCE) ──────────────────
  // A poster job holds media_kit's static `NativePlayer.lock` across `open` and
  // each `seek`+`screenshot`, so `PosterQuietRoute` closes this gate before its
  // page builds and releases it when that entrance's ticker ends — not when the
  // route goes away: the route's own Related list needs posters. A DEPTH counter,
  // and each route releases ONCE, so it counts "entrances still running".
  static int _posterSuspendDepth = 0;

  /// How many suspended jobs are held right now. Read by the kick plan: a
  /// parked job still owns its slot and may be mid-`open`, so nothing else may
  /// start until it is back in its loop.
  static int _posterParked = 0;

  /// Wakes every parked job when the gate opens. A broadcast stream, not a
  /// one-shot `Completer`: a second `resume()` used to complete it again and
  /// throw `Bad state: Future already completed` out of `dispose()`. An event
  /// with no listener is dropped, which is what a job that has not asked wants.
  static final StreamController<void> _posterResume =
      StreamController<void>.broadcast();

  /// True while a player route's entrance is still running — i.e. while the
  /// poster pool must stay quiet. Test-visible so the depth counter's pairing can
  /// be pinned without a media_kit Player.
  @visibleForTesting
  static bool get posterSuspended => _posterSuspendDepth > 0;

  /// Stop starting poster work and park what is running. Called by the player
  /// route's `install()`, so the gate closes before that route builds — the
  /// playback player is created inside the push, and the pool must already be
  /// quiet by then.
  static void suspend() {
    _posterSuspendDepth++;
    // The "pool is idle exactly when the push happens" case: that idle timer
    // would otherwise fire during playback and dispose the pool then.
    _poolIdleTimer?.cancel();
    _poolIdleTimer = null;
  }

  /// Let poster work continue. Called by `PosterQuietRoute` once per route: at the
  /// end of its entrance, or from `dispose()` if popped while still entering.
  static void resume() {
    if (_posterSuspendDepth > 0) _posterSuspendDepth--;
    if (_posterSuspendDepth == 0) _posterResume.add(null);
    // Wakes the jobs that were waiting for a slot, and arms the idle timer
    // again — `_posterKick` does both, and it refuses to arm it while suspended.
    _posterKick();
  }

  /// STICKY on purpose: the flag is read and the waiter created in one
  /// synchronous step. A job asks after a native `player.stop()`, and the route
  /// can be disposed inside that window — a waiter created then would wait for a
  /// resume already given, staying parked for ever with every kick blocked.
  static Future<void> _waitForPosterResume() {
    if (!posterSuspended) return Future<void>.value();
    return _posterResume.stream.first;
  }

  static void _parkJob() => _posterParked++;

  static void _unparkJob() {
    _posterParked--;
    // The parked job's departure is what lets waiting work move: the kick
    // refuses to start anything while a job is still parked.
    _posterKick();
  }

  static void _posterKick() {
    _poolIdleTimer?.cancel();
    final plan = planPosterKick(
      queue: _posterQ,
      running: _posterRunning,
      max: _maxRunning,
      suspended: posterSuspended,
      anyParked: _posterParked > 0,
    );
    for (var i = 0; i < plan.start; i++) {
      // The TOP of the stack: the newest request is the card on screen now.
      takePosterJob(_posterQ).run();
    }
    // Publish the planned count, not a decrement per start: the jobs handed a
    // slot here are running from this line, whatever a synchronous part of
    // `run` did in between.
    _posterRunning = plan.running;
    if (_posterQ.isEmpty && _posterRunning == 0) {
      // Never arm it while suspended: a pool that has just been parked (or one
      // that has no job at all) must not be disposed out from under the route
      // that suspended it. `resume()` kicks, and that is when it is armed.
      if (!posterSuspended) {
        _poolIdleTimer = Timer(const Duration(seconds: 30), _disposePool);
      }
    }
  }

  // ── The pool's idle lifecycle (owned here, because the queue knows) ──

  static Timer? _poolIdleTimer;

  /// Dispose the backend's pooled players after 30s with nothing to do.
  static void _disposePool() {
    _poolIdleTimer?.cancel();
    _poolIdleTimer = null;
    // The idle timer is armed only when both are empty/zero, so this is the
    // invariant rather than a new condition — but it is a hard one: a live job
    // is either inside a native call or parked holding its slot, and disposing
    // its player in either state is a native crash. Refuse instead.
    if (_posterRunning != 0 || _posterQ.isNotEmpty) return;
    MpvPoster.disposePool();
  }

  // ── Safe URL for the backends ────────────────────────────────

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

    // On-disk cache (when enabled): a hit skips both backends entirely. Keyed
    // by the stable file path so it survives new server sessions.
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

    // Where to look is a fraction of the real length, and the libmpv backend
    // cannot ask Dart for it, so the plan's input travels with the job. The
    // media_kit backend prefers the length the player itself reports and uses
    // this only as the fallback (see `posterSeekPlan`).
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
          if (result != null && result.isNotEmpty) await _cache(videoUrl, result);
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

  /// One run of whichever backend this build uses.
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

    switch (posterBackendForThisBuild()) {
      case PosterBackend.libmpv:
        final result = await LibMpvPoster.generate(
          safeUrl(url),
          headers: headers,
          durationHint: durationHint,
          targetWidth: posterWidth,
        );
        if (!result.unavailable) return result.bytes;
        // The export exists but libmpv itself will not load here. Under
        // media_kit the same app can still take a screenshot, so use it; on a
        // desktop target the player needs that very library, so no poster is
        // the honest answer rather than a second doomed attempt.
        posterLog('libmpv|unavailable|falling_back=${isMobile ? 'mpv' : 'none'}');
        if (!isMobile) return null;
        return MpvPoster.generate(
          url,
          headers: headers,
          durationHint: durationHint,
          targetWidth: posterWidth,
          parking: _parking,
        );
      case PosterBackend.mpv:
        return MpvPoster.generate(
          url,
          headers: headers,
          durationHint: durationHint,
          targetWidth: posterWidth,
          parking: _parking,
        );
    }
  }

  /// The server's `Authorization` header as the map both backends take, or null
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

/// `ThumbnailService`'s side of `PosterParking`: the backend only waits, the
/// queue owns the counts.
class _ServiceParking implements PosterParking {
  const _ServiceParking();

  @override
  bool get suspended => ThumbnailService.posterSuspended;

  @override
  void park() => ThumbnailService._parkJob();

  @override
  void unpark() => ThumbnailService._unparkJob();

  @override
  Future<void> waitForResume() => ThumbnailService._waitForPosterResume();
}
