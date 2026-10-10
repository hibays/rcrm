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
import '../utils/poster_queue.dart';
import 'item_cache_limit.dart';
import 'player_factory.dart';
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
  ///
  /// Waiting jobs, oldest first. Running jobs are not in here — the runner pops
  /// one as it hands it a slot — so this list is exactly what
  /// `ItemCacheLimit.videoPosterQueueMax` caps (see `admitPosterJob`).
  static final _posterQ = <PosterJob>[];
  static int _posterRunning = 0;
  static final int _maxRunning = ItemCacheLimit.videoPosterConcurrency;

  // ── Suspension (the player route owns the screen) ────────────
  // Poster players and the playback player share media_kit's STATIC
  // `NativePlayer.lock`, so one mobile poster job — which holds it across
  // `open`, and again across each `seek` + `screenshot` — is enough to make the
  // playback player's `open`/`play` wait. While the player route is installed,
  // the pool therefore starts nothing new and parks what it is already running.
  //
  // A DEPTH counter, not a bool: `_go`'s `pushReplacement` makes the outgoing
  // screen's `dispose` and the incoming route's `install` overlap, and with a
  // bool the first of those to run would lift the suspension while the other
  // route is still on screen.
  static int _posterSuspendDepth = 0;

  /// How many suspended jobs are held right now. Read by the kick plan: a
  /// parked job still owns its slot and may be mid-`open`, so nothing else may
  /// start until it is back in its loop.
  static int _posterParked = 0;

  static Completer<void>? _posterWake;

  /// Resolves when a suspended job may carry on. Created on demand and
  /// recreated once completed, so `resume()` always has a fresh one to signal
  /// and a job can await it any number of times.
  static Completer<void> get _posterResumeSignal {
    final wake = _posterWake;
    if (wake != null && !wake.isCompleted) return wake;
    return _posterWake = Completer<void>();
  }

  /// True while a player route is installed. Test-visible so the depth counter's
  /// pairing can be pinned without a media_kit `Player`.
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
    _tnIdleTimer?.cancel();
    _tnIdleTimer = null;
  }

  /// Let poster work continue: wake every parked job and restart the queue.
  /// Called by the player route's `dispose()`, so a pop or a replace both lift
  /// the gate immediately — no delay, and no ping-pong while the two overlap.
  static void resume() {
    if (_posterSuspendDepth > 0) _posterSuspendDepth--;
    if (_posterSuspendDepth == 0) _posterWake?.complete();
    // Wakes the jobs that were waiting for a slot, and arms the idle timer
    // again — `_posterKick` does both, and it refuses to arm it while suspended.
    _posterKick();
  }

  /// Park here until the suspension lifts. A parked job keeps its completer, its
  /// slot and its `_posterInflight` entry: it is never answered with null, never
  /// evicted and never re-admitted (see `_posterMobile`).
  static Future<void> _posterWaitForResume() => _posterResumeSignal.future;

  static void _posterKick() {
    _tnIdleTimer?.cancel();
    final plan = planPosterKick(
      queue: _posterQ,
      running: _posterRunning,
      max: _maxRunning,
      suspended: posterSuspended,
      anyParked: _posterParked > 0,
    );
    for (var i = 0; i < plan.start; i++) {
      final job = _posterQ.removeAt(0);
      // Before it runs, so the admission rule can never pick a job that already
      // owns a slot even if one were still in the list.
      job.started = true;
      job.run();
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
        _tnIdleTimer = Timer(const Duration(seconds: 30), _tnDisposePool);
      }
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
    final job = PosterJob(
      url: videoUrl,
      completer: completer,
      run: () async {
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

  /// Desktop: system ffmpeg CLI, stdout pipe → RAM, blank-frame detection.
  Future<Uint8List?> _posterDesktop(String videoUrl) async {
    final cached = _cacheGet(videoUrl);
    if (cached != null) return cached;

    // If auth isn't available yet, don't generate — retry later.
    if (sharedAuthHeader == null) return null;

    // The header map exists but is not guaranteed to carry the key: a missing
    // one must degrade to "no poster yet", not throw a null-check error.
    final authVal = sharedAuthHeader?['Authorization'];
    if (authVal == null) return null;
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
      final p = PlayerFactory.poster();
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
    // The idle timer is armed only when both are empty/zero, so this is the
    // invariant rather than a new condition — but it is a hard one: a live job
    // is either inside `screenshot()` (which holds the lock across a `compute`
    // the wrapper does not re-check `disposed` for) or parked holding its slot.
    // Disposing its player in either state is a native crash, so refuse instead.
    if (_posterRunning != 0 || _posterQ.isNotEmpty) return;
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
    // PARKED, NOT DROPPED. A job suspended mid-run finishes with real bytes or
    // with the "no poster" answer its own attempts produced — never with an
    // early null. A null makes `VideoCard` paint its gray placeholder, and
    // nothing retries: the card asked once per mount and the poster cache stores
    // successes only. So every card that was loading when the player opened
    // would stay blank for good after the user came back. That is why this job
    // keeps its completer pending, its slot (a running job is never evictable)
    // and its `_posterInflight` entry — a re-request joins this future — and why
    // it is never re-queued and never passes through `admitPosterJob` again.
    // True only while this job is parked, so the `finally` can tell "nothing was
    // left behind" from "the re-open threw while the pool was still holding us".
    var parked = false;
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
        // Yield point, taken BEFORE the seek: the player is between `open` and
        // the next lock-holding call, and each of seek/_waitForSeek/screenshot
        // is its own `lock.synchronized`, so the static `NativePlayer.lock` is
        // genuinely free here and playback's `open`/`play` can have it.
        // `_waitForSeek` is deliberately not a yield point — it is a stream
        // wait, lock-free already.
        while (posterSuspended) {
          parked = true;
          _posterParked++;
          try {
            try {
              await player.stop();
              // `stop()` is where a suspended job lets the lock go. No timeout:
              // timing out here could only answer this caller with null, and the
              // contract above says a parked job is never answered with null —
              // `resume()` is the one way out, and the route that suspended us
              // always reaches `dispose`.
              await _posterWaitForResume();
            } finally {
              _posterParked--;
            }
          } finally {
            // The parked job leaves even when the wait throws, and its own
            // departure is what kicks the queue again.
            _posterKick();
          }
          if (!posterSuspended) {
            // Re-open, because `stop()` ended the media session: without this
            // the remaining positions would seek a player with nothing loaded.
            // The single `continue` re-checks the gate at the top.
            await player
                .open(Media(videoUrl, httpHeaders: sharedAuthHeader), play: true)
                .timeout(const Duration(seconds: 15));
            parked = false;
          }
        }
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
      // Only if the re-open threw: otherwise the gate's own loop released both.
      if (parked) {
        _posterParked--;
        _posterKick();
      }
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
