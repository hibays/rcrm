// services/poster_mpv.dart
// The media_kit poster backend: one `Player.screenshot` per attempt, encoded by
// Rust.
//
// This is iOS's backend — media_kit links libmpv statically into the app there,
// so there is no shared library to load — and the fallback wherever a build has
// no `libmpv-poster` export. Every other platform uses `poster_libmpv.dart`,
// where libmpv renders the frame directly.
//
// A pool of reused `Player` + `VideoController` pairs (one per concurrency
// slot) is what makes this affordable: creating a player per poster costs an
// open, a first frame and a dispose, and the poster grid asks for dozens. The
// players are created lazily and disposed by the caller's idle timer
// (`ThumbnailService`), because the queue is what knows when nothing is
// running.
//
// Zero disk writes: the screenshot stays in RAM, Rust encodes it in RAM.

import 'dart:async';
import 'dart:ffi';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:media_kit/media_kit.dart';
import 'package:media_kit_video/media_kit_video.dart';

import '../ffi/rust_bridge.dart';
import '../utils/poster_frame.dart';
import '../utils/poster_log.dart';
import '../utils/poster_queue.dart';
import 'item_cache_limit.dart';
import 'player_factory.dart';
import 'thumb_webp_worker.dart';

class MpvPoster {
  MpvPoster._();

  /// Shot budget per position: the first ask plus two re-shots, 80ms apart, for
  /// the case where the video output hands back the frame it already had. On
  /// every sample measured, a missed 1080p seek landed on the first retry.
  static const int _staleRetries = 3;
  static const Duration _staleWait = Duration(milliseconds: 80);

  /// Bounds on every wait, so one unresponsive file cannot hold a poster slot
  /// forever. Each is generous: a seek on a slow phone is seconds, not
  /// milliseconds.
  static const Duration _openTimeout = Duration(seconds: 15);
  static const Duration _firstFrameTimeout = Duration(seconds: 15);
  static const Duration _seekTimeout = Duration(seconds: 5);
  static const Duration _shotTimeout = Duration(seconds: 9);

  /// Seek completion tolerance. Two-sided: the old one-sided comparison let a
  /// seek to 0 return immediately with a stale position.
  static const Duration _seekTolerance = Duration(milliseconds: 200);

  // ── The pool ─────────────────────────────────────────────────
  // One player per concurrency slot, created lazily when the first job runs.
  // [_freeSlots] holds the indices of idle slots; acquiring pops one and
  // releasing pushes it back (O(1), no scanning).
  static final List<Player> _players = [];
  static final List<VideoController> _controllers = [];
  static final List<int> _freeSlots = [];

  /// Dispose every pooled player. Only valid when no job is running: a live job
  /// is either inside `screenshot()` (which is a native call Dart cannot
  /// interrupt) or parked holding its slot, and disposing its player in either
  /// state is a native crash. The caller — `ThumbnailService`'s idle timer —
  /// tests that before calling.
  static void disposePool() {
    for (final player in _players) {
      try {
        player.dispose();
      } catch (_) {}
    }
    _players.clear();
    _controllers.clear();
    _freeSlots.clear();
  }

  static void _ensurePool(int targetWidth) {
    final size = ItemCacheLimit.videoPosterConcurrency;
    while (_players.length < size) {
      final player = PlayerFactory.poster();
      player.setVolume(0);
      // A plain constructor: it stores the player and starts an async
      // controller creation, so it cannot fail here (a failed creation shows up
      // later as `waitUntilFirstFrameRendered` throwing, which the caller
      // already catches). Nothing to roll back.
      final controller = VideoController(
        player,
        configuration: VideoControllerConfiguration(width: targetWidth),
      );
      _players.add(player);
      _controllers.add(controller);
      _freeSlots.add(_players.length - 1);
    }
  }

  static int _acquireSlot() =>
      _freeSlots.isEmpty ? -1 : _freeSlots.removeLast();

  /// Guard against a stale release: if the pool is ever torn down between a
  /// job's acquire and its release, the job's index no longer belongs to the
  /// (possibly rebuilt) pool, and pushing it would duplicate a slot so two jobs
  /// share one player.
  static void _releaseSlot(int slot) {
    if (slot < 0 || slot >= _players.length) return;
    if (_freeSlots.contains(slot)) return;
    _freeSlots.add(slot);
  }

  /// Generate a poster with a media_kit screenshot.
  ///
  /// [headers] are the HTTP headers the server wants (the app's own auth
  /// header); [durationHint] is the length the scan knows, used only when the
  /// player cannot report one; [parking] is the queue's suspension gate — while
  /// a player route owns the screen this job parks instead of holding
  /// media_kit's static `NativePlayer.lock` across the playback player's
  /// `open`.
  static Future<Uint8List?> generate(
    String url, {
    required Map<String, String> headers,
    required Duration durationHint,
    required int targetWidth,
    required PosterParking parking,
  }) async {
    _ensurePool(targetWidth);
    final slot = _acquireSlot();
    if (slot < 0) return null;
    final player = _players[slot];
    Uint8List? result;
    try {
      await player
          .open(Media(url, httpHeaders: headers), play: true)
          .timeout(_openTimeout);
      try {
        await _controllers[slot].waitUntilFirstFrameRendered.timeout(
          _firstFrameTimeout,
        );
      } catch (_) {}
      player.pause();

      final duration = player.state.duration > Duration.zero
          ? player.state.duration
          : durationHint;
      // The video's OWN pixel size, which is also the size `screenshot-raw`
      // hands back (a `VideoControllerConfiguration(width: 640)` only sizes the
      // texture). Null until a frame has been rendered, in which case every
      // position falls back to media_kit's JPEG path.
      final videoWidth = player.state.width;
      final videoHeight = player.state.height;
      final rawUsable =
          videoWidth != null &&
          videoHeight != null &&
          videoWidth > 0 &&
          videoHeight > 0;
      posterLog('mpv|source=${videoWidth}x$videoHeight|target=$targetWidth');
      // Where to look: `poster_frame.dart`.
      final positions = posterSeekPlan(duration);
      posterLog('mpv|plan=${positions.join(',')}');
      final started = DateTime.now();

      // The last RAW frame this job actually LOOKED at. It is seeded from a
      // capture taken BEFORE the first seek: the player is paused on the
      // pre-seek frame, and a seek can hand that same frame back (measured
      // 25-75% of paused-seek screenshots). Without that baseline the FIRST
      // candidate could not be noticed as stale.
      //
      // Raw and JPEG have separate baselines because their bytes are not
      // comparable, and the raw frame is kept in the representation it arrived
      // in (BGRA) — the channel swap, blank test and downscale are Rust's job.
      Uint8List? previousRaw;
      Uint8List? previousJpeg;
      var baselined = false;
      for (final position in positions) {
        // Yield point, taken BEFORE the seek: the player is between `open` and
        // the next lock-holding call, and each of seek/_waitForSeek/screenshot
        // is its own `lock.synchronized`, so the static `NativePlayer.lock` is
        // genuinely free here and playback's `open`/`play` can have it.
        while (parking.suspended) {
          // PARKED, NOT DROPPED. A job suspended mid-run finishes with real
          // bytes or with the "no poster" answer its own attempts produced —
          // never with an early null. A null makes `VideoCard` paint its grey
          // placeholder and nothing retries, so every card that was loading
          // when the player opened would stay blank for good after the user
          // came back. That is why this job keeps its completer pending, its
          // slot (a running job is never evictable) and its in-flight entry.
          await _park(player, url, headers, parking);
        }
        if (!baselined) {
          baselined = true;
          // The pre-seek frame, wanted only so the FIRST post-seek screenshot
          // can be recognised as stale. One extra capture per poster job.
          if (rawUsable) {
            final base = await _tryShot(player);
            if (base != null && base.length == videoWidth * videoHeight * 4) {
              previousRaw = base;
              posterLog('mpv|baseline|raw|bytes=${base.length}');
            }
          }
          if (previousRaw == null) {
            final baseJpeg = await _tryShot(player, 'image/jpeg');
            if (baseJpeg != null && baseJpeg.isNotEmpty) {
              previousJpeg = baseJpeg;
              posterLog('mpv|baseline|jpeg|bytes=${baseJpeg.length}');
            }
          }
        }
        final seekTo = Duration(milliseconds: (position * 1000).round());
        if (duration > Duration.zero && seekTo >= duration) continue;
        try {
          await player.seek(seekTo).timeout(_seekTimeout);
          await _waitForSeek(player, seekTo);
        } catch (_) {}
        Uint8List? bytes;
        var blank = false;
        for (var attempt = 0; attempt < _staleRetries; attempt++) {
          // Path 1: the raw screenshot. The blank test, bilinear downscale and
          // WebP encode all happen inside Rust (`rcrm_encode_poster_webp`), so
          // neither isolate scans or resamples a pixel.
          if (rawUsable) {
            final shotStarted = DateTime.now();
            final raw = await _tryShot(player);
            final shotMs = DateTime.now()
                .difference(shotStarted)
                .inMilliseconds;
            if (raw != null && raw.length == videoWidth * videoHeight * 4) {
              final compareStarted = DateTime.now();
              final stale = isStalePosterFrame(
                position: position,
                previous: previousRaw,
                current: raw,
              );
              final compareMs = DateTime.now()
                  .difference(compareStarted)
                  .inMilliseconds;
              if (stale) {
                posterLog(
                  'mpv|stale|pos=$position|attempt=$attempt|raw'
                  '|shot_ms=$shotMs|compare_ms=$compareMs',
                );
                await Future<void>.delayed(_staleWait);
                continue;
              }
              previousRaw = raw;
              final encodeStarted = DateTime.now();
              final poster = await ThumbWebpWorker.instance.encodePosterBgra(
                raw,
                videoWidth,
                videoHeight,
                targetWidth: targetWidth,
              );
              final encodeMs = DateTime.now()
                  .difference(encodeStarted)
                  .inMilliseconds;
              if (poster != null) {
                if (poster.blank) {
                  posterLog(
                    'mpv|blank|pos=$position|attempt=$attempt'
                    '|shot_ms=$shotMs|encode_ms=$encodeMs|path=rust',
                  );
                  blank = true;
                  break;
                }
                final webp = poster.bytes;
                if (webp != null && webp.isNotEmpty) {
                  posterLog(
                    'mpv|hit|pos=$position|bytes=${webp.length}'
                    '|path=rust|shot_ms=$shotMs|encode_ms=$encodeMs'
                    '|total_ms=${DateTime.now().difference(started).inMilliseconds}',
                  );
                  bytes = webp;
                  break;
                }
              } else {
                posterLog(
                  'mpv|rust_unavailable|pos=$position|attempt=$attempt'
                  '|shot_ms=$shotMs',
                );
              }
            }
          }
          // Path 2: media_kit's own JPEG, the contract of record. Used when the
          // pixel size is unknown, the raw buffer is not tightly packed, or the
          // Rust encoder/worker is unavailable. Its blank test is Rust too
          // (`rcrm_is_blank_frame`); no Dart pixel loop here either.
          final jpgStarted = DateTime.now();
          final jpg = await _tryShot(player, 'image/jpeg');
          final jpgMs = DateTime.now().difference(jpgStarted).inMilliseconds;
          if (jpg == null || jpg.isEmpty) break;
          if (isStalePosterFrame(
            position: position,
            previous: previousJpeg,
            current: jpg,
          )) {
            posterLog(
              'mpv|stale|pos=$position|attempt=$attempt|jpeg'
              '|shot_ms=$jpgMs',
            );
            await Future<void>.delayed(_staleWait);
            continue;
          }
          previousJpeg = jpg;
          bytes = jpg;
          blank = jpg.length <= 2000 || await _isBlank(jpg);
          if (blank) {
            posterLog(
              'mpv|blank|pos=$position|bytes=${jpg.length}'
              '|path=jpeg|shot_ms=$jpgMs',
            );
          } else {
            posterLog(
              'mpv|hit|pos=$position|bytes=${jpg.length}'
              '|path=jpeg|shot_ms=$jpgMs'
              '|total_ms=${DateTime.now().difference(started).inMilliseconds}',
            );
          }
          break;
        }
        // Nothing usable at this position — no frame at all, a blank one, or
        // every attempt handed back the frame the PREVIOUS position already
        // showed. That last case is skipped on purpose: the stale frame is a
        // real frame of this video, but it belongs to another position, and
        // filing it here would both mis-attribute it and hide the fact that
        // this seek produced nothing.
        if (bytes == null || bytes.isEmpty || blank) {
          posterLog(
            'mpv|rejected|pos=$position'
            '|bytes=${bytes?.length ?? -1}|blank=$blank',
          );
          continue;
        }
        result = bytes;
        return result;
      }
      posterLog(
        'mpv|no_frame|tried=${positions.length}'
        '|ms=${DateTime.now().difference(started).inMilliseconds}',
      );
    } catch (_) {
      try {
        await player.stop();
      } catch (_) {}
    } finally {
      _releaseSlot(slot);
    }
    return result;
  }

  /// Park until the player route lets go, then re-open.
  ///
  /// `stop()` is where a suspended job lets media_kit's static lock go, and the
  /// re-open is what makes the remaining positions seekable again. The job stays
  /// registered as parked ACROSS the re-open on purpose: the queue refuses to
  /// start another player job while a parked one may be mid-`open`, and that is
  /// exactly what the re-open is.
  static Future<void> _park(
    Player player,
    String url,
    Map<String, String> headers,
    PosterParking parking,
  ) async {
    parking.park();
    try {
      try {
        await player.stop();
      } catch (_) {}
      // No timeout: a parked job is never answered with null. Safe because
      // `waitForResume()` is sticky (it returns at once if the resume already ran).
      await parking.waitForResume();
      await player
          .open(Media(url, httpHeaders: headers), play: true)
          .timeout(_openTimeout);
    } finally {
      parking.unpark();
    }
  }

  /// Wait for the player to actually reach [target] after a seek by listening
  /// to its position stream (no busy polling). Seek completion is asynchronous
  /// and a blind delay either wastes time on fast devices or captures the wrong
  /// frame on slow ones.
  static Future<void> _waitForSeek(Player player, Duration target) async {
    if ((player.state.position - target).abs() <= _seekTolerance) return;
    final done = Completer<void>();
    final subscription = player.stream.position.listen((position) {
      if ((position - target).abs() <= _seekTolerance && !done.isCompleted) {
        done.complete();
      }
    });
    try {
      await done.future.timeout(const Duration(seconds: 4));
    } catch (_) {
      // Stream stalled or seek never reported — let the screenshot attempt
      // proceed anyway; isBlank will reject a bad frame and we retry.
    } finally {
      await subscription.cancel();
    }
  }

  /// One screenshot, bounded, with a failure as `null` — never a throw that
  /// would abandon the rest of the position's attempts.
  static Future<Uint8List?> _tryShot(Player player, [String? format]) async {
    try {
      return await player.screenshot(format: format).timeout(_shotTimeout);
    } catch (_) {
      return null;
    }
  }

  /// Blank test for an encoded (JPEG) frame, in Rust, off the UI isolate.
  static Future<bool> _isBlank(Uint8List jpeg) async {
    return Isolate.run(() {
      final bridge = RustBridge();
      if (!bridge.isLoaded) {
        try {
          bridge.load();
        } catch (_) {
          return false;
        }
      }
      final pointer = malloc<Uint8>(jpeg.length);
      pointer.asTypedList(jpeg.length).setAll(0, jpeg);
      final result = bridge.isBlankFrame(pointer, jpeg.length);
      malloc.free(pointer);
      return result == 1;
    });
  }
}
