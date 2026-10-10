// utils/poster_queue.dart
// The poster queue's two rules, as pure functions: admission (what the queue
// holds) and the kick (what the queue starts).
//
// `ThumbnailService` used to enqueue every poster request unconditionally:
// `ItemCacheLimit.videoPosterQueueMax` documented "Maximum queued poster
// requests. Oldest evicted when exceeded." but had no reference anywhere, so the
// queue grew without bound while each entry held a caller's future open. That is
// not a theoretical leak — a failing poster is the normal case on desktop, where
// ffmpeg ≥ 9 verifies TLS against our self-signed server, so all 16 attempts per
// video fail and every visible card asks again.
//
// The second rule is the suspension gate: while the player route is installed
// the UI must not start poster work at all, and a job that is already running
// parks at its next yield point instead of holding media_kit's static
// `NativePlayer.lock` across playback's `open`. So the kick is a decision too —
// how many waiting jobs may start, given what is running and what is parked —
// and it is written down here alongside the admission rule.
//
// Both rules live here rather than inside the service because the decision is
// what can be wrong (which entry, whether at all), and this way they are testable
// without an ffmpeg process or a media_kit Player — the same reason
// `advanceScrubPreview` and `planPlayerControlBar` are separated from their
// handlers.

import 'dart:async';
import 'dart:typed_data';

/// One poster request: waiting for a slot, or running.
class PosterJob {
  /// The URL whose poster is wanted. Unique among live jobs while it is queued —
  /// `ThumbnailService.generatePoster` hands a second request for the same URL
  /// the first job's completer instead of creating a job of its own.
  final String url;

  /// The caller's future. Completing it with null means "no poster", which is
  /// what an evicted request gets and what `VideoCard` already renders as its
  /// placeholder.
  final Completer<Uint8List?> completer;

  /// Runs the job: an `ffmpeg` process on desktop, a media_kit screenshot on
  /// mobile.
  final void Function() run;

  /// Set by the runner when this job is handed a concurrency slot. A running job
  /// is never evictable: the cap bounds the *waiting* work, and dropping a job
  /// that already holds a slot would free no capacity while its caller lost the
  /// answer it was waiting for.
  bool started = false;

  PosterJob({required this.url, required this.completer, required this.run});
}

/// Adds [job] to [queue] (oldest first) and returns the entry evicted to keep the
/// queue within [max], if one had to be: the OLDEST entry that has not started,
/// already removed from [queue], with its completer completed as null.
///
/// Dropped, never deferred. A queued request is waiting on work this cap exists
/// to bound, so its caller must get an answer rather than a future that stays
/// pending until the queue drains. This is `ItemCacheLimit.videoPosterQueueMax`'s
/// documented semantic ("Oldest evicted when exceeded") and the same rule
/// `ImageLoadGate` applies to its decode waiters.
///
/// The function reads and mutates only the list it is handed, so calling it is
/// the whole admission decision — see `test/poster_queue_test.dart`.
PosterJob? admitPosterJob(
  List<PosterJob> queue,
  PosterJob job, {
  required int max,
}) {
  assert(max > 0, 'a zero-length poster queue would admit nothing');
  PosterJob? evicted;
  if (queue.length >= max) {
    // Scans oldest first, and skips a started entry: if one is ever still in the
    // list (the runner normally pops it), evicting it would kill work that is
    // already under way rather than work that is merely waiting.
    final i = queue.indexWhere((j) => !j.started);
    if (i >= 0) evicted = queue.removeAt(i);
  }
  queue.add(job);
  if (evicted != null && !evicted.completer.isCompleted) {
    evicted.completer.complete(null);
  }
  return evicted;
}

/// The kick's decision: how many waiting jobs may start now, and what the
/// running count becomes once they have.
class PosterKickPlan {
  /// Waiting jobs to hand a slot to. Never more than the queue holds, and never
  /// more than the free capacity the caller reported.
  final int start;

  /// The running count after those starts — the caller must publish it, so the
  /// count reflects the jobs it is about to run rather than the jobs that have
  /// already finished.
  final int running;

  const PosterKickPlan({required this.start, required this.running});
}

/// Decide what the poster runner may start right now.
///
/// Two situations start nothing:
///
/// * [suspended] — the player route owns the screen, so no poster work may
///   begin; it would contend with playback for media_kit's static
///   `NativePlayer.lock`. Waiting jobs stay queued with their completers alive.
/// * [anyParked] — a suspended job is parked holding its slot and may be
///   mid-`open` right now. It holds that same lock across the re-open, so a
///   newcomer would only queue behind it: the contention this gate exists to
///   remove. It waits instead, and the parked job's own departure kicks again.
///
/// Otherwise it offers as many jobs as there is room for, in queue order. The
/// count returned here is the whole answer — the runner must not "help" by
/// starting one more, or the cap stops being a cap.
///
/// Reads its arguments only; it neither mutates [queue] nor removes anything
/// from it, so the caller owns every state change (`test/poster_suspend_test.dart`
/// pins that the queue is untouched by a plan).
PosterKickPlan planPosterKick({
  required List<PosterJob> queue,
  required int running,
  required int max,
  required bool suspended,
  required bool anyParked,
}) {
  assert(max > 0, 'a zero-slot poster runner would never run anything');
  assert(running >= 0, 'a negative running count is not a count');
  if (suspended || anyParked) {
    return PosterKickPlan(start: 0, running: running);
  }
  final free = max - running;
  final start = free <= 0 ? 0 : (free < queue.length ? free : queue.length);
  return PosterKickPlan(start: start, running: running + start);
}
