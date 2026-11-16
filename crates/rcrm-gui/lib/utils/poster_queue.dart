// utils/poster_queue.dart
// The poster queue's two rules, as pure functions: admission (what the queue
// holds) and the kick (what the queue starts).
//
// `ThumbnailService` used to enqueue every poster request unconditionally:
// `ItemCacheLimit.videoPosterQueueMax` documented "Maximum queued poster
// requests. Oldest evicted when exceeded." but had no reference anywhere, so the
// queue grew without bound while each entry held a caller's future open. That is
// not a theoretical leak: a failing poster is a normal case (a file libmpv
// cannot decode, a fetch the server refuses), and every visible card asks
// again.
//
// The second rule is the gate: through a player route's ENTRANCE nothing starts,
// and a running job parks instead of holding media_kit's static `NativePlayer.lock`
// across playback's `open`. It opens when that step ends, so [suspended] means
// "an entrance is running", not "a player is on screen".
//
// Both rules live here rather than inside the service because the decision is
// what can be wrong (which entry, whether at all), and this way they are testable
// without a libmpv render or a media_kit Player — the same reason
// `advanceScrubPreview` and `planPlayerControlBar` are separated from their
// handlers.

import 'dart:async';
import 'dart:typed_data';

/// The suspension gate a RUNNING poster job parks at.
///
/// The media_kit backend holds media_kit's static `NativePlayer.lock` across
/// `open` and across each `seek` + `screenshot`, and the playback player needs
/// that same lock. A job that is already running when the player route is
/// installed must therefore PARK — stop its player, wait for that route to go,
/// then re-open — rather than answer "no poster", which `VideoCard` would paint
/// as a permanent placeholder, because nothing retries a null.
///
/// `ThumbnailService` owns the queue and implements this; the backend only
/// waits. Park and unpark are separate calls because the count they keep is what
/// stops the queue from starting another player job, and the departure is what
/// lets waiting work move again.
abstract interface class PosterParking {
  /// True while a player route's entrance is still running (the step is playing).
  bool get suspended;

  /// Register a job that is parking. It keeps its slot: the queue must not
  /// start another player job while a parked one may be mid-`open`.
  void park();

  /// The parked job is done parking. Publishes the count and kicks the queue.
  void unpark();

  /// Resolves once [suspended] is false — AT ONCE when it already is: a job that
  /// asks after the last resume must not wait for a signal already given (it
  /// would stay parked, holding its slot, blocking every kick). Read the flag and
  /// create the waiter in one synchronous step.
  Future<void> waitForResume();
}

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

  /// Runs the job: one backend run (`services/poster_libmpv.dart` or
  /// `services/poster_mpv.dart`).
  final void Function() run;

  /// Set by the runner when this job is handed a concurrency slot. A running job
  /// is never evictable: the cap bounds the *waiting* work, and dropping a job
  /// that already holds a slot would free no capacity while its caller lost the
  /// answer it was waiting for.
  bool started = false;

  PosterJob({required this.url, required this.completer, required this.run});
}

/// Adds [job] to [queue] (oldest first, so the list reads as a stack: index 0 is
/// the BOTTOM, the end is the TOP) and returns the entry evicted to keep the
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

/// Takes the next job to run: the TOP of the stack (the newest request), marked
/// [PosterJob.started]. The caller asks [planPosterKick] how many may start; this
/// only decides WHICH one.
PosterJob takePosterJob(List<PosterJob> queue) {
  final job = queue.removeLast();
  // Marked before it runs, so the admission rule can never pick a job that
  // already owns a slot even if one were still in the list.
  job.started = true;
  return job;
}

/// Raises the queued job for [url] to the TOP: it was asked for again — the
/// poster half of `ImageLoadGate.restack`. A running or absent URL is a no-op.
void raisePosterJob(List<PosterJob> queue, String url) {
  final i = queue.indexWhere((job) => job.url == url);
  if (i < 0) return;
  queue.add(queue.removeAt(i));
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
/// * [suspended] — a player route's entrance is still running, so no poster work
///   may begin; it would contend with playback for media_kit's static
///   `NativePlayer.lock` inside the transition the user is watching. Waiting jobs
///   stay queued with their completers alive.
/// * [anyParked] — a suspended job is parked holding its slot and may be
///   mid-`open` right now. It holds that same lock across the re-open, so a
///   newcomer would only queue behind it: the contention this gate exists to
///   remove. It waits instead, and the parked job's own departure kicks again.
///
/// Otherwise it offers as many jobs as there is room for. Which ones is
/// [takePosterJob]'s decision (the TOP of the stack), and the count returned here
/// is the whole answer — the runner must not "help" by starting one more, or the
/// cap stops being a cap.
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
