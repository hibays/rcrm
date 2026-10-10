// test/poster_suspend_test.dart
// The poster pool's suspension, as the rules that decide it and the contract a
// parked job has to keep.
//
// What this file CAN drive: `planPosterKick` (a pure function) and
// `ThumbnailService.suspend/resume` (static state with no player in it). What it
// CANNOT drive is the mobile pool itself — `_posterMobile` needs a real media_kit
// `Player`, and the only other seam, `ThumbnailService.suppressPosterGeneration`,
// returns before the queue is touched. So the in-flight job below is a
// stand-in for it: same queue, same completer, same "the answer is decided when
// the job finishes, not when it parks" shape.

import 'dart:async';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/services/thumbnail_service.dart';
import 'package:rcrm_gui/utils/poster_queue.dart';

/// A queued request. [run] is never invoked by the rules — a waiting job has no
/// slot — so what it does is irrelevant here.
PosterJob job(String url) =>
    PosterJob(url: url, completer: Completer<Uint8List?>(), run: () {});

/// A poster job that is already running: it holds a slot, it may be parked, and
/// the bytes it will finally answer with are decided by what its loop produced.
class _RunningJob {
  _RunningJob(this.url, this.slot);

  final String url;

  /// The player slot index. A running job keeps it for its whole life —
  /// including while parked.
  int slot;

  /// True while this job sits at its yield point. Mirrors
  /// `ThumbnailService._posterParked`, which is not readable from a test.
  bool parked = false;

  final completer = Completer<Uint8List?>();

  /// The job's result, as `_posterMobile` builds it: the first frame that was
  /// neither missing nor blank. Null only when no position produced one.
  Uint8List? result;

  /// The single future every duplicate request for [url] gets handed
  /// (`_posterInflight`), so a re-request while parked joins it rather than
  /// asking for a second poster.
  Future<Uint8List?> get poster => completer.future;

  /// The runner's bookkeeping for one job: `_posterRunning--`, `_posterKick()`.
  void release(List<PosterJob> queue, _Pool pool) {
    if (parked) {
      parked = false;
      pool.parked--;
    }
    pool.running--;
    pool.kick(queue);
  }
}

class _Pool {
  _Pool({this.max = 1});

  /// Slot count, as `ItemCacheLimit.videoPosterConcurrency` gives it (1 on
  /// mobile — the case that matters here).
  final int max;

  final queue = <PosterJob>[];
  int running = 0;
  int parked = 0;
  bool suspended = false;

  /// `ThumbnailService._posterKick`, minus the players: decide through the pure
  /// function, then hand that many waiting jobs a slot.
  void kick(List<PosterJob> ready) {
    final plan = planPosterKick(
      queue: queue,
      running: running,
      max: max,
      suspended: suspended,
      anyParked: parked > 0,
    );
    for (var i = 0; i < plan.start; i++) {
      final j = queue.removeAt(0);
      j.started = true;
      ready.add(j);
    }
    running = plan.running;
  }

  /// `ThumbnailService.suspend()`.
  void suspend() {
    suspended = true;
    kick([]);
  }

  /// `ThumbnailService.resume()`: guard the depth, wake the parked jobs, kick.
  void resume(List<PosterJob> ready) {
    suspended = false;
    kick(ready);
  }

  /// A running job's yield point: park there, and take a byte answer only after
  /// the suspension lifts. Null comes back only if this was never resumed.
  Future<Uint8List?> parkUntilResumed(_RunningJob j) async {
    if (!suspended) return j.result;
    parked++;
    j.parked = true;
    while (suspended) {
      await Future<void>.delayed(Duration.zero);
    }
    parked--;
    j.parked = false;
    return j.result;
  }
}

void main() {
  group('planPosterKick', () {
    test('room and work: fills the free slots, in queue order', () {
      final queue = [job('a'), job('b'), job('c')];
      final plan = planPosterKick(
        queue: queue,
        running: 0,
        max: 2,
        suspended: false,
        anyParked: false,
      );
      expect(plan.start, 2);
      expect(plan.running, 2);
    });

    test('the cap is the cap: nothing starts when every slot is taken', () {
      final plan = planPosterKick(
        queue: [job('a')],
        running: 1,
        max: 1,
        suspended: false,
        anyParked: false,
      );
      expect(plan.start, 0);
      expect(plan.running, 1);
    });

    test('an empty queue starts nothing, and the count is unchanged', () {
      final plan = planPosterKick(
        queue: <PosterJob>[],
        running: 1,
        max: 3,
        suspended: false,
        anyParked: false,
      );
      expect(plan.start, 0);
      expect(plan.running, 1);
    });

    test('suspended: a free slot starts nothing', () {
      // The contention this removes is the whole point of the gate: while the
      // player route is up, a poster job must not take the static
      // `NativePlayer.lock` that playback's `open`/`play` is waiting for.
      final plan = planPosterKick(
        queue: [job('a'), job('b')],
        running: 0,
        max: 4,
        suspended: true,
        anyParked: false,
      );
      expect(plan.start, 0);
      expect(plan.running, 0);
    });

    test('any parked job: a free slot still starts nothing', () {
      // A parked job holds its slot and may be mid-`open`, which holds the same
      // lock — so a newcomer would only wait behind it. It waits instead.
      for (final parked in [1, 3]) {
        final plan = planPosterKick(
          queue: [job('a')],
          running: parked,
          max: 4,
          suspended: false,
          anyParked: true,
        );
        expect(plan.start, 0, reason: 'with $parked parked');
        expect(plan.running, parked);
      }
    });

    test('deciding changes nothing: the queue is the caller\'s to mutate', () {
      final queue = [job('a'), job('b')];
      final plan = planPosterKick(
        queue: queue,
        running: 0,
        max: 1,
        suspended: false,
        anyParked: false,
      );
      expect(plan.start, 1);
      // The planner only counts. If it removed the entry itself, the runner
      // would start it twice (or start the wrong one).
      expect(queue.map((j) => j.url), ['a', 'b']);
    });
  });

  group('parking contract', () {
    test(
      'a parked job keeps its caller pending — never a null answer',
      () async {
        final pool = _Pool();
        final running = _RunningJob('a.mkv', 0);
        pool.running = 1; // it took the only slot

        pool.suspend();
        var answered = false;
        final answer = pool.parkUntilResumed(running)
          ..then((_) => answered = true);

        // Let it reach the yield point.
        await Future<void>.delayed(Duration.zero);
        expect(running.parked, isTrue);
        expect(pool.parked, 1, reason: 'the parked job holds the parked count');
        expect(answered, isFalse, reason: 'a parked job is not answered early');
        // Null here is what makes `VideoCard` paint its gray placeholder, and
        // nothing retries it — the card asked once per mount, the poster cache
        // stores successes only. So the future must still be open.
        expect(running.completer.isCompleted, isFalse);
        expect(pool.running, 1, reason: 'it keeps its slot while parked');

        // ...and the answer it finally gives is the real one.
        running.result = Uint8List.fromList(List.filled(4096, 7));
        pool.resume([]);
        final bytes = await answer;
        expect(bytes, isNotNull);
        expect(bytes!.length, 4096);
      },
    );

    test('a parked job is never evicted and never re-enters the cap', () async {
      final pool = _Pool(max: 1);
      final running = _RunningJob('a.mkv', 0);
      pool.running = 1;

      pool.suspend();
      final answer = pool.parkUntilResumed(running);
      await Future<void>.delayed(Duration.zero);
      expect(running.parked, isTrue);

      // A wall of new requests arrives while the player route is up.
      final ready = <PosterJob>[];
      for (var i = 0; i < 200; i++) {
        admitPosterJob(pool.queue, job('new$i'), max: 4);
        pool.kick(ready);
      }
      expect(pool.queue.length, lessThanOrEqualTo(4));
      expect(ready, isEmpty, reason: 'suspended: not one of them starts');
      expect(
        pool.running,
        1,
        reason: 'the parked job still holds the only slot',
      );

      // None of that eviction reached the parked job: it is not in the queue,
      // and a running job is never evictable — dropping it would free no
      // capacity while its caller lost the answer it was waiting for.
      running.result = Uint8List.fromList(List.filled(4096, 9));
      pool.resume(ready);
      final bytes = await answer;
      expect(bytes, isNotNull);
      expect(bytes!.length, 4096);
      // The runner answers the caller on the way out, with the bytes the job
      // produced — never a null.
      running.completer.complete(bytes);
      expect(running.completer.isCompleted, isTrue);

      // Resuming starts work again, but the parked job is already out of the
      // queue — it can never be handed a second slot by a kick.
      expect(ready.map((j) => j.url).toList(), isNot(contains('a.mkv')));
      expect(
        pool.running,
        1,
        reason: 'it kept its slot the whole time, so no new job could start',
      );

      // Its own exit is the ordinary one, and that is what frees the slot for
      // the queue it was holding up — oldest waiting first.
      final queuedBefore = pool.queue.map((j) => j.url).toList();
      running.release(ready, pool);
      expect(
        pool.running,
        1,
        reason: 'the slot passes to the next waiting job',
      );
      expect(ready.map((j) => j.url).toList(), [queuedBefore.first]);
    });
  });

  group('ThumbnailService.suspend/resume', () {
    tearDown(() {
      // Never leave the gate shut for another test in this file.
      while (ThumbnailService.posterSuspended) {
        ThumbnailService.resume();
      }
    });

    test('is a depth counter, not a bool', () {
      // `_go`'s `pushReplacement` makes the outgoing screen's dispose and the
      // incoming route's install overlap. With a bool the first of the two to
      // run would lift the suspension while the other route is still on screen.
      expect(ThumbnailService.posterSuspended, isFalse);
      ThumbnailService.suspend();
      ThumbnailService.suspend();
      expect(ThumbnailService.posterSuspended, isTrue);

      ThumbnailService.resume();
      expect(
        ThumbnailService.posterSuspended,
        isTrue,
        reason: 'one route is still installed',
      );
      ThumbnailService.resume();
      expect(ThumbnailService.posterSuspended, isFalse);
    });

    test('an unmatched resume cannot drive the depth negative', () {
      ThumbnailService.resume();
      expect(ThumbnailService.posterSuspended, isFalse);
      ThumbnailService.suspend();
      ThumbnailService.resume();
      ThumbnailService.resume();
      expect(ThumbnailService.posterSuspended, isFalse);
    });
  });
}
