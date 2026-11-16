// test/poster_suspend_test.dart
// The poster start gate: what the kick may start while a player route's
// entrance is running, and the depth counter behind it.
//
// The backend cannot be driven from a test (a run descends into a libmpv render
// in Rust), so what is pinned here is the decision (`planPosterKick`) and the
// static gate (`ThumbnailService.suspend/resume`).

import 'dart:async';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/services/thumbnail_service.dart';
import 'package:rcrm_gui/utils/poster_queue.dart';

/// A queued request. [run] is never invoked by the rule — a waiting job has no
/// slot — so what it does is irrelevant here.
PosterJob job(String url) =>
    PosterJob(url: url, completer: Completer<Uint8List?>(), run: () {});

void main() {
  group('planPosterKick', () {
    test('room and work: fills the free slots, and only that many', () {
      final queue = [job('a'), job('b'), job('c')];
      final plan = planPosterKick(
        queue: queue,
        running: 0,
        max: 2,
        suspended: false,
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
      );
      expect(plan.start, 0);
      expect(plan.running, 1);
    });

    test('suspended: a free slot starts nothing', () {
      // The entrance is opening the file the user just tapped; a new poster
      // decode would compete for the same cores.
      final plan = planPosterKick(
        queue: [job('a'), job('b')],
        running: 0,
        max: 4,
        suspended: true,
      );
      expect(plan.start, 0);
      expect(plan.running, 0);
    });

    test('deciding changes nothing: the queue is the caller\'s to mutate', () {
      final queue = [job('a'), job('b')];
      final plan = planPosterKick(
        queue: queue,
        running: 0,
        max: 1,
        suspended: false,
      );
      expect(plan.start, 1);
      // The planner only counts. If it removed the entry itself, the runner
      // would start it twice (or start the wrong one).
      expect(queue.map((j) => j.url), ['a', 'b']);
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
