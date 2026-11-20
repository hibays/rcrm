// test/poster_queue_test.dart
// The poster queue's cap, as a rule rather than as a hope.
//
// `ItemCacheLimit.videoPosterQueueMax` documented "Maximum queued poster
// requests. Oldest evicted when exceeded." and had zero references in the
// repository: `_posterQ` was appended to unconditionally, so a wall of failing
// posters (a file libmpv cannot decode, a fetch the server refuses — every
// visible card asks again) grew the queue without bound while every queued
// caller kept a future open. `admitPosterJob` is the missing rule; the service calls it right
// before enqueueing.
//
// The service itself cannot be driven from a test — a backend run descends into
// a libmpv render (Rust), and the one seam
// (`ThumbnailService.debugPosterLoader`) answers before the queue is touched, so
// nothing here can observe it. That is why the decision is a pure function,
// following `advanceScrubPreview` / `planPlayerControlBar`.

import 'dart:async';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/services/item_cache_limit.dart';
import 'package:rcrm_gui/utils/poster_queue.dart';

/// A queued request. [run] is never invoked by the rule — a queued job has no
/// slot — so what it does is irrelevant here.
PosterJob job(String url) =>
    PosterJob(url: url, completer: Completer<Uint8List?>(), run: () {});

void main() {
  group('admitPosterJob', () {
    test('room is room: nothing is evicted below the cap', () {
      final queue = <PosterJob>[];
      expect(admitPosterJob(queue, job('a'), max: 2), isNull);
      expect(admitPosterJob(queue, job('b'), max: 2), isNull);
      expect(queue.map((j) => j.url), ['a', 'b']);
    });

    test('the queue never exceeds the cap, oldest dropped first', () {
      const max = 4;
      final queue = <PosterJob>[];
      final evicted = <PosterJob>[];
      for (var i = 0; i < 500; i++) {
        final e = admitPosterJob(queue, job('u$i'), max: max);
        if (e != null) evicted.add(e);
        expect(
          queue.length,
          lessThanOrEqualTo(max),
          reason: 'queue exceeded its cap after $i admissions',
        );
      }
      // 500 admissions into a queue of 4: the first 4 sit, and every later one
      // pushes out the oldest — 496 evictions, in request order.
      expect(evicted.length, 496);
      expect(evicted.first.url, 'u0');
      expect(evicted.last.url, 'u495');
      // And what stayed is the newest [max] requests, not the oldest.
      expect(queue.map((j) => j.url), ['u496', 'u497', 'u498', 'u499']);
    });

    test('an evicted entry is answered with null, never left pending', () async {
      final queue = <PosterJob>[];
      admitPosterJob(queue, job('a'), max: 2);
      admitPosterJob(queue, job('b'), max: 2);

      final newcomer = job('c');
      final evicted = admitPosterJob(queue, newcomer, max: 2);

      expect(evicted, isNotNull);
      expect(evicted!.url, 'a', reason: 'the OLDEST waiting entry is dropped');
      // Dropped, not deferred: the caller gets "no poster" (the placeholder
      // `VideoCard` already renders) instead of a future that waits behind work
      // the cap exists to bound.
      expect(await evicted.completer.future, isNull);
      // The requests that are still waiting are untouched.
      expect(newcomer.completer.isCompleted, isFalse);
      expect(queue.map((j) => j.url), ['b', 'c']);
    });

    test('a running job is never evicted', () {
      final queue = <PosterJob>[];
      final running = job('running');
      // The runner marks a job started (and pops it) as it hands over a slot;
      // even if a started entry were still in the list, the rule must skip it.
      // Dropping it would free no capacity — its slot is already taken — while
      // its caller lost the answer it was waiting for.
      running.started = true;
      queue.add(running);

      final waiting = job('waiting');
      final evicted = admitPosterJob(queue, waiting, max: 1);

      expect(evicted, isNull, reason: 'only a waiting entry may be dropped');
      expect(running.completer.isCompleted, isFalse);
      expect(waiting.completer.isCompleted, isFalse);
      expect(queue, contains(running));
    });

    test('the shipped constant is the cap the service hands it', () {
      // It had no references at all before; this pins that the value can
      // actually bound a queue.
      expect(ItemCacheLimit.videoPosterQueueMax, greaterThan(0));
    });
  });

  group('takePosterJob', () {
    test('the newest request runs first', () {
      final queue = <PosterJob>[];
      for (final url in ['a', 'b', 'c']) {
        admitPosterJob(queue, job(url), max: 8);
      }

      expect(takePosterJob(queue).url, 'c', reason: 'the TOP of the stack');
      expect(takePosterJob(queue).url, 'b');
      expect(takePosterJob(queue).url, 'a');
    });

    test('a taken job is marked started and leaves the queue', () {
      final queue = <PosterJob>[];
      admitPosterJob(queue, job('old'), max: 8);
      admitPosterJob(queue, job('new'), max: 8);

      final taken = takePosterJob(queue);
      expect(taken.url, 'new');
      expect(taken.started, isTrue, reason: 'a running job is never evictable');
      expect(queue.map((j) => j.url), ['old']);
      // And with the taken one gone, the cap can no longer pick it: the only
      // candidate left is the one still waiting.
      expect(admitPosterJob(queue, job('newer'), max: 1)!.url, 'old');
    });

    test('a repeat request raises the waiting job to the top', () {
      // The image gate's `restack`, on the poster side: the reader came back to
      // this card, so the request already queued is the freshest statement of
      // what is wanted now.
      final queue = <PosterJob>[];
      for (final url in ['a', 'b', 'c']) {
        admitPosterJob(queue, job(url), max: 8);
      }

      raisePosterJob(queue, 'b');

      expect(takePosterJob(queue).url, 'b');
      expect(takePosterJob(queue).url, 'c');
      expect(takePosterJob(queue).url, 'a');
    });

    test('raising a URL that is not waiting changes nothing', () {
      final queue = <PosterJob>[];
      for (final url in ['a', 'b']) {
        admitPosterJob(queue, job(url), max: 8);
      }
      // Already running, or never asked: not in the queue.
      raisePosterJob(queue, 'running');
      expect(queue.map((j) => j.url), ['a', 'b']);
    });

    test('the stack and the cap agree on which end is which', () {
      // A full stack: every pop takes the newest, every admission drops the
      // oldest. This is the pair of rules the reader experiences as "the card I
      // am looking at fills in first".
      final queue = <PosterJob>[];
      for (var i = 0; i < 3; i++) {
        admitPosterJob(queue, job('u$i'), max: 3);
      }
      expect(takePosterJob(queue).url, 'u2', reason: 'newest served first');
      expect(queue.map((j) => j.url), ['u0', 'u1']);
      // Full again from the bottom end: the newcomer is admitted at the top and
      // the OLDEST request is the one answered with a placeholder.
      expect(admitPosterJob(queue, job('u3'), max: 2)!.url, 'u0');
      expect(queue.map((j) => j.url), ['u1', 'u3']);
    });
  });
}
