// test/playback_open_guard_test.dart
// The open/error state machine behind the player's spinner. The screen cannot
// be mounted in a test (it creates a native media_kit Player), so these are the
// tests that pin the rules the screen relies on: one generation at a time, a
// timeout that can be withdrawn by a late first frame, and no stale failure
// painting over a newer file.

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/utils/playback_open_guard.dart';

void main() {
  group('PlaybackOpenGuard', () {
    test('begin advances the generation and clears the previous outcome', () {
      final guard = PlaybackOpenGuard();
      final first = guard.begin();
      expect(guard.isCurrent(first), isTrue);
      expect(guard.waitingForFirstFrame, isTrue);

      guard.fail(first, 'boom');
      expect(guard.hasFailure, isTrue);
      expect(guard.failure!.message, 'boom');

      final second = guard.begin();
      expect(second, greaterThan(first));
      expect(guard.isCurrent(second), isTrue);
      expect(guard.hasFailure, isFalse);
      expect(guard.opened, isFalse);
      expect(guard.waitingForFirstFrame, isTrue);
    });

    test('a timeout is only eligible for the current, not-opened attempt', () {
      final guard = PlaybackOpenGuard();
      final gen = guard.begin();

      expect(guard.shouldTimeout(gen), isTrue);
      expect(guard.shouldTimeout(gen + 1), isFalse);

      guard.markOpened();
      expect(guard.shouldTimeout(gen), isFalse);

      final next = guard.begin();
      expect(guard.shouldTimeout(next), isTrue);
    });

    test('a stale timeout cannot fail a newer attempt', () {
      final guard = PlaybackOpenGuard();
      final old = guard.begin();
      final current = guard.begin();

      expect(
        guard.fail(old, 'old timeout', watchdog: true),
        isFalse,
        reason: 'the watchdog for a superseded open must be ignored',
      );
      expect(guard.failure, isNull);
      expect(guard.shouldTimeout(current), isTrue);
    });

    test('a late first frame withdraws a timeout', () {
      final guard = PlaybackOpenGuard();
      final gen = guard.begin();
      guard.fail(gen, 'timed out', watchdog: true);

      expect(guard.waitingForFirstFrame, isFalse);
      expect(guard.markOpened(), isTrue);
      expect(guard.opened, isTrue);
      expect(guard.hasFailure, isFalse);
    });

    test('a first frame never hides a player error', () {
      final guard = PlaybackOpenGuard();
      final gen = guard.begin();
      guard.fail(gen, 'No video decoder');

      expect(guard.markOpened(), isFalse);
      expect(guard.hasFailure, isTrue);
      expect(guard.failure!.message, 'No video decoder');
    });

    test(
      'a player error may replace a timeout; a timeout may not replace it',
      () {
        final guard = PlaybackOpenGuard();
        final gen = guard.begin();

        guard.fail(gen, 'timed out', watchdog: true);
        expect(guard.fail(gen, 'HTTP 404'), isTrue);
        expect(guard.failure!.watchdog, isFalse);
        expect(guard.failure!.message, 'HTTP 404');

        expect(guard.fail(gen, 'timed out again', watchdog: true), isFalse);
        expect(guard.failure!.message, 'HTTP 404');
      },
    );

    test(
      'clearFailure keeps the generation for a Retry that must create a player',
      () {
        final guard = PlaybackOpenGuard();
        final gen = guard.begin();
        guard.fail(gen, 'player could not start');

        guard.clearFailure();
        expect(guard.hasFailure, isFalse);
        expect(guard.generation, gen);

        expect(guard.fail(gen, 'still could not start'), isTrue);
        expect(guard.failure!.message, 'still could not start');
      },
    );

    test('markOpened is idempotent for an already-open attempt', () {
      final guard = PlaybackOpenGuard();
      guard.begin();
      expect(guard.markOpened(), isTrue);
      expect(guard.markOpened(), isTrue);
      expect(guard.opened, isTrue);
      expect(guard.hasFailure, isFalse);
    });
  });
}
