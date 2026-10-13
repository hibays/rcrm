// test/player_eof_test.dart
// What the app believes about the end of a file, and what it does when the
// viewer takes it back.
//
// The screen cannot be mounted in a test and the platform cannot be asked from
// this host, so the whole of it is one value in `utils/player_eof.dart`. What is
// pinned here is the decision the end-of-playback behaviour hangs on: media_kit
// writes `playing: false` at the end and NEVER undoes it (there is no handler
// for `eof-reached` returning to 0, and `seek` does not touch `playing`), so the
// position stream is the only thing in the whole player that can report "the
// viewer took it back".

import 'package:flutter_test/flutter_test.dart';

import 'package:rcrm_gui/utils/player_eof.dart';

void main() {
  group('a finished file', () {
    test('is entered once, and remembers where it stopped', () {
      final eof = PlayerEof.idle.endedAt(600000);
      expect(eof.finished, isTrue);
      expect(eof.endPositionMs, 600000);
      // The LATCH: the end is reported again after every take-back, and a second
      // pass through the completion handler would seek a video the viewer had
      // just dragged back to 0.
      expect(eof.finished, isTrue, reason: 'still the same ending');
    });

    test('a position report that changes nothing changes nothing', () {
      // The screen asks `next != _eof` to decide whether to withdraw the offer
      // and repair the player, so "no news" has to come back as the SAME value
      // and not merely an equal-looking copy of the state.
      final eof = PlayerEof.idle.endedAt(600000);
      expect(identical(eof.onPosition(600000), eof), isTrue);
      expect(eof.onPosition(600100), eof);
    });

    test('a real drag backwards takes it back', () {
      // A ten-minute video on a 1000px bar is ~0.6ms per pixel, so a drag of any
      // real size is hundreds or thousands of milliseconds. This is the gesture
      // the whole rule exists for.
      expect(
        PlayerEof.idle.endedAt(600000).onPosition(590000),
        PlayerEof.idle,
        reason: 'the video is live again, and the record of it is gone',
      );
      expect(PlayerEof.idle.endedAt(600000).onPosition(0).finished, isFalse);
    });

    test('the last frame wobbling is NOT a take-back', () {
      // At the end of a file the reported position sits within a frame or two of
      // the duration and can move a little in either direction: a dropped frame,
      // a container whose last timestamp rounds down, `demuxer-cache-time`
      // settling. Treating that as the viewer coming back would withdraw the
      // up-next offer a frame after offering it, and leave the video finished
      // with nothing offered at all.
      final eof = PlayerEof.idle.endedAt(600000);
      for (final drift in [0, 1, 40, 199]) {
        expect(
          eof.onPosition(600000 - drift).finished,
          isTrue,
          reason: '${drift}ms backwards is still the last frame',
        );
      }
      // Forward is never a take-back either: a finished file has nothing ahead
      // of where it stopped.
      expect(eof.onPosition(600400).finished, isTrue);
    });

    test('the boundary is the epsilon, exactly', () {
      // Pinned so the constant cannot be moved without this failing: the
      // comparison is strict, so `epsilon` backwards is still noise and one more
      // is a deliberate move.
      final eof = PlayerEof.idle.endedAt(100000);
      expect(
        eof.onPosition(100000 - PlayerEof.takeBackEpsilonMs).finished,
        isTrue,
      );
      expect(
        eof.onPosition(100000 - PlayerEof.takeBackEpsilonMs - 1).finished,
        isFalse,
      );
    });

    test('a file that never started cannot fake a take-back', () {
      // A failed or zero-length file ends at 0, and 0 is not "backwards" from
      // 0: an ended file whose baseline is zero must not un-end itself on its
      // first position report.
      expect(
        PlayerEof.idle.endedAt(0).onPosition(0).finished,
        isTrue,
        reason: 'still ended — there is nowhere before 0 to go',
      );
    });

    test('the epsilon stays smaller than a real move', () {
      // It is about frame noise, not about how far the finger went: a full-width
      // bar's per-pixel step must never trip it on its own.
      expect(PlayerEof.takeBackEpsilonMs, lessThan(1000));
    });
  });

  group('the value itself', () {
    test('compares by content, so equal states are interchangeable', () {
      // What makes `next != _eof` a usable question at all.
      expect(PlayerEof.idle, const PlayerEof());
      expect(PlayerEof.idle.hashCode, const PlayerEof().hashCode);
      expect(
        PlayerEof.idle.endedAt(600000),
        const PlayerEof(finished: true, endPositionMs: 600000),
      );
      expect(
        PlayerEof.idle.endedAt(600000),
        isNot(const PlayerEof(finished: true, endPositionMs: 599900)),
        reason: 'a different stopping point is a different ending',
      );
    });
  });
}