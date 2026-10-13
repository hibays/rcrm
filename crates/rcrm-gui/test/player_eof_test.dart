// test/player_eof_test.dart
// What the app believes about the end of a file, and what a seek does to it.
//
// The screen cannot be mounted in a test and the platform cannot be asked from
// this host, so the decision lives in `utils/player_eof.dart`. What is pinned
// here is the decision the end-of-playback behaviour hangs on: media_kit writes
// `playing: false` at the end and NEVER undoes it (there is no handler for
// `eof-reached` returning to 0, and `seek` does not touch `playing`), so nothing
// in the player can report that a finished file has become live again — and the
// only thing that CAN is a seek this screen issued itself.

import 'package:flutter_test/flutter_test.dart';

import 'package:rcrm_gui/utils/player_eof.dart';

void main() {
  const at50 = Duration(seconds: 50);
  const at10 = Duration(seconds: 10);
  const at60 = Duration(seconds: 60);

  group('a finished file', () {
    test('is entered once, and stays entered', () {
      final eof = PlayerEof.idle.ended();
      expect(eof.finished, isTrue);
      // The LATCH: the end is reported again after every take-back, and a second
      // pass through the completion handler would seek a video the viewer had
      // just dragged back to 0.
      expect(eof.finished, isTrue, reason: 'still the same ending');
    });
  });

  group('a seek', () {
    PlayerEof finished() => PlayerEof.idle.ended();

    test('backwards past the epsilon takes it back', () {
      // The gesture the whole mechanism exists for.
      expect(
        finished().seeked(target: at10, current: at50),
        PlayerEof.idle,
        reason: 'the video is live again, and the record of the ending is gone',
      );
      expect(finished().seeked(target: Duration.zero, current: at50).finished,
          isFalse);
    });

    test('forwards is never a take-back, however far', () {
      expect(finished().seeked(target: at60, current: at50), finished());
      // THIS is the one that shipped broken: holding the right arrow key seeks
      // past the end, the cached `state.position` is stale because the file is
      // paused at its last frame, and mpv CLAMPS the result. Reconstructing the
      // direction from the position reports read that clamp as a backwards move,
      // which withdrew the up-next offer and un-paused a file that immediately
      // reached eof again — a frozen picture with the transport claiming
      // "playing". The direction is our own call, so it cannot be misread.
      expect(
        finished().seeked(
          target: const Duration(seconds: 1050),
          current: const Duration(seconds: 1050),
        ),
        finished(),
      );
    });

    test('a nudge inside the frame is not a take-back', () {
      // The scrub bar re-seeks continuously while a pointer or finger is down,
      // and a target a few milliseconds behind the reported position is a hand
      // settling, not a decision.
      final eof = finished();
      for (final back in [0, 1, 199]) {
        expect(
          eof
                  .seeked(
                    target: at50 - Duration(milliseconds: back),
                    current: at50,
                  )
                  .finished,
          isTrue,
          reason: '${back}ms backwards is still the same place',
        );
      }
      // The boundary is the epsilon, exactly.
      expect(
        eof
            .seeked(target: at50 - PlayerEof.takeBackEpsilon, current: at50)
            .finished,
        isTrue,
      );
      expect(
        eof
            .seeked(
              target: at50 - PlayerEof.takeBackEpsilon - const Duration(milliseconds: 1),
              current: at50,
            )
            .finished,
        isFalse,
      );
    });

    test('a seek on a file that has not finished changes nothing', () {
      // Mid-video scrubbing must not be mistaken for anything: the offer only
      // exists at an ending, and the un-pause would be a lie there.
      expect(
        PlayerEof.idle.seeked(target: at10, current: at50),
        PlayerEof.idle,
      );
      // Identity, not just equality: the screen asks `next == _eof` and must not
      // be told "something happened" for a seek that changed nothing.
      expect(
        identical(
          PlayerEof.idle.seeked(target: at10, current: at50),
          PlayerEof.idle,
        ),
        isTrue,
      );
    });

    test('the epsilon stays smaller than a real move', () {
      // It is about a settling hand, not about how far the finger went: the
      // arrow keys jump 10s, and a full-width bar on a ten-minute video is
      // ~0.6ms per pixel.
      expect(PlayerEof.takeBackEpsilon, lessThan(const Duration(seconds: 1)));
    });
  });

  group('the value itself', () {
    test('compares by content, so equal states are interchangeable', () {
      expect(PlayerEof.idle, const PlayerEof());
      expect(PlayerEof.idle.hashCode, const PlayerEof().hashCode);
      expect(const PlayerEof(finished: true), PlayerEof.idle.ended());
      expect(
        PlayerEof.idle.ended().seeked(target: at10, current: at50),
        PlayerEof.idle,
      );
    });
  });
}