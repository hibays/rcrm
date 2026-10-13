// test/player_volume_test.dart
// The player screen's volume session, pinned where it can be: the screen itself
// cannot be mounted in a test (its first frame builds a real media_kit `Player`),
// so `utils/player_volume.dart` owns the decisions.
//
// Both defects these tests cover were found by review AFTER the screen's routing
// looked right:
//
//  * an unmute that could only ever return the level the session started with,
//    because the "last audible" memory began at 100 and was never 0 — so a phone
//    that was already silent when the video opened jumped to full scale;
//  * a quantised echo that notified nobody: the bar kept the 41% the finger
//    asked for while the phone sat on the 40% step it really has.

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/services/system_volume.dart';
import 'package:rcrm_gui/utils/player_volume.dart';

/// A phone's media stream: fifteen steps, index 0 silent.
SystemVolumeReading phone({
  int index = 8,
  int min = 0,
  int max = 15,
  bool muted = false,
  int lastAudible = 8,
  bool fixed = false,
}) => SystemVolumeReading(
  index: index,
  min: min,
  max: max,
  muted: muted,
  lastAudible: lastAudible,
  fixed: fixed,
);

/// What the device answers when it is currently on [index].
SystemVolumeReading onStep(int index) => phone(index: index, lastAudible: index);

void main() {
  group('seeding a session', () {
    test('binds to the device and starts at ITS level', () {
      final v = PlayerVolume.initial.seeded(
        supported: true,
        setting: true,
        reading: onStep(8),
        fallbackLevel: 100,
      );

      expect(v.bound, isTrue);
      // 8 of 15 = 53.33%, not the 100 this app last played at: the phone's
      // volume IS the volume, so opening a video must not move it.
      expect(v.level, closeTo(53.33, 0.01));
      expect(v.playerGain, 100, reason: 'libmpv stays wide open while bound');
      expect(v.remembersAppVolume, isFalse);
    });

    test('falls back to the stored level for every reason not to bind', () {
      const fallback = 42.0;
      final cases = <String, SystemVolumeReading?>{
        'the device could not be read': null,
        'the output is fixed-volume': phone(fixed: true),
        'the stream has no travel': phone(min: 0, max: 0, fixed: true),
      };
      for (final MapEntry<String, SystemVolumeReading?> e in cases.entries) {
        final v = PlayerVolume.initial.seeded(
          supported: true,
          setting: true,
          reading: e.value,
          fallbackLevel: fallback,
        );
        expect(v.bound, isFalse, reason: e.key);
        expect(v.level, fallback, reason: e.key);
        expect(v.playerGain, fallback, reason: e.key);
        expect(v.remembersAppVolume, isTrue, reason: e.key);
        expect(
          v.lastAudible,
          fallback,
          reason:
              'the level the session OPENED at is an audible level: muting and '
              'unmuting it must come back here, not to full scale (${e.key})',
        );
      }
    });

    test('normalises a level that came from outside the session', () {
      // The stored `player_volume` is the one level this class is handed rather
      // than computes, and it outlives every rule the session has: a hand-edited
      // preference must not put the bar outside its range, and one that is not a
      // number must not move it at all.
      double seed({required double stored}) => PlayerVolume.initial
          .seeded(
            supported: false,
            setting: false,
            reading: null,
            fallbackLevel: stored,
          )
          .level;
      expect(seed(stored: 180), 100);
      expect(seed(stored: -20), 0);
      expect(
        seed(stored: double.nan),
        100,
        reason: 'the untouched session already sat at 100',
      );
    });

    test('the setting and the platform both have a veto', () {
      expect(
        PlayerVolume.initial
            .seeded(
              supported: true,
              setting: false,
              reading: onStep(8),
              fallbackLevel: 42,
            )
            .bound,
        isFalse,
      );
      expect(
        PlayerVolume.initial
            .seeded(
              supported: false,
              setting: true,
              reading: onStep(8),
              fallbackLevel: 42,
            )
            .bound,
        isFalse,
      );
    });

    test('a fresh reading can DROP a binding the cached one allowed', () {
      // The seed path runs twice: what was already known, then what the platform
      // answers. A device that turns out to be fixed on the second pass must end
      // unbound -- and the caller adopts this value, so the device subscription
      // follows it rather than a flag of its own.
      final cached = PlayerVolume.initial.seeded(
        supported: true,
        setting: true,
        reading: onStep(8),
        fallbackLevel: 42,
      );
      expect(cached.bound, isTrue);

      final fresh = cached.reconfirmed(
        supported: true,
        setting: true,
        reading: phone(fixed: true),
        fallbackLevel: 42,
      );
      expect(fresh.bound, isFalse);
      expect(fresh.level, cached.level, reason: 'what is on screen is kept');
    });

    test('but a confirming reading does NOT re-adopt its own level', () {
      // The second answer was already in flight when anything in between did: a
      // volume-key press in the first moments of a video arrives as a push and
      // must not be undone by the stale reading that was on its way.
      final bound = PlayerVolume.initial.seeded(
        supported: true,
        setting: true,
        reading: onStep(8),
        fallbackLevel: 42,
      );
      final movedByTheKeys = bound.reported(onStep(12));

      final confirmed = movedByTheKeys.reconfirmed(
        supported: true,
        setting: true,
        reading: onStep(8), // the stale answer
        fallbackLevel: 42,
      );
      expect(confirmed.level, movedByTheKeys.level);
      expect(confirmed.lastAudible, movedByTheKeys.lastAudible);

      // ... while a first pass that could not bind still gets its chance.
      final waiting = PlayerVolume.initial.seeded(
        supported: true,
        setting: true,
        reading: null,
        fallbackLevel: 42,
      );
      expect(waiting.bound, isFalse);
      final answered = waiting.reconfirmed(
        supported: true,
        setting: true,
        reading: onStep(8),
        fallbackLevel: 42,
      );
      expect(answered.bound, isTrue);
      expect(answered.level, closeTo(53.33, 0.01));
    });

    test('an unanswerable round trip does not hand a binding back', () {
      final bound = PlayerVolume.initial.seeded(
        supported: true,
        setting: true,
        reading: onStep(8),
        fallbackLevel: 42,
      );
      final failed = bound.reconfirmed(
        supported: true,
        setting: true,
        reading: null,
        fallbackLevel: 42,
      );
      expect(failed.bound, isTrue);
      expect(failed.level, bound.level);
    });
  });

  group('a level the user asked for', () {
    test('moves the level and remembers every audible one', () {
      final v = PlayerVolume.initial.withLevel(70).withLevel(0);
      expect(v.level, 0);
      expect(
        v.lastAudible,
        70,
        reason: 'muting must not erase the level to come back to',
      );
    });

    test('is clamped to the range a player has', () {
      expect(PlayerVolume.initial.withLevel(180).level, 100);
      expect(PlayerVolume.initial.withLevel(-20).level, 0);
    });

    test('refuses a level that is not a number', () {
      // A gesture area with no height yet produces one, and `clamp` is
      // transparent to NaN -- it would reach the device, where `round()` throws
      // from inside an unawaited write.
      final v = PlayerVolume.initial.withLevel(60);
      expect(v.withLevel(double.nan).level, 60);
      expect(v.withLevel(double.infinity).level, 60);
      expect(identical(v.withLevel(double.nan), v), isTrue);
    });
  });

  group('what the device reports', () {
    test('wins over what was asked for, which is how the bar stays honest', () {
      // The finger asked for 41% on a 15-step stream; the device landed on step
      // 6, which is 40%. The bar must show 40%.
      final bound = PlayerVolume.initial.seeded(
        supported: true,
        setting: true,
        reading: onStep(8),
        fallbackLevel: 100,
      );
      final asked = bound.withLevel(41);
      expect(asked.level, 41, reason: 'the finger is followed immediately');

      final answered = asked.reported(onStep(6));
      expect(answered.level, closeTo(40, 0.01));
      expect(
        asked.reported(onStep(6)).level,
        isNot(41),
        reason:
            'a reply equal to an earlier reading still has to reach the bar: '
            'the notifier cannot be relied on to notify for it',
      );
    });

    test('changes nothing for a session that is not bound', () {
      final v = PlayerVolume.initial.withLevel(55);
      expect(v.reported(onStep(3)).level, 55);
      expect(v.reported(null).level, 55);
      expect(v.reported(onStep(3)).bound, isFalse);
    });

    test('a FIXED output arriving mid-session hands the volume back', () {
      // An HDMI or USB sink can appear while a video is playing. Ignoring it
      // would leave the control bound to a stream whose writes are no-ops, with
      // the player pinned wide open -- no volume control at all.
      final bound = PlayerVolume.initial.seeded(
        supported: true,
        setting: true,
        reading: onStep(8),
        fallbackLevel: 42,
      );
      final handedBack = bound.reported(phone(fixed: true));
      expect(handedBack.bound, isFalse);
      expect(
        handedBack.level,
        bound.level,
        reason: 'the level on screen is what the app now has to attenuate',
      );
      expect(handedBack.playerGain, bound.level);
      expect(handedBack.remembersAppVolume, isTrue);
      expect(
        handedBack.lastAudible,
        bound.lastAudible,
        reason: 'the audible memory survives the hand-over',
      );
    });

    test('a muted stream reads as silence and keeps the audible memory', () {
      final bound = PlayerVolume.initial.seeded(
        supported: true,
        setting: true,
        reading: onStep(8),
        fallbackLevel: 100,
      );
      // `lastAudible: 0` in the READING, so this can only pass if the session
      // preserved its own memory rather than taking the reading's.
      final muted = bound.reported(phone(index: 8, muted: true, lastAudible: 0));
      expect(muted.level, 0);
      expect(muted.lastAudible, closeTo(53.33, 0.01));
    });
  });

  group('unmute', () {
    test('comes back to the level this session saw', () {
      final v = PlayerVolume.initial.seeded(
        supported: true,
        setting: true,
        reading: onStep(8),
        fallbackLevel: 100,
      );
      expect(v.unmuteTo(onStep(0)), closeTo(53.33, 0.01));
    });

    test('asks the DEVICE when the session opened silent', () {
      // The phone was already at 0 when the video opened, so this session has
      // seen nothing -- the memory starts at 0 precisely so the device's own
      // last audible level is reached instead of jumping to full scale.
      const silent = SystemVolumeReading(
        index: 0,
        min: 0,
        max: 15,
        muted: true,
        lastAudible: 5,
      );
      final v = PlayerVolume.initial.seeded(
        supported: true,
        setting: true,
        reading: silent,
        fallbackLevel: 100,
      );
      expect(v.level, 0);
      expect(v.lastAudible, 0, reason: 'nothing audible has been seen yet');
      expect(v.unmuteTo(silent), closeTo(33.33, 0.01));
    });

    test('and lands in the middle when the device cannot say either', () {
      final silent = phone(index: 0, lastAudible: 0);
      final v = PlayerVolume.initial
          .seeded(
            supported: true,
            setting: true,
            reading: silent,
            fallbackLevel: 100,
          )
          .reported(silent);
      expect(v.unmuteTo(silent), 50);
      expect(v.unmuteTo(null), 50);
    });
  });
}
