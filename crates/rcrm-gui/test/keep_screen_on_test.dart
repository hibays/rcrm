// test/keep_screen_on_test.dart
// The mobile player's screen-awake policy, the one platform write behind it, and
// the preference that chooses it.
//
// The policy is pure because the player screen cannot be mounted in a test; the
// service has a test seam because the desktop VM has no wakelock platform. The
// stored default is pinned here too: ON is a product decision (a video that dims
// while it is watched is the defect this feature fixes), and a later change to
// it should have to delete an assertion.

import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:rcrm_gui/services/screen_wakelock.dart';
import 'package:rcrm_gui/services/settings_service.dart';
import 'package:rcrm_gui/utils/keep_screen_on.dart';

void main() {
  group('the policy', () {
    test(
      'fullscreen holds only while the setting is on and the file plays',
      () {
        expect(
          shouldKeepScreenOn(
            mobile: true,
            fullscreen: true,
            enabled: true,
            playing: true,
          ),
          isTrue,
        );
        // Paused is NOT held, even with the switch on: that is the system's
        // timeout doing its job, and the whole point of the setting.
        expect(
          shouldKeepScreenOn(
            mobile: true,
            fullscreen: true,
            enabled: true,
            playing: false,
          ),
          isFalse,
        );
        // Switching it off really does hand a PLAYING fullscreen video back;
        // otherwise the switch would be a dead control in the one state it
        // exists for.
        expect(
          shouldKeepScreenOn(
            mobile: true,
            fullscreen: true,
            enabled: false,
            playing: true,
          ),
          isFalse,
        );
        expect(
          shouldKeepScreenOn(
            mobile: true,
            fullscreen: true,
            enabled: false,
            playing: false,
          ),
          isFalse,
        );
      },
    );

    test('outside fullscreen the player follows playback, as it always did', () {
      // Windowed playback must not regress: the engine's own Video widget used
      // to hold the screen while playing, and the player now owns that flag.
      expect(
        shouldKeepScreenOn(
          mobile: true,
          fullscreen: false,
          enabled: true,
          playing: true,
        ),
        isTrue,
      );
      expect(
        shouldKeepScreenOn(
          mobile: true,
          fullscreen: false,
          enabled: true,
          playing: false,
        ),
        isFalse,
      );
      // The switch is a FULLSCREEN choice: with it off, a windowed player that
      // is playing still holds the screen, exactly as it did before the row
      // existed.
      expect(
        shouldKeepScreenOn(
          mobile: true,
          fullscreen: false,
          enabled: false,
          playing: true,
        ),
        isTrue,
      );
      expect(
        shouldKeepScreenOn(
          mobile: true,
          fullscreen: false,
          enabled: false,
          playing: false,
        ),
        isFalse,
      );
    });

    test('desktop is not this policy', () {
      // A desktop player keeps the engine's own wakelock and is not offered the
      // row; the service is a no-op there, so the policy says so too rather
      // than pretending it could act.
      expect(
        shouldKeepScreenOn(
          mobile: false,
          fullscreen: true,
          enabled: true,
          playing: true,
        ),
        isFalse,
      );
    });
  });

  group('ScreenWakelock', () {
    setUp(() {
      ScreenWakelock.resetForTest();
      debugWakelockSupported = true;
    });
    tearDown(ScreenWakelock.resetForTest);

    test('asks the platform once per state change', () async {
      final calls = <bool>[];
      debugWakelockApply = (awake) async => calls.add(awake);

      await ScreenWakelock.setAwake(true);
      // A player re-applies its policy on every playback event; the service
      // must not write the channel each time.
      await ScreenWakelock.setAwake(true);
      await ScreenWakelock.setAwake(false);
      await ScreenWakelock.setAwake(false);
      await ScreenWakelock.setAwake(true);

      expect(calls, <bool>[true, false, true]);
    });

    test('a platform that cannot answer is not asked', () async {
      debugWakelockSupported = false;
      var calls = 0;
      debugWakelockApply = (awake) async => calls++;

      await ScreenWakelock.setAwake(true);

      expect(calls, 0);
      expect(ScreenWakelock.supported, isFalse);
    });

    test('a failed write is retried by the next event', () async {
      // Best-effort: the player must not break, but the record must not claim
      // success either -- otherwise the next event would dedupe the retry away.
      var tries = 0;
      debugWakelockApply = (awake) async {
        tries++;
        if (tries == 1) throw StateError('platform refused');
      };

      await ScreenWakelock.setAwake(true);
      await ScreenWakelock.setAwake(true);

      expect(tries, 2);
    });
  });

  group('the stored preference', () {
    setUp(() => SharedPreferences.setMockInitialValues({}));

    test('defaults to on', () async {
      // ON is the product decision: the player is the only thing that acts on
      // it, and the fullscreen video is exactly what must not let the phone
      // sleep.
      expect(await SettingsService().getPlayerKeepScreenOn(), isTrue);
    });

    test('round-trips both answers', () async {
      final service = SettingsService();

      await service.setPlayerKeepScreenOn(false);
      expect(await service.getPlayerKeepScreenOn(), isFalse);

      await service.setPlayerKeepScreenOn(true);
      expect(await service.getPlayerKeepScreenOn(), isTrue);
    });
  });
}
