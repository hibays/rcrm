// test/settings_playback_mode_test.dart
// The persisted playback mode, at the seam where a preference file this build
// did not write meets the four modes this build knows.
//
// The mode lives in the transport bar's chip now, and its vocabulary is
// `PlaybackMode.key` (`utils/player_playback_mode.dart`); the service's
// whitelist is the read-side guard for everything else an older build, a
// hand-edited preference file, or a downgrade can put in storage.

import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:rcrm_gui/services/settings_service.dart';
import 'package:rcrm_gui/utils/player_playback_mode.dart';

void main() {
  setUp(() => SharedPreferences.setMockInitialValues({}));

  test('every mode round-trips through storage', () async {
    final service = SettingsService();
    for (final mode in PlaybackMode.values) {
      await service.setPlaybackMode(mode.key);
      expect(
        await service.getPlaybackMode(),
        mode.key,
        reason: '${mode.label} survives a save and a load',
      );
    }
  });

  test('an unknown stored value reads as the default, not as a mode', () async {
    // A downgrade (a build that knew a mode this one does not) or a hand edit
    // must not conjure a mode the player has no behaviour for: it reads as
    // `pauseAfter`, the app's own default — the same answer an empty store
    // gives.
    SharedPreferences.setMockInitialValues({'playback_mode': 'loopEverything'});
    final service = SettingsService();
    expect(await service.getPlaybackMode(), PlaybackMode.pauseAfter.key);
  });

  test('an empty store reads as the default', () async {
    final service = SettingsService();
    expect(await service.getPlaybackMode(), PlaybackMode.pauseAfter.key);
  });
}
