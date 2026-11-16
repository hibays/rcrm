// services/screen_wakelock.dart
// The one owner of the phone's screen-awake flag while a video player is open.
//
// Mobile only. The policy is pure and lives in `utils/keep_screen_on.dart`;
// this service is the platform edge. It exists because `media_kit_video`'s
// built-in wakelock cannot express this setting:
//
//  * Its only public control is `Video(wakelock: bool)`, and it follows
//    `playing`: on while the file rolls, off on pause and on dispose. The
//    setting needs to be able to switch a PLAYING fullscreen video OFF, and a
//    live switch has to take effect without remounting the picture; neither is
//    expressible there (the flag is read only in `initState`).
//  * Its wakelock is held through a PROCESS-WIDE static count, and when the
//    count reaches zero it calls `WakelockPlus.disable()`. A preview clip
//    ending would therefore clear a hold this service owns while the player is
//    still playing; left on in the player itself, its own enable would also
//    override the setting's OFF state.
//
// So the player's `Video`s (and the card previews, which can be mounted beside
// it) pass `wakelock: false` on mobile: media_kit never writes the flag while a
// player is open, and this service is its ONE writer. The other `Video`s in the
// app -- the cast receiver, a live photo -- keep the engine's behaviour because
// they live on their own routes/tabs and are not mounted beside a player; if
// one ever can be, it must opt out too or its own disable will clear this hold.
//
// The package behind both is `wakelock_plus` (`FLAG_KEEP_SCREEN_ON` on
// Android's window, `UIApplication.isIdleTimerDisabled` on iOS), which already
// ships in this app as a dependency of `media_kit_video`. It is declared in
// pubspec because this file imports it directly; it is the same platform flag
// with one owner, not a second mechanism. Best-effort by design: a platform
// that cannot answer must not break the player.

import 'dart:io' show Platform;

import 'package:flutter/foundation.dart';
import 'package:wakelock_plus/wakelock_plus.dart';

/// Test seam for the mobile-only branch below.
///
/// The tests run the desktop VM, where the real platform check is false -- so
/// neither the platform call nor a policy assertion would be reachable there.
/// Only `test/keep_screen_on_test.dart` writes it.
@visibleForTesting
bool debugWakelockSupported = Platform.isAndroid || Platform.isIOS;

/// Test seam for the platform write itself. When null the service calls
/// `wakelock_plus`; the tests replace it so no MethodChannel is touched.
@visibleForTesting
Future<void> Function(bool awake)? debugWakelockApply;

class ScreenWakelock {
  ScreenWakelock._();

  /// Where the setting is offered AND honoured: the two mobile platforms. A
  /// desktop player keeps the engine's own wakelock, and the row is not shown
  /// there (see `player_settings_panel.dart`).
  static bool get supported => debugWakelockSupported;

  /// The last state this process ASKED for -- not platform truth. A platform
  /// that refused the request is retried by the next event.
  static bool _awake = false;

  /// Tells the platform whether the screen may sleep.
  ///
  /// [awake] is a REQUEST, not a toggle: repeated calls in the same state are
  /// dropped here, so a player that re-applies its policy on every playback
  /// event does not write the channel each time.
  static Future<void> setAwake(bool awake) async {
    if (!supported) return;
    if (_awake == awake) return;
    final bool previous = _awake;
    _awake = awake;
    try {
      final apply = debugWakelockApply;
      if (apply != null) {
        await apply(awake);
      } else {
        await WakelockPlus.toggle(enable: awake);
      }
    } catch (_) {
      // A platform that cannot answer must not break the player. Put the
      // record back so the next event tries again.
      if (_awake == awake) _awake = previous;
    }
  }

  /// Puts the seam back to "a fresh process", the way
  /// `ThumbCache.resetForTest` / `SettingsService.clearPrimedAppearance` do.
  @visibleForTesting
  static void resetForTest() {
    _awake = false;
    debugWakelockApply = null;
    debugWakelockSupported = Platform.isAndroid || Platform.isIOS;
  }
}
