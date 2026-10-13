// services/screen_orientation.dart
// The one orientation request the framework cannot make: "follow how the phone is
// held", rotation lock or no lock.
//
// `SystemChrome.setPreferredOrientations` carries a LIST of orientations, and the
// Android embedding turns that list into one `SCREEN_ORIENTATION_*` value with a
// fixed table. Every entry in that table either respects the rotation lock
// (`fullUser` for all four) or ignores the sensor entirely (`landscape`,
// `portrait`); `fullSensor` -- "Ignores user's setting to turn off sensor-based
// rotation" -- is not reachable from any list. So the app asks for it itself,
// through its own channel, exactly like the screenshot policy and the storage
// ask.
//
// iOS needs a different mechanism for the same idea, and the native half there
// does it: `UIDevice.current.orientation` is the hardware posture (unaffected by
// the rotation lock), and the interface is moved to it with
// `requestGeometryUpdate` (iOS 16+) or the `setValue(_:forKey:)` pair before
// that. Both halves answer to the same two methods.
//
// ORDER MATTERS, and ONE place owns it (`utils/player_orientation.dart`,
// `applyOrientationRequest` / `releaseOrientationRequest`): going IN, the mask is
// written first and the sensor request second; coming OUT it is the other way
// round. Both are the same activity property on Android, so the last write is the
// one that stands, and iOS only honours a geometry request its supported mask
// already allows.
//
// The call is deliberately narrow: two methods, no state reported back, and no
// latch -- the sensor request is re-sent after every mask write precisely because
// the mask would otherwise be the last word.

import 'dart:io' show Platform;

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// Test seam for the mobile-only branch below.
///
/// The tests run the desktop VM, where the real platform check is false, so
/// neither the call nor the fallback would be reachable. Only
/// `test/screen_orientation_test.dart` writes it.
@visibleForTesting
bool debugScreenOrientationSupported = Platform.isAndroid || Platform.isIOS;

class ScreenOrientation {
  ScreenOrientation._();

  /// The channel both halves implement. Pinned here because a mismatch between
  /// this name and either platform file is silent.
  static const MethodChannel channel = MethodChannel('rcrm/orientation');

  /// True where "follow the phone" means anything: the two mobile platforms. A
  /// desktop window has no sensor to follow and no mask to move, so neither the
  /// row nor the call happens there.
  static bool get supported => debugScreenOrientationSupported;

  /// Whether the native half is being asked to follow the device.
  ///
  /// There is deliberately NO latch here. The masking call that precedes this one
  /// writes the SAME platform property on Android, and it writes the
  /// lock-RESPECTING value (`FULL_USER`), so the sensor request has to be re-sent
  /// after every mask write or the strategy silently degrades to "follow the
  /// system" — which is exactly what a latch caused: it held only until the first
  /// call, and everything after it (the video's shape arriving, a jump into a new
  /// player, the settings panel) went through the mask alone. Both native halves
  /// are idempotent, so asking again costs a channel call and nothing else.
  @visibleForTesting
  static bool debugFollowing = false;

  /// Starts or stops following the phone's real posture.
  ///
  /// Always asks: the caller must send its `SystemChrome` mask FIRST and this
  /// second (see `utils/player_orientation.dart` for why, and for the one place
  /// that owns the order).
  ///
  /// Best-effort like every other platform call here: a host without the native
  /// half must not break playback, and the caller's mask is what restores the
  /// app's own direction either way.
  static Future<void> followDevice(bool follow) async {
    if (!supported) return;
    debugFollowing = follow;
    try {
      await channel.invokeMethod<void>(follow ? 'follow' : 'release');
    } catch (_) {
      // A platform that cannot answer leaves the orientation where it was.
    }
  }
}
