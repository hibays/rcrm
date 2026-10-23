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
// `applyOrientationRequest` / `releaseOrientationRequest`): coming OUT the sensor
// stops first and the mask second; going IN the mask is written first and the
// sensor second, EXCEPT on Android, where a Follow request writes no mask at all
// -- the all-four list is the lock-RESPECTING value there, so writing it before
// FULL_SENSOR is the "system, then back" flash. FULL_SENSOR is a complete policy
// on its own; iOS still needs the mask first because it only honours a geometry
// request its supported mask already allows.
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
  /// Always asks. On iOS the caller writes its `SystemChrome` mask FIRST and
  /// this second; on Android it writes no mask for a Follow request, because
  /// `FULL_SENSOR` already allows every orientation and the all-four mask would
  /// only flash the system's locked orientation first (see
  /// `utils/player_orientation.dart`, which owns the order).
  ///
  /// Returns whether the request reached the platform. On Android the Follow
  /// request carries no mask of its own, so `false` is the caller's cue to write
  /// the all-four fallback instead of leaving a previous, narrower mask (a
  /// Portrait lock, for one) in force; on iOS the mask was already written first
  /// and the answer is ignored. A missing native half still never throws --
  /// best-effort like every other platform call here.
  static Future<bool> followDevice(bool follow) async {
    if (!supported) return false;
    debugFollowing = follow;
    try {
      await channel.invokeMethod<void>(follow ? 'follow' : 'release');
      return true;
    } catch (_) {
      // A platform that cannot answer leaves the orientation where it was; the
      // caller's mask is the best-effort fallback.
      debugFollowing = false;
      return false;
    }
  }
}
