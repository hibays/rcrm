// services/screen_capture.dart
// Whether the system may capture this app's pixels — the mobile-only setting
// behind Settings → Privacy.
//
// The two mobile platforms promise different things, and the row says so:
//
//  * Android — ONE window flag does all of it. `FLAG_SECURE` makes a screenshot
//    come out blank, keeps the content out of screen recordings, and hides the
//    task in the recent-apps preview.
//  * iOS — nothing blocks a still screenshot; the OS only tells an app AFTER the
//    fact (`userDidTakeScreenshotNotification`). What iOS does expose is whether
//    the screen is being recorded or mirrored (`UIScreen.isCaptured`) and the
//    moment the app stops being frontmost — which is when the system photographs
//    it for the app switcher. That half therefore HIDES the library in those two
//    situations instead of refusing the capture.
//
// Both halves are the app's own code, beside the generated plugin
// registrations: `android/app/src/main/kotlin/com/rcrm/app/ScreenCaptureChannel.kt`
// and `ios/Runner/ScreenCaptureChannel.swift`. No plugin package sits behind
// them — the Android half is one flag, and iOS has nothing to buy.
//
// The default is NOT allowed: the app shows decrypted media, and a screenshot of
// it outlives the session. The Android window is secured in `onCreate`, before
// Dart is even up, so the answer while the app starts is never "capturable"; the
// stored choice is then applied by `SettingsNotifier.load`.
//
// `setAllowed` never throws — a platform that cannot answer must not break the
// settings screen.

import 'dart:io' show Platform;

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// Test seam for the mobile-only branch below.
///
/// The tests run the desktop VM, where the real platform check is false — so
/// neither the row nor the channel call would be reachable from a test, and the
/// row IS this feature. Only `test/screen_capture_test.dart` writes it.
/// Untouched, it is exactly `Platform.isAndroid || Platform.isIOS`.
@visibleForTesting
bool debugScreenCaptureSupported = Platform.isAndroid || Platform.isIOS;

class ScreenCapture {
  ScreenCapture._();

  /// The channel both halves implement. Pinned here because a mismatch between
  /// this name and either platform file is silent.
  static const MethodChannel channel = MethodChannel('rcrm/screen');

  /// Where the setting is offered AND honoured: the two mobile platforms. A
  /// desktop window's pixels are the OS's business and no app API reaches them,
  /// so neither the row nor the channel call happens there.
  static bool get supported => debugScreenCaptureSupported;

  /// Whether the platform can refuse a still screenshot — Android can, iOS
  /// cannot. The switch promises only what it can keep, so the wordings differ
  /// ([capturePolicyNote]).
  static bool get canBlockScreenshots => Platform.isAndroid;

  /// Tells the platform what the user chose (and, at startup, what was stored).
  ///
  /// Best-effort by design: a platform that cannot answer must not break the
  /// settings screen, and a platform with no capture surface is not asked at all.
  static Future<void> setAllowed(bool allowed) async {
    if (!supported) return;
    try {
      await channel.invokeMethod<void>('setCaptureAllowed', <String, dynamic>{
        'allowed': allowed,
      });
    } catch (_) {
      // Nothing to configure on this platform.
    }
  }
}

/// The Settings row's subtitle: what the switch really does, on the platform it
/// is shown on.
///
/// A pure function of [canBlockScreenshots] rather than a read of `Platform`, so
/// both wordings are assertable on any host — the tests run the desktop VM,
/// where neither mobile branch is reachable.
String capturePolicyNote({required bool canBlockScreenshots}) =>
    canBlockScreenshots
    ? 'Block screenshots and screen recording, and hide the library from the '
          'recent-apps preview'
    : 'Hide the library while the screen is recorded, mirrored or listed in the '
          'app switcher; iOS itself cannot block a still screenshot';
