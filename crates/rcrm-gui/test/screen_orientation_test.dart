// test/screen_orientation_test.dart
// The "follow how the phone is held" request: the channel both native halves
// implement, and the latch that keeps a per-frame caller from crossing it per
// frame.
//
// What the halves do with it cannot be exercised from this desktop host —
// Android's `SCREEN_ORIENTATION_FULL_SENSOR` and iOS's hardware posture plus a
// geometry request — so what is pinned here is everything the app decides: the
// exact method names, that the two platforms are the only ones asked, that a
// caller repeating itself does not repeat the call, and that a platform which
// cannot answer leaves the latch where it was rather than believing it worked.

import 'dart:io' show Platform;

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:rcrm_gui/services/screen_orientation.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  final channel = ScreenOrientation.channel;
  final calls = <MethodCall>[];

  void answerWith(Future<Object?> Function(MethodCall) handler) {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          calls.add(call);
          return handler(call);
        });
    addTearDown(
      () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, null),
    );
  }

  setUp(() {
    calls.clear();
    ScreenOrientation.debugFollowing = false;
    // The mobile branch, which is where the call lives; this host is a desktop.
    debugScreenOrientationSupported = true;
  });
  tearDown(() {
    debugScreenOrientationSupported = Platform.isAndroid || Platform.isIOS;
    ScreenOrientation.debugFollowing = false;
  });

  test('the request travels as one named flag, each way', () async {
    answerWith((_) async => null);

    expect(await ScreenOrientation.followDevice(true), isTrue);
    expect(calls.single.method, 'follow');

    expect(await ScreenOrientation.followDevice(false), isTrue);
    expect(calls.last.method, 'release');
    expect(calls.length, 2);
  });

  test('EVERY ask crosses the channel, repeats included', () async {
    // There is no latch, and that is the fix for a real bug rather than an
    // oversight: the masking call that precedes this one writes the same platform
    // property on Android with the lock-RESPECTING value (`FULL_USER`), so a
    // sensor request that is not re-sent after every mask write silently degrades
    // the strategy to "follow the system". A latch held only until the first
    // call, and everything after it — the video's shape arriving, a jump into a
    // new player — went through the mask alone.
    answerWith((_) async => null);

    await ScreenOrientation.followDevice(true);
    await ScreenOrientation.followDevice(true);
    await ScreenOrientation.followDevice(true);
    expect(calls.length, 3);
    expect(calls.every((c) => c.method == 'follow'), isTrue);

    await ScreenOrientation.followDevice(false);
    await ScreenOrientation.followDevice(false);
    expect(calls.length, 5);
    expect(calls.last.method, 'release');
  });

  test('a platform that cannot answer does not break the caller', () async {
    answerWith((_) async => throw MissingPluginException('no native half'));

    // Best-effort: the caller's mask is what restores the app's own direction, so
    // a missing native half must not become an exception in the player.
    expect(await ScreenOrientation.followDevice(true), isFalse);
    expect(await ScreenOrientation.followDevice(false), isFalse);
    expect(ScreenOrientation.debugFollowing, isFalse);
  });

  test('a platform with no sensor is not asked at all', () async {
    debugScreenOrientationSupported = false;
    answerWith((_) async => null);

    expect(await ScreenOrientation.followDevice(true), isFalse);
    expect(await ScreenOrientation.followDevice(false), isFalse);

    expect(
      calls,
      isEmpty,
      reason: 'a desktop window has no sensor to follow and no mask to move',
    );
  });
}
