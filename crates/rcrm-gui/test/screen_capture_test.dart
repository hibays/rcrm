// test/screen_capture_test.dart
// The mobile-only screenshot policy: the channel both platform halves implement,
// the default it ships with, and the row that offers it.
//
// The enforcement itself is native — Android's `FLAG_SECURE`
// (`ScreenCaptureChannel.kt`), iOS's capture observers
// (`ScreenCaptureChannel.swift`) — and cannot be exercised from this desktop
// host. What CAN be pinned is everything the app decides: the channel name and
// its argument, the default being "not allowed", the write-through when the
// switch moves, the re-apply at launch (which is what lifts the window Android
// secured before Dart existed), and that the row promises only what the platform
// can really do.

import 'dart:async';
import 'dart:io' show Platform;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:rcrm_gui/config/theme.dart';
import 'package:rcrm_gui/providers/settings_provider.dart';
import 'package:rcrm_gui/screens/settings_screen.dart';
import 'package:rcrm_gui/services/screen_capture.dart';
import 'package:rcrm_gui/services/settings_service.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const channel = MethodChannel('rcrm/screen');
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
    SharedPreferences.setMockInitialValues({});
    calls.clear();
    // The mobile branch, which is where both the row and the channel call live;
    // this host is a desktop, so without the seam neither is reachable.
    debugScreenCaptureSupported = true;
  });
  tearDown(
    () => debugScreenCaptureSupported = Platform.isAndroid || Platform.isIOS,
  );

  /// Lets the (mocked) platform answer — the launch push is fire-and-forget.
  Future<void> settle() => Future<void>.delayed(Duration.zero);

  group('the platform contract', () {
    test('the choice travels as one named flag', () async {
      answerWith((_) async => null);

      await ScreenCapture.setAllowed(true);
      expect(calls.single.method, 'setCaptureAllowed');
      expect((calls.single.arguments as Map)['allowed'], isTrue);

      await ScreenCapture.setAllowed(false);
      expect((calls.last.arguments as Map)['allowed'], isFalse);
    });

    test('a platform without the handler is not an error', () async {
      answerWith((_) async => throw MissingPluginException('desktop'));
      await ScreenCapture.setAllowed(true); // must not throw
    });

    test('a platform with no capture surface is not asked at all', () async {
      debugScreenCaptureSupported = false;
      answerWith((_) async => null);

      await ScreenCapture.setAllowed(true);

      expect(
        calls,
        isEmpty,
        reason:
            'desktop has no capture API to configure — and a channel call '
            'nothing answers is how a settings restore stalls',
      );
    });

    test('the row promises only what the platform can do', () {
      final android = capturePolicyNote(canBlockScreenshots: true);
      final ios = capturePolicyNote(canBlockScreenshots: false);

      expect(android, contains('Block screenshots'));
      expect(ios, contains('cannot block a still screenshot'));
      // The two are not interchangeable: iOS must not be shown a promise it
      // cannot keep, and Android must not be told it cannot.
      expect(ios, isNot(contains('Block screenshots')));
      expect(android, isNot(contains('cannot block')));
    });
  });

  group('the setting', () {
    test('ships NOT allowed, and the state agrees with the store', () async {
      expect(
        const SettingsState().allowScreenshots,
        isFalse,
        reason:
            'the library is decrypted media: capture is opt-in, never a '
            'default',
      );
      expect(await SettingsService().getAllowScreenshots(), isFalse);
    });

    test(
      'a choice is persisted under its own key and told to the platform',
      () async {
        answerWith((_) async => null);
        final c = ProviderContainer();
        addTearDown(c.dispose);

        await c.read(uiSettingsProvider.notifier).setAllowScreenshots(true);

        expect(c.read(uiSettingsProvider).allowScreenshots, isTrue);
        expect(
          (await SharedPreferences.getInstance()).getBool('allow_screenshots'),
          isTrue,
          reason: 'the key hand-edited settings and this service share',
        );
        expect((calls.single.arguments as Map)['allowed'], isTrue);
      },
    );

    test('launch re-applies the stored choice', () async {
      // What `app.dart` does at startup. This call is the one that lifts the
      // window Android secured in `MainActivity.onCreate`, so a stored "allowed"
      // that never reached the platform would leave the switch stuck off.
      SharedPreferences.setMockInitialValues({'allow_screenshots': true});
      answerWith((_) async => null);
      final c = ProviderContainer();
      addTearDown(c.dispose);

      await c.read(uiSettingsProvider.notifier).load();
      await settle();

      expect(c.read(uiSettingsProvider).allowScreenshots, isTrue);
      expect((calls.single.arguments as Map)['allowed'], isTrue);
    });

    test('a stored "not allowed" is re-applied too', () async {
      SharedPreferences.setMockInitialValues({'allow_screenshots': false});
      answerWith((_) async => null);
      final c = ProviderContainer();
      addTearDown(c.dispose);

      await c.read(uiSettingsProvider.notifier).load();
      await settle();

      expect(c.read(uiSettingsProvider).allowScreenshots, isFalse);
      expect((calls.single.arguments as Map)['allowed'], isFalse);
    });

    test('loading the settings never waits on the platform', () async {
      // A restore that hangs on a platform call is worse than a policy applied a
      // frame late, so the push is fire-and-forget — measured the hard way: an
      // awaited channel round-trip inside `testWidgets` never resolves at all
      // (the fake clock does not advance the engine's reply), which stalled
      // every existing test that calls `load()`.
      answerWith((_) async => Completer<Object?>().future); // never answers
      final c = ProviderContainer();
      addTearDown(c.dispose);

      await c.read(uiSettingsProvider.notifier).load();

      expect(c.read(uiSettingsProvider).allowScreenshots, isFalse);
    });
  });

  group('the row', () {
    Future<ProviderContainer> pumpSettings(WidgetTester tester) async {
      await tester.binding.setSurfaceSize(const Size(1000, 1400));
      addTearDown(() => tester.binding.setSurfaceSize(null));
      final c = ProviderContainer();
      addTearDown(c.dispose);
      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: c,
          child: MaterialApp(
            theme: RCrmTheme.dark,
            home: const SettingsScreen(),
          ),
        ),
      );
      await tester.pump();
      return c;
    }

    testWidgets('is not offered on a platform that could not act', (
      tester,
    ) async {
      debugScreenCaptureSupported = false;
      await pumpSettings(tester);

      expect(find.text('Allow Screenshots'), findsNothing);
      expect(find.text('Privacy'), findsNothing);
      // The sections that stay are still there, so this is the row being gated
      // rather than the page failing to build.
      expect(find.text('Thumbnail Cache'), findsOneWidget);
      expect(find.text('Cast Auto-Next'), findsOneWidget);
    });

    testWidgets('offers the choice where the platform has a capture surface', (
      tester,
    ) async {
      debugScreenCaptureSupported = true;
      // The row writes through to the platform, so the platform has to answer.
      answerWith((_) async => null);
      final c = await pumpSettings(tester);

      expect(find.text('Privacy'), findsOneWidget);
      final tile = tester.widget<SwitchListTile>(
        find.widgetWithText(SwitchListTile, 'Allow Screenshots'),
      );
      expect(
        tile.value,
        isFalse,
        reason: 'the default has to be visible as OFF, not just be off',
      );
      // The subtitle is the platform's own truth: this host cannot block a still
      // screenshot, and the row says so instead of promising otherwise.
      expect(
        find.text(capturePolicyNote(canBlockScreenshots: false)),
        findsOneWidget,
      );

      tile.onChanged!(true);
      await tester.pump();

      expect(c.read(uiSettingsProvider).allowScreenshots, isTrue);
      expect(
        tester
            .widget<SwitchListTile>(
              find.widgetWithText(SwitchListTile, 'Allow Screenshots'),
            )
            .value,
        isTrue,
      );
      expect(
        (calls.last.arguments as Map)['allowed'],
        isTrue,
        reason: 'the platform is the thing that enforces this',
      );
      expect(
        (await SharedPreferences.getInstance()).getBool('allow_screenshots'),
        isTrue,
      );
    });
  });
}
