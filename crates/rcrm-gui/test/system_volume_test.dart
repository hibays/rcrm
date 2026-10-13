// test/system_volume_test.dart
// The mobile-only volume binding: the stream arithmetic both directions use,
// the channel both platform halves implement, the default it ships with, and
// the row that offers it.
//
// The device half is native -- Android's media stream
// (`SystemVolumeChannel.kt`), iOS's output volume (`SystemVolumeChannel.swift`)
// -- and cannot be exercised from this desktop host. What CAN be pinned is
// everything the app decides: the index <-> percentage conversion (including
// the quantisation a 15-step stream forces, which is the one thing that decides
// whether the bar tells the truth), the exact numbers that cross the channel,
// the refusal to bind on a device that cannot answer, the default per platform,
// and the row's wording.

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
import 'package:rcrm_gui/services/settings_service.dart';
import 'package:rcrm_gui/services/system_volume.dart';

/// A phone's media stream as Android describes it: fifteen steps, one of them
/// (index 0) silent.
Map<String, Object?> phoneReading({
  int index = 8,
  int min = 0,
  int max = 15,
  bool muted = false,
  int lastAudible = 8,
  bool fixed = false,
}) => <String, Object?>{
  'index': index,
  'min': min,
  'max': max,
  'muted': muted,
  'lastAudible': lastAudible,
  'fixed': fixed,
};

SystemVolumeReading reading({
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

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  final channel = SystemVolume.channel;
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
    SystemVolume.debugReset();
    // The mobile branch, which is where both the row and the channel calls
    // live; this host is a desktop, so without the seam neither is reachable.
    debugSystemVolumeSupported = true;
  });
  tearDown(() {
    debugSystemVolumeSupported = Platform.isAndroid || Platform.isIOS;
    SystemVolume.debugReset();
  });

  group('the stream arithmetic', () {
    test('a percentage becomes a step of THIS stream, and back', () {
      // A 15-step phone stream: the ends are exact, the middle is not.
      expect(systemVolumeIndex(0, min: 0, max: 15), 0);
      expect(systemVolumeIndex(100, min: 0, max: 15), 15);
      expect(systemVolumeIndex(50, min: 0, max: 15), 8); // 7.5, away from zero
      expect(systemVolumePercent(15, min: 0, max: 15), 100);
      expect(systemVolumePercent(0, min: 0, max: 15), 0);
      expect(systemVolumePercent(8, min: 0, max: 15), closeTo(53.33, 0.01));
    });

    test('the device quantises, and the bar must show what it landed on', () {
      // 43% is a level this phone does not have. The step it does have is
      // 6/15 = 40%, and that is the number the bar has to show once the device
      // has answered -- anything else is a volume the phone is not at.
      final step = systemVolumeIndex(43, min: 0, max: 15);
      expect(step, 6);
      expect(systemVolumePercent(step, min: 0, max: 15), closeTo(40, 0.01));
    });

    test('a stream that does not start at zero is still a percentage', () {
      // `getStreamMinVolume` is not always 0: it is the stream's own floor.
      expect(systemVolumePercent(1, min: 1, max: 16), 0);
      expect(systemVolumePercent(16, min: 1, max: 16), 100);
      expect(systemVolumeIndex(0, min: 1, max: 16), 1);
      expect(systemVolumeIndex(100, min: 1, max: 16), 16);
    });

    test('the ends are closed, whatever arrives', () {
      expect(systemVolumeIndex(-20, min: 0, max: 15), 0);
      expect(systemVolumeIndex(180, min: 0, max: 15), 15);
      expect(systemVolumePercent(-4, min: 0, max: 15), 0);
      expect(systemVolumePercent(99, min: 0, max: 15), 100);
    });

    test('a percent that is not a number has a step, and does not throw', () {
      // `clamp` passes NaN through and `round()` throws on it, which would break
      // this file's promise from inside an `unawaited` write. `PlayerVolume`
      // refuses the value first, so this is the belt under that guard.
      expect(systemVolumeIndex(double.nan, min: 0, max: 15), 0);
      expect(systemVolumeIndex(double.infinity, min: 0, max: 15), 0);
      expect(systemVolumeIndex(double.negativeInfinity, min: 2, max: 15), 2);
    });

    test('iOS, whose own unit is the percentage, is the identity', () {
      for (final p in <double>[0, 7, 43, 99.4, 100]) {
        expect(systemVolumeIndex(p, min: 0, max: 100), p.round());
      }
      expect(systemVolumePercent(43, min: 0, max: 100), 43);
    });
  });

  group('the reading', () {
    test('reads a complete platform map', () {
      final r = SystemVolumeReading.fromPlatform(phoneReading());
      expect(r, isNotNull);
      expect(r!.index, 8);
      expect(r.min, 0);
      expect(r.max, 15);
      expect(r.muted, isFalse);
      expect(r.fixed, isFalse);
      expect(r.percent, closeTo(53.33, 0.01));
    });

    test('a reply that is not a whole stream is refused', () {
      // Half a reading is worse than none: an invented `max` would put a wrong
      // level on the bar, and an invented `min` would set the phone somewhere
      // nobody asked for.
      final broken = <String, Object?>{
        'index': 8,
        'min': 0,
        'max': 15,
        'muted': false,
        'lastAudible': 8,
        'fixed': false,
      };
      expect(SystemVolumeReading.fromPlatform(null), isNull);
      expect(SystemVolumeReading.fromPlatform('8 of 15'), isNull);
      expect(SystemVolumeReading.fromPlatform(<Object?>[]), isNull);
      for (final key in broken.keys) {
        final partial = Map<String, Object?>.from(broken)..remove(key);
        expect(
          SystemVolumeReading.fromPlatform(partial),
          isNull,
          reason: 'a reply without `$key` is not a stream',
        );
      }
      final wrongType = Map<String, Object?>.from(broken)..['muted'] = 'no';
      expect(SystemVolumeReading.fromPlatform(wrongType), isNull);
      final noTravel = Map<String, Object?>.from(broken)
        ..['min'] = 7
        ..['max'] = 7;
      expect(
        SystemVolumeReading.fromPlatform(noTravel),
        isNull,
        reason:
            'a stream with no travel and no explanation is not a reading this '
            'app may act on',
      );
      // A floor ABOVE its ceiling: malformed whatever the `fixed` claim says, and
      // `clamp` throws on it -- which on the push path is an unhandled error,
      // because nothing catches between the platform and `fromPlatform`.
      final inverted = Map<String, Object?>.from(broken)
        ..['min'] = 9
        ..['max'] = 3
        ..['fixed'] = true;
      expect(SystemVolumeReading.fromPlatform(inverted), isNull);
    });

    test('a fixed output IS a reading, so the row can say so', () {      // A TV box or an HDMI sink reports a stream with no travel AND says the
      // output is fixed. That is a fact about the device, not a broken reply:
      // the binding refuses it (`shouldBindSystemVolume`) and the Settings row
      // repeats it, which it could not do if this came back as "no reading".
      final r = SystemVolumeReading.fromPlatform(
        phoneReading(index: 0, min: 0, max: 0, muted: true, fixed: true),
      );
      expect(r, isNotNull);
      expect(r!.fixed, isTrue);
      expect(
        shouldBindSystemVolume(supported: true, setting: true, reading: r),
        isFalse,
      );
    });

    test('an index outside the stream is pulled back into it', () {
      final r = SystemVolumeReading.fromPlatform(
        phoneReading(index: 99, lastAudible: -3),
      );
      expect(r!.index, 15);
      expect(r.lastAudible, 0);
    });

    test('a stream muted elsewhere reads as silence, not as a level', () {
      // Muted at a non-zero index (another app, or a system toggle): the app
      // must not draw a live speaker at 53%. What unmute restores is still the
      // level the device was at, which is why it is reported separately.
      final r = SystemVolumeReading.fromPlatform(
        phoneReading(index: 8, muted: true),
      )!;
      expect(r.percent, 0);
      expect(r.lastAudiblePercent, closeTo(53.33, 0.01));
    });

    test('the conversion back uses this stream, not a default', () {
      expect(reading(index: 8).indexFor(0), 0);
      expect(reading(index: 8).indexFor(100), 15);
      expect(reading(index: 8).indexFor(40), 6);
    });
  });

  group('unmute', () {
    test('prefers the level this app saw', () {
      expect(
        unmuteLevel(lastSeen: 70, reading: reading(index: 3, lastAudible: 3)),
        70,
        reason: 'the level the user was just at is the one to come back to',
      );
    });

    test('falls back to the device, for a session that began silent', () {
      // The phone was muted before the app opened, so nothing was ever seen --
      // and "unmute" must not jump to full scale on a phone that was quietly
      // at 30%.
      expect(
        unmuteLevel(lastSeen: 0, reading: reading(index: 0, lastAudible: 5)),
        closeTo(33.33, 0.01),
      );
    });

    test('and to the middle when neither the app nor the device knows', () {
      expect(
        unmuteLevel(lastSeen: 0, reading: reading(index: 0, lastAudible: 0)),
        50,
      );
      expect(unmuteLevel(lastSeen: 0), 50);
    });
  });

  group('whether to bind at all', () {
    test('needs the platform, the setting and a usable reading', () {
      expect(
        shouldBindSystemVolume(
          supported: true,
          setting: true,
          reading: reading(),
        ),
        isTrue,
      );
      expect(
        shouldBindSystemVolume(
          supported: false,
          setting: true,
          reading: reading(),
        ),
        isFalse,
        reason: 'a desktop has no media stream this app may set',
      );
      expect(
        shouldBindSystemVolume(
          supported: true,
          setting: false,
          reading: reading(),
        ),
        isFalse,
      );
      expect(
        shouldBindSystemVolume(supported: true, setting: true),
        isFalse,
        reason: 'a bar starting from a number nobody read is invented',
      );
      expect(
        shouldBindSystemVolume(
          supported: true,
          setting: true,
          reading: reading(fixed: true),
        ),
        isFalse,
        reason:
            'a fixed-volume output cannot be set, so the slider would be dead',
      );
    });
  });

  group('the platform contract', () {
    test('a read adopts what the device says', () async {
      answerWith((_) async => phoneReading());
      final r = await SystemVolume.read();

      expect(calls.single.method, 'read');
      expect(r!.index, 8);
      expect(SystemVolume.state.value, r);
    });

    test('a set sends a STEP of the stream, never a percentage', () async {
      answerWith(
        (call) async => call.method == 'read'
            ? phoneReading(index: 8)
            : phoneReading(index: 6, lastAudible: 8),
      );

      await SystemVolume.read();
      final after = await SystemVolume.setPercent(43);

      final set = calls.last;
      expect(set.method, 'setIndex');
      expect(
        (set.arguments as Map)['index'],
        6,
        reason:
            'the platform is told a step, because a percentage is not a level '
            'this device has',
      );
      // The reply is where the stream really landed, and it is what the bar must
      // show.
      expect(after!.index, 6);
      expect(SystemVolume.state.value!.percent, closeTo(40, 0.01));
    });

    test('a set that asks for the step the stream is on is not sent', () async {
      // A drag asks for the same step on most of its frames, and each write is a
      // Binder call into the system server plus a reading pushed back.
      answerWith(
        (call) async => call.method == 'read'
            ? phoneReading(index: 6)
            : phoneReading(index: 9),
      );

      await SystemVolume.read();
      final same = await SystemVolume.setPercent(41); // 0.41 * 15 -> step 6
      expect(
        same!.index,
        6,
        reason: 'the caller still learns where the device really is',
      );
      expect(
        calls.where((c) => c.method == 'setIndex'),
        isEmpty,
        reason: 'the phone is already on that step',
      );
    });

    test('and neither is a repeat sent while the answer is in flight', () async {
      // The confirmed step lags by a round trip, so comparing against it alone
      // would send one redundant write per step change -- the request itself is
      // remembered until a reading lands.
      final gate = Completer<Object?>();
      answerWith((call) async {
        if (call.method == 'read') return phoneReading(index: 5);
        return gate.future;
      });

      await SystemVolume.read();
      unawaited(SystemVolume.setPercent(40)); // step 6, different from 5: sent
      await SystemVolume.setPercent(41); // still step 6, answer still out
      await SystemVolume.setPercent(39); // still step 6

      expect(
        calls.where((c) => c.method == 'setIndex').length,
        1,
        reason: 'one step change is one write, whatever the frame rate',
      );

      gate.complete(phoneReading(index: 6));
      await Future<void>.delayed(Duration.zero);
    });

    test('a change made elsewhere is never suppressed by a stale request', () async {
      final gate = Completer<Object?>();
      answerWith((call) async {
        if (call.method == 'read') return phoneReading(index: 5);
        return gate.future;
      });

      await SystemVolume.read();
      unawaited(SystemVolume.setPercent(40)); // requests step 6, in flight
      // The hardware keys move the phone while that write is out; the push
      // REPLACES what the app believes it has asked for.
      SystemVolume.watch();
      await TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .handlePlatformMessage(
            channel.name,
            const StandardMethodCodec().encodeMethodCall(
              MethodCall('onChanged', phoneReading(index: 9)),
            ),
            (_) {},
          );
      unawaited(SystemVolume.setPercent(40));

      expect(
        calls.where((c) => c.method == 'setIndex').length,
        2,
        reason: 'the second request is a real change from step 9, not a repeat',
      );

      gate.complete(phoneReading(index: 6));
      await Future<void>.delayed(Duration.zero);
    });

    test('but a MUTED stream is written to, because the write unmutes it', () async {
      // Skipping the write here would leave the phone silent while the bar shows
      // a level: `SystemVolumeChannel.apply` is what clears the mute flag.
      answerWith(
        (call) async => call.method == 'read'
            ? phoneReading(index: 6, muted: true)
            : phoneReading(index: 6),
      );

      await SystemVolume.read();
      final after = await SystemVolume.setPercent(40);
      expect((calls.last.arguments as Map)['index'], 6);
      expect(after!.muted, isFalse);
    });

    test('a level that is not a number is never sent', () async {
      answerWith((_) async => phoneReading(index: 8));
      await SystemVolume.read();

      // `round()` throws on NaN, and this write is unawaited: the throw would
      // surface as an unhandled async error rather than a rejected future.
      expect(await SystemVolume.setPercent(double.nan), isNull);
      expect(await SystemVolume.setPercent(double.infinity), isNull);
      expect(calls.where((c) => c.method == 'setIndex'), isEmpty);
    });

    test('a set without a reading does nothing at all', () async {
      answerWith((_) async => phoneReading());
      // No read has happened, so the stream's travel is unknown and a step
      // cannot be computed: sending a guess would move the phone to a level
      // nobody asked for.
      expect(await SystemVolume.setPercent(50), isNull);
      expect(calls, isEmpty);
    });

    test('a platform without the native half is not an error', () async {
      answerWith((_) async => throw MissingPluginException('desktop'));
      expect(await SystemVolume.read(), isNull);
      expect(SystemVolume.state.value, isNull);
    });

    test('a reply the codec refused is not a reading', () async {
      answerWith((_) async => 'not a map');
      expect(await SystemVolume.read(), isNull);
      expect(SystemVolume.state.value, isNull);
    });

    test('a device with no audio service is refused, not invented', () async {
      // Android answers exactly this when it has no AudioManager: a stream with
      // no travel and no claim about the output (`fixed: false` — a "cannot
      // read" is not a "cannot set"). It must reach Dart as "no reading", never
      // as 0 of 0.
      answerWith(
        (_) async => phoneReading(index: 0, min: 0, max: 0, fixed: false),
      );
      expect(await SystemVolume.read(), isNull);
      expect(SystemVolume.state.value, isNull);
    });

    test('a volume change made elsewhere reaches the state', () async {
      SystemVolume.watch();
      expect(SystemVolume.state.value, isNull);

      await TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .handlePlatformMessage(
            channel.name,
            const StandardMethodCodec().encodeMethodCall(
              MethodCall('onChanged', phoneReading(index: 0, muted: true)),
            ),
            (_) {},
          );

      // The hardware keys, another app, the system panel: the bar follows,
      // because the phone's volume is the number it is showing.
      expect(SystemVolume.state.value!.percent, 0);
      expect(SystemVolume.state.value!.index, 0);
    });

    test('a garbled push changes nothing', () async {
      SystemVolume.watch();
      SystemVolume.state.value = reading(index: 8);

      for (final bad in <Object?>[
        null,
        'loud',
        <String, Object?>{'index': 3},
      ]) {
        await TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .handlePlatformMessage(
              channel.name,
              const StandardMethodCodec().encodeMethodCall(
                MethodCall('onChanged', bad),
              ),
              (_) {},
            );
      }
      // An unrelated method is not a reading either.
      await TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .handlePlatformMessage(
            channel.name,
            const StandardMethodCodec().encodeMethodCall(
              MethodCall('somethingElse'),
            ),
            (_) {},
          );

      expect(SystemVolume.state.value!.index, 8);
    });

    test('a platform with no media stream is not asked at all', () async {
      debugSystemVolumeSupported = false;
      answerWith((_) async => phoneReading());

      expect(await SystemVolume.read(), isNull);
      expect(await SystemVolume.setPercent(50), isNull);
      SystemVolume.watch();

      expect(
        calls,
        isEmpty,
        reason: 'desktop has no stream to read, set or follow',
      );
    });
  });

  group('the setting', () {
    test('ships ON for mobile and OFF for desktop', () async {
      expect(useSystemVolumeDefault(isDesktop: false), isTrue);
      expect(useSystemVolumeDefault(isDesktop: true), isFalse);
      // This host is a desktop, and the store agrees with the function.
      expect(await SettingsService().getUseSystemVolume(), isFalse);
      // The state's own default is the mobile one: only mobile code reads it,
      // and the platform gate is `SystemVolume.supported`.
      expect(const SettingsState().useSystemVolume, isTrue);
    });

    test('a choice is persisted under its own key', () async {
      final c = ProviderContainer();
      addTearDown(c.dispose);
      answerWith((_) async => phoneReading());

      await c.read(uiSettingsProvider.notifier).setUseSystemVolume(false);

      expect(c.read(uiSettingsProvider).useSystemVolume, isFalse);
      expect(
        (await SharedPreferences.getInstance()).getBool('use_system_volume'),
        isFalse,
        reason: 'the key hand-edited settings and this service share',
      );
      // Nothing is pushed to the platform for it: the choice is read when a
      // player opens, and the player is the only thing that acts on it.
      expect(calls, isEmpty);
    });

    test('loading restores it', () async {
      SharedPreferences.setMockInitialValues({'use_system_volume': false});
      final c = ProviderContainer();
      addTearDown(c.dispose);

      await c.read(uiSettingsProvider.notifier).load();

      expect(c.read(uiSettingsProvider).useSystemVolume, isFalse);
    });

    test('the row promises only what the device can do', () {
      final on = systemVolumeBindingNote(
        bound: true,
        readable: true,
        fixedOutput: false,
      );
      final off = systemVolumeBindingNote(
        bound: false,
        readable: true,
        fixedOutput: false,
      );
      final fixed = systemVolumeBindingNote(
        bound: true,
        readable: true,
        fixedOutput: true,
      );
      final unreadable = systemVolumeBindingNote(
        bound: true,
        readable: false,
        fixedOutput: false,
      );

      expect(on, contains("device's media volume"));
      expect(off, contains('inside the player only'));
      expect(fixed, contains('fixed'));
      expect(unreadable, contains('has not reported'));
      // The four are not interchangeable. Two of them are the switch failing to
      // keep its promise -- a fixed output, and a device that never answered --
      // and in both the player keeps its own volume, so neither may carry the
      // bound wording; and the switch's own OFF state outranks both, because
      // what happens then is simply the app's own volume.
      expect(unreadable, isNot(contains('moves the')));
      expect(fixed, isNot(contains('moves the')));
      expect(on, isNot(contains('fixed')));
      expect(on, isNot(contains('has not reported')));
      expect(
        off,
        isNot(contains('has not reported')),
        reason: 'turned off, the copy is about the choice, not the device',
      );
    });
  });

  group('the row', () {
    Future<ProviderContainer> pumpSettings(WidgetTester tester) async {
      await tester.binding.setSurfaceSize(const Size(1000, 1600));
      addTearDown(() => tester.binding.setSurfaceSize(null));
      final c = ProviderContainer();
      addTearDown(c.dispose);
      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: c,
          child: MaterialApp(theme: RCrmTheme.dark, home: const SettingsScreen()),
        ),
      );
      await tester.pump();
      await tester.pump();
      return c;
    }

    testWidgets('is not offered on a platform that could not act', (
      tester,
    ) async {
      debugSystemVolumeSupported = false;
      await pumpSettings(tester);

      expect(find.text('System Volume'), findsNothing);
      // The sections that stay are still there, so this is the row being gated
      // rather than the page failing to build.
      expect(find.text('Thumbnail Cache'), findsOneWidget);
      expect(find.text('Jump History'), findsOneWidget);
    });

    testWidgets('is ON by default where the device has a media stream', (
      tester,
    ) async {
      answerWith((_) async => phoneReading());
      final c = await pumpSettings(tester);

      final tile = tester.widget<SwitchListTile>(
        find.widgetWithText(SwitchListTile, 'System Volume'),
      );
      expect(
        tile.value,
        isTrue,
        reason: 'the default has to be visible as ON, not just be on',
      );
      expect(
        find.text(
          systemVolumeBindingNote(
            bound: true,
            readable: true,
            fixedOutput: false,
          ),
        ),
        findsOneWidget,
      );

      tile.onChanged!(false);
      await tester.pump();

      expect(c.read(uiSettingsProvider).useSystemVolume, isFalse);
      expect(
        tester
            .widget<SwitchListTile>(
              find.widgetWithText(SwitchListTile, 'System Volume'),
            )
            .value,
        isFalse,
      );
      expect(
        find.text(
          systemVolumeBindingNote(
            bound: false,
            readable: true,
            fixedOutput: false,
          ),
        ),
        findsOneWidget,
      );
      expect(
        (await SharedPreferences.getInstance()).getBool('use_system_volume'),
        isFalse,
      );
    });

    testWidgets('says so when this device cannot be set at all', (
      tester,
    ) async {
      // A fixed-volume output (some TV boxes, car head units, HDMI sinks): the
      // player falls back to its own volume, and the row says so rather than
      // letting the switch promise a slider that cannot move the phone.
      answerWith((_) async => phoneReading(fixed: true));
      await pumpSettings(tester);

      expect(
        find.text(
          systemVolumeBindingNote(
            bound: true,
            readable: true,
            fixedOutput: true,
          ),
        ),
        findsOneWidget,
      );
    });

    testWidgets('and when the device never answered at all', (tester) async {
      // No native half, or a reply the codec refused: `shouldBindSystemVolume`
      // refuses to bind without a reading, so the player keeps its own volume and
      // the row must not promise the device's.
      answerWith((_) async => throw MissingPluginException('no native half'));
      await pumpSettings(tester);

      expect(
        find.text(
          systemVolumeBindingNote(
            bound: true,
            readable: false,
            fixedOutput: false,
          ),
        ),
        findsOneWidget,
      );
    });
  });
}
