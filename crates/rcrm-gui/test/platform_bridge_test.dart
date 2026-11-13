// test/platform_bridge_test.dart
// The typed bridge is the single replaceable boundary for the app's own
// platform channels. These tests pin the WIRE contract (names, argument keys,
// reply shape and the native-to-Dart push), because a rename that only exists
// on the Dart side does not fail to compile — it fails at runtime with
// MissingPluginException on a real device.

import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/services/platform_bridge.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  final TestDefaultBinaryMessenger messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;

  const List<MethodChannel> channels = <MethodChannel>[
    PlatformBridge.window,
    PlatformBridge.tv,
    PlatformBridge.orientation,
    PlatformBridge.screen,
    PlatformBridge.volume,
    PlatformBridge.storage,
    PlatformBridge.app,
  ];

  final List<MethodCall> calls = <MethodCall>[];

  void answer(
    MethodChannel channel,
    Future<Object?> Function(MethodCall) handler,
  ) {
    messenger.setMockMethodCallHandler(channel, (MethodCall call) async {
      calls.add(call);
      return handler(call);
    });
  }

  setUp(calls.clear);

  tearDown(() {
    for (final MethodChannel channel in channels) {
      messenger.setMockMethodCallHandler(channel, null);
    }
    PlatformBridge.stopWatchingVolumeChanges();
  });

  Future<void> push(
    String channelName,
    String method,
    Object? arguments,
  ) async {
    await messenger.handlePlatformMessage(
      channelName,
      const StandardMethodCodec().encodeMethodCall(
        MethodCall(method, arguments),
      ),
      (_) {},
    );
  }

  group('wire contract', () {
    test('all seven channel names are pinned', () {
      expect(PlatformChannelNames.all, <String>[
        'rcrm/window',
        'rcrm/tv',
        'rcrm/orientation',
        'rcrm/screen',
        'rcrm/volume',
        'rcrm/storage',
        'rcrm/app',
      ]);
      expect(
        channels.map((MethodChannel c) => c.name).toList(),
        PlatformChannelNames.all,
      );
    });

    test('ten Dart-to-native methods and one native-to-Dart push', () {
      expect(PlatformMethods.dartToNative, <String>[
        'startWindowDrag',
        'isTv',
        'follow',
        'release',
        'setCaptureAllowed',
        'read',
        'setIndex',
        'status',
        'request',
        'exitApp',
      ]);
      expect(PlatformMethods.nativeToDart, <String>['onChanged']);
      expect(PlatformArgs.allowed, 'allowed');
      expect(PlatformArgs.index, 'index');
    });
  });

  group('reply normalisation', () {
    test('a String-keyed map keeps every value', () {
      final Map<String, Object?>? typed = PlatformBridge.reply(
        <String, Object?>{'index': 4, 'muted': false, 'extra': null},
      );
      expect(typed, <String, Object?>{'index': 4, 'muted': false, 'extra': null});
    });

    test('non-map replies and non-string keys are no answer', () {
      expect(PlatformBridge.reply(null), isNull);
      expect(PlatformBridge.reply('loud'), isNull);
      expect(PlatformBridge.reply(<int>[1, 2]), isNull);
      expect(PlatformBridge.reply(<Object?, Object?>{1: 'x'}), isNull);
    });
  });

  group('typed Dart-to-native calls', () {
    test('isTv returns the platform answer, or false for null', () async {
      answer(PlatformBridge.tv, (MethodCall call) async => true);
      expect(await PlatformBridge.isTv(), isTrue);
      expect(calls.single.method, 'isTv');
      expect(calls.single.arguments, isNull);

      calls.clear();
      answer(PlatformBridge.tv, (MethodCall call) async => null);
      expect(await PlatformBridge.isTv(), isFalse);
    });

    test('followDevice picks follow / release and sends no arguments', () async {
      answer(PlatformBridge.orientation, (MethodCall call) async => null);
      await PlatformBridge.followDevice(true);
      await PlatformBridge.followDevice(false);
      expect(
        calls.map((MethodCall c) => c.method),
        <String>['follow', 'release'],
      );
      expect(calls.every((MethodCall c) => c.arguments == null), isTrue);
    });

    test('setCaptureAllowed carries the typed allowed key', () async {
      answer(PlatformBridge.screen, (MethodCall call) async => null);
      await PlatformBridge.setCaptureAllowed(false);
      expect(calls.single.method, 'setCaptureAllowed');
      expect(calls.single.arguments, <String, Object?>{'allowed': false});
    });

    test('storage status and request use their own methods', () async {
      answer(
        PlatformBridge.storage,
        (MethodCall call) async => <String, Object?>{
          'sdk': 33,
          'granted': true,
          'action': 'none',
          'canAsk': false,
        },
      );
      expect(
        await PlatformBridge.storageStatus(),
        <String, Object?>{
          'sdk': 33,
          'granted': true,
          'action': 'none',
          'canAsk': false,
        },
      );
      await PlatformBridge.requestStorageAccess();
      expect(
        calls.map((MethodCall c) => c.method),
        <String>['status', 'request'],
      );
    });

    test('volume read / setIndex normalise the reply', () async {
      answer(
        PlatformBridge.volume,
        (MethodCall call) async => <String, Object?>{
          'index': 7,
          'min': 0,
          'max': 15,
          'muted': false,
          'lastAudible': 7,
          'fixed': false,
        },
      );
      expect((await PlatformBridge.volumeRead())?['index'], 7);
      expect((await PlatformBridge.volumeSetIndex(9))?['index'], 7);
      expect(calls.first.method, 'read');
      expect(calls.first.arguments, isNull);
      expect(calls.last.method, 'setIndex');
      expect(calls.last.arguments, <String, Object?>{'index': 9});
    });

    test('startWindowDrag is a bare void call', () async {
      answer(PlatformBridge.window, (MethodCall call) async => null);
      await PlatformBridge.startWindowDrag();
      expect(calls.single.method, 'startWindowDrag');
      expect(calls.single.arguments, isNull);
    });

    test('exitApp is fire-and-forget', () async {
      final Completer<MethodCall> seen = Completer<MethodCall>();
      answer(PlatformBridge.app, (MethodCall call) async {
        seen.complete(call);
        return null;
      });
      PlatformBridge.exitApp();
      expect((await seen.future).method, 'exitApp');
    });
  });

  group('native-to-Dart volume push', () {
    test('delivers onChanged as a typed map and ignores other methods',
        () async {
      final List<Map<String, Object?>> received = <Map<String, Object?>>[];
      PlatformBridge.watchVolumeChanges(received.add);

      await push(
        PlatformChannelNames.volume,
        'onChanged',
        <String, Object?>{'index': 5},
      );
      await push(
        PlatformChannelNames.volume,
        'somethingElse',
        <String, Object?>{'index': 99},
      );
      await push(PlatformChannelNames.volume, 'onChanged', 'not a map');

      expect(received, <Map<String, Object?>>[
        <String, Object?>{'index': 5},
      ]);
    });

    test('stopWatchingVolumeChanges removes the handler', () async {
      final List<Map<String, Object?>> received = <Map<String, Object?>>[];
      PlatformBridge.watchVolumeChanges(received.add);
      PlatformBridge.stopWatchingVolumeChanges();
      await push(
        PlatformChannelNames.volume,
        'onChanged',
        <String, Object?>{'index': 5},
      );
      expect(received, isEmpty);
    });
  });
}
