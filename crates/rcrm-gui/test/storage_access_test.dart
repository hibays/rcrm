// test/storage_access_test.dart
// Android's "all files access" ask: the channel the native half implements, the
// version rules behind it, the wording each version shows, and the two screens
// that offer it.
//
// The enforcement itself is native (`StorageAccessChannel.kt`: an app-op opened
// through the system settings screen on Android 11+, an ordinary runtime
// permission on Android 6-10) and cannot run on this desktop host -- there is no
// Android device or emulator here. What CAN be pinned is everything the app
// decides: the channel name and its two methods, the defensive read of the
// platform's reply, the three wordings that must not be interchangeable, the
// re-read on resume (the ONLY signal that the user came back from Android's
// settings screen), and that both the setup card and the settings row appear
// exactly where the permission exists.

import 'dart:io' show Platform;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:rcrm_gui/config/theme.dart';
import 'package:rcrm_gui/screens/library_setup_screen.dart';
import 'package:rcrm_gui/screens/settings_screen.dart';
import 'package:rcrm_gui/services/storage_access.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const channel = MethodChannel('rcrm/storage');
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

  /// The reply `StorageAccessChannel.status` sends, so these tests speak the
  /// native half's own shape rather than a Dart-side invention.
  Map<String, Object?> platformStatus({
    required int sdk,
    required bool granted,
    required String action,
    required bool canAsk,
  }) => <String, Object?>{
    'sdk': sdk,
    'granted': granted,
    'action': action,
    'canAsk': canAsk,
  };

  StorageAccessStatus statusOf({
    required int sdk,
    required bool granted,
    required String action,
    required bool canAsk,
  }) => StorageAccessStatus.fromPlatform(
    platformStatus(sdk: sdk, granted: granted, action: action, canAsk: canAsk),
  );

  /// Lets the (mocked) platform answer -- the reads are fire-and-forget.
  Future<void> settle(WidgetTester tester) async {
    await tester.pump();
    await tester.pump();
  }

  setUp(() {
    SharedPreferences.setMockInitialValues({});
    calls.clear();
    // The Android branch, which is where the ask, the channel call and the row
    // all live; this host is a desktop, so without the seam none is reachable.
    debugStorageAccessSupported = true;
  });
  tearDown(() {
    debugStorageAccessSupported = Platform.isAndroid;
    StorageAccess.debugReset();
  });

  group('what each Android version is told', () {
    test('Android 11+ is told there is no dialog to show', () {
      final copy = storageAccessCopy(
        statusOf(sdk: 30, granted: false, action: 'settings', canAsk: true),
      );

      expect(copy.title, 'Allow access to all files');
      expect(copy.body, contains('Android 11 and later have no dialog'));
      expect(copy.actionLabel, 'Open Android settings');
      // The three flows are not interchangeable: this wording must not carry
      // the dialog's promise or the "will not ask again" claim.
      expect(copy.body, isNot(contains('Android 6 to 10')));
      expect(copy.body, isNot(contains('will not ask again')));
    });

    test('Android 6-10 is told a permission dialog asks', () {
      for (final sdk in <int>[23, 29]) {
        final copy = storageAccessCopy(
          statusOf(sdk: sdk, granted: false, action: 'dialog', canAsk: true),
        );

        expect(
          copy.title,
          'Allow access to your media folders',
          reason: 'sdk $sdk',
        );
        expect(copy.body, contains('Android 6 to 10'), reason: 'sdk $sdk');
        expect(copy.body, contains('permission dialog'), reason: 'sdk $sdk');
        expect(copy.actionLabel, 'Allow storage access', reason: 'sdk $sdk');
        expect(
          copy.body,
          isNot(contains('Android 11 and later')),
          reason: 'sdk $sdk',
        );
        expect(
          copy.body,
          isNot(contains('will not ask again')),
          reason: 'sdk $sdk',
        );
      }
    });

    test('a refusal Android will not repeat gets its own wording and action', () {
      final copy = storageAccessCopy(
        statusOf(sdk: 29, granted: false, action: 'dialog', canAsk: false),
      );

      expect(copy.title, 'Storage access is turned off');
      expect(copy.body, contains('Android will not ask again'));
      expect(copy.actionLabel, 'Open app settings');
      // A settings page is not the same offer as a dialog, and the labels are
      // the only thing the user reads before tapping.
      final askable = storageAccessCopy(
        statusOf(sdk: 29, granted: false, action: 'dialog', canAsk: true),
      );
      expect(copy.actionLabel, isNot(askable.actionLabel));
      expect(copy.body, isNot(askable.body));
      // It is also not the Android 11+ flow: different screen, different words.
      final settings = storageAccessCopy(
        statusOf(sdk: 30, granted: false, action: 'settings', canAsk: true),
      );
      expect(copy.actionLabel, isNot(settings.actionLabel));
    });

    test('Android 5 and older has nothing to ask', () {
      final copy = storageAccessCopy(
        statusOf(sdk: 22, granted: true, action: 'none', canAsk: false),
      );

      expect(copy.body, contains('grants storage access when the app is'));
      // Nothing is promised here, and nothing can be run: this is the ONE case
      // where the app has nothing to do.
      expect(copy.body, isNot(contains('dialog')));
      expect(copy.body, isNot(contains('settings')));
    });

    test(
      'a status that could not be read claims nothing and offers no flow',
      () {
        final copy = storageAccessCopy(StorageAccessStatus.unknown);

        expect(copy.title, 'Storage access is unknown');
        expect(copy.body, contains('did not report its storage permission'));
        expect(copy.actionLabel, 'Check again');
        // NOT the Android 11 wording: an unreadable reply is not a version.
        expect(copy.body, isNot(contains('Android 11')));
        expect(copy.body, isNot(contains('Android 6 to 10')));
      },
    );

    test(
      'every ask explains WHY the app needs it, not just that it wants it',
      () {
        // The library is served to the app by a local server that opens the
        // folders by real path, so a per-folder document grant is not enough --
        // that reason is the difference between an ask and a demand.
        for (final s in <StorageAccessStatus>[
          statusOf(sdk: 30, granted: false, action: 'settings', canAsk: true),
          statusOf(sdk: 29, granted: false, action: 'dialog', canAsk: true),
          statusOf(sdk: 29, granted: false, action: 'dialog', canAsk: false),
        ]) {
          expect(
            storageAccessCopy(s).body,
            contains('real path'),
            reason: s.toString(),
          );
        }
      },
    );

    test('the one-line note says which Android this is, on every branch', () {
      // The note is what a settings ROW has space for, and it is the half the
      // user reads first -- it must be short, and it must still distinguish the
      // three flows and the unreadable case from each other.
      final notes = <String, String>{
        'android 11': storageAccessCopy(
          statusOf(sdk: 30, granted: false, action: 'settings', canAsk: true),
        ).note,
        'android 6-10': storageAccessCopy(
          statusOf(sdk: 29, granted: false, action: 'dialog', canAsk: true),
        ).note,
        'refused for good': storageAccessCopy(
          statusOf(sdk: 29, granted: false, action: 'dialog', canAsk: false),
        ).note,
        'granted at install': storageAccessCopy(
          statusOf(sdk: 21, granted: true, action: 'none', canAsk: false),
        ).note,
        'unreadable': storageAccessCopy(StorageAccessStatus.unknown).note,
      };
      for (final entry in notes.entries) {
        expect(entry.value, isNotEmpty, reason: '${entry.key} has a note');
        expect(
          entry.value.length,
          lessThanOrEqualTo(90),
          reason: '${entry.key} fits a settings row',
        );
        expect(
          entry.value,
          isNot(contains('\n')),
          reason: '${entry.key} is ONE line',
        );
      }
      expect(
        notes.values.toSet(),
        hasLength(notes.length),
        reason: 'no two branches say the same thing',
      );
    });
  });

  group('reading the platform', () {
    test('status parses the native half\'s reply', () async {
      answerWith(
        (_) async => platformStatus(
          sdk: 30,
          granted: false,
          action: 'settings',
          canAsk: true,
        ),
      );

      final status = await StorageAccess.status();

      expect(
        status,
        statusOf(sdk: 30, granted: false, action: 'settings', canAsk: true),
      );
      expect(status.action, StorageAccessAction.settings);
      expect(status.granted, isFalse);
      expect(calls.single.method, 'status');
    });

    test('an unknown extra field does not spoil a good reply', () async {
      answerWith(
        (_) async => <String, Object?>{
          ...platformStatus(
            sdk: 29,
            granted: true,
            action: 'dialog',
            canAsk: true,
          ),
          'somethingNewer': 7,
        },
      );

      expect((await StorageAccess.status()).granted, isTrue);
    });

    test('a reply that cannot be read never becomes a claim of access', () {
      final broken = <Object?>[
        null,
        'nonsense',
        <String, Object?>{},
        // sdk as a string: no version may be invented from it.
        <String, Object?>{
          'sdk': '30',
          'granted': false,
          'action': 'settings',
          'canAsk': true,
        },
        // A grant is only a grant if the flow that produced it is readable too:
        // this one says granted, and must still not be believed.
        <String, Object?>{
          'sdk': 30,
          'granted': true,
          'action': 'bogus',
          'canAsk': true,
        },
        <String, Object?>{'sdk': 30, 'granted': true, 'action': 'settings'},
      ];

      for (final reply in broken) {
        final status = StorageAccessStatus.fromPlatform(reply);
        expect(status, StorageAccessStatus.unknown, reason: '$reply');
        expect(status.granted, isFalse, reason: '$reply');
        expect(
          status.sdk,
          0,
          reason: 'no version is invented for a reply that did not carry one',
        );
        expect(status.action, StorageAccessAction.none, reason: '$reply');
      }
    });

    test(
      'a malformed reply survives the round trip through status()',
      () async {
        answerWith((_) async => 'not a map at all');

        expect(await StorageAccess.status(), StorageAccessStatus.unknown);
      },
    );

    test('a platform without the handler is not an error', () async {
      answerWith((_) async => throw MissingPluginException('desktop'));

      expect(await StorageAccess.status(), StorageAccessStatus.unknown);
    });

    test(
      'a host where the permission does not exist is not asked at all',
      () async {
        debugStorageAccessSupported = false;
        answerWith(
          (_) async => platformStatus(
            sdk: 30,
            granted: false,
            action: 'settings',
            canAsk: true,
          ),
        );

        expect(await StorageAccess.status(), StorageAccessStatus.unknown);
        expect(
          calls,
          isEmpty,
          reason:
              'desktop has no all-files access to configure -- and a channel '
              'call nothing answers is how a first screen stalls',
        );
      },
    );
  });

  group('asking', () {
    test('request starts the flow and re-reads the status', () async {
      // The answer is NOT the return value: the user leaves the app for the
      // settings screen, so the app has to read the state back.
      var granted = false;
      answerWith((call) async {
        if (call.method == 'request') {
          granted = true; // what the user does while they are away
          return <String, Object?>{'launched': true};
        }
        return platformStatus(
          sdk: 30,
          granted: granted,
          action: 'settings',
          canAsk: true,
        );
      });

      await StorageAccess.request();

      expect(calls.map((c) => c.method), <String>['request', 'status']);
      expect(StorageAccess.state.value?.granted, isTrue);
    });

    test(
      'a request a platform cannot launch leaves the app claiming nothing',
      () async {
        answerWith((_) async => throw MissingPluginException('desktop'));

        await StorageAccess.request(); // must not throw

        expect(StorageAccess.state.value, StorageAccessStatus.unknown);
        expect(StorageAccess.state.value?.granted, isFalse);
      },
    );

    test('a host without the permission does not call the channel', () async {
      debugStorageAccessSupported = false;
      answerWith((_) async => null);

      await StorageAccess.request();

      expect(calls, isEmpty);
      expect(StorageAccess.state.value, isNull);
    });
  });

  group('coming back to the foreground', () {
    testWidgets('resume re-reads the status -- the only signal the settings '
        'trip ended', (tester) async {
      var granted = false;
      answerWith(
        (_) async => platformStatus(
          sdk: 30,
          granted: granted,
          action: 'settings',
          canAsk: true,
        ),
      );
      // Registering twice must not mean asking twice: the observer belongs to
      // the process, not to a build or a screen.
      StorageAccess.watch();
      StorageAccess.watch();
      await StorageAccess.refresh();
      expect(calls.length, 1);
      expect(StorageAccess.state.value?.granted, isFalse);

      // The user grants it in Android's settings screen and comes back.
      granted = true;
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
      await settle(tester);

      expect(
        StorageAccess.state.value?.granted,
        isTrue,
        reason: 'no other signal exists for a trip to another app\'s activity',
      );
      expect(calls.length, 2);
    });

    testWidgets('other lifecycle states do not re-read', (tester) async {
      answerWith(
        (_) async => platformStatus(
          sdk: 30,
          granted: false,
          action: 'settings',
          canAsk: true,
        ),
      );
      StorageAccess.watch();
      await StorageAccess.refresh();
      expect(calls.length, 1);

      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
      await settle(tester);

      expect(
        calls.length,
        1,
        reason:
            'losing focus is not coming back -- the permission dialog itself '
            'leaves the app inactive while it is on screen',
      );
    });
  });

  group('the setup screen', () {
    Future<void> pumpSetup(
      WidgetTester tester, {
      List<String> dirs = const <String>[],
    }) async {
      await tester.binding.setSurfaceSize(const Size(1000, 1400));
      addTearDown(() => tester.binding.setSurfaceSize(null));
      final c = ProviderContainer();
      addTearDown(c.dispose);
      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: c,
          child: MaterialApp(
            theme: RCrmTheme.dark,
            home: LibrarySetupScreen(initialDirs: dirs),
          ),
        ),
      );
      await settle(tester);
    }

    testWidgets('at sdk 30 the card says Android 11 has no dialog', (
      tester,
    ) async {
      answerWith(
        (_) async => platformStatus(
          sdk: 30,
          granted: false,
          action: 'settings',
          canAsk: true,
        ),
      );

      await pumpSetup(tester);

      expect(find.text('Allow access to all files'), findsOneWidget);
      expect(
        find.textContaining('Android 11 and later have no dialog'),
        findsOneWidget,
      );
      expect(find.text('Open Android settings'), findsOneWidget);
    });

    testWidgets('at sdk 29 the card says a dialog asks', (tester) async {
      answerWith(
        (_) async => platformStatus(
          sdk: 29,
          granted: false,
          action: 'dialog',
          canAsk: true,
        ),
      );

      await pumpSetup(tester);

      expect(find.text('Allow access to your media folders'), findsOneWidget);
      expect(find.textContaining('Android 6 to 10'), findsOneWidget);
      expect(find.text('Allow storage access'), findsOneWidget);
      expect(find.text('Open Android settings'), findsNothing);
    });

    testWidgets('the button runs the flow the version needs', (tester) async {
      answerWith(
        (call) async => call.method == 'request'
            ? <String, Object?>{'launched': true}
            : platformStatus(
                sdk: 30,
                granted: false,
                action: 'settings',
                canAsk: true,
              ),
      );
      await pumpSetup(tester);

      await tester.tap(find.text('Open Android settings'));
      await settle(tester);

      expect(
        calls.map((c) => c.method),
        contains('request'),
        reason: 'the button is the only thing that starts the platform flow',
      );
    });

    testWidgets(
      'a folder picked before the grant is admitted to be unreadable',
      (tester) async {
        answerWith(
          (_) async => platformStatus(
            sdk: 29,
            granted: false,
            action: 'dialog',
            canAsk: true,
          ),
        );

        // The folder picker works without the permission, so a user can get this
        // far -- and a silently empty library afterwards is the failure this
        // whole ask exists to remove.
        await pumpSetup(tester, dirs: <String>['/storage/emulated/0/Movies']);

        expect(
          find.textContaining('cannot read these folders yet'),
          findsOneWidget,
        );
        expect(find.textContaining('Android is not allowing'), findsOneWidget);
      },
    );

    testWidgets('the card goes away when Android grants it', (tester) async {
      var granted = false;
      answerWith(
        (_) async => platformStatus(
          sdk: 30,
          granted: granted,
          action: 'settings',
          canAsk: true,
        ),
      );
      await pumpSetup(tester);
      expect(find.text('Allow access to all files'), findsOneWidget);

      granted = true;
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
      await settle(tester);

      expect(find.text('Allow access to all files'), findsNothing);
      expect(find.text('Open Android settings'), findsNothing);
    });

    testWidgets('a granted device is asked nothing at all', (tester) async {
      answerWith(
        (_) async => platformStatus(
          sdk: 30,
          granted: true,
          action: 'settings',
          canAsk: true,
        ),
      );

      await pumpSetup(tester);

      expect(find.text('Allow access to all files'), findsNothing);
      expect(find.text('Storage access is unknown'), findsNothing);
    });

    testWidgets('is not offered on a platform that has no such permission', (
      tester,
    ) async {
      debugStorageAccessSupported = false;
      answerWith(
        (_) async => platformStatus(
          sdk: 30,
          granted: false,
          action: 'settings',
          canAsk: true,
        ),
      );

      await pumpSetup(tester);

      expect(find.text('Allow access to all files'), findsNothing);
      expect(find.text('Storage access is unknown'), findsNothing);
      // The rest of the screen still builds, so this is the ask being gated
      // rather than the screen failing.
      expect(find.text('Add Folder'), findsOneWidget);
      expect(calls, isEmpty);
    });
  });

  group('the settings row', () {
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
      await settle(tester);
      return c;
    }

    testWidgets('is not offered where the permission does not exist', (
      tester,
    ) async {
      debugStorageAccessSupported = false;
      answerWith((_) async => null);

      await pumpSettings(tester);

      expect(find.text('Storage Access'), findsNothing);
      // The server group it belongs to is still there, so this is the row being
      // gated rather than the page failing to build.
      expect(find.text('Managed Directories'), findsOneWidget);
      expect(calls, isEmpty);
    });

    testWidgets('shows the state, once, and runs the flow from its button', (
      tester,
    ) async {
      answerWith(
        (call) async => call.method == 'request'
            ? <String, Object?>{'launched': true}
            : platformStatus(
                sdk: 30,
                granted: false,
                action: 'settings',
                canAsk: true,
              ),
      );

      await pumpSettings(tester);

      final copy = storageAccessCopy(
        statusOf(sdk: 30, granted: false, action: 'settings', canAsk: true),
      );
      expect(find.text(copy.title), findsOneWidget);
      expect(
        find.text(copy.note),
        findsOneWidget,
        reason: 'the SHORT line: a settings row is a row, not a card',
      );
      expect(
        find.text(copy.body),
        findsNothing,
        reason: 'the card-sized explanation belongs on the setup screen',
      );

      // ONE affordance. A tappable row as well would be the same action twice;
      // this asserts the row really is not one.
      await tester.tap(find.text(copy.title));
      await settle(tester);
      expect(calls.map((c) => c.method), isNot(contains('request')));

      await tester.tap(find.text(copy.actionLabel));
      await settle(tester);
      expect(calls.map((c) => c.method), contains('request'));
    });

    testWidgets('updates live when the user comes back from Android settings', (
      tester,
    ) async {
      var granted = false;
      answerWith(
        (_) async => platformStatus(
          sdk: 30,
          granted: granted,
          action: 'settings',
          canAsk: true,
        ),
      );
      await pumpSettings(tester);
      expect(find.text('Open Android settings'), findsOneWidget);

      granted = true;
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
      await settle(tester);

      expect(find.textContaining('Allowed'), findsOneWidget);
      expect(find.text('Open Android settings'), findsNothing);
    });
  });
}
