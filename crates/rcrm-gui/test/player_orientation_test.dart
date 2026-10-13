// test/player_orientation_test.dart
// What each fullscreen orientation strategy asks the platform for, pinned where
// it can be: the player screen cannot be mounted in a test, and the platform
// cannot be asked from this host.
//
// The regression behind the strategies: the old "Auto-Rotate" switch said
// "Ignore system rotation lock; follow device orientation" and made the only call
// the framework has for it — `setPreferredOrientations` with all four — which the
// Android embedding decodes to `SCREEN_ORIENTATION_FULL_USER`. The platform's own
// documentation for that value is "Respect the user's sensor-based rotation
// preference", so with the phone's rotation lock on the switch did nothing at
// all. The request that ignores the lock is `FULL_SENSOR`, and no
// `DeviceOrientation` list can express it — hence the app's own channel, and the
// `fullSensor` shape below.

import 'package:flutter/services.dart' show DeviceOrientation;
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:rcrm_gui/providers/settings_provider.dart';
import 'package:rcrm_gui/services/settings_service.dart';
import 'package:rcrm_gui/utils/player_orientation.dart';

const _landscape = <DeviceOrientation>[
  DeviceOrientation.landscapeLeft,
  DeviceOrientation.landscapeRight,
];
const _portrait = <DeviceOrientation>[
  DeviceOrientation.portraitUp,
  DeviceOrientation.portraitDown,
];
// "Every orientation", in the framework's own order -- which is the list
// `orientationRequestFor` hands straight to `setPreferredOrientations`, and the
// one the Android table decodes to FULL_USER.
const _any = DeviceOrientation.values;

OrientationRequest requestFor(
  PlayerOrientation mode, {
  bool fullscreen = true,
  bool? landscapeVideo = true,
}) => orientationRequestFor(
  mode: mode,
  fullscreen: fullscreen,
  landscapeVideo: landscapeVideo,
);

void main() {
  group('what each strategy asks for', () {
    test('fit follows the VIDEO, both ways round', () {
      expect(
        requestFor(PlayerOrientation.fill),
        const OrientationRequest.allow(_landscape),
      );
      expect(
        requestFor(PlayerOrientation.fill, landscapeVideo: false),
        const OrientationRequest.allow(_portrait),
      );
    });

    test('fit refuses to guess while the video has not reported its shape', () {
      // The old code guessed landscape, and nothing re-applied the answer when
      // the real size arrived — so a portrait video stayed locked landscape.
      // Asking for everything forces nothing, and the player applies the real
      // request the moment the size lands.
      //
      // Deliberately the same request `system` sends, and that is the honest
      // answer rather than an oversight: of a shape nobody knows, either guess
      // locks the picture into an orientation the viewer may not be holding the
      // phone in — and a LOCK also stops them turning it to see a wide video.
      // "Allow what the system allows" leaves that door open, and `fill` locks
      // the moment the player answers.
      expect(
        requestFor(PlayerOrientation.fill, landscapeVideo: null),
        requestFor(PlayerOrientation.system),
      );
    });

    test('system asks for everything, which is what respects the lock', () {
      expect(
        requestFor(PlayerOrientation.system),
        const OrientationRequest.allow(_any),
      );
      // The video's shape is none of this strategy's business.
      expect(
        requestFor(PlayerOrientation.system, landscapeVideo: false),
        const OrientationRequest.allow(_any),
      );
    });

    test('follow-the-phone asks for the mask AND the sensor', () {
      // Both parts, in this order: the mask is what the framework can send, and
      // it must go first — iOS only honours a geometry request its supported mask
      // already allows, and on Android the channel call has to be the last word.
      // The sensor request itself is the one the framework cannot make (no list
      // of `DeviceOrientation`s decodes to `FULL_SENSOR`).
      final request = requestFor(PlayerOrientation.device);
      expect(request, const OrientationRequest.followPhone());
      expect(request.orientations, _any);
      expect(request.followDevice, isTrue);
      expect(
        requestFor(PlayerOrientation.system).followDevice,
        isFalse,
        reason: 'every other strategy is the framework channel alone',
      );
    });

    test('the locks hold their axis, and ignore the video', () {
      expect(
        requestFor(PlayerOrientation.portrait, landscapeVideo: true),
        const OrientationRequest.allow(_portrait),
      );
      expect(
        requestFor(PlayerOrientation.landscape, landscapeVideo: false),
        const OrientationRequest.allow(_landscape),
      );
    });

    test('outside fullscreen every strategy hands the app back', () {
      // Which is the whole of "fullscreen only": the library lives in its own
      // direction again the moment the player is not fullscreen — including on
      // the way out of the player, where the chrome is restored before the route
      // pops and `fullscreen` is still true.
      for (final m in PlayerOrientation.values) {
        expect(
          requestFor(m, fullscreen: false),
          const OrientationRequest.allow(_any),
          reason: m.key,
        );
      }
    });
  });

  group('the request value', () {
    test('compares by content, so a test can name what it expects', () {
      expect(
        const OrientationRequest.allow(_landscape),
        const OrientationRequest.allow(_landscape),
      );
      expect(
        const OrientationRequest.allow(_landscape),
        isNot(const OrientationRequest.allow(_portrait)),
      );
      expect(
        const OrientationRequest.followPhone(),
        isNot(const OrientationRequest.allow(_any)),
      );
      expect(
        const OrientationRequest.followPhone().hashCode,
        const OrientationRequest.followPhone().hashCode,
      );
    });
  });

  group('applying a request', () {
    /// Records the order the two platform calls were made in.
    ({List<String> order, OrientationMaskWriter mask, DeviceFollowWriter follow})
    recorder() {
      final order = <String>[];
      return (
        order: order,
        mask: (List<DeviceOrientation> o) async => order.add('mask:${o.length}'),
        follow: (bool f) async => order.add('follow:$f'),
      );
    }

    test('the mask goes FIRST, then the sensor request', () async {
      // The order is the whole reason this lives in a function with a test: iOS
      // only honours a geometry request its supported mask already allows, and on
      // Android both calls write the same activity property, so the sensor
      // request has to be the last word. Backwards, it is invisible on a phone
      // with auto-rotate on and only shows up on one with the rotation lock set —
      // the exact bug this strategy exists to fix.
      final r = recorder();
      await applyOrientationRequest(
        requestFor(PlayerOrientation.device),
        writeMask: r.mask,
        writeFollow: r.follow,
      );
      expect(r.order, ['mask:4', 'follow:true']);
    });

    test('and both parts are always sent, even for the framework-only ones', () async {
      // `follow:false` is not noise: it is what stops the iOS half from forcing a
      // geometry after the user picked another strategy.
      final r = recorder();
      await applyOrientationRequest(
        requestFor(PlayerOrientation.landscape),
        writeMask: r.mask,
        writeFollow: r.follow,
      );
      expect(r.order, ['mask:2', 'follow:false']);
    });

    test('the way OUT does it the other way round', () async {
      // Leaving the player: the sensor stops FIRST, because on iOS the native
      // half keeps forcing a geometry while it is following and would fight the
      // mask written after it.
      final r = recorder();
      await releaseOrientationRequest(
        writeMask: r.mask,
        writeFollow: r.follow,
        mask: _any,
      );
      expect(r.order, ['follow:false', 'mask:4']);
    });
  });

  group('the strategy list', () {
    test('offers all four on mobile, which is where the row exists', () {
      // Both mobile platforms can do all four: Android reaches "follow the
      // phone" with FULL_SENSOR, iOS with the hardware posture plus an explicit
      // geometry request. Desktop never shows the row (`showOrientation`), which
      // is the only place the list could have been shorter.
      expect(orientationPolicies(), OrientationPolicy.values);
      expect(OrientationPolicy.values.length, 4);
      expect(
        orientationPolicies(),
        contains(OrientationPolicy.device),
        reason: 'the strategy the old switch promised and could not deliver',
      );
    });

    test('each policy knows what picking it means', () {
      expect(OrientationPolicy.fill.entry, PlayerOrientation.fill);
      expect(OrientationPolicy.system.entry, PlayerOrientation.system);
      expect(OrientationPolicy.device.entry, PlayerOrientation.device);
      // The lock enters at landscape: this is a video player, and the direction
      // is one tap away under it.
      expect(OrientationPolicy.lock.entry, PlayerOrientation.landscape);
      expect(OrientationPolicy.lock.entry.isLock, isTrue);
    });

    test('the two locks are one policy', () {
      expect(PlayerOrientation.portrait.policy, OrientationPolicy.lock);
      expect(PlayerOrientation.landscape.policy, OrientationPolicy.lock);
      expect(PlayerOrientation.fill.policy, OrientationPolicy.fill);
      expect(PlayerOrientation.portrait.isLock, isTrue);
      expect(PlayerOrientation.fill.isLock, isFalse);
    });
  });

  group('storage', () {
    setUp(() => SharedPreferences.setMockInitialValues({}));

    test('round-trips every strategy through its key', () {
      for (final m in PlayerOrientation.values) {
        expect(PlayerOrientation.fromKey(m.key), m);
      }
    });

    test('an unknown or missing value is the default, not a crash', () {
      // The key is hand-editable and an older build could write something this
      // one does not know.
      expect(PlayerOrientation.fromKey(null), defaultOrientation);
      expect(PlayerOrientation.fromKey('sideways'), defaultOrientation);
      expect(defaultOrientation, PlayerOrientation.fill);
    });

    test('the old auto_rotate boolean keeps its meaning', () {
      // `true` was asking for exactly what `device` now delivers (and silently
      // got `system`); `false` was the fit-the-video default this app shipped.
      expect(
        orientationFromLegacyAutoRotate(true),
        PlayerOrientation.device,
      );
      expect(
        orientationFromLegacyAutoRotate(false),
        PlayerOrientation.fill,
      );
    });

    test('a stored choice is read, and the legacy bool is the fallback', () async {
      // The one-shot migration, at the layer that really reads it. Three
      // branches, and the ORDER between them is the whole thing: a choice made
      // under the new key must win over the boolean the old switch left behind.
      final s = SettingsService();

      expect(
        await s.getPlayerOrientation(),
        defaultOrientation,
        reason: 'a fresh install has neither key',
      );

      SharedPreferences.setMockInitialValues({'auto_rotate': true});
      expect(await SettingsService().getPlayerOrientation(), PlayerOrientation.device);

      SharedPreferences.setMockInitialValues({'auto_rotate': false});
      expect(await SettingsService().getPlayerOrientation(), PlayerOrientation.fill);

      SharedPreferences.setMockInitialValues({
        'auto_rotate': true,
        'player_orientation': 'portrait',
      });
      expect(
        await SettingsService().getPlayerOrientation(),
        PlayerOrientation.portrait,
        reason: 'the new key wins over the legacy boolean',
      );

      // An unknown stored value falls back rather than throwing.
      SharedPreferences.setMockInitialValues({'player_orientation': 'sideways'});
      expect(await SettingsService().getPlayerOrientation(), defaultOrientation);

      // And a write round-trips.
      SharedPreferences.setMockInitialValues({});
      await s.setPlayerOrientation(PlayerOrientation.landscape);
      expect(
        (await SharedPreferences.getInstance()).getString('player_orientation'),
        'landscape',
      );
      expect(await SettingsService().getPlayerOrientation(), PlayerOrientation.landscape);
    });

    test('loading brings it into the settings the app reads', () async {
      SharedPreferences.setMockInitialValues({'player_orientation': 'device'});
      final c = ProviderContainer();
      addTearDown(c.dispose);

      await c.read(uiSettingsProvider.notifier).load();

      expect(c.read(uiSettingsProvider).playerOrientation, PlayerOrientation.device);
    });
  });

  group('the note under the row', () {
    test('says what the choice does, on either mobile platform', () {
      // One wording per policy, and no platform caveat: both mobile platforms
      // implement all four, each with its own API (`screen_orientation.dart`).
      // A caveat belongs on the rows where a platform REALLY cannot do the thing
      // — the screenshot policy, the volume binding — not here.
      for (final p in OrientationPolicy.values) {
        final note = orientationNote(p);
        expect(note, isNotEmpty, reason: p.label);
        expect(
          note,
          isNot(contains('iOS')),
          reason: '${p.label}: a caveat would be a promise this app cannot keep',
        );
      }
      expect(
        orientationNote(OrientationPolicy.device),
        contains('even when the rotation lock is on'),
        reason: 'the strategy exists for exactly that',
      );
      // Four policies, four different sentences: two that read the same would be
      // two rows the viewer cannot tell apart.
      final notes = OrientationPolicy.values.map(orientationNote).toSet();
      expect(notes.length, OrientationPolicy.values.length);
    });
  });
}
