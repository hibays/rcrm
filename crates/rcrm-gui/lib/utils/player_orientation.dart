// utils/player_orientation.dart
// Which way the mobile player's fullscreen may face -- five strategies, decided
// here so the screen (which cannot be mounted in a test) only carries them out.
//
// This replaces a boolean called "Auto-Rotate" whose row said "Ignore system
// rotation lock; follow device orientation". The only call the framework has for
// that is `SystemChrome.setPreferredOrientations`, and a list of all four
// orientations decodes -- in the Android embedding's own table -- to
// `SCREEN_ORIENTATION_FULL_USER`, which the platform documents as "Respect the
// user's sensor-based rotation preference". So the one thing that switch existed
// for was the one thing it could not do: with the phone's rotation lock on,
// turning it on changed nothing at all. The request that really ignores the lock
// is `SCREEN_ORIENTATION_FULL_SENSOR` ("Ignores user's setting to turn off
// sensor-based rotation"), and NO list of `DeviceOrientation`s can express it --
// hence `services/screen_orientation.dart`, the app's own channel, for that one
// strategy. iOS reaches the same place its own way (hardware posture + an
// explicit geometry request); see that service.
//
// The Android decode table (engine `PlatformChannel.decodeOrientations`) is what
// every mode below is written against:
//
//   portraitUp                        -> SCREEN_ORIENTATION_PORTRAIT       (1)
//   landscapeLeft                     -> SCREEN_ORIENTATION_LANDSCAPE      (0)
//   portraitUp + portraitDown         -> SCREEN_ORIENTATION_USER_PORTRAIT  (12)
//   landscapeLeft + landscapeRight    -> SCREEN_ORIENTATION_USER_LANDSCAPE (11)
//   all four                          -> SCREEN_ORIENTATION_FULL_USER      (13)
//   (none)                            -> SCREEN_ORIENTATION_UNSPECIFIED    (-1)
//
// `userPortrait` / `userLandscape` are the two that LOCK THE AXIS while letting
// the sensor pick which way up it is ("Would like to have the screen in portrait
// orientation, but if the user has enabled sensor-based rotation then we can use
// the sensor to change which direction the screen is facing") -- which is what
// both "fit the video" and the explicit locks want.

import 'package:flutter/services.dart' show DeviceOrientation;

/// How the fullscreen player chooses which way up it is.
enum PlayerOrientation {
  /// Fit the video: a wide video locks landscape, a tall one portrait. This is
  /// what the player always did before the strategy existed, and what most
  /// viewers want -- the picture uses the screen instead of being letterboxed
  /// into half of it.
  fill,

  /// Follow the system's own preference, rotation lock included: the app asks
  /// for every orientation and lets the OS decide. Nothing is forced, so a
  /// locked phone stays put.
  system,

  /// Follow how the phone is actually held, whichever way that is, EVEN IF the
  /// system's rotation lock says otherwise.
  ///
  /// Both mobile platforms do this, each with its own API
  /// (`services/screen_orientation.dart`): Android asks the activity for
  /// `SCREEN_ORIENTATION_FULL_SENSOR`, and iOS reads the hardware posture and
  /// requests that geometry. The row is offered on both, and the note below says
  /// the same thing on both — this is not one of the cases where a platform
  /// cannot do it.
  device,

  /// Stay upright, whatever the system allows.
  portrait,

  /// Stay sideways, whatever the system allows.
  landscape;

  /// The key this is stored under. Pinned here because a mismatch between it and
  /// the stored string is silent -- an unknown value would fall back to the
  /// default and the choice would quietly not stick.
  String get key => switch (this) {
    PlayerOrientation.fill => 'fill',
    PlayerOrientation.system => 'system',
    PlayerOrientation.device => 'device',
    PlayerOrientation.portrait => 'portrait',
    PlayerOrientation.landscape => 'landscape',
  };

  /// Which of the four policies the settings row shows. The two locks are one
  /// policy with a direction, because that is how a person chooses it: "stay in
  /// one orientation" is the decision, and which one is the detail under it.
  OrientationPolicy get policy => switch (this) {
    PlayerOrientation.portrait || PlayerOrientation.landscape =>
      OrientationPolicy.lock,
    PlayerOrientation.fill => OrientationPolicy.fill,
    PlayerOrientation.system => OrientationPolicy.system,
    PlayerOrientation.device => OrientationPolicy.device,
  };

  /// Whether this is one of the two locked orientations.
  bool get isLock =>
      this == PlayerOrientation.portrait || this == PlayerOrientation.landscape;

  static PlayerOrientation fromKey(String? key) {
    for (final PlayerOrientation m in PlayerOrientation.values) {
      if (m.key == key) return m;
    }
    return defaultOrientation;
  }
}

/// The four things the settings row offers; the two locks are its fifth state.
enum OrientationPolicy {
  fill('Fit'),
  system('System'),
  device('Follow'),
  lock('Lock');

  const OrientationPolicy(this.label);

  final String label;

  /// Which of the two locks picking this policy means.
  ///
  /// Landscape, because this is a video player and a video is wide until it says
  /// otherwise. A direction picked earlier is NOT remembered once another policy
  /// is chosen: coming back to the lock re-enters at landscape, and the direction
  /// row is one tap away. (`entry` is only consulted when the mode in force is
  /// not already a lock — the framework does not call back for the segment that
  /// is already selected — so an existing lock keeps its direction.)
  PlayerOrientation get entry => this == OrientationPolicy.lock
      ? PlayerOrientation.landscape
      : PlayerOrientation.values.firstWhere((m) => m.policy == this);
}

/// What a fullscreen player starts as, and what the old `auto_rotate` boolean
/// meant: `true` asked for exactly the [PlayerOrientation.device] behaviour (and
/// silently got [PlayerOrientation.system]); `false` is the fit-the-video
/// default this app shipped with.
const PlayerOrientation defaultOrientation = PlayerOrientation.fill;

PlayerOrientation orientationFromLegacyAutoRotate(bool autoRotate) =>
    autoRotate ? PlayerOrientation.device : PlayerOrientation.fill;

/// The policies this platform can honour, in the order they are offered.
///
/// All four, on both mobile platforms: Android reaches "follow the phone" with
/// `SCREEN_ORIENTATION_FULL_SENSOR`, and iOS with the hardware posture plus an
/// explicit geometry request (`services/screen_orientation.dart`). The row is
/// gated on being mobile at all, not on which mobile.
List<OrientationPolicy> orientationPolicies() => OrientationPolicy.values;

/// What the player asks the platform for.
///
/// Two parts GO to the platform, and the caller must send them in this order:
/// [orientations] is the mask `SystemChrome.setPreferredOrientations` takes, and
/// [followDevice] asks the app's own channel to follow the phone's real posture,
/// lock or no lock. [fittedShape] is the third field and is not sent at all: it
/// is the shape that mask locks to, kept so the NEXT request knows what is in
/// force (see the field).
///
/// The mask comes FIRST because iOS only honours a geometry request its
/// supported mask already allows, and it must also be sent when
/// [followDevice] is true -- on Android both write the same activity property, so
/// the channel call has to be the last word, and on iOS the mask is what opens
/// the door for it.
class OrientationRequest {
  const OrientationRequest.allow(this.orientations, {this.fittedShape})
    : followDevice = false;

  /// Asks for every orientation AND for the sensor to decide between them.
  const OrientationRequest.followPhone()
    : orientations = DeviceOrientation.values,
      followDevice = true,
      fittedShape = null;

  final List<DeviceOrientation> orientations;

  /// True when the caller must also ask the app's own channel
  /// (`ScreenOrientation.followDevice(true)`), after the mask above.
  final bool followDevice;

  /// Which video shape this request's axis is locked to, and null when it locks
  /// the screen to no shape at all (outside fullscreen, a strategy that does not
  /// consult the video, or a shape nobody knows yet).
  ///
  /// It is bookkeeping the platform never sees, and it exists because "which
  /// lock is in force right now" is the one fact the next request needs: while a
  /// file loads and the player reports no size, this is what is held rather than
  /// released (see [orientationRequestFor]). The caller keeps one record of it,
  /// written from the request it sends — so the mask and the record cannot
  /// disagree.
  final bool? fittedShape;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is OrientationRequest &&
          other.followDevice == followDevice &&
          other.fittedShape == fittedShape &&
          _sameOrientations(other.orientations, orientations);

  @override
  int get hashCode => Object.hash(
    followDevice,
    fittedShape,
    Object.hashAll(orientations),
  );

  @override
  String toString() => followDevice
      ? 'OrientationRequest.followPhone()'
      : 'OrientationRequest.allow(${orientations.map((o) => o.name).join(', ')}'
            '${fittedShape == null ? '' : ', fit: ${fittedShape! ? 'landscape' : 'portrait'}'})';

  static bool _sameOrientations(
    List<DeviceOrientation> a,
    List<DeviceOrientation> b,
  ) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

const List<DeviceOrientation> _landscape = <DeviceOrientation>[
  DeviceOrientation.landscapeLeft,
  DeviceOrientation.landscapeRight,
];
const List<DeviceOrientation> _portrait = <DeviceOrientation>[
  DeviceOrientation.portraitUp,
  DeviceOrientation.portraitDown,
];

/// Writes the mask the framework channel carries.
typedef OrientationMaskWriter =
    Future<void> Function(List<DeviceOrientation> orientations);

/// Asks the app's own channel to follow (or stop following) the device.
typedef DeviceFollowWriter = Future<void> Function(bool follow);

/// Applies [request] to the platform, in the one order that works on both.
///
/// The mask FIRST, always, even when [OrientationRequest.followDevice] is true:
/// iOS only honours a geometry request its supported mask already allows, and on
/// Android both calls write the same activity property, so the sensor request has
/// to be the last word. The two calls are awaited in turn for that reason — not
/// merely dispatched together, which would leave the order to the scheduler.
///
/// The order is here, in a function with a test, rather than in the screen, which
/// cannot be mounted in a test: getting it backwards is invisible on a phone with
/// auto-rotate on and only shows up on one with the rotation lock set — the exact
/// bug this whole strategy exists to fix.
Future<void> applyOrientationRequest(
  OrientationRequest request, {
  required OrientationMaskWriter writeMask,
  required DeviceFollowWriter writeFollow,
}) async {
  await writeMask(request.orientations);
  await writeFollow(request.followDevice);
}

/// Hands the app back to its own direction — the way OUT of a fullscreen player.
///
/// The opposite order on purpose: the sensor stops first, because on iOS the
/// native half keeps forcing a geometry while it is following and would fight the
/// mask written after it.
Future<void> releaseOrientationRequest({
  required OrientationMaskWriter writeMask,
  required DeviceFollowWriter writeFollow,
  required List<DeviceOrientation> mask,
}) async {
  await writeFollow(false);
  await writeMask(mask);
}

/// The request [mode] means right now.
///
/// Only the FULLSCREEN player has a strategy: with [fullscreen] false -- and so
/// on the way out of the player -- the app hands itself back to the system's own
/// preference, which is what `_restoreExitChrome` wants and what the user asked
/// for ("fullscreen only; the app goes back to its own direction on the way
/// out").
///
/// [landscapeVideo] is the video's own aspect, and `null` while the player has
/// not reported one. [PlayerOrientation.fill] refuses to GUESS with it: the
/// guess this code used to make (unknown = landscape) locked a portrait video
/// into landscape, and nothing re-applied it when the real size arrived.
///
/// What it does instead depends on whether a lock is already in force, which is
/// what [lockedShape] carries (the [OrientationRequest.fittedShape] of the last
/// request that went out — see `video_player_screen`, the one place that keeps
/// that record):
///
///  * nothing locked yet (fullscreen entered before the player has reported a
///    size): ask for everything, which forces nothing, and lock the moment the
///    size lands.
///  * a lock IS in force (a video was skipped to while one is held, and mpv
///    reports no size for the file it is loading): HOLD it. Releasing it here is
///    what made every video change cost two rotations — off the fitted axis to
///    wherever the system's own preference points, then back onto the new video's
///    axis a moment later — and for two same-shaped videos, two rotations that
///    cancelled out and still took the viewer's eyes with them. The answer to
///    "which way up" a moment before the player could say is the way up it is
///    already at; only the new shape, when it arrives, changes anything.
OrientationRequest orientationRequestFor({
  required PlayerOrientation mode,
  required bool fullscreen,
  required bool? landscapeVideo,
  bool? lockedShape,
}) {
  if (!fullscreen) {
    return const OrientationRequest.allow(DeviceOrientation.values);
  }
  switch (mode) {
    case PlayerOrientation.fill:
      final shape = landscapeVideo ?? lockedShape;
      if (shape == null) {
        return const OrientationRequest.allow(DeviceOrientation.values);
      }
      return OrientationRequest.allow(
        shape ? _landscape : _portrait,
        fittedShape: shape,
      );
    case PlayerOrientation.system:
      return const OrientationRequest.allow(DeviceOrientation.values);
    case PlayerOrientation.device:
      return const OrientationRequest.followPhone();
    case PlayerOrientation.portrait:
      return const OrientationRequest.allow(_portrait);
    case PlayerOrientation.landscape:
      return const OrientationRequest.allow(_landscape);
  }
}

/// The one-line note under the strategy row: what the choice really does.
///
/// The same words on both mobile platforms on purpose. Android's
/// `SCREEN_ORIENTATION_FULL_SENSOR` and iOS's hardware posture plus geometry
/// request are the same promise made with the two platforms' own API — neither
/// is a case of a platform that cannot do it, which is when this app says so
/// instead (see `capturePolicyNote`, `systemVolumeBindingNote`).
String orientationNote(OrientationPolicy policy) => switch (policy) {
  OrientationPolicy.fill =>
    'Match the video: a wide video locks landscape, a tall one portrait',
  OrientationPolicy.system =>
    'Only as the system allows — the rotation lock is respected',
  OrientationPolicy.device =>
    'Follow how the phone is held, even when the rotation lock is on',
  OrientationPolicy.lock => 'Stay in one orientation until you change it',
};
