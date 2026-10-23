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

import 'dart:io' show Platform;

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
/// Two parts GO to the platform, and on iOS the caller must send them in this
/// order: [orientations] is the mask `SystemChrome.setPreferredOrientations`
/// takes, and [followDevice] asks the app's own channel to follow the phone's
/// real posture, lock or no lock. [fittedShape] is the third field and is not
/// sent at all: it is the shape that mask locks to, kept so the NEXT request
/// knows what is in force (see the field).
///
/// The mask comes FIRST on iOS because it only honours a geometry request its
/// supported mask already allows. On Android a Follow request writes NO mask at
/// all (see [applyOrientationRequest]): the all-four list decodes to
/// `FULL_USER`, the lock-RESPECTING value, so writing it before the sensor
/// request made the screen take the system's orientation for the instant before
/// `FULL_SENSOR` landed -- the "system, then back to the phone" flash every
/// video change under Follow used to play. If the sensor request cannot be
/// delivered, the all-four mask is written as the fallback instead.
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

/// Asks the app's own channel to follow (or stop following) the device, and
/// reports whether the request reached the platform.
typedef DeviceFollowWriter = Future<bool> Function(bool follow);

/// The platform whose ordering rule applies to [applyOrientationRequest].
///
/// The rule lives here, not at the call site, because getting it backwards is
/// silent on a phone with auto-rotate on: Android must NOT write the all-four
/// mask before a Follow request (it is `FULL_USER`, the lock-respecting value,
/// so the screen flashes to the system's orientation before `FULL_SENSOR` wins),
/// while iOS MUST write it (a geometry request is only honoured inside the
/// supported mask).
enum OrientationPlatform { android, ios }

/// The platform this process is running on.
///
/// Only mobile callers matter; a desktop host falls on the iOS side (mask
/// first), which is the safe order and what the tests exercise by default.
OrientationPlatform get hostOrientationPlatform =>
    Platform.isAndroid ? OrientationPlatform.android : OrientationPlatform.ios;

/// Applies [request] to the platform, in the one order that works.
///
/// On iOS the mask comes FIRST, even when [OrientationRequest.followDevice] is
/// true: iOS only honours a geometry request its supported mask already allows.
/// The two calls are awaited in turn — not merely dispatched together, which would
/// leave the order to the scheduler.
///
/// [platform] selects the ordering rule and defaults to [hostOrientationPlatform].
/// On ANDROID, a Follow request writes no mask first: the all-four mask decodes to
/// `FULL_USER`, the lock-RESPECTING value, so writing it makes the screen obey
/// the system's rotation for the instant before `FULL_SENSOR` lands — the
/// "system, then back to the phone" flash on every video change under Follow.
/// `FULL_SENSOR` already allows every orientation, so the channel call is the
/// whole policy WHEN IT IS DELIVERED; if `writeFollow` reports it could not be,
/// the all-four mask is written as the fallback (the system's own preference)
/// rather than leaving a previous, narrower mask in force. A non-Follow request
/// still writes its mask, and on Android its following `release` is a no-op, so
/// the mask is the last word. On iOS the mask is always written first.
///
/// The order is here, in a function with a test, rather than in the screen, which
/// cannot be mounted in a test: getting it backwards is invisible on a phone with
/// auto-rotate on and only shows up on one with the rotation lock set — the exact
/// bug this whole strategy exists to fix.
Future<void> applyOrientationRequest(
  OrientationRequest request, {
  required OrientationMaskWriter writeMask,
  required DeviceFollowWriter writeFollow,
  OrientationPlatform? platform,
}) async {
  final host = platform ?? hostOrientationPlatform;
  if (request.followDevice && host == OrientationPlatform.android) {
    // Android: `FULL_SENSOR` is already a complete policy -- every orientation,
    // rotation lock ignored -- so the channel call is the whole request. The
    // mask that would go first is the all-four list, which the embedding decodes
    // to `FULL_USER` ("Respect the user's sensor-based rotation preference");
    // writing it makes the screen obey the lock for the moment before the sensor
    // request replaces it, which is the flash the viewer sees as "system, then
    // back to where it was".
    final delivered = await writeFollow(request.followDevice);
    if (!delivered) {
      // No native half, or the channel refused: leaving no mask would strand the
      // screen on whatever narrower mask was in force (a previous Portrait lock,
      // for one). The all-four mask is the platform's own sane fallback -- it
      // still respects the system, which is what the app did before this
      // strategy existed.
      await writeMask(request.orientations);
    }
    return;
  }
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

/// The screen's orientation record and its exit latch, in one value.
///
/// The screen cannot be mounted in a test, so the two facts that decide whether
/// a mask may be written live here:
///
///  * [lockedShape] — the [OrientationRequest.fittedShape] of the last request
///    that went out, which [orientationRequestFor] HOLDS while the next file has
///    no shape to give (a video change reports 0x0). [record] is the only writer,
///    so the record cannot drift from the mask the platform holds.
///  * [released] — whether the exit has already handed the mask back. It is a
///    ONE-WAY LATCH for the life of the screen: every caller of the release pops
///    the route, and two asynchronous writers are still live at that moment —
///    the video parameters stream, subscribed for the whole pop (only a route
///    step cancels it). A report applying the fullscreen request after the
///    release puts the video's axis back on top of the library that is arriving.
///
/// The equality rule alone protected only fill: its record is the video's own
/// shape, so a repeated report matched and was ignored. An explicit Portrait lock
/// records no shape ([OrientationRequest.fittedShape] is null for every strategy
/// that does not read the video), so every report looked like news — and the
/// report that arrived during the exit re-applied the portrait mask AFTER the
/// release. That is the "some choices self-lock portrait" bug; the latch is what
/// closes it for every strategy, not just the one whose record happened to match.
class PlayerOrientationSession {
  PlayerOrientationSession({bool? lockedShape}) : this._(lockedShape);

  PlayerOrientationSession._(this._lockedShape);

  bool? _lockedShape;
  bool _released = false;

  /// The shape the mask in force holds, or null when it holds none.
  bool? get lockedShape => _lockedShape;

  /// True once the exit has written the library's mask; nothing may re-arm a
  /// fullscreen request after that.
  bool get released => _released;

  /// Whether the screen may still write the fullscreen mask.
  bool get mayWrite => !_released;

  /// The exit has happened. One-way until [reenterFullscreen].
  ///
  /// The record is cleared with the latch: the release writes the app's default
  /// all-four mask, so there is no fitted shape in force to hold any more. It
  /// used to be kept on the premise that no writer could run after the release
  /// (the old equality guard needed it to recognise a repeated report); the
  /// latch now silences those writers, and leaving a stale shape behind would
  /// make a re-entered fullscreen hold the pre-exit video's axis while the
  /// player reports no size — the guess `orientationRequestFor` refuses to make.
  void release() {
    _released = true;
    _lockedShape = null;
  }

  /// Fullscreen was entered again on a screen that is still mounted — the only
  /// way back from a release, and needed so a cancelled exit cannot leave the
  /// writers dead.
  void reenterFullscreen() {
    _released = false;
  }

  /// Records the request that just went out. Nothing is recorded after a
  /// release, because nothing is sent after one; [release] itself clears the
  /// record.
  void record(OrientationRequest request) {
    if (_released) return;
    _lockedShape = request.fittedShape;
  }

  /// Whether a video-params report is news the screen must act on.
  ///
  /// Only [PlayerOrientation.fill] reads the video: the other strategies take
  /// their axis from the viewer or the phone, so a shape arriving (or changing)
  /// is not news for them. Re-applying one of them on a shape report is a
  /// platform write for a decision the video cannot change. (It used to be
  /// worse: before the Android Follow request skipped the lock-respecting
  /// all-four mask, every such re-apply made the screen obey the system for the
  /// instant before FULL_SENSOR put it back on the phone's real posture.)
  ///
  /// Not news either: no size (the player is between files), the shape already in
  /// force (mpv repeats the report per property change), or ANY report after the
  /// release.
  bool videoShapeIsNews(PlayerOrientation mode, bool? landscapeVideo) {
    if (_released) return false;
    if (mode != PlayerOrientation.fill) return false;
    if (landscapeVideo == null) return false;
    return landscapeVideo != _lockedShape;
  }

  /// Runs [writer] only while the screen may still write, and reports `true` when
  /// the latch is closed so a caller's Android fallback does not write either.
  ///
  /// The latch is re-read HERE rather than only before the apply starts: an apply
  /// that began just before the exit has already sent its mask (same-channel FIFO
  /// keeps the release's mask last), but on iOS it sends the follow request only
  /// after that mask's reply. If the exit starts in between, that `follow(true)`
  /// would land AFTER the release's `follow(false)` and leave the native half
  /// forcing a geometry while the library arrives. `true` on the closed latch is
  /// "handled": it suppresses the fallback mask as well.
  Future<bool> followThrough(DeviceFollowWriter writer, bool follow) {
    if (!mayWrite) return Future<bool>.value(true);
    return writer(follow);
  }

  /// Runs [writer] only while the screen may still write.
  ///
  /// This is the other half of [followThrough]: a follow that fails after the
  /// latch closes would otherwise take `applyOrientationRequest`'s fallback path
  /// and write a mask after the release.
  Future<void> maskThrough(
    OrientationMaskWriter writer,
    List<DeviceOrientation> mask,
  ) {
    if (!mayWrite) return Future<void>.value();
    return writer(mask);
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
