// services/system_volume.dart
// The DEVICE's media volume -- the mobile-only setting behind
// Settings -> Display -> System Volume.
//
// The player has always scaled its own gain (`Player.setVolume`), which is what
// a desktop app does: the OS mixer is the user's business, and the app's slider
// is a second, app-local volume stacked on top of it. A phone is the other way
// round. Its hardware keys move the media stream, every other media app moves
// that same stream, and a video holding a private volume above it is a video
// whose loudness disagrees with the phone -- which is the complaint this setting
// answers. So on mobile the app's volume control drives the system stream by
// default, the player itself is pinned wide open, and the two halves cannot
// disagree because there is only one number.
//
// The arithmetic lives HERE and only here. The platform answers with raw stream
// numbers (`index`, `min`, `max`) and applies an index; turning one of those
// into the other -- including the quantisation a stream with a handful of steps
// causes, which is what makes the bar snap to the levels the phone can really
// be at -- is a pure function this file unit-tests. A percent travelling to the
// platform instead would put the same arithmetic in two languages, and the two
// would drift.
//
// Every call is defensive, and a platform with no answer is not an error: no
// reading means the caller stays on the player's own volume, which always
// works. Nothing here throws.

import 'dart:io' show Platform;

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// Test seam for the mobile-only branch below.
///
/// The tests run the desktop VM, where the real platform check is false -- so
/// neither the row nor the channel call would be reachable from a test, and the
/// binding IS this feature. Only `test/system_volume_test.dart` writes it.
/// Untouched, it is exactly `Platform.isAndroid || Platform.isIOS`.
@visibleForTesting
bool debugSystemVolumeSupported = Platform.isAndroid || Platform.isIOS;

/// The stream index that means [percent] on a stream with `min..max` steps.
///
/// Pure, and the only place a percentage becomes a step: a phone with 15 steps
/// cannot be at 43%, it can be at 6/15 (40%) or 7/15 (46.7%), and rounding here
/// is what lets the bar show the level the phone really landed on instead of
/// the one the finger asked for.
///
/// A percent that is not a number has no step. `clamp` is transparent to NaN and
/// `round()` THROWS on it, which would break this file's "nothing here throws"
/// promise from inside an `unawaited` write (an unhandled async error rather
/// than a rejected future) — so the floor is returned instead. It is
/// unreachable by design: `PlayerVolume.withLevel` refuses a non-finite level
/// and [SystemVolume.setPercent] refuses to send one.
int systemVolumeIndex(double percent, {required int min, required int max}) {
  if (max <= min) return min;
  if (!percent.isFinite) return min;
  final span = max - min;
  return (min + (percent.clamp(0.0, 100.0) / 100) * span)
      .round()
      .clamp(min, max);
}

/// The percentage [index] means on that stream -- the inverse of
/// [systemVolumeIndex], up to the quantisation it cannot avoid.
double systemVolumePercent(int index, {required int min, required int max}) {
  // A stream with no travel is not a percentage of anything; 100 is the honest
  // answer ("this output is as loud as it gets"). It is only ever asked about a
  // stream the app may NOT set -- `fromPlatform` accepts one solely when the
  // device declares it fixed, and the binding refuses those -- so the number is
  // never shown on a bar.
  if (max <= min) return 100;
  return (index - min).clamp(0, max - min) / (max - min) * 100;
}

/// What an unmute should come back to.
///
/// Preference order: the highest level this app has seen audible, then the
/// level the DEVICE itself would restore, then the middle. The device's own
/// answer matters because a session can begin already silent -- the bar is at 0
/// with nothing remembered, and "unmute" must not jump to full scale on a phone
/// that was quietly at 30%.
double unmuteLevel({required double lastSeen, SystemVolumeReading? reading}) {
  if (lastSeen > 0) return lastSeen;
  final last = reading?.lastAudiblePercent ?? 0;
  if (last > 0) return last;
  return 50;
}

/// Whether this session's volume control drives the device.
///
/// All four have to hold at once, and each one is a way the binding would
/// otherwise promise something it cannot do:
///
///  * `supported` -- the platform family has a media stream the app may set;
///  * `setting` -- the user asked for it (ON by default on mobile, never on
///    desktop, where the row is not offered at all);
///  * a reading -- the device was readable, because a binding that starts from
///    a number nobody read is a slider whose position is invented;
///  * not `fixed` -- the output is not a fixed-volume one (some TV boxes, car
///    head units, HDMI sinks): `setStreamVolume` is a no-op there, so the
///    control would be dead. The player keeps its own volume instead.
bool shouldBindSystemVolume({
  required bool supported,
  required bool setting,
  SystemVolumeReading? reading,
}) =>
    supported && setting && reading != null && !reading.fixed;

/// The device's media volume, as the platform last reported it.
///
/// The fields are the platform's own raw numbers -- what the bar shows is
/// [percent], and the conversion is deliberately not stored: the same reading is
/// also what `setPercent` converts back, so both directions describe one stream.
@immutable
class SystemVolumeReading {
  const SystemVolumeReading({
    required this.index,
    required this.min,
    required this.max,
    required this.muted,
    required this.lastAudible,
    this.fixed = false,
  });

  /// The stream's current step.
  final int index;

  /// The ends of the stream's travel (`AudioManager.getStreamMinVolume` /
  /// `getStreamMaxVolume` on Android; 0..100 on iOS, where the platform's own
  /// unit already is the percentage).
  final int min;
  final int max;

  /// Whether the stream is silent: the index is at its floor, or the platform
  /// reports the stream muted at a non-zero index (another app, or a system
  /// toggle). Either way the app must not claim to be audible.
  final bool muted;

  /// The level the device itself would restore on unmute.
  final int lastAudible;

  /// True when this output's volume cannot be set at all
  /// ([shouldBindSystemVolume]). The platform says so with
  /// `AudioManager.isVolumeFixed()`: the levels exist (or do not), and every
  /// volume call is documented as having no effect.
  final bool fixed;

  /// 0..100 -- the number the bar's slider and the gesture chip speak, and 0
  /// whenever the stream is silent: one fact, so "silent" can never be drawn as
  /// a live speaker at 5%.
  double get percent =>
      muted ? 0 : systemVolumePercent(index, min: min, max: max);

  /// [lastAudible] in the bar's units.
  double get lastAudiblePercent =>
      systemVolumePercent(lastAudible, min: min, max: max);

  /// The step that means [percent] on this stream.
  int indexFor(double percent) => systemVolumeIndex(percent, min: min, max: max);

  /// Reads a platform map without trusting a single field of it.
  ///
  /// A reply that is not a complete, usable description of a stream is refused
  /// whole (null) rather than half-read: a reading with an invented `max` would
  /// put a wrong percentage on the bar, and one with an invented `min` would set
  /// the phone to a level nobody asked for.
  ///
  /// A stream with NO travel (`max <= min`) is refused too — there is no
  /// percentage of it, and it cannot be set — with one exception: a reply that
  /// says `fixed: true`. That is not a stream the app may use, it is the device
  /// stating that this output has one level and every volume API is a no-op
  /// there, which is a fact the Settings row has to be able to repeat. The
  /// binding refuses it in `shouldBindSystemVolume` either way.
  static SystemVolumeReading? fromPlatform(Object? reply) {
    if (reply is! Map) return null;
    final Object? index = reply['index'];
    final Object? min = reply['min'];
    final Object? max = reply['max'];
    final Object? muted = reply['muted'];
    final Object? lastAudible = reply['lastAudible'];
    final Object? fixed = reply['fixed'];
    if (index is! int ||
        min is! int ||
        max is! int ||
        muted is! bool ||
        lastAudible is! int ||
        fixed is! bool) {
      return null;
    }
    // A floor ABOVE its ceiling is malformed whatever the `fixed` claim says, and
    // `clamp` would throw on it (Dart requires a lower limit that is not above the
    // upper one) -- on the push path (`watch`) that is an unhandled error, because
    // no try/catch stands between it and the platform.
    if (min > max) return null;
    if (max == min && !fixed) return null;
    return SystemVolumeReading(
      index: index.clamp(min, max),
      min: min,
      max: max,
      muted: muted,
      lastAudible: lastAudible.clamp(min, max),
      fixed: fixed,
    );
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is SystemVolumeReading &&
          other.index == index &&
          other.min == min &&
          other.max == max &&
          other.muted == muted &&
          other.lastAudible == lastAudible &&
          other.fixed == fixed;

  @override
  int get hashCode => Object.hash(index, min, max, muted, lastAudible, fixed);

  @override
  String toString() =>
      'SystemVolumeReading(index: $index, $min..$max, muted: $muted, '
      'lastAudible: $lastAudible, fixed: $fixed)';
}

class SystemVolume {
  SystemVolume._();

  /// The channel both halves implement. Pinned here because a mismatch between
  /// this name and either platform file is silent.
  static const MethodChannel channel = MethodChannel('rcrm/volume');

  /// Where the binding is offered AND honoured: the two mobile platforms. A
  /// desktop app's volume is its own mixer's business, and the app's own slider
  /// is what a desktop user expects -- so neither the row nor the channel call
  /// happens there.
  static bool get supported => debugSystemVolumeSupported;

  /// The last reading, shared process-wide.
  ///
  /// A [ValueNotifier] rather than a provider because a reading arrives from the
  /// platform at moments no user action explains -- the hardware volume keys,
  /// another app, the system's own panel -- and the player and the Settings row
  /// must see the same one.
  static final ValueNotifier<SystemVolumeReading?> state =
      ValueNotifier<SystemVolumeReading?>(null);

  /// True once the channel handler below is installed (once per process).
  static bool _watching = false;

  /// The step this app last ASKED for — valid only until the device answers.
  ///
  /// A drag repeats the same step on most of its frames while the answer that
  /// would confirm it is a round trip away, so comparing against the confirmed
  /// step alone would send one redundant write per step change. It is cleared by
  /// every published reading ([_publish]), so a change made anywhere else can
  /// never be suppressed by a stale request.
  static int? _requested;

  /// The ONE place a reading reaches the app.
  ///
  /// Writing `state` and forgetting what was asked for belong together: after
  /// this, the device's own answer is the only thing a request is compared
  /// against.
  static void _publish(SystemVolumeReading reading) {
    state.value = reading;
    _requested = null;
  }

  /// Starts following the device, so a volume change made anywhere else reaches
  /// [state]. Idempotent: a channel carries one handler, and re-registering it
  /// per screen would replace the one the previous screen installed.
  static void watch() {
    if (!supported || _watching) return;
    _watching = true;
    channel.setMethodCallHandler((MethodCall call) async {
      if (call.method != 'onChanged') return null;
      final SystemVolumeReading? reading = SystemVolumeReading.fromPlatform(
        call.arguments,
      );
      if (reading != null) _publish(reading);
      return null;
    });
  }

  /// Reads the device's current volume.
  ///
  /// Returns null when the platform could not answer -- no native half, a reply
  /// the codec refused, a stream with no travel -- and [state] is left alone in
  /// that case, so a failed read can never look like a reading.
  static Future<SystemVolumeReading?> read() async {
    if (!supported) return null;
    final SystemVolumeReading? reading = await _call('read');
    if (reading != null) _publish(reading);
    return reading;
  }

  /// Moves the device's volume to [percent].
  ///
  /// Needs a reading to convert with, and does nothing without one: the two
  /// numbers the conversion needs are the stream's, not the app's, so guessing
  /// them would set the phone to a level nobody asked for. The reply is the
  /// stream AFTER the write, which is how the bar learns the level the device
  /// really landed on -- the only honest source for that.
  ///
  /// Two writes are refused before they leave: a percent that is not a number
  /// (there is no step for it), and a step the app has already asked for or the
  /// device has already confirmed -- a drag asks for the same step on most of its
  /// frames, and each write costs a Binder call into the system server plus a
  /// reading pushed back. A muted stream is never skipped: the write is also what
  /// clears the mute flag (`SystemVolumeChannel.kt`).
  static Future<SystemVolumeReading?> setPercent(double percent) async {
    final SystemVolumeReading? current = state.value;
    if (!supported || current == null || !percent.isFinite) return null;
    final int index = current.indexFor(percent);
    if (index == (_requested ?? current.index) && !current.muted) return current;
    _requested = index;
    final SystemVolumeReading? reading = await _call(
      'setIndex',
      <String, Object?>{'index': index},
    );
    if (reading != null) _publish(reading);
    return reading;
  }

  static Future<SystemVolumeReading?> _call(
    String method, [
    Object? arguments,
  ]) async {
    try {
      return SystemVolumeReading.fromPlatform(
        await channel.invokeMethod<Object?>(method, arguments),
      );
    } catch (_) {
      // MissingPluginException on a host without the native half, or a reply the
      // codec refused. Either way: no reading, and no claim about the device's
      // volume.
      return null;
    }
  }

  /// Test-only: drops the handler and the last reading so one test cannot start
  /// from what another one read. [watch] installs the handler again.
  @visibleForTesting
  static void debugReset() {
    channel.setMethodCallHandler(null);
    _watching = false;
    _requested = null;
    state.value = null;
  }
}

/// The Settings row's subtitle: what the switch really does, on this device.
///
/// A pure function of the three things the row knows, so every wording is
/// assertable on any host -- the tests run the desktop VM, where neither mobile
/// branch is reachable.
///
/// The switch's own state is asked FIRST: with the binding off, what happens is
/// "the app's own volume", whatever this device could have done. After that come
/// the two cases where the switch cannot keep its promise, and they are the
/// reason this is a function rather than a string:
///
///  * **no reading** — the platform could not be asked (no native half, a reply
///    the codec refused, a stream with no travel that is not declared fixed), and
///    `shouldBindSystemVolume` refuses to bind without one, so the player keeps
///    its own volume. One wording covers "not answered yet" and "never will":
///    both mean the same thing to the player looking at it;
///  * **a fixed output** — `isVolumeFixed()` (some TV boxes, car head units,
///    HDMI sinks), where every volume API in the SDK is documented as having no
///    effect.
///
/// A row that still promised the device's volume in either case would be selling
/// a slider that cannot move the phone.
String systemVolumeBindingNote({
  required bool bound,
  required bool readable,
  required bool fixedOutput,
}) {
  if (!bound) {
    return "Volume is applied inside the player only; the device's media volume "
        'is left alone';
  }
  if (!readable) {
    return 'This device has not reported a media volume, so the player keeps its '
        'own volume control';
  }
  if (fixedOutput) {
    return "This device's output volume is fixed, so the player keeps its own "
        'volume control';
  }
  return "The player's volume control moves the device's media volume, starting "
      'from whatever it is now';
}
