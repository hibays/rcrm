// utils/player_volume.dart
// Where a player screen's volume control sends its value, and what the bar shows
// afterwards -- the whole decision, as one value with pure transitions.
//
// It lives outside the screen because the screen cannot be mounted in a test:
// its first frame builds a real media_kit `Player`. That is the same reason
// `utils/seek_preview.dart` and `utils/player_exit.dart` exist, and this one
// earned its place the same way -- the two defects it now pins were both found
// by review in the screen's routing: an unmute that could only ever return the
// level it started with, and a quantised echo that notified nobody.
//
// Three facts move together and none of them may be decided twice:
//
//  * WHICH volume the screen's control drives -- the device's media stream, or
//    libmpv's own gain (`shouldBindSystemVolume`, `services/system_volume.dart`);
//  * the level the bar shows. While bound that level is the DEVICE's, in the
//    device's own resolution: a 15-step phone cannot be at 43%, so 43% is only
//    ever a request, and the answer is what the bar shows;
//  * the last level the device was AUDIBLE at this session, which is what an
//    unmute comes back to. It starts at 0 -- "nothing seen" -- precisely so that
//    a session opening on a silent phone asks the device (or the middle) rather
//    than jumping to full scale.

import 'package:flutter/foundation.dart';

import '../services/system_volume.dart';

/// A player screen's volume: which volume it drives, the level the bar shows,
/// and the last level the device was audible at.
@immutable
class PlayerVolume {
  const PlayerVolume({
    required this.bound,
    required this.level,
    required this.lastAudible,
  });

  /// A screen that has decided nothing yet: the app's own volume, full scale,
  /// nothing seen, nothing bound.
  static const PlayerVolume initial = PlayerVolume(
    bound: false,
    level: 100,
    lastAudible: 0,
  );

  /// True when [level] IS the device's media volume.
  final bool bound;

  /// What the bar shows, 0..100.
  final double level;

  /// The last non-zero level this session has seen, 0 when it has seen none.
  final double lastAudible;

  /// Whether the app's own `player_volume` may be written: bound, that number
  /// belongs to the phone, and remembering it here would override the system
  /// volume at the next launch.
  bool get remembersAppVolume => !bound;

  /// The gain libmpv itself must sit at. While bound it is pinned WIDE OPEN --
  /// the device's stream does the attenuating, and writing both would multiply
  /// the two.
  double get playerGain => bound ? 100 : level;

  /// The level an unmute should ask for.
  ///
  /// Preference order is `unmuteLevel`'s: the level this session saw last, then
  /// the level the DEVICE would restore, then the middle. The device's answer is
  /// reachable exactly because [lastAudible] starts at 0.
  double unmuteTo(SystemVolumeReading? reading) =>
      unmuteLevel(lastSeen: lastAudible, reading: reading);

  /// Decides the binding from what the device said and adopts its level.
  ///
  /// A reading this app may use (`shouldBindSystemVolume`) hands the control to
  /// the device and shows the device's level; anything else -- the setting is
  /// off, the platform cannot be asked, the reply was refused, the output is
  /// fixed-volume -- leaves the app's own volume in charge at [fallbackLevel].
  ///
  /// [fallbackLevel] comes from outside the session (the persisted
  /// `player_volume`), so it is normalised like any other level, and it counts as
  /// an audible level the session has seen: an unmute in a session that opened
  /// on the app's own volume must come back to the level it opened at, not to
  /// full scale.
  ///
  /// The `fixed` case is why this can DROP a binding that was already decided
  /// from a cached reading: the caller adopts whatever comes back, so the
  /// device subscription follows the value rather than a flag of its own.
  PlayerVolume seeded({
    required bool supported,
    required bool setting,
    required SystemVolumeReading? reading,
    required double fallbackLevel,
  }) {
    if (!shouldBindSystemVolume(
      supported: supported,
      setting: setting,
      reading: reading,
    )) {
      return _unboundAt(_normalise(fallbackLevel));
    }
    return _boundTo(reading!);
  }

  /// What a reading that arrived AFTER the session was seeded may change.
  ///
  /// The seed path runs twice -- what was already known, then what the platform
  /// answers -- and the second answer was already in flight when anything that
  /// happened in between did. So it may still DROP a binding (a fresh `fixed`)
  /// and it may still establish one the first pass could not, but it never
  /// rewrites a level the session has already taken from the device: a volume-key
  /// press in the first moments of a video, which is exactly when keys are
  /// pressed, must not be undone by the answer that was already on its way.
  ///
  /// A failed read changes nothing here: one unanswerable round trip is not a
  /// reason to hand a working binding back.
  PlayerVolume reconfirmed({
    required bool supported,
    required bool setting,
    required SystemVolumeReading? reading,
    required double fallbackLevel,
  }) {
    if (!bound) {
      return seeded(
        supported: supported,
        setting: setting,
        reading: reading,
        fallbackLevel: fallbackLevel,
      );
    }
    if (reading != null && reading.fixed) return _unboundAt(level);
    return this;
  }

  /// The same session at level [v], with the memory updated.
  ///
  /// A non-finite value -- a gesture area with no height yet produces one, and
  /// `clamp` is transparent to NaN while `round()` throws on it -- leaves the
  /// session untouched, at the one place every volume path goes through.
  ///
  /// What happens NEXT is the caller's: a level the USER asked for goes on to
  /// the device (or to the player), while a level that came FROM the player's
  /// own gain stream is only adopted, or the two would echo each other.
  PlayerVolume withLevel(double v) {
    if (!v.isFinite) return this;
    final nv = v.clamp(0.0, 100.0);
    return PlayerVolume(
      bound: bound,
      level: nv,
      lastAudible: _audibleAt(nv),
    );
  }

  /// What the DEVICE reports: the level pushed after somebody moved it with the
  /// hardware keys, or the answer to this app's own write.
  ///
  /// While bound the device's level WINS over what was asked for -- that is how
  /// the bar learns the step the phone really landed on. Unbound this is not the
  /// device's business and nothing moves.
  ///
  /// A reading that says the output is FIXED gets the same refusal `seeded`
  /// makes, on the runtime path: an HDMI or USB sink can appear mid-session, and
  /// ignoring that would leave the control bound to a stream whose writes are
  /// documented no-ops -- the player pinned wide open and the slider doing
  /// nothing, which is no volume control at all. The level on screen is kept and
  /// the app's own gain takes the attenuation over.
  PlayerVolume reported(SystemVolumeReading? reading) {
    if (!bound || reading == null) return this;
    if (reading.fixed) return _unboundAt(level);
    return _boundTo(reading);
  }

  PlayerVolume _boundTo(SystemVolumeReading reading) {
    final v = reading.percent;
    return PlayerVolume(
      bound: true,
      level: v,
      lastAudible: _audibleAt(v),
    );
  }

  /// The same session handed back to the app's own volume, keeping [kept] on
  /// screen -- the device can no longer attenuate, so the player has to.
  PlayerVolume _unboundAt(double kept) => PlayerVolume(
    bound: false,
    level: kept,
    lastAudible: _audibleAt(kept),
  );

  /// The level the memory should hold after seeing [v]: the last AUDIBLE one,
  /// which is what an unmute comes back to.
  double _audibleAt(double v) => v > 0 ? v : lastAudible;

  /// A level from outside the session, put through the same rules as one from
  /// inside it: a hand-edited preference cannot put the bar outside 0..100, and
  /// a value that is not a number leaves the session alone.
  double _normalise(double v) =>
      v.isFinite ? v.clamp(0.0, 100.0) : level;

  @override
  String toString() =>
      'PlayerVolume(bound: $bound, level: $level, lastAudible: $lastAudible)';
}
