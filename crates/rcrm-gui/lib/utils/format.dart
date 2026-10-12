// utils/format.dart

/// Formats milliseconds as `mm:ss`, switching to `h:mm:ss` past one hour.
///
/// Negative input is clamped to zero rather than formatted: Dart's `%` is always
/// non-negative, so `-1` used to come out as `-1:59:59` and a large negative
/// millisecond count (an unclamped scrub value, say) printed something that
/// looked like a stray memory address. Callers should clamp too — this is the
/// last line of defence, not the only one.
String formatMs(int ms) {
  final safe = ms < 0 ? 0 : ms;
  final s = (safe / 1000).round();
  final h = s ~/ 3600;
  final m = (s % 3600) ~/ 60;
  final sec = s % 60;
  final mm = m.toString().padLeft(2, '0');
  final ss = sec.toString().padLeft(2, '0');
  return h > 0 ? '$h:$mm:$ss' : '$mm:$ss';
}

/// A pixel size as a person reads it: `1920 × 1080 (1080p)`.
///
/// The shorthand is the name viewers already use for the height, and it is
/// taken from the SHORTER side in both orientations — a phone clip that stores
/// 1080x1920 is still a 1080p clip, and a portrait video that called itself
/// "1920p" is the kind of number that makes a reader distrust the rest of the
/// panel.
///
/// The name is only used when the size really IS that class, within
/// [_kClassTolerance]: one percent covers the real near-misses (1088 is 1080p
/// in every practical sense) while refusing the tempting cascade, where a `>=`
/// ladder calls a 1000x640 letterbox "576p" and a 2.40:1 crop of a 720p master
/// "576p" too. A size with no name gets its numbers and nothing else — an
/// invented name is worse than none.
String resolutionLabel(int width, int height) {
  final short = width < height ? width : height;
  final tall = width < height ? height : width;
  int? best;
  String? name;
  for (final entry in _kResolutionClasses.entries) {
    final gap = (short - entry.key).abs();
    if (gap > entry.key * _kClassTolerance) continue;
    if (best == null || gap < best) {
      best = gap;
      name = entry.value;
    }
  }
  return name == null ? '$tall × $short' : '$tall × $short ($name)';
}

/// How far off a class a size may be and still be called by its name.
const double _kClassTolerance = 0.01;

/// Vertical resolutions with names people use, tallest first.
const Map<int, String> _kResolutionClasses = {
  2160: '4K',
  1440: '1440p',
  1080: '1080p',
  720: '720p',
  576: '576p',
  540: '540p',
  480: '480p',
  360: '360p',
  240: '240p',
};
