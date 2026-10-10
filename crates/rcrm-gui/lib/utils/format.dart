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
