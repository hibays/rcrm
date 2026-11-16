// utils/poster_frame.dart
// The one pure decision in video-poster generation: WHERE to look.
//
// Both sides use this order — Dart sends it to `rcrm_generate_poster_async`,
// Rust walks it in the libmpv client and skips any position at or past the
// duration it reads itself. Everything that touches pixels (the blank test, the
// WebP encode) lives in Rust.
//
// The order exists because the old fixed list started at 0.0s, which is the
// frame no film advertises itself with (a black leader, a fade, a distributor
// card), and its other entries were absolute seconds. The first candidate
// decides a lot, because the pipeline stops at the first frame that passes the
// blank test. [posterSeekPlan] is that order.

/// Candidate positions in SECONDS, most promising first.
///
/// * [duration] is the real duration when it is known; pass [Duration.zero]
///   when nobody has reported one (the absolute fallbacks then run, which is
///   what the pipeline always did).
/// * No entry reaches or passes the end of a KNOWN duration: a seek to exactly
///   the duration returns the last frame or nothing. 0.0 IS allowed — it is the
///   file's first frame, not a seek past its end.
/// * Entries are unique after rounding to 0.1s. 0.0 is the fallback that runs
///   only when nothing else produced a usable frame; an extremely short clip,
///   where every rounded candidate collapses to 0.0, may legitimately start
///   there.
List<double> posterSeekPlan(Duration duration) {
  final d = duration.inMilliseconds / 1000.0;
  if (d <= 0) {
    // Duration unknown — which is the DESKTOP path's normal case today
    // (`MediaItem.durationSeconds` is never filled by a scan): a fraction
    // cannot be taken of a length nobody reported, so this is the old absolute
    // ladder, re-ordered. Content first: 30s and 15s are past the leader of
    // almost everything, 3s is the short-clip fallback (a feature's title card
    // often still lives there), 0.5s helps a very short clip, the far guesses
    // cover long leaders, and 0.0 is last.
    return const [30.0, 15.0, 3.0, 0.5, 60.0, 120.0, 240.0, 0.0];
  }

  // 10% in, but never earlier than 1s (nothing has happened yet) and never
  // later than 5 minutes (a 3-hour film should not be sampled at minute 18 —
  // the middle of an act says less about the film than its opening does).
  final first = (d * 0.10).clamp(1.0, 300.0);
  // A quarter in: the second bet, far enough from the first to be a different
  // scene on anything longer than a few seconds.
  final quarter = d * 0.25;
  // Halfway: the most "representative" frame a film ever offers.
  final half = d * 0.50;

  final out = <double>[];
  void add(double v) {
    if (v <= 0) {
      if (v == 0 && !out.contains(0.0)) out.add(0.0);
      return;
    }
    // Stay inside the file: a seek to exactly the duration returns the last
    // frame (or nothing), which is what the last-entry 0.0 is for instead.
    final capped = v >= d ? d - 0.25 : v;
    if (capped <= 0) return;
    final rounded = double.parse(capped.toStringAsFixed(1));
    if (!out.contains(rounded)) out.add(rounded);
  }

  add(first);
  add(quarter);
  add(half);
  // Absolute fallbacks, in the order the old list ranked them once 0.0 was
  // demoted: a few seconds in, then just past the start, then the first frame.
  add(3.0);
  add(0.5);
  add(0.0);
  return out;
}
