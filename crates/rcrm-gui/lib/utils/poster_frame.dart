// utils/poster_frame.dart
// The two pure decisions in video-poster generation: WHERE to look, and
// whether the frame that came back is a new one.
//
// Both poster backends use this file: the libmpv one for the search order (Rust
// skips any position past the duration it reads itself), the media_kit one for
// both decisions. Everything that touches pixels — the blank test, the
// downscale, the WebP encode — lives in Rust either way. The measurements behind
// the search order are in CHANGELOG/AGENTS: a paused-seek screenshot can be the
// previous frame, so the media_kit pipeline has to notice a stale capture and ask
// again; and the first candidate must not be the black leader.
//
//   1. A screenshot taken right after a paused seek hands back the frame the
//      video output ALREADY had while the seek's frame is still decoding.
//      25–75% of paused-seek screenshots were byte-identical to the previous
//      position's. So the pipeline cannot assume its first screenshot belongs
//      to the position it asked for — it has to notice that it did not, and
//      ask again. [sameEncodedFrame] is that notice.
//   2. The old fixed position list started at 0.0s, which is the frame no film
//      advertises itself with (a black leader, a fade, a distributor card), and
//      its other entries were absolute seconds. The first candidate decides a
//      lot, because the pipeline stops at the first frame that passes the blank
//      test. [posterSeekPlan] is that order.

import 'dart:typed_data';

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

/// Whether [current] is the SAME frame as the previous capture at a given
/// candidate position, i.e. the seek handed back the frame the video output
/// already had.
///
/// The 0.0 fallback is deliberately exempt: there the pre-seek frame IS the
/// first frame, and it is also the only frame a static video or a slideshow
/// ever produces. Rejecting it as stale would leave that video with no poster
/// at all (the earlier candidates are all the same frame, so they exhaust the
/// retries first).
bool isStalePosterFrame({
  required double position,
  required Uint8List? previous,
  required Uint8List current,
}) =>
    position != 0.0 && previous != null && sameEncodedFrame(previous, current);

/// Whether [a] and [b] are the SAME encoded frame.
///
/// Used for the raw BGRA screenshots and for media_kit's JPEG fallback. Two
/// captures of the same picture are byte-identical when the same source and
/// encoder produce them, which is exactly the case here: the pipeline asks for
/// a frame, gets the previous one back untouched, and compares two encodes of
/// that same buffer. Equality is therefore a reliable staleness signal — no
/// decode, no allocation.
///
/// Compared BYTE FOR BYTE, with an early exit, and not by sampling: a stale
/// frame and a fresh one usually differ in the first few hundred bytes, so the
/// loop returns on the first mismatch and is cheaper than a sampled pass in the
/// common case. Sampling was the first version; it cannot promise that a
/// changed pixel is noticed, and "almost certainly not the same frame" is not
/// a thing a pipeline that caches the answer may say.
bool sameEncodedFrame(Uint8List a, Uint8List b) {
  if (identical(a, b)) return true;
  final len = a.length;
  if (len != b.length) return false;
  // A raw 1920x1080 frame is 8 MB. Comparing it byte by byte on the UI
  // isolate costs tens of milliseconds per position, which is the same order
  // as the whole raw->WebP pipeline. Four bytes at a time cuts the loop by 4
  // with identical semantics; the tail and any unaligned view still go byte by
  // byte. `Uint32List` (not `Uint64List`) so this stays valid on every Dart
  // target, including the web compiler.
  final ao = a.offsetInBytes;
  final bo = b.offsetInBytes;
  var i = 0;
  if (ao % 4 == 0 && bo % 4 == 0 && len >= 4) {
    final blocks = len ~/ 4;
    final av = a.buffer.asUint32List(ao, blocks);
    final bv = b.buffer.asUint32List(bo, blocks);
    for (var j = 0; j < blocks; j++) {
      if (av[j] != bv[j]) return false;
    }
    i = blocks * 4;
  }
  for (; i < len; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
