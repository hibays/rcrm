// utils/thumb_cache_policy.dart
// Thumbnail-cache MANAGEMENT, as a pure decision: which cached entries to drop,
// and the tiers that decision came from.
//
// `ThumbCache` is a flat key -> file store with no bound at all, and the only
// cleanup it has ever had is `clear()` — everything, manually, because nothing
// in the app knows what is worth keeping. This file is that missing knowledge:
// entries are graded by GENERATION time (the file's write time; nothing records
// a "last used"), and the coldest go first.
//
// The grading is a heuristic in two senses, and neither asserts an age:
//
//   * The boundary is a QUANTILE OF THE CACHE ITSELF — "the oldest third of what
//     is here", not "older than seven days". A library scanned weekly
//     regenerates everything anyway, so a week-old entry is worthless there and
//     valuable in a library opened twice a year: the same age means opposite
//     things, and no constant is right for both. A third of the current cache is
//     a third of it either way.
//   * How much to shed is decided in BYTES, because the budget is bytes: one
//     large cold entry can cover an overshoot that would take several small
//     ones, and a count of files would not see that.
//
// The result is management rather than eviction: an overshoot of a few hundred
// kilobytes costs a few cold entries, not the whole cache.

/// The three tiers, coldest first — the unit of the user's own choice: the UI
/// shows what each holds (when it was generated, what it weighs) and lets them
/// decide which may be spent, which is the difference between a policy applied to
/// someone and a policy offered to them.
enum ThumbCacheTier { cold, warm, fresh }

/// What the user asked the cache to do. THREE intents that cannot be combined —
/// which is the whole point of a sealed type here: the record this replaces carried
/// four fields for three mutually exclusive meanings, so `clearAll: true` together
/// with a tier list was expressible and meaningless. Now the caller does not read
/// fields and guess; it matches, and the analyzer checks the cases.
sealed class ThumbCacheIntent {
  const ThumbCacheIntent();
}

/// Delete every entry.
final class ClearAll extends ThumbCacheIntent {
  const ClearAll();
}

/// Delete these tiers WHOLE: no budget, no veto — a row's own delete.
final class DeleteTiers extends ThumbCacheIntent {
  final Set<ThumbCacheTier> tiers;
  const DeleteTiers(this.tiers);
}

/// The default strategy: coldest entries first, down to [targetMb] (`0` = the
/// platform's default budget).
final class AutoTrim extends ThumbCacheIntent {
  final int targetMb;
  const AutoTrim(this.targetMb);
}

/// Every tier — the default, "manage it for me, down to the budget".
const Set<ThumbCacheTier> kAllThumbCacheTiers = {
  ThumbCacheTier.cold,
  ThumbCacheTier.warm,
  ThumbCacheTier.fresh,
};

/// One cached entry, as the policy sees it. [name] is opaque — it is only used
/// to name the answer, so callers can delete exactly those files.
class ThumbCacheEntry {
  /// Opaque identity (the cache file's name).
  final String name;

  /// When this entry was generated — the file's write time.
  final DateTime generatedAt;

  /// When it was last READ, or null when nothing recorded a read.
  ///
  /// The second axis, and the one that says whether an entry is HOT: an old
  /// thumbnail somebody looked at yesterday is worth more than a newer one nobody
  /// has ever opened. Deliberately a separate field from [generatedAt] — a read
  /// must never be written back into the generation time, or the axis that makes
  /// the grading stable would be destroyed by using the cache.
  final DateTime? lastUsedAt;

  final int bytes;

  const ThumbCacheEntry({
    required this.name,
    required this.generatedAt,
    this.lastUsedAt,
    required this.bytes,
  });
}

/// The tiers the cache was graded into, and what the policy chose to drop.
class ThumbCachePlan {
  /// Names to delete, coldest first — the order they should go in.
  final List<String> drop;

  /// The newest third of the entries: what a session is most likely showing.
  /// Dropped only when everything colder is not enough (see [planThumbCache]).
  final List<String> fresh;

  /// The middle third.
  final List<String> warm;

  /// The oldest third.
  final List<String> cold;

  /// Bytes the plan leaves behind, and bytes it removes.
  final int keptBytes;
  final int droppedBytes;

  /// What each tier WEIGHS, so the grading can be shown rather than asserted.
  /// A tier's entries are counted by `graded`; these are the bytes behind them.
  final int coldBytes;
  final int warmBytes;
  final int freshBytes;

  /// Where the cold and warm tiers END — the newest generation time in each, i.e.
  /// the two cut points. `generatedAt <= coldUpTo` is cold, `<= warmUpTo` is warm,
  /// later is fresh. Null when that tier is empty.
  ///
  /// This is what makes the heuristic legible in the UI: a boundary a user can
  /// read as a date, rather than a rule they have to take on faith.
  final DateTime? coldUpTo;
  final DateTime? warmUpTo;

  /// The most recent READ in each tier, or null when nothing in that tier has an
  /// access record. The second axis, and the one the user is shown beside the
  /// age: "generated 2 months ago" and "last opened 3 days ago" are two different
  /// facts, and it is the second one that says whether a tier is really cold.
  final DateTime? coldUsedAt;
  final DateTime? warmUsedAt;
  final DateTime? freshUsedAt;

  /// Bytes a cache of exactly [graded] entries occupied before the plan.
  int get totalBytes => keptBytes + droppedBytes;

  const ThumbCachePlan({
    required this.drop,
    required this.fresh,
    required this.warm,
    required this.cold,
    required this.keptBytes,
    required this.droppedBytes,
    this.coldBytes = 0,
    this.warmBytes = 0,
    this.freshBytes = 0,
    this.coldUpTo,
    this.warmUpTo,
    this.coldUsedAt,
    this.warmUsedAt,
    this.freshUsedAt,
  });

  bool get isEmpty => drop.isEmpty;

  /// Entries in the cache — the tiers, counted even when nothing is dropped.
  int get graded => fresh.length + warm.length + cold.length;
}

/// Grade [entries] and choose what to drop so that at most [maxBytes] remain.
///
/// The grading is a SCORE, not an age, because age alone cannot tell a hot entry
/// from a dead one: a thumbnail generated three years ago and opened yesterday is
/// worth more than one generated last week that nobody has ever opened. Three
/// features go into it, and each is normalised by the MEDIAN OF THIS CACHE — so
/// nothing is asserted from outside, and a cache whose entries are all recent is
/// still graded relative to itself:
///
///   * last use (weight 3) — `lastUsedAt`, falling back to `generatedAt` when no
///     read was ever recorded: "never opened" means we know only when it was
///     made, and pretending otherwise would invent evidence;
///   * generation time (weight 1) — the stable axis, because nothing rewrites it
///     (a read records the access separately, on purpose);
///   * size (weight -2) — a large entry is worth more reclaimed, but cannot
///     outvote a recent read.
///
/// Those weights ARE the algorithm; they are not thresholds. Every boundary — the
/// tier cuts and the shed order — comes out of the distribution those weights
/// produce for the cache at hand. The tiers are terciles of the SCORE order, so
/// the coldest third of this cache is cold whatever its calendar ages are, and
/// the shedding walks them coldest-scoring first. Ties break by name, so the
/// answer is deterministic.
ThumbCachePlan planThumbCache(
  List<ThumbCacheEntry> entries, {

  /// The byte budget a size-targeted clean-up aims at. OPTIONAL because the other
  /// intent — [dropWholeTiers] — has no use for it, and a required parameter that
  /// one of two callers must pass and ignore is a lie about the signature.
  int? maxBytes,
  Set<ThumbCacheTier> spend = kAllThumbCacheTiers,
  bool dropWholeTiers = false,
  DateTime? now,
}) {
  final at = now ?? DateTime.now();
  // Floors of a minute and a byte: a cache generated entirely in this instant
  // would otherwise give every ratio a zero denominator. These are units, not
  // thresholds — nothing about the grading depends on their value.
  final medUsed = _atLeastOne(
    _medianOf([
      for (final e in entries) _ageMinutes(at, e.lastUsedAt ?? e.generatedAt),
    ]),
  );
  final medGen = _atLeastOne(
    _medianOf([for (final e in entries) _ageMinutes(at, e.generatedAt)]),
  );
  final medBytes = _atLeastOne(_medianOf([for (final e in entries) e.bytes]));

  /// What this entry is worth KEEPING, higher being hotter. Relative, so every
  /// value here is comparable only within one call — which is all the grading
  /// ever needs (`_tiersByScore` below).
  double keepScore(ThumbCacheEntry e) {
    final used = _ageMinutes(at, e.lastUsedAt ?? e.generatedAt);
    final generated = _ageMinutes(at, e.generatedAt);
    final hot = medUsed / (used + medUsed); // → 1 as it is used now
    final fresh = medGen / (generated + medGen); // → 1 as it is generated now
    final cost = e.bytes / (e.bytes + medBytes); // → 1 as it gets large
    return 3 * hot + fresh - 2 * cost;
  }

  // Scores are computed ONCE per entry, not once per comparison. `sort` calls its
  // comparator O(n log n) times, and this cache can hold a hundred thousand
  // entries: 1.7 million identical median divisions to order them is work the
  // algorithm never needed to do. Same answer, one pass over the entries.
  final scored = [for (final e in entries) (entry: e, score: keepScore(e))]
    ..sort((a, b) {
      final byScore = a.score.compareTo(b.score);
      return byScore != 0 ? byScore : a.entry.name.compareTo(b.entry.name);
    });
  final sorted = [for (final s in scored) s.entry];

  final total = sorted.fold<int>(0, (sum, e) => sum + e.bytes);
  // Where the tiers are separated: the two largest STEPS in the score order, when
  // those steps are significant against this cache's own typical step — so the
  // boundaries follow the clusters the cache actually has, and a cache with no
  // shape keeps the equal thirds it always had. See `_tierCuts`.
  final (coldEnd, warmEnd) = _tierCuts(scored);
  final coldRun = sorted.sublist(0, coldEnd);
  final warmRun = sorted.sublist(coldEnd, warmEnd);
  final freshRun = sorted.sublist(warmEnd);

  var kept = total;
  final drop = <String>[];
  void shed(List<ThumbCacheEntry> run) {
    for (final e in run) {
      // Two intents, one walk. With [dropWholeTiers] the SELECTION is the whole
      // decision: the tier the user ticked goes entirely, and the budget gets no
      // veto — that is what "a row's delete removes that tier whole" has to mean,
      // or the button is a suggestion. Without it the walk stops as soon as the
      // budget is
      // met, which is the size-targeted clean-up `maxBytes` describes.
      if (!dropWholeTiers && kept <= (maxBytes ?? total)) return;
      drop.add(e.name);
      kept -= e.bytes;
    }
  }

  // Only the tiers the caller allows are spent, coldest first, and still only as
  // far as the budget: a user who spends the cold tier alone gets the cold tier
  // alone, even when that leaves the cache over budget — their call, not the
  // policy's.
  if (spend.contains(ThumbCacheTier.cold)) shed(coldRun);
  if (spend.contains(ThumbCacheTier.warm)) shed(warmRun);
  if (spend.contains(ThumbCacheTier.fresh)) shed(freshRun);

  return ThumbCachePlan(
    drop: drop,
    fresh: [for (final e in freshRun) e.name],
    warm: [for (final e in warmRun) e.name],
    cold: [for (final e in coldRun) e.name],
    keptBytes: kept,
    droppedBytes: total - kept,
    coldBytes: _sum(coldRun),
    warmBytes: _sum(warmRun),
    freshBytes: _sum(freshRun),
    // The newest GENERATION time in each tier — not `last`, which under score
    // ordering is merely the highest-scoring entry and says nothing about age.
    coldUpTo: _newestGenerated(coldRun),
    warmUpTo: _newestGenerated(warmRun),
    coldUsedAt: _newestUsed(coldRun),
    warmUsedAt: _newestUsed(warmRun),
    freshUsedAt: _newestUsed(freshRun),
  );
}

int _sum(List<ThumbCacheEntry> run) =>
    run.fold<int>(0, (sum, e) => sum + e.bytes);

/// How many times the typical gap a step must be to count as a boundary.
const double _gapSignificance = 2.0;

/// Below this many entries there is no shape to read: three points are three
/// points, and equal thirds is the honest answer.
const int _minEntriesForGaps = 6;

/// Where the three tiers are separated, as indices into the SCORE-ordered list.
///
/// The boundaries are the two largest gaps in that order — the places this cache's
/// own scores step down hardest. A library whose entries fall into three
/// generations is therefore cut BETWEEN them rather than through the middle of one,
/// which is the difference between a boundary the user can recognise and one they
/// have to take on faith.
///
/// A gap only counts as a boundary when it is [_gapSignificance] times the MEDIAN
/// gap of the same cache: a relative test, so nothing is asserted from outside, and
/// a cache whose scores are evenly spread keeps equal thirds — the rule this
/// replaces, and still the right answer when there is nothing to read.
(int, int) _tierCuts(List<({ThumbCacheEntry entry, double score})> ordered) {
  final n = ordered.length;
  final third = n ~/ 3;
  if (n < _minEntriesForGaps) return (third, third * 2);

  final gaps = [
    for (var i = 1; i < n; i++) ordered[i].score - ordered[i - 1].score,
  ];
  final median = _medianDouble(gaps);
  if (median <= 0) return (third, third * 2); // nothing steps at all

  // The two largest, tracked in one pass.
  var best = -1;
  var bestGap = 0.0;
  var next = -1;
  var nextGap = 0.0;
  for (var i = 1; i < n; i++) {
    final gap = gaps[i - 1];
    if (gap > bestGap) {
      next = best;
      nextGap = bestGap;
      best = i;
      bestGap = gap;
    } else if (gap > nextGap) {
      next = i;
      nextGap = gap;
    }
  }

  // Both cuts must be real boundaries AND interior: a cut at either end would make
  // an empty tier, and an empty tier is not a tier.
  final significant =
      bestGap >= median * _gapSignificance &&
      nextGap >= median * _gapSignificance;
  final interior = best >= 1 && best <= n - 2 && next >= 1 && next <= n - 2;
  if (!significant || !interior || best == next) return (third, third * 2);

  return best < next ? (best, next) : (next, best);
}

double _medianDouble(List<double> values) {
  if (values.isEmpty) return 0;
  final sorted = [...values]..sort();
  final mid = sorted.length ~/ 2;
  return sorted.length.isOdd
      ? sorted[mid]
      : (sorted[mid - 1] + sorted[mid]) / 2;
}

/// Minutes since [when], never negative: a cache written by a clock that is ahead
/// of ours must not produce a negative age (it would score as hotter than an
/// entry generated now).
int _ageMinutes(DateTime at, DateTime when) {
  final minutes = at.difference(when).inMinutes;
  return minutes < 0 ? 0 : minutes;
}

int _medianOf(List<int> values) {
  if (values.isEmpty) return 0;
  final sorted = [...values]..sort();
  final mid = sorted.length ~/ 2;
  return sorted.length.isOdd
      ? sorted[mid]
      : ((sorted[mid - 1] + sorted[mid]) / 2).round();
}

int _atLeastOne(int value) => value < 1 ? 1 : value;

DateTime? _newestGenerated(List<ThumbCacheEntry> run) {
  DateTime? newest;
  for (final e in run) {
    if (newest == null || e.generatedAt.isAfter(newest)) newest = e.generatedAt;
  }
  return newest;
}

/// The newest ACCESS in [run] — null when nothing there was ever read, which is
/// not the same as "read long ago" and must not be displayed as if it were.
DateTime? _newestUsed(List<ThumbCacheEntry> run) {
  DateTime? newest;
  for (final e in run) {
    final used = e.lastUsedAt;
    if (used == null) continue;
    if (newest == null || used.isAfter(newest)) newest = used;
  }
  return newest;
}

/// The sizes Auto trim can aim for, in MB; `0` is the platform default.
///
/// Here rather than in the dialog: these are PRODUCT values — what the app offers
/// to trim to — and the view layer is where they are shown, not where they are
/// decided. Same layer as [thumbCacheBudgetBytes], which turns one of them into
/// bytes.
const List<int> kThumbCacheLimitChoices = [0, 64, 256, 1024];

String thumbCacheLimitLabel(int mb) => switch (mb) {
  0 => 'Default',
  1024 => '1 GB',
  _ => '$mb MB',
};

/// The cache's own budget: mobile keeps less, because its private cache counts
/// against a tighter app-storage allowance.
///
/// [limitMb] is the USER'S setting, and one number carries the whole decision:
/// `0` (the default) is this platform's budget, `>0` is that many MB regardless
/// of platform, and a negative value means the same as `0` here — "off" is not a
/// budget at all, it is the absence of automatic management, which the caller
/// decides (see `ThumbCache.write`).
int thumbCacheBudgetBytes({required bool isMobile, int limitMb = 0}) =>
    limitMb > 0
    ? limitMb * 1024 * 1024
    : (isMobile ? 96 * 1024 * 1024 : 512 * 1024 * 1024);

/// How long ago [generatedAt] was, in the units a person reads: minutes, hours,
/// days, months, years.
///
/// Deliberately NOT a date. A tier boundary answers "how old is this?", and a
/// calendar date makes the reader subtract two dates to find out; the age is the
/// answer, so it is what gets shown.
String describeAge(DateTime generatedAt, {required DateTime now}) {
  final elapsed = now.difference(generatedAt);
  if (elapsed.inMinutes < 1) return 'just now';
  if (elapsed.inMinutes < 60) return _ago(elapsed.inMinutes, 'min');
  if (elapsed.inHours < 24) return _ago(elapsed.inHours, 'hour');
  if (elapsed.inDays < 30) return _ago(elapsed.inDays, 'day');
  if (elapsed.inDays < 365) return _ago(elapsed.inDays ~/ 30, 'month');
  return _ago(elapsed.inDays ~/ 365, 'year');
}

String _ago(int n, String unit) => n == 1 ? '1 $unit ago' : '$n ${unit}s ago';

///
/// [formatBytes] exists so this file owns no byte formatting of its own —
/// `ThumbCache.human` already does, and the two would drift.
String describeThumbCachePlan(
  ThumbCachePlan plan, {
  String Function(int bytes)? formatBytes,
}) {
  final show = formatBytes ?? (int b) => '$b B';
  if (plan.graded == 0) return 'cache is empty';
  if (plan.isEmpty) {
    return 'kept all ${plan.graded} (${show(plan.keptBytes)})';
  }
  return 'dropped ${plan.drop.length} of ${plan.graded} '
      '(${show(plan.droppedBytes)}): ${plan.cold.length} cold, '
      '${plan.warm.length} warm, ${plan.fresh.length} fresh kept';
}
