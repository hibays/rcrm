// utils/related_videos.dart
// The player's "Related" list, as a pure function.
//
// Lifted out of `screens/video_player_screen.dart` for one reason: the jump
// stack's entries (providers/video_jump_stack.dart) must be excluded from the
// list, and that rule has to be provable without a media_kit `Player` — the
// player screen creates a real one in its first frame, so it cannot be mounted
// in a widget test. The screen keeps the call and the caching; the algorithm
// lives here.

import 'dart:math';

import '../models/media_item.dart';
import 'keywords.dart';

/// Most rows the Related list ever shows.
const int kRelatedMax = 24;

/// Seed for the shuffle: a hash of the video's URL. The same video therefore
/// always produces the same order for the same candidate set, which is what
/// makes the list read as a property of the video rather than of the moment it
/// was opened.
int relatedSeedFor(String url) =>
    url.codeUnits.fold(0, (h, c) => ((h << 5) + h) ^ c);

/// Up to [kRelatedMax] videos related to [vid], drawn from [allVideos].
///
/// [vid] itself is never in the result, and neither is any video whose `path`
/// is in [excludePaths] — the caller passes the jump stack's paths, so the
/// videos `Back` can return to are not offered as something to jump to.
///
/// The order is a URL-seeded Fisher-Yates shuffle, then a score: same
/// directory (the pre-keyword priority), same extension, and — when a
/// [KeywordIndex] is supplied — shared tags weighted by [relevance].
///
/// The shuffle runs BEFORE the exclusions are applied, which is deliberate: for
/// a given (url, candidate set) the shuffle — and therefore the relative order
/// of the survivors — is unchanged by *which* entries are excluded. Excluding
/// an entry can only drop it, or promote one that the [kRelatedMax] cap had cut
/// off; it can never re-order the rows that remain.
///
/// [relevance] is 0..100. At 0 the keyword term is zero and the order is
/// exactly the old folder/extension order; at 100 a strong tag overlap can put
/// a video ahead of a folder neighbour. With no [keywords] the term is absent
/// wherever the value is, so callers that have no index keep the old behaviour.
List<MediaItem> relatedFor(
  MediaItem vid,
  List<MediaItem> allVideos, {
  Set<String> excludePaths = const {},
  KeywordIndex? keywords,
  int relevance = 60,
}) {
  final dir = vid.name.contains('/')
      ? vid.name.substring(0, vid.name.lastIndexOf('/') + 1)
      : '';
  final rng = Random(relatedSeedFor(vid.url));

  final all = allVideos.where((v) => v.path != vid.path).toList();

  // Fisher-Yates shuffle with the URL-seeded RNG. Its position is also the
  // tie-break below, so two files with equal scores stay in the stable order
  // this list has always had.
  for (var i = all.length - 1; i > 0; i--) {
    final j = rng.nextInt(i + 1);
    final tmp = all[i];
    all[i] = all[j];
    all[j] = tmp;
  }

  final current = keywords?.setFor(vid.path);
  final influence = relevance.clamp(0, 100) / 100.0;
  final scored = <({MediaItem item, double score, int order})>[];
  for (var i = 0; i < all.length; i++) {
    final v = all[i];
    if (excludePaths.contains(v.path)) continue;
    final vDir = v.name.contains('/')
        ? v.name.substring(0, v.name.lastIndexOf('/') + 1)
        : '';
    var score = 0.0;
    if (vDir == dir && dir.isNotEmpty) score += 0.55;
    if (v.extension == vid.extension) score += 0.15;
    if (current != null && keywords != null && influence > 0) {
      final other = keywords.setFor(v.path);
      score += current.similarityTo(other) * 2.5 * influence;
    }
    scored.add((item: v, score: score, order: i));
  }

  scored.sort((a, b) {
    final byScore = b.score.compareTo(a.score);
    if (byScore != 0) return byScore;
    return a.order.compareTo(b.order);
  });
  return scored.take(kRelatedMax).map((s) => s.item).toList();
}
