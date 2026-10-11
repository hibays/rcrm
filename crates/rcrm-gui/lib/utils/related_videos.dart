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
/// The order is a URL-seeded Fisher-Yates shuffle followed by a stable
/// priority (same directory, then same extension, then the rest). The shuffle
/// runs BEFORE the exclusions are applied, which is deliberate: for a given
/// (url, candidate set) the shuffle — and therefore the relative order of the
/// survivors — is unchanged by *which* entries are excluded. Excluding an entry
/// can only drop it, or promote one that the [kRelatedMax] cap had cut off; it
/// can never re-order the rows that remain.
List<MediaItem> relatedFor(
  MediaItem vid,
  List<MediaItem> allVideos, {
  Set<String> excludePaths = const {},
}) {
  final dir = vid.name.contains('/')
      ? vid.name.substring(0, vid.name.lastIndexOf('/') + 1)
      : '';
  final rng = Random(relatedSeedFor(vid.url));

  final all = allVideos.where((v) => v.path != vid.path).toList();

  // Fisher-Yates shuffle with the URL-seeded RNG.
  for (var i = all.length - 1; i > 0; i--) {
    final j = rng.nextInt(i + 1);
    final tmp = all[i];
    all[i] = all[j];
    all[j] = tmp;
  }

  // Stable priority: same-directory first, then same-extension, then rest.
  // The exclusions are dropped here, so each bucket keeps the shuffled relative
  // order of what is left in it.
  final sameDir = <MediaItem>[];
  final sameExt = <MediaItem>[];
  final rest = <MediaItem>[];
  for (final v in all) {
    if (excludePaths.contains(v.path)) continue;
    final vDir = v.name.contains('/')
        ? v.name.substring(0, v.name.lastIndexOf('/') + 1)
        : '';
    if (vDir == dir && dir.isNotEmpty) {
      sameDir.add(v);
    } else if (v.extension == vid.extension) {
      sameExt.add(v);
    } else {
      rest.add(v);
    }
  }
  return [...sameDir, ...sameExt, ...rest].take(kRelatedMax).toList();
}
