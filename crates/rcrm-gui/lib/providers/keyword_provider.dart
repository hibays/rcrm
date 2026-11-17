// providers/keyword_provider.dart
// RCrm GUI — the library's automatic keywords, tag filter and channels.
//
// The pure work lives in `utils/keywords.dart`; this file is the reactive layer:
// it builds the index from the scanned list, remembers which tag the video tab
// is filtering by, and derives the Home tab's keyword channels and its
// Recommended row.

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../models/media_item.dart';
import '../utils/keywords.dart';
import 'library_provider.dart';
import 'settings_provider.dart';

/// Kept alive for the whole session so tokenisation survives scan batches.
final keywordExtractorProvider = Provider<KeywordExtractor>(
  (_) => KeywordExtractor(),
);

/// The whole library's tags, rebuilt as the scanned list grows.
final keywordIndexProvider = Provider<KeywordIndex>((ref) {
  final videos = ref.watch(videosListProvider);
  final extractor = ref.watch(keywordExtractorProvider);
  return KeywordIndex.build(videos, extractor: extractor);
});

/// The tags the video tab is filtered by. EMPTY means every video.
///
/// Session state, not a preference: it belongs to the view the user is in, and a
/// relaunch should open the library, not yesterday's filter. Multi-select is
/// deliberate — a file carries several tags, and several selected tags narrow
/// to the files that carry ALL of them (the chips are filters, not radio
/// buttons).
class VideoTagFilterNotifier extends Notifier<Set<String>> {
  @override
  Set<String> build() => const <String>{};

  /// Add or remove one tag. A new set every time so Riverpod sees the change.
  void toggle(String tag) {
    final next = Set<String>.of(state);
    if (!next.remove(tag)) next.add(tag);
    state = Set<String>.unmodifiable(next);
  }

  /// Drop tags the current index no longer has (a re-scan retired them).
  void removeAll(Iterable<String> tags) {
    final next = Set<String>.of(state)..removeAll(tags);
    if (next.length != state.length) {
      state = Set<String>.unmodifiable(next);
    }
  }

  void clear() {
    if (state.isNotEmpty) state = const <String>{};
  }
}

final videoTagFilterProvider =
    NotifierProvider<VideoTagFilterNotifier, Set<String>>(
      VideoTagFilterNotifier.new,
    );

/// The toolbar's extension filter first, then the keyword filter — both are
/// properties of the list, and the tag bar's chip count has to agree with what
/// the grid is showing.
///
/// With several tags selected the match is ALL of them: a tag filter is a
/// narrowing action, so adding a second chip asks for the files that carry
/// both, never a union that grows as the user narrows.
final taggedVideosProvider = Provider<List<MediaItem>>((ref) {
  final videos = ref.watch(sortedVideosProvider);
  final tags = ref.watch(videoTagFilterProvider);
  if (tags.isEmpty) return videos;
  final index = ref.watch(keywordIndexProvider);
  return [
    for (final video in videos)
      if (tags.every((tag) => index.setFor(video.path).contains(tag))) video,
  ];
});

/// The Home tab's channels: the strongest repeated tags, each with its own row.
///
/// Two files make a tag a channel on purpose — a small library still gets a
/// section, and a tag that occurs once is a description, not a way to browse.
final keywordChannelsProvider = Provider<List<KeywordChannel>>((ref) {
  final index = ref.watch(keywordIndexProvider);
  return index.channels(minItems: 2, max: 3, perChannel: 12);
});

/// The Home tab's Recommended row. Public and day-seeded, like the row it
/// replaced; the ranking itself is `keywordRecommendations`.
final recommendedProvider = Provider.autoDispose.family<List<MediaItem>, int>((
  ref,
  daySeed,
) {
  final index = ref.watch(keywordIndexProvider);
  final videos = ref.watch(videosListProvider);
  final recent = ref.watch(recentVideosProvider);
  final relevance = ref.watch(
    uiSettingsProvider.select((s) => s.keywordRelevance),
  );
  return keywordRecommendations(
    index,
    videos,
    recent: recent,
    daySeed: daySeed,
    relevance: relevance,
  );
});
