// test/related_videos_test.dart
// The player's Related list, as a pure function: the jump stack's entries are
// excluded, and excluding them removes rows without reshuffling the ones that
// remain.
//
// This is the honest unit for the exclusion. The rule itself lives in
// `utils/related_videos.dart` precisely because the player screen — its only
// caller — cannot be mounted in a test (it creates a real media_kit `Player` in
// its first frame); the screen's part is passing
// `jumpExcludedPathsProvider` into it.

import 'package:flutter_test/flutter_test.dart';

import 'package:rcrm_gui/models/media_item.dart';
import 'package:rcrm_gui/utils/related_videos.dart';

MediaItem _video(String name, {String dir = ''}) {
  final where = dir.isEmpty ? name : '$dir/$name';
  return MediaItem(
    name: where,
    path: '/$where',
    url: 'http://127.0.0.1:18443/$where',
    type: MediaType.video,
    size: 1024,
    modified: DateTime(2024, 1, 1),
  );
}

List<String> _paths(List<MediaItem> items) => [for (final v in items) v.path];

/// The current video, two siblings in its folder, a same-extension video
/// elsewhere and four unrelated ones — every bucket the priority order uses.
final _current = _video('ep1.mp4', dir: 'shows');
final _candidates = <MediaItem>[
  _video('ep2.mp4', dir: 'shows'),
  _video('ep3.mkv', dir: 'shows'),
  _video('a.mp4', dir: 'movies'),
  _video('b.mkv', dir: 'movies'),
  _video('c.webm', dir: 'clips'),
  _video('ep4.mp4', dir: 'shows'),
  _video('d.mp4', dir: 'music'),
  _video('e.mp4', dir: 'misc'),
];

void main() {
  test('a video in the jump stack is never offered as related', () {
    final all = [_current, ..._candidates];
    final unfiltered = relatedFor(_current, all);
    expect(unfiltered, isNotEmpty);

    // Two videos that WOULD be offered — so the assertion below cannot pass
    // just because the shuffle happened to leave them out.
    final excluded = {unfiltered[0].path, unfiltered[2].path};
    expect(_paths(unfiltered), containsAll(excluded));

    final filtered = relatedFor(_current, all, excludePaths: excluded);
    for (final path in excluded) {
      expect(
        _paths(filtered),
        isNot(contains(path)),
        reason: 'a jump-stack entry must not appear in Related',
      );
    }
  });

  test('excluding entries removes rows without reshuffling the survivors', () {
    final all = [_current, ..._candidates];
    final unfiltered = relatedFor(_current, all);

    // Exclude videos that survive into the unfiltered result, so the two lists
    // really are the same candidates.
    final excluded = {
      unfiltered[1].path,
      unfiltered[3].path,
      unfiltered[5].path,
    };
    final filtered = relatedFor(_current, all, excludePaths: excluded);

    expect(_paths(filtered), [
      for (final p in _paths(unfiltered))
        if (!excluded.contains(p)) p,
    ]);
  });

  test('the same inputs always produce the same list', () {
    final all = [_current, ..._candidates];
    expect(
      _paths(relatedFor(_current, all)),
      _paths(relatedFor(_current, all)),
    );

    const excluded = {'/movies/a.mp4', '/clips/c.webm'};
    expect(
      _paths(relatedFor(_current, all, excludePaths: excluded)),
      _paths(relatedFor(_current, all, excludePaths: excluded)),
    );

    // And the exclusion is not a reshuffle button: adding an entry that is not
    // in the list cannot move the entries that are.
    final withoutOne = relatedFor(_current, all, excludePaths: excluded);
    final withoutTwo = relatedFor(
      _current,
      all,
      excludePaths: {...excluded, '/not/in/the/library.mp4'},
    );
    expect(_paths(withoutTwo), _paths(withoutOne));
  });

  test('the current video is never related to itself', () {
    final all = [_current, ..._candidates];
    expect(_paths(relatedFor(_current, all)), isNot(contains(_current.path)));
  });

  test(
    'same-directory videos come first, then same-extension, then the rest',
    () {
      final all = [_current, ..._candidates];
      final result = relatedFor(_current, all);
      expect(result, hasLength(_candidates.length));

      String dirOf(MediaItem v) => v.name.contains('/')
          ? v.name.substring(0, v.name.lastIndexOf('/') + 1)
          : '';
      final dir = dirOf(_current);
      final ranks = [
        for (final v in result)
          if (dirOf(v) == dir && dir.isNotEmpty)
            0
          else if (v.extension == _current.extension)
            1
          else
            2,
      ];
      for (var i = 1; i < ranks.length; i++) {
        expect(ranks[i], greaterThanOrEqualTo(ranks[i - 1]));
      }
      expect(ranks, containsAll([0, 1, 2]));
    },
  );

  test('excluding everything yields an empty list, not a fallback', () {
    final all = [_current, ..._candidates];
    final filtered = relatedFor(
      _current,
      all,
      excludePaths: {for (final v in all) v.path},
    );
    expect(filtered, isEmpty);
  });

  test('the list is capped at kRelatedMax, exclusions applied first', () {
    final many = [
      _current,
      for (var i = 0; i < 30; i++) _video('ep$i.mp4', dir: 'shows'),
    ];
    expect(relatedFor(_current, many), hasLength(kRelatedMax));

    final excluded = {
      for (final v in relatedFor(_current, many).take(5)) v.path,
    };
    final filtered = relatedFor(_current, many, excludePaths: excluded);
    expect(filtered, hasLength(kRelatedMax));
    for (final path in excluded) {
      expect(_paths(filtered), isNot(contains(path)));
    }
  });
}
