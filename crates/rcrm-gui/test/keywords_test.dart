// test/keywords_test.dart
// The automatic keywords, the library index and the ranking they feed.
//
// The point of these tests is not that a particular file name produces a
// particular tag (that is a heuristic), but that the rules which make tags
// USEFUL hold: technical release noise never becomes a tag, a repeated tag
// becomes a channel and a one-off does not, and the relevance setting really
// changes what Related offers.

import 'package:flutter_test/flutter_test.dart';

import 'package:rcrm_gui/models/media_item.dart';
import 'package:rcrm_gui/utils/keywords.dart';
import 'package:rcrm_gui/utils/related_videos.dart';

MediaItem _video(String name, {String folder = ''}) => MediaItem(
  name: folder.isEmpty ? name : '$folder/$name',
  path: folder.isEmpty ? '/$name' : '/$folder/$name',
  url: 'http://127.0.0.1:18443/${folder.isEmpty ? '' : '$folder/'}$name',
  type: MediaType.video,
  size: 1024,
  modified: DateTime(2024, 1, 1),
  albumName: folder,
);

List<String> _keys(KeywordSet set) => [for (final t in set.tags) t.key];

void main() {
  group('keyword extraction', () {
    test('release and technical noise never becomes a tag', () {
      final set = KeywordExtractor().forItem(
        _video('Amateur.Couple.2023.1080p.WEB-DL.x264-GROUP.mp4'),
      );
      final keys = _keys(set);
      expect(keys, containsAll(['amateur', 'couple']));
      for (final noise in ['2023', '1080p', 'web', 'dl', 'x264', 'group']) {
        expect(keys, isNot(contains(noise)), reason: noise);
      }
    });

    test('Chinese runs keep their words and drop subtitle/quality markers', () {
      final set = KeywordExtractor().forItem(_video('国产剧情 中文字幕 高清.mp4'));
      final keys = _keys(set);
      expect(keys, containsAll(['国产剧情', '国产', '剧情']));
      expect(keys, isNot(contains('中文字幕')));
      expect(keys, isNot(contains('高清')));
    });

    test('one file keeps every meaningful word as its own tag', () {
      final set = KeywordExtractor().forItem(
        _video('amateur couple studio.mp4'),
      );
      expect(_keys(set), containsAll(['amateur', 'couple', 'studio']));
    });

    test('the folder is a weaker tag than the file name', () {
      final fromFolder = KeywordExtractor().forItem(
        _video('clip.mp4', folder: 'Documentary'),
      );
      expect(_keys(fromFolder), contains('documentary'));

      final named = KeywordExtractor().forItem(
        _video('Amateur.mp4', folder: 'Documentary'),
      );
      expect(
        named.weightOf('amateur'),
        greaterThan(named.weightOf('documentary')),
      );
    });
  });

  group('library index', () {
    final a = _video('amateur couple.mp4');
    final b = _video('amateur solo.mp4');
    final c = _video('solo.mp4');
    final d = _video('cooking show.mp4');
    final index = KeywordIndex.build([a, b, c, d]);

    test('only repeated tags become filters and channels', () {
      final keys = [for (final t in index.topTags) t.key];
      expect(keys, containsAll(['amateur', 'solo']));
      expect(keys, isNot(contains('couple')));
      expect(index.countFor('amateur'), 2);
      expect(index.countFor('couple'), 1);
    });

    test('a channel carries its videos and its full count', () {
      final channels = index.channels(minItems: 2, max: 3);
      expect(channels.map((c) => c.tag.key).toSet(), {'amateur', 'solo'});
      final amateur = channels.firstWhere((c) => c.tag.key == 'amateur');
      expect(amateur.itemCount, 2);
      expect(amateur.items.map((v) => v.path), containsAll([a.path, b.path]));
    });

    test('related tags are the co-occurring ones, never the selected one', () {
      final related = index.relatedTags({'amateur'});
      final keys = [for (final tag in related) tag.key];
      expect(keys, containsAll(['couple', 'solo']));
      expect(keys, isNot(contains('amateur')));
      expect(index.relatedTags({'amateur', 'couple'}), isEmpty);
    });

    test('similarity is symmetric and zero without shared tags', () {
      final left = index.setFor(a.path);
      final right = index.setFor(b.path);
      final unrelated = index.setFor(d.path);
      expect(left.similarityTo(right), greaterThan(0));
      expect(
        left.similarityTo(right),
        closeTo(right.similarityTo(left), 0.0001),
      );
      expect(left.similarityTo(unrelated), 0);
    });
  });

  group('relevance', () {
    final current = _video('amateur couple.mp4', folder: 'Shows');
    final neighbour = _video('unrelated thing.mp4', folder: 'Shows');
    final tagged = _video('amateur couple 2.mp4', folder: 'Elsewhere');
    final all = [current, neighbour, tagged];
    final index = KeywordIndex.build(all);

    test('0 keeps the folder neighbour first', () {
      final list = relatedFor(current, all, keywords: index, relevance: 0);
      expect(list.first.path, neighbour.path);
    });

    test('100 lets a strong tag match outrank the folder neighbour', () {
      final list = relatedFor(current, all, keywords: index, relevance: 100);
      expect(list.first.path, tagged.path);
    });

    test('a day-seeded recommendation follows the recent tags', () {
      final picks = keywordRecommendations(
        index,
        all,
        recent: [current],
        daySeed: 7,
        relevance: 100,
      );
      expect(picks.first.path, tagged.path);
    });
  });
}
