// test/shuffle_next_test.dart
// What `Shuffle` draws when a file ends, as a pure function: a uniform pick from
// the RELATED list.
//
// It is tested here for the reason `related_videos_test.dart` gives about its
// own rule: the screen — the only caller — creates a real media_kit `Player` in
// its first frame, so it cannot be mounted in a widget test. The draw owns none
// of the list's rules (those are `relatedFor`'s, tested there); it owns the
// pick: uniform, never null on a non-empty list, and reproducible under a seed.

import 'dart:math';

import 'package:flutter_test/flutter_test.dart';

import 'package:rcrm_gui/models/media_item.dart';
import 'package:rcrm_gui/utils/related_videos.dart';
import 'package:rcrm_gui/utils/shuffle_next.dart';

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

void main() {
  final current = _video('ep1.mp4', dir: 'shows');
  final siblings = [
    _video('ep2.mp4', dir: 'shows'),
    _video('ep3.mkv', dir: 'shows'),
    _video('a.mp4', dir: 'movies'),
    _video('b.mkv', dir: 'movies'),
  ];

  test('draws from the Related list, and only from it', () {
    // The draw is handed the list, so this is almost tautological — but the
    // guarantee the mode rests on is that the card never offers a video the
    // list refuses to show, and that holds for the random row too.
    final related = relatedFor(current, [current, ...siblings]);
    final rng = Random(7);
    final listed = {for (final v in related) v.path};
    for (var i = 0; i < 200; i++) {
      expect(listed, contains(shuffledPick(related, rng: rng)!.path));
    }
  });

  test('can reach every row of the list, and nothing else', () {
    // Loop All always plays the top row; Shuffle's whole point is the other
    // rows. Over enough draws every row must come up — and no row outside the
    // list can, which is what keeps the card's promise true for a random offer.
    final related = relatedFor(current, [current, ...siblings]);
    final rng = Random(3);
    final seen = <String>{};
    for (var i = 0; i < 400; i++) {
      seen.add(shuffledPick(related, rng: rng)!.path);
    }
    expect(seen, {for (final v in related) v.path});
  });

  test('an empty list is null, not an error', () {
    // A library of one video: the Related list is empty, there is no next one,
    // and the caller must be able to tell that apart from "here is the next
    // one".
    expect(shuffledPick(const [], rng: Random(1)), isNull);
  });

  test('the seed decides the draw, so a failure can be reproduced', () {
    // The whole point of injecting `rng`: a test that cannot re-run the draw
    // that failed is a test that can only say "something, somewhere, went
    // wrong".
    final a = shuffledPick(siblings, rng: Random(42));
    final b = shuffledPick(siblings, rng: Random(42));
    expect(a!.path, b!.path);
  });
}
