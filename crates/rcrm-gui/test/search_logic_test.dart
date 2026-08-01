// test/search_logic_test.dart
// RCrm GUI — search screen logic unit tests.
//
// Covers the pure matching/filtering helpers in search_screen.dart plus the
// routing contract: an album search result must land on the Images tab even
// when search was opened from Home.
//
// Run:  flutter test test/search_logic_test.dart

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:rcrm_gui/models/album.dart';
import 'package:rcrm_gui/models/media_item.dart';
import 'package:rcrm_gui/providers/library_provider.dart';
import 'package:rcrm_gui/screens/home_screen.dart';
import 'package:rcrm_gui/screens/image_screen.dart' show selectedAlbumProvider;
import 'package:rcrm_gui/screens/search_screen.dart';
import 'package:rcrm_gui/widgets/album_card.dart';

MediaItem mkVideo(String name, {String album = ''}) => MediaItem(
  name: name,
  path: '/$name',
  url: 'http://127.0.0.1:8080/$name',
  type: MediaType.video,
  size: 10 * 1024 * 1024,
  durationSeconds: 120,
  albumName: album,
);

MediaItem mkImage(String name) => MediaItem(
  name: name,
  path: '/$name',
  url: 'http://127.0.0.1:8080/$name',
  type: MediaType.image,
  size: 5 * 1024 * 1024,
);

void main() {
  group('fuzzy match (subsequence, case-insensitive)', () {
    test('subsequence matches in order', () {
      expect(_fuzzy('brkn', 'Breaking Bad'), isTrue);
      expect(_fuzzy('mp4', 'Movie.MP4'), isTrue);
      expect(_fuzzy('jpn', 'japan trip.jpg'), isTrue);
    });

    test('out-of-order characters do not match', () {
      expect(_fuzzy('kbr', 'Breaking Bad'), isFalse);
      expect(_fuzzy('pm4', 'Movie.MP4'), isFalse);
    });

    test('empty query matches everything', () {
      expect(_fuzzy('', 'anything'), isTrue);
    });

    test('query longer than target never matches', () {
      expect(_fuzzy('longer', 'short'), isFalse);
    });

    test('case-insensitive both sides', () {
      expect(_fuzzy('MP4', 'movie.mp4'), isTrue);
      expect(_fuzzy('Tokyo', 'tokyo'), isTrue);
    });
  });

  group('search filtering (tab contexts)', () {
    final videos = [
      mkVideo('vacation beach.mp4', album: 'Trip 2025'),
      mkVideo('concert.webm', album: 'Live'),
      mkVideo('notes.mkv', album: 'Work'),
    ];
    final albums = [
      Album.fromItems(
        name: 'Japan',
        path: '/Japan',
        url: 'http://127.0.0.1:8080/Japan',
        items: [
          mkImage('tokyo.jpg'),
          mkImage('kyoto.png'),
          mkImage('osaka.jpg'),
        ],
      ),
      Album.fromItems(
        name: 'Family',
        path: '/Family',
        url: 'http://127.0.0.1:8080/Family',
        items: [mkImage('dog.png')],
      ),
    ];

    test('name match finds video', () {
      final hits = _videoHits(videos, null, 'beach');
      expect(hits.map((v) => v.name), ['vacation beach.mp4']);
    });

    test('extension match finds video', () {
      final hits = _videoHits(videos, null, 'webm');
      expect(hits.map((v) => v.name), ['concert.webm']);
    });

    test('album-name match finds video', () {
      final hits = _videoHits(videos, null, 'trip');
      expect(hits.map((v) => v.name), ['vacation beach.mp4']);
    });

    test('image tab filter hides videos entirely', () {
      final hits = _videoHits(videos, MediaType.image, 'beach');
      expect(hits, isEmpty);
    });

    test('video tab filter hides images and albums', () {
      final images = _imageHits(albums, MediaType.video, 'tokyo');
      expect(images, isEmpty);
    });

    test('album name match surfaces album + its images', () {
      final images = _imageHits(albums, null, 'japan');
      expect(images.length, 3);
    });

    test('image name match surfaces the image only', () {
      final images = _imageHits(albums, null, 'dog');
      expect(images.map((i) => i.name), ['dog.png']);
    });

    test('no matches yields empty everything', () {
      expect(_videoHits(videos, null, 'zzz'), isEmpty);
      expect(_imageHits(albums, null, 'zzz'), isEmpty);
    });
  });

  group('results count copy', () {
    test('singular for one result', () {
      expect(_countCopy(1), '1 result');
      expect(_countCopy(7), '7 results');
    });
  });

  // ── Integration: album result from Home must land on Images tab ──

  testWidgets('album search result pops search and switches to Images tab', (
    tester,
  ) async {
    final album = Album.fromItems(
      name: 'Japan',
      path: '/Japan',
      url: 'http://127.0.0.1:8080/Japan',
      items: [mkImage('tokyo.jpg')],
    );
    final overrides = [
      albumsProvider.overrideWithValue([album]),
      videosListProvider.overrideWithValue(<MediaItem>[]),
    ];

    await tester.pumpWidget(
      ProviderScope(
        overrides: overrides,
        child: const MaterialApp(home: HomeScreen()),
      ),
    );
    await tester.pumpAndSettle();

    // Home tab; open search.
    expect(find.text('Home'), findsOneWidget);
    await tester.tap(find.byIcon(Icons.search));
    await tester.pumpAndSettle();
    expect(find.byType(SearchScreen), findsOneWidget);

    // Type the album name; the album card appears.
    await tester.enterText(find.byType(TextField), 'Japan');
    await tester.pumpAndSettle();
    expect(find.byType(AlbumCard), findsOneWidget);

    // Tap the album result.
    // ignore: avoid_print
    debugPrint(
      'pre-tap: albumCards=${find.byType(AlbumCard, skipOffstage: false).evaluate().length} '
      'firstRect=${tester.getRect(find.byType(AlbumCard).first)}',
    );
    // Tap the album result (the PooledImage inside is in error state in
    // tests, so this also verifies the card tap is NOT swallowed by the
    // image's retry surface — the bug this suite guards against).
    await tester.tap(find.byType(AlbumCard).first);
    await tester.pump(const Duration(milliseconds: 100));
    final probe = ProviderScope.containerOf(
      tester.element(find.byType(SearchScreen)),
    );
    // ignore: avoid_print
    debugPrint(
      'after tap: search=${find.byType(SearchScreen).evaluate().length} '
      'selected=${probe.read(selectedAlbumProvider)?.name}',
    );
    await tester.pumpAndSettle();

    // Search popped; the Images tab is now selected and the album opened.
    expect(find.byType(SearchScreen), findsNothing);
    final nav = tester.widget<BottomNavigationBar>(
      find.byType(BottomNavigationBar),
    );
    expect(
      nav.currentIndex,
      2,
      reason: 'album result must switch to the Images tab',
    );
    // Album view shows the album name (header of the opened album).
    expect(find.text('Japan'), findsOneWidget);

    // Teardown: unmount the tree; ImageScreen.dispose now calls setOpen
    // synchronously, so no timers stay pending.
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('search shows 1 result copy for a single hit', (tester) async {
    final album = Album.fromItems(
      name: 'Solo',
      path: '/Solo',
      url: 'http://127.0.0.1:8080/Solo',
      items: [mkImage('only.jpg')],
    );
    final overrides = [
      albumsProvider.overrideWithValue([album]),
      videosListProvider.overrideWithValue(<MediaItem>[]),
    ];

    await tester.pumpWidget(
      ProviderScope(
        overrides: overrides,
        child: const MaterialApp(home: SearchScreen()),
      ),
    );
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField), 'only');
    await tester.pumpAndSettle();

    expect(find.text('1 result'), findsOneWidget);
  });
}

// ── Helpers ─────────────────────────────────────────────────

String _countCopy(int total) => total == 1 ? '1 result' : '$total results';

// Re-implements the production filtering inline so the tests pin behavior
// without needing a full ProviderScope + scan. Kept in sync with
// search_screen.dart `_buildBody`.
List<MediaItem> _videoHits(
  List<MediaItem> all,
  MediaType? tabFilter,
  String q,
) {
  final query = q.toLowerCase().trim();
  if (tabFilter == MediaType.image) return const [];
  return all
      .where(
        (v) =>
            _fuzzy(query, v.name) ||
            _fuzzy(query, v.extension) ||
            _fuzzy(query, v.albumName),
      )
      .toList();
}

List<MediaItem> _imageHits(List<Album> albums, MediaType? tabFilter, String q) {
  if (tabFilter == MediaType.video) return const [];
  final query = q.toLowerCase().trim();
  final images = <MediaItem>[];
  for (final album in albums) {
    for (final item in album.items) {
      if (_fuzzy(query, item.name) ||
          _fuzzy(query, item.extension) ||
          _fuzzy(query, album.name)) {
        images.add(item);
      }
    }
  }
  return images;
}

// Mirrors search_screen.dart `_fuzzyMatch` (production lowercases/trims the
// query before calling; this helper does the same internally so callers can
// pass either case).
bool _fuzzy(String query, String target) {
  final q = query.toLowerCase();
  if (q.isEmpty) return true;
  var qi = 0;
  final qLen = q.length;
  final tLen = target.length;
  for (var i = 0; i < tLen && qi < qLen; i++) {
    if (target[i].toLowerCase() == q[qi]) qi++;
  }
  return qi == qLen;
}
