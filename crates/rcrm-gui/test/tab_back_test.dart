// test/tab_back_test.dart
// The BACK KEY and a tab's sub-view — the video tab's folder view and the photo
// tab's album view, which answer it the same way.
//
// A sub-view is a step INSIDE the tab, not a route: opening a folder or an album
// swaps the grid in place, so back has to undo that step. The shell owns the key
// (it owns tab switching and, on Android, the double-back exit guard), so it has
// to DEFER to the tab's own sub-view; each screen publishes a flag for exactly
// that (`videoFolderOpenProvider` / `imageAlbumOpenProvider`). Without the video
// tab's half of it, back from inside a folder jumped to the Home tab and left
// the folder standing behind it.
//
// Four things are pinned, on both tabs: the back key really closes the sub-view,
// the shell's own rule is unchanged when nothing is open (the fix must not
// swallow every back press in the tab), the flag cannot outlive the view that
// published it — and clearing it is not allowed to blow up in the framework,
// which is where the photo tab's original `dispose()` write landed.

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:rcrm_gui/config/theme.dart';
import 'package:rcrm_gui/models/media_item.dart';
import 'package:rcrm_gui/providers/library_provider.dart';
import 'package:rcrm_gui/providers/settings_provider.dart';
import 'package:rcrm_gui/screens/home_screen.dart';
import 'package:rcrm_gui/screens/image_screen.dart';
import 'package:rcrm_gui/screens/video_screen.dart';
import 'package:rcrm_gui/services/media_library.dart';
import 'package:rcrm_gui/services/thumbnail_service.dart';
import 'package:rcrm_gui/services/webdav_client.dart';
import 'package:rcrm_gui/widgets/album_card.dart';
import 'package:rcrm_gui/widgets/video_card.dart';
import 'package:rcrm_gui/widgets/video_folder_card.dart';

MediaItem _item(
  String name, {
  String folder = '',
  MediaType type = MediaType.video,
}) => MediaItem(
  name: folder.isEmpty ? name : '$folder/$name',
  path: folder.isEmpty ? '/$name' : '/$folder/$name',
  url: 'http://127.0.0.1:18443/${folder.isEmpty ? '' : '$folder/'}$name',
  type: type,
  size: 1024,
  durationSeconds: type == MediaType.video ? 60 : null,
  modified: DateTime(2024, 1, 1),
  albumName: folder,
);

MediaItem _video(String name, {String folder = ''}) =>
    _item(name, folder: folder);

MediaItem _image(String name, {String folder = ''}) =>
    _item(name, folder: folder, type: MediaType.image);

final _alpha = _video('a1.mp4', folder: 'Alpha');
final _alpha2 = _video('a2.mkv', folder: 'Alpha');
final _bravo = _video('b1.mkv', folder: 'Bravo');
final _root = _video('loose.mp4');
final _allVideos = [_alpha, _alpha2, _bravo, _root];
final _allImages = [
  _image('p1.jpg', folder: 'Alpha'),
  _image('p2.png', folder: 'Bravo'),
];

/// A WebDAV client that reaches nothing and finds nothing.
///
/// HomeScreen scans on its first frame (`_scanLibrary`), and a scan CLEARS the
/// stores before it fills them — so a test that seeds media has to know when
/// that is over. This client makes the scan an immediate, offline, empty answer.
class _EmptyWebDav extends WebDavClient {
  _EmptyWebDav() : super(baseUrl: 'http://127.0.0.1:1');

  @override
  Future<ListAllResult> listAll(String path) async =>
      const ListAllResult([], []);
}

/// The video tab's folder arrangement, which is the one with a sub-view. The
/// photo tab's album arrangement is the default and needs no override.
class _FolderGrouping extends SettingsNotifier {
  @override
  SettingsState build() => const SettingsState(videoClassification: 'folder');
}

ProviderContainer _container() => ProviderContainer(
  overrides: [
    uiSettingsProvider.overrideWith(_FolderGrouping.new),
    mediaLibraryProvider.overrideWithValue(MediaLibrary(_EmptyWebDav())),
  ],
);

List<String> _videoCards(WidgetTester tester) => tester
    .widgetList<VideoCard>(find.byType(VideoCard))
    .map((c) => c.item.name)
    .toList();

List<String> _folderCards(WidgetTester tester) => tester
    .widgetList<VideoFolderCard>(find.byType(VideoFolderCard))
    .map((c) => c.folder.name)
    .toList();

List<String> _albumCards(WidgetTester tester) => tester
    .widgetList<AlbumCard>(find.byType(AlbumCard))
    .map((c) => c.album.name)
    .toList();

/// Which tab the shell is on — the AppBar names it, and the bottom nav's labels
/// are the other half of that name, so the finder has to be scoped to the bar.
String _tab(WidgetTester tester) => tester
    .widget<Text>(
      find.descendant(of: find.byType(AppBar), matching: find.byType(Text)),
    )
    .data!;

/// One tab on its own, with no shell above it: `handlePopRoute` then reaches
/// this screen's route directly, which is what the screen's `PopScope` registers
/// with.
Future<void> _pumpTab(WidgetTester tester, ProviderContainer c) async {
  await tester.binding.setSurfaceSize(const Size(1000, 800));
  addTearDown(() => tester.binding.setSurfaceSize(null));
  await tester.pumpWidget(
    UncontrolledProviderScope(
      container: c,
      child: MaterialApp(
        theme: RCrmTheme.dark,
        home: const Scaffold(body: VideoScreen()),
      ),
    ),
  );
  await tester.pump();
}

/// Replaces the tab inside a scope that STAYS MOUNTED — the app's shape, where
/// the shell is the scope's child and the tab comes and goes below it.
Future<void> _dropTab(WidgetTester tester, ProviderContainer c) async {
  await tester.pumpWidget(
    UncontrolledProviderScope(
      container: c,
      child: const MaterialApp(home: SizedBox()),
    ),
  );
  await tester.pump();
}

/// The real shell, so the back key meets the handler that actually owns it.
Future<void> _pumpShell(WidgetTester tester, ProviderContainer c) async {
  await tester.binding.setSurfaceSize(const Size(1000, 800));
  addTearDown(() => tester.binding.setSurfaceSize(null));
  await tester.pumpWidget(
    UncontrolledProviderScope(
      container: c,
      child: const MaterialApp(home: HomeScreen()),
    ),
  );
  // Frame one: HomeScreen's post-frame callback starts the (empty) scan.
  await tester.pump();
  await tester.pump(const Duration(milliseconds: 50));
  // The scan clears the stores before filling them, so the media goes in after
  // it — a seed placed before would simply be wiped.
  c.read(videosMapProvider.notifier).addAll(_allVideos);
  c.read(imagesMapProvider.notifier).addAll(_allImages);
  await tester.pump();
}

Future<void> _tapText(WidgetTester tester, String text) async {
  await tester.tap(find.text(text));
  await tester.pump();
}

void main() {
  setUp(() {
    SharedPreferences.setMockInitialValues({});
    ThumbnailService.suppressPosterGeneration = true;
  });
  tearDown(() => ThumbnailService.suppressPosterGeneration = false);

  group('the video tab\'s folder view', () {
    testWidgets('the back key closes an open folder', (tester) async {
      final c = _container();
      addTearDown(c.dispose);
      c.read(videosMapProvider.notifier).addAll(_allVideos);
      await _pumpTab(tester, c);
      await _tapText(tester, 'Alpha');

      expect(_videoCards(tester), ['Alpha/a1.mp4', 'Alpha/a2.mkv']);
      expect(
        c.read(videoFolderOpenProvider),
        isTrue,
        reason: 'the shell is told what is open, or it cannot defer to it',
      );

      await tester.binding.handlePopRoute();
      await tester.pump();

      expect(_folderCards(tester), [
        'Alpha',
        'Bravo',
        'Unorganized',
      ], reason: 'back undoes the folder, like it undoes an open album');
      expect(_videoCards(tester), isEmpty);
      expect(c.read(videoFolderOpenProvider), isFalse);
    });

    testWidgets('coming back from an opened item lands in the folder again — '
        'and the folder\'s PopScope stays out of the pushed route\'s way', (
      tester,
    ) async {
      final c = _container();
      addTearDown(c.dispose);
      c.read(videosMapProvider.notifier).addAll(_allVideos);
      await _pumpTab(tester, c);
      await _tapText(tester, 'Alpha');

      // A stand-in for the pushed player route: what matters here is the
      // push/pop cycle, and the player itself cannot be mounted in a test (it
      // creates a real media_kit Player).
      final nav = tester.state<NavigatorState>(find.byType(Navigator));
      nav.push(
        MaterialPageRoute<void>(
          builder: (_) => const Scaffold(body: Text('the player')),
        ),
      );
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 400));
      expect(find.text('the player'), findsOneWidget);

      nav.pop();
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 400));
      // The exit transition has to run its course before the route leaves the
      // overlay; a single jumped frame does not get there (measured).
      for (var i = 0; i < 6; i++) {
        await tester.pump(const Duration(milliseconds: 100));
      }

      expect(find.text('the player'), findsNothing);
      expect(_videoCards(tester), [
        'Alpha/a1.mp4',
        'Alpha/a2.mkv',
      ], reason: 'the folder is a step inside the tab: it survives a push');
      expect(c.read(videoFolderOpenProvider), isTrue);
    });

    testWidgets('the flag does not outlive the screen that published it', (
      tester,
    ) async {
      final c = _container();
      addTearDown(c.dispose);
      c.read(videosMapProvider.notifier).addAll(_allVideos);
      await _pumpTab(tester, c);
      await _tapText(tester, 'Alpha');
      expect(c.read(videoFolderOpenProvider), isTrue);

      // The user switches tabs: the shell builds another tab in this one's
      // place, and the folder goes with it. A flag left behind would make the
      // shell defer to a folder view that no longer exists — and clearing it
      // from `dispose` is not allowed to throw, either.
      await _dropTab(tester, c);

      expect(c.read(videoFolderOpenProvider), isFalse);
    });

    testWidgets('a folder a re-scan dropped cannot go on refusing the back '
        'key', (tester) async {
      final c = _container();
      addTearDown(c.dispose);
      c.read(videosMapProvider.notifier).addAll(_allVideos);
      await _pumpTab(tester, c);
      await _tapText(tester, 'Alpha');
      expect(c.read(videoFolderOpenProvider), isTrue);

      // A re-scan that no longer knows Alpha: the open folder is re-resolved by
      // path on every build, so the view is back at the list — and the flag has
      // to follow it, or the next back press would be spent on an invisible
      // folder.
      c.read(videosMapProvider.notifier)
        ..clear()
        ..addAll([_bravo, _root]);
      await tester.pump();

      expect(_videoCards(tester), isEmpty, reason: 'the folder view is gone');
      expect(c.read(videoFolderOpenProvider), isFalse);
    });
  });

  group('the shell defers to an open sub-view', () {
    testWidgets('back walks out of a video folder, and only then out of the '
        'tab', (tester) async {
      final c = _container();
      addTearDown(c.dispose);
      await _pumpShell(tester, c);

      await _tapText(tester, 'Videos');
      expect(_tab(tester), 'Videos');
      expect(_folderCards(tester), ['Alpha', 'Bravo', 'Unorganized']);
      await _tapText(tester, 'Alpha');
      expect(_videoCards(tester), ['Alpha/a1.mp4', 'Alpha/a2.mkv']);

      await tester.binding.handlePopRoute();
      await tester.pump();

      expect(
        _tab(tester),
        'Videos',
        reason:
            'the shell owns the back key, so it has to let the open folder '
            'answer first — otherwise back jumps to Home and the folder stays '
            'open',
      );
      expect(_folderCards(tester), ['Alpha', 'Bravo', 'Unorganized']);
      expect(c.read(videoFolderOpenProvider), isFalse);

      // With nothing open the shell's own rule is unchanged: back leaves the tab.
      await tester.binding.handlePopRoute();
      await tester.pump();
      expect(_tab(tester), 'RCrm');
    });

    testWidgets('and to an open photo album — the rule the video tab now '
        'matches', (tester) async {
      final c = _container();
      addTearDown(c.dispose);
      await _pumpShell(tester, c);

      await _tapText(tester, 'Images');
      expect(_tab(tester), 'Images');
      expect(_albumCards(tester), ['Alpha', 'Bravo']);
      await _tapText(tester, 'Alpha');
      expect(c.read(imageAlbumOpenProvider), isTrue);

      await tester.binding.handlePopRoute();
      await tester.pump();

      expect(_tab(tester), 'Images');
      expect(_albumCards(tester), ['Alpha', 'Bravo']);
      expect(c.read(imageAlbumOpenProvider), isFalse);
    });

    testWidgets(
      'leaving a tab with its sub-view open clears that tab\'s flag',
      (tester) async {
        final c = _container();
        addTearDown(c.dispose);
        await _pumpShell(tester, c);

        await _tapText(tester, 'Images');
        await _tapText(tester, 'Alpha');
        expect(c.read(imageAlbumOpenProvider), isTrue);

        // Straight out of the tab. The album's own `dispose` is what clears the
        // flag, and a provider cannot be written while the tree is being
        // finalised — the write has to be deferred or the framework reports
        // "Tried to modify a provider while the widget tree was building".
        await _tapText(tester, 'Videos');
        expect(c.read(imageAlbumOpenProvider), isFalse);
      },
    );
  });
}
