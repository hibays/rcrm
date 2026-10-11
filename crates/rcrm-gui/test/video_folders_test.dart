// test/video_folders_test.dart
// The video tab's two arrangements, and the grouping they are built on.
//
// The flat grid/list is what the tab has always shown and stays the default; the
// folder view is the photo tab's album idea applied to videos — 2×2 poster
// previews, opened into that folder. They are the same list under two groupings,
// so both halves of the contract are pinned here: `MediaLibrary.buildAlbums`
// groups correctly (and keeps the two tabs' settings apart), and the screen
// really switches between the arrangements, opens a folder, and comes back.
//
// The grouping rule is `MediaLibrary`'s, not the screen's or the library
// instance's: the video tab passes its own classification in, which is what stops
// a change made for videos from regrouping the photo tab.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:rcrm_gui/config/theme.dart';
import 'package:rcrm_gui/models/media_item.dart';
import 'package:rcrm_gui/providers/library_provider.dart';
import 'package:rcrm_gui/providers/settings_provider.dart';
import 'package:rcrm_gui/screens/video_screen.dart';
import 'package:rcrm_gui/services/media_library.dart';
import 'package:rcrm_gui/services/settings_service.dart';
import 'package:rcrm_gui/services/thumbnail_service.dart';
import 'package:rcrm_gui/services/webdav_client.dart';
import 'package:rcrm_gui/widgets/video_card.dart';
import 'package:rcrm_gui/widgets/video_folder_card.dart';

MediaItem _video(String name, {String folder = ''}) => MediaItem(
  name: folder.isEmpty ? name : '$folder/$name',
  path: folder.isEmpty ? '/$name' : '/$folder/$name',
  url: 'http://127.0.0.1:18443/${folder.isEmpty ? '' : '$folder/'}$name',
  type: MediaType.video,
  size: 1024,
  durationSeconds: 60,
  modified: DateTime(2024, 1, 1),
  albumName: folder,
);

/// Three folders' worth, plus one video sitting at the root — the case that makes
/// the folder grouping produce its "Unorganized" group.
final _alpha = _video('a1.mp4', folder: 'Alpha');
final _alpha2 = _video('a2.mkv', folder: 'Alpha');
final _bravo = _video('b1.mkv', folder: 'Bravo');
final _root = _video('loose.mp4');

/// All of them, so a test that says "Alpha holds two videos" is really looking
/// at two — the omission of one is what a wrong expectation looks like here.
final _all = [_alpha, _alpha2, _bravo, _root];

MediaLibrary _library({
  MediaClassification images = MediaClassification.folder,
}) => MediaLibrary(
  WebDavClient(baseUrl: 'http://127.0.0.1:18443'),
  imageClassification: images,
);

class _GroupingSettings extends SettingsNotifier {
  _GroupingSettings(this._classification);
  final String _classification;

  @override
  SettingsState build() => SettingsState(videoClassification: _classification);
}

ProviderContainer _container(List<MediaItem> videos, {String? classification}) {
  final container = ProviderContainer(
    overrides: [
      if (classification != null)
        uiSettingsProvider.overrideWith(
          () => _GroupingSettings(classification),
        ),
      mediaLibraryProvider.overrideWithValue(_library()),
    ],
  );
  addTearDown(container.dispose);
  container.read(videosMapProvider.notifier).addAll(videos);
  return container;
}

/// The same harness `video_sort_toggle_test.dart` uses: list layout so a name's
/// vertical position is its rank, fixed pumps because poster placeholders carry
/// spinners that never settle.
Future<void> _pump(WidgetTester tester, ProviderContainer c) async {
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

List<String> _videoCards(WidgetTester tester) => tester
    .widgetList<VideoCard>(find.byType(VideoCard))
    .map((c) => c.item.name)
    .toList();

List<String> _folderCards(WidgetTester tester) => tester
    .widgetList<VideoFolderCard>(find.byType(VideoFolderCard))
    .map((c) => c.folder.name)
    .toList();

void main() {
  setUp(() {
    SharedPreferences.setMockInitialValues({});
    ThumbnailService.suppressPosterGeneration = true;
  });
  tearDown(() => ThumbnailService.suppressPosterGeneration = false);

  group('MediaLibrary.buildAlbums', () {
    test('groups by folder, root included, sorted naturally', () {
      final folders = _library().buildAlbums([
        _root,
        _bravo,
        _alpha2,
        _alpha,
      ], classification: MediaClassification.folder);

      expect(folders.map((f) => f.name).toList(), [
        'Alpha',
        'Bravo',
        'Unorganized',
      ]);
      expect(folders[0].itemCount, 2);
      expect(
        folders[2].itemCount,
        1,
        reason: 'the root video is its own group',
      );
      // The tabs name a folder after the albumName the WebDAV parse filled in.
      expect(folders[0].path, '/Alpha');
    });

    test('groups by format, most-populated first', () {
      final groups = _library().buildAlbums([
        _root,
        _bravo,
        _alpha2,
        _alpha,
      ], classification: MediaClassification.format);

      // MP4 twice, MKV twice, then the natural-name tiebreak between them; the
      // labels are the uppercase extension when `_formatNames` has no nicer one.
      expect(groups.map((g) => g.name).toSet(), {'MP4', 'MKV'});
      expect(groups.every((g) => g.itemCount == 2), isTrue);
    });

    test('the explicit classification wins over the library\'s own', () {
      // The library was built for the PHOTO tab (format grouping); asking for
      // folders must not consult it. This is what keeps the two tabs' settings
      // from regrouping each other.
      final lib = _library(images: MediaClassification.format);
      final folders = lib.buildAlbums([
        _root,
        _bravo,
        _alpha,
      ], classification: MediaClassification.folder);
      expect(folders.map((f) => f.name).toSet(), {
        'Alpha',
        'Bravo',
        'Unorganized',
      });

      // ...and with no classification passed, the library's own rule applies, so
      // the photo path is unchanged.
      final byFormat = lib.buildAlbums([_root, _bravo, _alpha]);
      expect(byFormat.map((g) => g.name).toSet(), {'MP4', 'MKV'});
    });

    test('the video tab derives nothing while its grouping is flat', () {
      final c = _container([_alpha, _bravo, _root]);
      expect(
        c.read(videoFoldersProvider),
        isEmpty,
        reason:
            '"no grouping" is the flat grid of every video, not one folder '
            'holding them all',
      );
    });
  });

  group('the video screen', () {
    testWidgets('flat is the default and still renders the videos themselves', (
      tester,
    ) async {
      await _pump(tester, _container([_alpha, _bravo, _root]));

      expect(_folderCards(tester), isEmpty);
      expect(_videoCards(tester), hasLength(3));
      expect(find.byTooltip('Organize'), findsOneWidget);
    });

    testWidgets('folder grouping shows folders, and opening one shows ITS '
        'videos', (tester) async {
      await _pump(tester, _container(_all, classification: 'folder'));

      expect(
        _videoCards(tester),
        isEmpty,
        reason: 'the folder LIST is showing',
      );
      expect(_folderCards(tester), ['Alpha', 'Bravo', 'Unorganized']);
      expect(find.text('2 videos'), findsOneWidget);
      expect(find.text('1 video'), findsNWidgets(2));

      // Opening a folder swaps the list for that folder's videos — the sorted
      // order is the toolbar's, so a folder never re-sorts behind its back.
      await tester.tap(find.text('Alpha'));
      await tester.pump();

      expect(_videoCards(tester), ['Alpha/a1.mp4', 'Alpha/a2.mkv']);
      expect(_folderCards(tester), isEmpty);
      expect(find.text('Alpha'), findsOneWidget, reason: 'the header names it');
      expect(find.text('2 videos'), findsOneWidget);

      // Back returns to the folders, and Esc does the same.
      await tester.tap(find.byTooltip('Back to the list'));
      await tester.pump();
      expect(_folderCards(tester), [
        'Alpha',
        'Bravo',
        'Unorganized',
      ], reason: 'after the header back button');

      await tester.tap(find.text('Bravo'));
      await tester.pump();
      expect(_videoCards(tester), ['Bravo/b1.mkv']);
      await tester.sendKeyEvent(LogicalKeyboardKey.escape);
      await tester.pump();
      expect(_folderCards(tester), [
        'Alpha',
        'Bravo',
        'Unorganized',
      ], reason: 'after Esc');
    });

    testWidgets('the toolbar\'s organize menu commits and persists the '
        'grouping', (tester) async {
      await _pump(tester, _container([_alpha, _bravo]));

      // Flat: no folder cards, and the button reports the arrangement in effect.
      expect(_folderCards(tester), isEmpty);
      expect(find.byIcon(Icons.apps), findsOneWidget);

      await tester.tap(find.byTooltip('Organize'));
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 400));
      expect(find.text('By folder'), findsOneWidget);
      await tester.tap(find.widgetWithText(PopupMenuItem<String>, 'By folder'));
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 400));

      expect(_folderCards(tester), ['Alpha', 'Bravo']);
      await tester.pump();
      expect(
        await SettingsService().getVideoClassification(),
        'folder',
        reason: 'the choice has to survive a relaunch, not just this frame',
      );
    });

    testWidgets('switching arrangement never keeps a folder open', (
      tester,
    ) async {
      await _pump(tester, _container(_all, classification: 'folder'));
      await tester.tap(find.text('Alpha'));
      await tester.pump();
      expect(_videoCards(tester), ['Alpha/a1.mp4', 'Alpha/a2.mkv']);

      // Back to flat: the open folder must not survive as a stale view of a
      // grouping that no longer exists.
      await tester.tap(find.byTooltip('Organize'));
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 400));
      await tester.tap(find.widgetWithText(PopupMenuItem<String>, 'Ungrouped'));
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 400));

      expect(_folderCards(tester), isEmpty);
      expect(_videoCards(tester), [
        'Alpha/a1.mp4',
        'Alpha/a2.mkv',
        'Bravo/b1.mkv',
        'loose.mp4',
      ]);
      expect(find.byTooltip('Back to the list'), findsNothing);
    });
  });
}
