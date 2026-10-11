// test/image_ungrouped_test.dart
// The photo tab's UNGROUPED mode: no groups at all, and no "All Images" album.
//
// It used to gather every image into one album called 'All Images' — an album
// you had to open to see anything, i.e. a grouping, which is the opposite of
// what the setting says. It now behaves like the video tab's ungrouped view:
// `MediaLibrary.buildAlbums` returns NOTHING for `none`, and the screen shows
// the images themselves in one flat grid.
//
// The label moved with it ('None' → 'Ungrouped', the video tab's word), so the
// two tabs name the same thing the same way.

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:rcrm_gui/config/theme.dart';
import 'package:rcrm_gui/models/media_item.dart';
import 'package:rcrm_gui/providers/library_provider.dart';
import 'package:rcrm_gui/providers/settings_provider.dart';
import 'package:rcrm_gui/screens/image_screen.dart';
import 'package:rcrm_gui/services/media_library.dart';
import 'package:rcrm_gui/services/webdav_client.dart';
import 'package:rcrm_gui/widgets/album_card.dart';
import 'package:rcrm_gui/widgets/image_grid.dart';

MediaItem _image(String name, {String folder = ''}) => MediaItem(
  name: folder.isEmpty ? name : '$folder/$name',
  path: folder.isEmpty ? '/$name' : '/$folder/$name',
  url: 'http://127.0.0.1:18443/${folder.isEmpty ? '' : '$folder/'}$name',
  type: MediaType.image,
  size: 512,
  modified: DateTime(2024, 1, 1),
  albumName: folder,
);

final _images = [
  _image('a.jpg', folder: 'Alpha'),
  _image('b.png', folder: 'Alpha'),
  _image('c.jpg', folder: 'Bravo'),
];

class _ClassificationSettings extends SettingsNotifier {
  _ClassificationSettings(this._classification);
  final String _classification;

  @override
  SettingsState build() => SettingsState(imageClassification: _classification);
}

MediaLibrary _library({String images = 'folder'}) => MediaLibrary(
  WebDavClient(baseUrl: 'http://127.0.0.1:18443'),
  imageClassification: images == 'format'
      ? MediaClassification.format
      : images == 'none'
      ? MediaClassification.none
      : MediaClassification.folder,
);

ProviderContainer _container(String classification) {
  final container = ProviderContainer(
    overrides: [
      uiSettingsProvider.overrideWith(
        () => _ClassificationSettings(classification),
      ),
      mediaLibraryProvider.overrideWithValue(_library(images: classification)),
    ],
  );
  addTearDown(container.dispose);
  container.read(imagesMapProvider.notifier).addAll(_images);
  return container;
}

Future<void> _pump(WidgetTester tester, ProviderContainer c) async {
  await tester.binding.setSurfaceSize(const Size(1000, 800));
  addTearDown(() => tester.binding.setSurfaceSize(null));
  await tester.pumpWidget(
    UncontrolledProviderScope(
      container: c,
      child: MaterialApp(
        theme: RCrmTheme.dark,
        home: const Scaffold(body: ImageScreen()),
      ),
    ),
  );
  await tester.pump();
}

void main() {
  setUp(() => SharedPreferences.setMockInitialValues({}));

  test('no grouping produces no groups — not one group holding everything', () {
    final lib = _library();
    expect(
      lib.buildAlbums(_images, classification: MediaClassification.none),
      isEmpty,
    );
    // The contrast, so this cannot pass by returning nothing always.
    expect(
      lib.buildAlbums(_images, classification: MediaClassification.folder),
      hasLength(2),
    );
  });

  test('the home page still gets ONE album to reach those images by', () {
    // Ungrouped has no groups to show, but a home page offers albums and nothing
    // else — without this the photos would be unreachable from there. The album
    // opens the same flat view the tab shows.
    final none = _container('none').read(albumsProvider);
    expect(none, hasLength(1));
    expect(none.single.name, kUngroupedAlbumName);
    expect(none.single.itemCount, _images.length);

    // Grouped: the home page shows the real albums, untouched.
    expect(_container('folder').read(albumsProvider), hasLength(2));
  });

  testWidgets('the ungrouped tab shows the images themselves', (tester) async {
    await _pump(tester, _container('none'));

    expect(
      find.byType(AlbumCard),
      findsNothing,
      reason: 'nothing to open: ungrouped is not a folder',
    );
    expect(find.byType(ImageGrid), findsOneWidget);
    expect(find.text('Ungrouped'), findsOneWidget);
    expect(find.text('3 images'), findsOneWidget);
    expect(
      find.byIcon(Icons.arrow_back),
      findsNothing,
      reason: 'the flat view has nothing to go back from',
    );
  });

  testWidgets('grouping still shows albums, as it always did', (tester) async {
    await _pump(tester, _container('folder'));
    expect(find.byType(AlbumCard), findsNWidgets(2));
    expect(find.byType(ImageGrid), findsNothing);
  });
}
