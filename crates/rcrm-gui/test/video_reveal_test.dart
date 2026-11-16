// test/video_reveal_test.dart
// "Show in folder" from a video's item menu.
//
// The video tab's folders are DERIVED from the scanned list, so revealing one is
// free: switching the arrangement and opening the folder costs no re-scan. (The
// photo tab has no such row for exactly the opposite reason — its albums are
// built inside the scanned library, so reaching one means a full scan.) This
// test pins the round trip: menu -> grouping switch -> the folder is open.

import 'package:flutter_smart_dialog/flutter_smart_dialog.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:rcrm_gui/config/theme.dart';
import 'package:rcrm_gui/models/media_item.dart';
import 'package:rcrm_gui/providers/library_provider.dart';
import 'package:rcrm_gui/providers/settings_provider.dart';
import 'package:rcrm_gui/screens/video_screen.dart';
import 'package:rcrm_gui/services/media_library.dart';
import 'package:rcrm_gui/services/thumbnail_service.dart';
import 'package:rcrm_gui/services/webdav_client.dart';
import 'package:rcrm_gui/widgets/video_card.dart';

MediaItem _video(String name, String folder) => MediaItem(
  name: '$folder/$name',
  path: '/$folder/$name',
  url: 'http://127.0.0.1:18443/$folder/$name',
  type: MediaType.video,
  size: 1024,
  durationSeconds: 60,
  modified: DateTime(2024, 1, 1),
  albumName: folder,
);

final _videos = [
  _video('a1.mp4', 'Alpha'),
  _video('a2.mkv', 'Alpha'),
  _video('b1.mkv', 'Bravo'),
];

class _FlatSettings extends SettingsNotifier {
  @override
  SettingsState build() => const SettingsState(videoClassification: 'none');
}

ProviderContainer _container() {
  final container = ProviderContainer(
    overrides: [
      uiSettingsProvider.overrideWith(_FlatSettings.new),
      mediaLibraryProvider.overrideWithValue(
        MediaLibrary(WebDavClient(baseUrl: 'http://127.0.0.1:18443')),
      ),
    ],
  );
  addTearDown(container.dispose);
  container.read(videosMapProvider.notifier).addAll(_videos);
  return container;
}

Future<void> _pump(WidgetTester tester, ProviderContainer c) async {
  tester.view.physicalSize = const Size(1000, 800);
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.reset);
  await tester.pumpWidget(
    UncontrolledProviderScope(
      container: c,
      child: MaterialApp(
        theme: RCrmTheme.dark,
        navigatorObservers: [FlutterSmartDialog.observer],
        builder: FlutterSmartDialog.init(),
        home: const Scaffold(body: VideoScreen()),
      ),
    ),
  );
  await tester.pump();
}

void main() {
  setUp(() {
    SharedPreferences.setMockInitialValues({});
    ThumbnailService.suppressPosterGeneration = true;
  });
  tearDown(() => ThumbnailService.suppressPosterGeneration = false);

  testWidgets('Show in folder switches the grouping and opens the folder', (
    tester,
  ) async {
    final c = _container();
    await _pump(tester, c);

    expect(c.read(uiSettingsProvider).videoClassification, 'none');

    // The first card is a1.mp4, which lives in Alpha.
    await tester.longPress(find.byType(VideoCard).first);
    await tester.pumpAndSettle();
    expect(find.text('Show in folder'), findsOneWidget);

    await tester.tap(find.text('Show in folder'));
    await tester.pumpAndSettle();

    expect(c.read(uiSettingsProvider).videoClassification, 'folder');
    expect(
      find.byTooltip('Back to the list'),
      findsOneWidget,
      reason: 'the folder view is open, and its header is the way back',
    );
    expect(find.text('Alpha'), findsOneWidget);
  });
}
