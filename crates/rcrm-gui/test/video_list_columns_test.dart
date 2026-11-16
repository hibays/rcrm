// test/video_list_columns_test.dart
// The video LIST's width: one row per line, or two when the window is wide —
// and the two-finger pinch that overrules the automatic answer.
//
// The breakpoint itself lives in `utils/library_columns.dart` and is unit-tested
// there; this file pins what the SCREEN does with it: the layout really changes,
// and a pinch really writes the setting the layout reads.

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

MediaItem _video(String name) => MediaItem(
  name: name,
  path: '/$name',
  url: 'http://127.0.0.1:18443/$name',
  type: MediaType.video,
  size: 1024,
  durationSeconds: 60,
  modified: DateTime(2024, 1, 1),
);

final _videos = [
  _video('a.mp4'),
  _video('b.mkv'),
  _video('c.mp4'),
  _video('d.webm'),
];

class _ListSettings extends SettingsNotifier {
  _ListSettings(this.mode);
  final String mode;

  @override
  SettingsState build() =>
      SettingsState(videoLayout: 'list', videoListColumns: mode);
}

ProviderContainer _container(String mode) {
  final container = ProviderContainer(
    overrides: [
      uiSettingsProvider.overrideWith(() => _ListSettings(mode)),
      mediaLibraryProvider.overrideWithValue(
        MediaLibrary(WebDavClient(baseUrl: 'http://127.0.0.1:18443')),
      ),
    ],
  );
  addTearDown(container.dispose);
  container.read(videosMapProvider.notifier).addAll(_videos);
  return container;
}

/// The view is resized through `tester.view`, not `setSurfaceSize`: the screen
/// reads its column breakpoint from MediaQuery, and only the view changes what
/// MediaQuery reports.
Future<void> _pump(
  WidgetTester tester,
  ProviderContainer c, {
  Size size = const Size(1000, 800),
  double textScale = 1,
}) async {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.reset);
  Widget app = MaterialApp(
    theme: RCrmTheme.dark,
    navigatorObservers: [FlutterSmartDialog.observer],
    builder: FlutterSmartDialog.init(),
    home: const Scaffold(body: VideoScreen()),
  );
  if (textScale != 1) {
    app = MediaQuery(
      data: MediaQueryData(textScaler: TextScaler.linear(textScale)),
      child: app,
    );
  }
  await tester.pumpWidget(UncontrolledProviderScope(container: c, child: app));
  await tester.pump();
}

/// A library long enough to scroll — the scroll-position case needs more rows
/// than one screen holds.
ProviderContainer _containerMany(String mode) {
  final c = ProviderContainer(
    overrides: [
      uiSettingsProvider.overrideWith(() => _ListSettings(mode)),
      mediaLibraryProvider.overrideWithValue(
        MediaLibrary(WebDavClient(baseUrl: 'http://127.0.0.1:18443')),
      ),
    ],
  );
  addTearDown(c.dispose);
  c.read(videosMapProvider.notifier).addAll([
    for (var i = 0; i < 60; i++)
      MediaItem(
        name: 'clip-$i.mp4',
        path: '/p/$i.mp4',
        url: 'http://127.0.0.1:18443/p/$i.mp4',
        type: MediaType.video,
        size: 1024,
        durationSeconds: 60,
        modified: DateTime(2024, 1, 1),
      ),
  ]);
  return c;
}

/// A library whose one title is long enough to wrap onto a second line in a
/// two-column cell — the case a short fixture cannot reach.
ProviderContainer _containerWithLongTitle() {
  final c = ProviderContainer(
    overrides: [
      uiSettingsProvider.overrideWith(() => _ListSettings('two')),
      mediaLibraryProvider.overrideWithValue(
        MediaLibrary(WebDavClient(baseUrl: 'http://127.0.0.1:18443')),
      ),
    ],
  );
  addTearDown(c.dispose);
  c.read(videosMapProvider.notifier).addAll([
    MediaItem(
      name:
          'A very long episode title that has to wrap across two lines in a '
          'narrow cell.mp4',
      path: '/dir/long.mp4',
      url: 'http://127.0.0.1:18443/dir/long.mp4',
      type: MediaType.video,
      size: 1234567,
      durationSeconds: 3600,
      modified: DateTime(2024, 1, 1),
    ),
  ]);
  return c;
}

Rect _tile(WidgetTester tester, int index) =>
    tester.getRect(find.byType(VideoListTile).at(index));

void main() {
  setUp(() {
    SharedPreferences.setMockInitialValues({});
    // Poster placeholders carry spinners that never settle; the list's geometry
    // does not depend on them.
    ThumbnailService.debugPosterLoader = ThumbnailService.noPoster;
  });
  tearDown(() => ThumbnailService.debugPosterLoader = null);

  testWidgets('auto lays one row per line on a phone-width window', (
    tester,
  ) async {
    final c = _container('auto');
    await _pump(tester, c, size: const Size(500, 800));

    final first = _tile(tester, 0);
    final second = _tile(tester, 1);
    expect(second.top, greaterThan(first.top));
    expect(second.left, first.left);
  });

  testWidgets('auto lays two rows per line once the window is wide', (
    tester,
  ) async {
    final c = _container('auto');
    await _pump(tester, c, size: const Size(1000, 800));

    final first = _tile(tester, 0);
    final second = _tile(tester, 1);
    expect(second.top, closeTo(first.top, 0.5));
    expect(second.left, greaterThan(first.left));
  });

  testWidgets('an explicit Two is ignored on a phone-width window', (
    tester,
  ) async {
    final c = _container('two');
    await _pump(tester, c, size: const Size(414, 800));

    final first = _tile(tester, 0);
    final second = _tile(tester, 1);
    expect(second.top, greaterThan(first.top));
    expect(second.left, first.left);
    expect(
      tester.takeException(),
      isNull,
      reason: 'half a phone is not a place for a 100dp list row',
    );
  });

  testWidgets('an explicit One wins on a wide window', (tester) async {
    final c = _container('one');
    await _pump(tester, c, size: const Size(1000, 800));

    final first = _tile(tester, 0);
    final second = _tile(tester, 1);
    expect(second.top, greaterThan(first.top));
    expect(second.left, first.left);
  });

  testWidgets('a pinch inward commits two columns and the list follows', (
    tester,
  ) async {
    final c = _container('auto');
    // 700dp: auto is one column here, but an explicit Two is allowed (>= 600).
    await _pump(tester, c, size: const Size(700, 800));

    expect(_tile(tester, 1).top, greaterThan(_tile(tester, 0).top));

    // Two fingers 100dp apart, brought to 40dp: a cumulative scale of 0.4, well
    // past the list's 20% step.
    final a = await tester.createGesture(pointer: 1);
    final b = await tester.createGesture(pointer: 2);
    await a.down(const Offset(300, 400));
    await b.down(const Offset(400, 400));
    await tester.pump();
    await a.moveTo(const Offset(330, 400));
    await b.moveTo(const Offset(370, 400));
    await tester.pump();
    await a.up();
    await b.up();
    await tester.pumpAndSettle();

    expect(c.read(uiSettingsProvider).videoListColumns, 'two');
    final first = _tile(tester, 0);
    final second = _tile(tester, 1);
    expect(second.top, closeTo(first.top, 0.5));
    expect(second.left, greaterThan(first.left));
  });

  testWidgets('a two-column row at the 600dp floor fits a wrapped title', (
    tester,
  ) async {
    await _pump(tester, _containerWithLongTitle(), size: const Size(600, 800));
    expect(
      tester.takeException(),
      isNull,
      reason:
          '600dp is the width Two columns is allowed at, so a two-line '
          'title and the size line must fit the row there',
    );
    // The row grew, and the poster it sizes follows it (the 16:9 derivation
    // reads the same number) — a fixed 100dp row overflowed by 14px.
    expect(
      tester.getSize(find.byType(VideoListTile).first).height,
      greaterThan(100),
    );
  });

  testWidgets('a two-column row at 700dp fits enlarged text', (tester) async {
    await _pump(
      tester,
      _containerWithLongTitle(),
      size: const Size(700, 800),
      textScale: 1.2,
    );
    expect(tester.takeException(), isNull);
  });

  testWidgets('a pinch that flips the list keeps the scroll position', (
    tester,
  ) async {
    final c = _containerMany('one');
    await _pump(tester, c, size: const Size(700, 800));
    await tester.drag(find.byType(Scrollable).first, const Offset(0, -1200));
    await tester.pumpAndSettle();
    final scrolled = tester
        .state<ScrollableState>(find.byType(Scrollable).first)
        .position
        .pixels;
    expect(scrolled, greaterThan(0));

    final a = await tester.createGesture(pointer: 1);
    final b = await tester.createGesture(pointer: 2);
    await a.down(const Offset(300, 400));
    await b.down(const Offset(400, 400));
    await tester.pump();
    await a.moveTo(const Offset(330, 400));
    await b.moveTo(const Offset(370, 400));
    await tester.pump();
    await a.up();
    await b.up();
    await tester.pumpAndSettle();

    expect(c.read(uiSettingsProvider).videoListColumns, 'two');
    // Swapping a ListView for a GridView (or back) replaces the Scrollable and
    // drops the reader at row 0. The list is one GridView at BOTH counts, so
    // the position survives the flip.
    final after = tester
        .state<ScrollableState>(find.byType(Scrollable).first)
        .position
        .pixels;
    expect(after, greaterThan(0), reason: 'the pinch must not scroll to top');
  });

  testWidgets('a pinch-in on a phone-width list does nothing', (tester) async {
    final c = _container('auto');
    await _pump(tester, c, size: const Size(500, 800));

    final a = await tester.createGesture(pointer: 1);
    final b = await tester.createGesture(pointer: 2);
    await a.down(const Offset(300, 400));
    await b.down(const Offset(400, 400));
    await tester.pump();
    await a.moveTo(const Offset(330, 400));
    await b.moveTo(const Offset(370, 400));
    await tester.pump();
    await a.up();
    await b.up();
    await tester.pumpAndSettle();

    // The list cannot show two columns here, so the gesture must not store a
    // preference that has no visible answer.
    expect(c.read(uiSettingsProvider).videoListColumns, 'auto');
    expect(_tile(tester, 1).top, greaterThan(_tile(tester, 0).top));
  });
}
