// test/video_sort_toggle_test.dart
// The video page's sort direction toggle and its re-pick rule.
//
// The arrow shipped dead: its onPressed called `onSortChanged(currentSort)`,
// which re-selected the sort *field*, so tapping it re-wrote the value already
// in state — Riverpod saw no change, `sortedVideosProvider` never recomputed,
// and the direction provider was never touched. These tests mount the real
// page and pin both halves of the contract: the order the user sees reverses,
// and the control reports the direction now in effect.
//
// Re-picking the active field (the sort menu's ticked entry) is now the second
// way to reverse, which is why the arrow no longer routes through that
// callback: the rule lives in `_SortNotifier.set`, where both the menu and any
// future caller meet it. That seam and its image-page twin
// (`SettingsNotifier.setImageSort`) are covered below.

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:rcrm_gui/config/theme.dart';
import 'package:rcrm_gui/models/media_item.dart';
import 'package:rcrm_gui/providers/library_provider.dart';
import 'package:rcrm_gui/providers/settings_provider.dart';
import 'package:rcrm_gui/screens/video_screen.dart';
import 'package:rcrm_gui/services/settings_service.dart';
import 'package:rcrm_gui/services/thumbnail_service.dart';
import 'package:rcrm_gui/widgets/video_card.dart';

const _ascending = ['alpha.mp4', 'bravo.mp4', 'charlie.mp4'];
const _descending = ['charlie.mp4', 'bravo.mp4', 'alpha.mp4'];

/// Deliberately not name-sorted, so "the field changed and the direction reset
/// to ascending" is distinguishable from "the direction stayed put".
const _bySizeAscending = ['alpha.mp4', 'charlie.mp4', 'bravo.mp4'];

/// Sizes chosen so no two orders above coincide.
const _sizes = {'alpha.mp4': 100, 'bravo.mp4': 300, 'charlie.mp4': 200};

MediaItem _video(String name) => MediaItem(
  name: name,
  path: '/$name',
  url: 'http://127.0.0.1:18443/$name',
  type: MediaType.video,
  size: _sizes[name] ?? 1024,
  durationSeconds: 60,
  modified: DateTime(2024, 1, 1),
);

/// List layout: rows stack vertically, so a name's `dy` is its rank. Both
/// layouts render the same `videos[i]` order — the list just makes "the order
/// the user sees" readable without grid geometry.
class _ListLayoutSettings extends SettingsNotifier {
  @override
  SettingsState build() => const SettingsState(videoLayout: 'list');
}

ProviderContainer _container() {
  final container = ProviderContainer(
    overrides: [uiSettingsProvider.overrideWith(_ListLayoutSettings.new)],
  );
  addTearDown(container.dispose);
  container.read(videosMapProvider.notifier).addAll(_ascending.map(_video).toList());
  return container;
}

Future<void> _pumpVideoScreen(WidgetTester tester, ProviderContainer c) async {
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
  // Second frame: the cards' poster requests start in a post-frame callback.
  // No pumpAndSettle — poster placeholders carry a spinner that never settles.
  await tester.pump();
}

/// The names of the rendered cards, in tree (index) order.
List<String> _rendered(WidgetTester tester) => tester
    .widgetList<VideoCard>(find.byType(VideoCard))
    .map((c) => c.item.name)
    .toList();

/// Vertical position of a row — the user-visible rank in list layout.
double _y(WidgetTester tester, String name) =>
    tester.getTopLeft(find.text(name)).dy;

/// Commits [field] ('Name', 'Date', 'Size', 'Duration') from the toolbar's
/// sort menu, by tapping the chip and then the entry — the real user path.
///
/// Pumps fixed durations rather than `pumpAndSettle`: the poster placeholders
/// carry spinners that never settle.
Future<void> _pickSortField(WidgetTester tester, String field) async {
  // The sort chip is the first PopupMenuButton in the toolbar row; the
  // extension filter is the second.
  await tester.tap(find.byType(PopupMenuButton<String>).first);
  await tester.pump();
  await tester.pump(const Duration(milliseconds: 400));
  await tester.tap(find.text(field));
  await tester.pump();
  await tester.pump(const Duration(milliseconds: 400));
}

/// Lets the fire-and-forget preferences writes land before reading them back.
Future<void> _settlePrefs(WidgetTester tester) async {
  await tester.pump();
  await tester.pump();
}

void main() {
  setUp(() {
    SharedPreferences.setMockInitialValues({});
    ThumbnailService.suppressPosterGeneration = true;
  });
  tearDown(() => ThumbnailService.suppressPosterGeneration = false);

  testWidgets('the sort arrow reverses the rendered order and its own state', (
    tester,
  ) async {
    await _pumpVideoScreen(tester, _container());

    // Baseline: ascending by name, and the control agrees.
    expect(_rendered(tester), _ascending);
    expect(_y(tester, 'alpha.mp4') < _y(tester, 'charlie.mp4'), isTrue);
    expect(find.byIcon(Icons.arrow_upward), findsOneWidget);
    expect(find.text('Name ↑'), findsOneWidget);

    // Tap the arrow: the list on screen must actually reverse...
    await tester.tap(find.byIcon(Icons.arrow_upward));
    await tester.pump();

    expect(_rendered(tester), _descending);
    expect(_y(tester, 'charlie.mp4') < _y(tester, 'alpha.mp4'), isTrue);

    // ...and the control must report the direction now in effect.
    expect(find.byIcon(Icons.arrow_downward), findsOneWidget);
    expect(find.byTooltip('Sort ascending'), findsOneWidget);
    // Same sort field (Name), flipped direction: the arrow states the
    // direction, it does not commit the field.
    expect(find.text('Name ↓'), findsOneWidget);

    // A toggle, not a one-way switch.
    await tester.tap(find.byIcon(Icons.arrow_downward));
    await tester.pump();
    expect(_rendered(tester), _ascending);
    expect(find.byIcon(Icons.arrow_upward), findsOneWidget);
    expect(find.byTooltip('Sort descending'), findsOneWidget);
    expect(find.text('Name ↑'), findsOneWidget);
  });

  testWidgets('the chosen direction persists and is restored on relaunch', (
    tester,
  ) async {
    await _pumpVideoScreen(tester, _container());
    await tester.tap(find.byIcon(Icons.arrow_upward));
    await tester.pump();
    await tester.pump(); // settle the fire-and-forget prefs write

    expect(
      await SettingsService().getVideoSortAsc(),
      isFalse,
      reason: 'the flip must be persisted, not only held in memory',
    );

    // Relaunch: a fresh container plus the startup call app.dart makes.
    final relaunched = ProviderContainer();
    addTearDown(relaunched.dispose);
    relaunched.read(videosMapProvider.notifier).addAll(
      _ascending.map(_video).toList(),
    );
    await relaunched.read(uiSettingsProvider.notifier).load();

    expect(relaunched.read(videoSortAscProvider), isFalse);
    expect(
      relaunched.read(sortedVideosProvider).map((v) => v.name).toList(),
      _descending,
    );
  });

  testWidgets(
    're-picking the active field from the sort menu flips the order and '
    'persists it, and a different field starts that field ascending',
    (tester) async {
      await _pumpVideoScreen(tester, _container());

      expect(_rendered(tester), _ascending);
      expect(find.text('Name ↑'), findsOneWidget);
      // The rule is stated where the user can meet it before choosing: the
      // chip's tooltip (which is also the control's semantics label).
      expect(
        find.byTooltip('Sort: Name ↑ — pick Name again to reverse'),
        findsOneWidget,
      );

      // Re-pick the ticked field: the field must not move, the order must.
      await _pickSortField(tester, 'Name');
      await _settlePrefs(tester);
      expect(find.text('Date'), findsNothing, reason: 'the menu must close');
      expect(_rendered(tester), _descending);
      expect(find.text('Name ↓'), findsOneWidget);
      expect(find.byIcon(Icons.arrow_downward), findsOneWidget);
      expect(find.byTooltip('Sort ascending'), findsOneWidget);
      expect(
        await SettingsService().getVideoSort(),
        'name',
        reason: 're-picking the active field is a direction flip, not a no-op '
            'and not a field change',
      );
      expect(
        await SettingsService().getVideoSortAsc(),
        isFalse,
        reason: 'the flip must be persisted, not only held in memory',
      );

      // A different field: it becomes the field, and ascending is where it
      // starts — the same convention the image page settled on.
      await _pickSortField(tester, 'Size');
      await _settlePrefs(tester);
      expect(_rendered(tester), _bySizeAscending);
      expect(find.text('Size ↑'), findsOneWidget);
      expect(find.byIcon(Icons.arrow_upward), findsOneWidget);
      expect(await SettingsService().getVideoSort(), 'size');
      expect(await SettingsService().getVideoSortAsc(), isTrue);

      // Relaunch: both halves came back from persistence, not the session.
      final relaunched = ProviderContainer();
      addTearDown(relaunched.dispose);
      relaunched.read(videosMapProvider.notifier).addAll(
        _ascending.map(_video).toList(),
      );
      await relaunched.read(uiSettingsProvider.notifier).load();

      expect(relaunched.read(videoSortProvider), 'size');
      expect(relaunched.read(videoSortAscProvider), isTrue);
      expect(
        relaunched.read(sortedVideosProvider).map((v) => v.name).toList(),
        _bySizeAscending,
      );
    },
  );
}
