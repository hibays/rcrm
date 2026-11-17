// test/tag_search_test.dart
// A tag is a query, and tags are MULTI-select: '#amateur' opens that tag's
// results, related tags are offered below it, and adding one narrows to the
// files that carry both.

import 'package:material_ui/material_ui.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:rcrm_gui/config/theme.dart';
import 'package:rcrm_gui/models/media_item.dart';
import 'package:rcrm_gui/providers/keyword_provider.dart';
import 'package:rcrm_gui/providers/library_provider.dart';
import 'package:rcrm_gui/screens/search_screen.dart';
import 'package:rcrm_gui/services/thumbnail_service.dart';
import 'package:rcrm_gui/utils/keywords.dart';
import 'package:rcrm_gui/widgets/keyword_chip.dart';
import 'package:rcrm_gui/widgets/video_card.dart';

MediaItem _video(String name, {String folder = ''}) => MediaItem(
  name: folder.isEmpty ? name : '$folder/$name',
  path: folder.isEmpty ? '/$name' : '/$folder/$name',
  url: 'http://127.0.0.1:18443/${folder.isEmpty ? '' : '$folder/'}$name',
  type: MediaType.video,
  size: 1024 * 1024,
  durationSeconds: 60,
  modified: DateTime(2024, 1, 1),
  albumName: folder,
);

final _videos = [
  _video('amateur couple.mp4', folder: 'F'),
  _video('amateur solo.mp4', folder: 'F'),
  _video('cooking show.mp4', folder: 'C'),
];

Future<ProviderContainer> _pump(
  WidgetTester tester, {
  KeywordTag? initialTag,
  MediaType? tabFilter,
  List<MediaItem>? videos,
}) async {
  await tester.binding.setSurfaceSize(const Size(900, 800));
  addTearDown(() => tester.binding.setSurfaceSize(null));
  final c = ProviderContainer();
  addTearDown(c.dispose);
  c.read(videosMapProvider.notifier).addAll(videos ?? _videos);
  await tester.pumpWidget(
    UncontrolledProviderScope(
      container: c,
      child: MaterialApp(
        theme: RCrmTheme.dark,
        home: SearchScreen(tabFilter: tabFilter, initialTag: initialTag),
      ),
    ),
  );
  await tester.pump();
  return c;
}

List<String> _cardNames(WidgetTester tester) => tester
    .widgetList<VideoCard>(find.byType(VideoCard))
    .map((card) => card.item.name)
    .toList();

void main() {
  setUp(() {
    SharedPreferences.setMockInitialValues({});
    ThumbnailService.debugPosterLoader = ThumbnailService.noPoster;
  });
  tearDown(() => ThumbnailService.debugPosterLoader = null);

  testWidgets('opening a tag shows exactly that tag, with #tag in the field', (
    tester,
  ) async {
    final c = await _pump(
      tester,
      initialTag: const KeywordTag('amateur', 'Amateur'),
      tabFilter: MediaType.video,
    );

    expect(_cardNames(tester).toSet(), {
      'F/amateur couple.mp4',
      'F/amateur solo.mp4',
    });
    expect(
      tester.widget<TextField>(find.byType(TextField)).controller!.text,
      '#Amateur',
    );
    expect(
      c.read(videoTagFilterProvider),
      isEmpty,
      reason: 'a search is not the video tab filter',
    );
  });

  testWidgets('a typed word offers its tag, and the chip starts the search', (
    tester,
  ) async {
    await _pump(tester, tabFilter: MediaType.video);

    await tester.enterText(find.byType(TextField), 'ama');
    await tester.pump();
    expect(find.widgetWithText(KeywordChip, '#Amateur'), findsOneWidget);

    await tester.tap(find.widgetWithText(KeywordChip, '#Amateur'));
    await tester.pump();

    expect(
      tester.widget<TextField>(find.byType(TextField)).controller!.text,
      '#Amateur',
    );
    expect(_cardNames(tester).toSet(), {
      'F/amateur couple.mp4',
      'F/amateur solo.mp4',
    });
  });

  testWidgets(
    'related tags add a second constraint, and tapping one removes it',
    (tester) async {
      await _pump(
        tester,
        initialTag: const KeywordTag('amateur', 'Amateur'),
        tabFilter: MediaType.video,
      );

      // Co-occurrence, not fuzzy matching: the files tagged Amateur also carry
      // Couple and Solo, so those are the useful next tags.
      expect(find.widgetWithText(KeywordChip, '#Couple'), findsOneWidget);
      expect(find.widgetWithText(KeywordChip, '#Solo'), findsOneWidget);

      await tester.tap(find.widgetWithText(KeywordChip, '#Couple'));
      await tester.pump();

      expect(
        tester.widget<TextField>(find.byType(TextField)).controller!.text,
        '#Amateur #Couple',
      );
      expect(_cardNames(tester), ['F/amateur couple.mp4']);

      // The selected chip is the removal affordance.
      await tester.tap(find.widgetWithText(SelectedKeywordChip, '#Couple'));
      await tester.pump();
      expect(
        tester.widget<TextField>(find.byType(TextField)).controller!.text,
        '#Amateur',
      );
      expect(_cardNames(tester).length, 2);
    },
  );

  testWidgets('clearing a tag search returns to Browse by tag', (tester) async {
    await _pump(
      tester,
      initialTag: const KeywordTag('amateur', 'Amateur'),
      tabFilter: MediaType.video,
    );

    await tester.tap(find.byTooltip('Clear'));
    await tester.pump();

    expect(find.text('Browse by tag'), findsOneWidget);
    expect(find.text('#Amateur'), findsOneWidget);
  });

  testWidgets('a file belongs to every tag it carries, not one primary tag', (
    tester,
  ) async {
    final video = _video('aa bb cc.mp4', folder: 'aa');

    await _pump(
      tester,
      videos: [video],
      initialTag: const KeywordTag('bb', 'Bb'),
      tabFilter: MediaType.video,
    );
    expect(_cardNames(tester), ['aa/aa bb cc.mp4']);

    await _pump(
      tester,
      videos: [video],
      initialTag: const KeywordTag('cc', 'Cc'),
      tabFilter: MediaType.video,
    );
    expect(_cardNames(tester), ['aa/aa bb cc.mp4']);
  });

  testWidgets('a tag with no hits still keeps its chip, so it can be removed', (
    tester,
  ) async {
    await _pump(
      tester,
      initialTag: const KeywordTag('zzz', 'Zzz'),
      tabFilter: MediaType.video,
    );

    expect(find.widgetWithText(SelectedKeywordChip, '#Zzz'), findsOneWidget);
    expect(find.text('No videos with "#Zzz"'), findsOneWidget);

    await tester.tap(find.widgetWithText(SelectedKeywordChip, '#Zzz'));
    await tester.pump();
    expect(find.text('Browse by tag'), findsOneWidget);
  });

  testWidgets('the image tab does not advertise video tags', (tester) async {
    await _pump(tester, tabFilter: MediaType.image);

    expect(find.text('Browse by tag'), findsNothing);
    expect(find.text('#Amateur'), findsNothing);
  });
}
