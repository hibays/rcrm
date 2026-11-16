// test/video_list_tile_test.dart
// The list row's thumbnail is a 16:9 poster and must stay one.
//
// The regression this pins: the thumbnail used to be `Expanded(flex: 2)`, so it
// grew with the window — a 1600px list drew a 630 × 100 strip and `BoxFit.cover`
// cropped the poster into a band. The width is now capped at the 16:9 box the
// 100dp row implies, and only shrinks on a narrow phone so the text column
// survives.

import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:rcrm_gui/models/media_item.dart';
import 'package:rcrm_gui/services/thumbnail_service.dart';
import 'package:rcrm_gui/widgets/video_card.dart';

// A SHORT name on purpose: the test VM draws with the Ahem font, whose line
// metrics are not Roboto's, and a two-line title overflows the 100dp row there
// while the real-font render is fine (see .local_backup/render_video_list_test).
// These tests are about the thumbnail's box, not about text metrics.
MediaItem _video() => const MediaItem(
  name: 'N.mkv',
  path: '/movies/night.mkv',
  url: 'http://127.0.0.1:8080/movies/night.mkv',
  type: MediaType.video,
  size: 1024 * 1024 * 700,
  durationSeconds: 780,
);

void main() {
  setUp(() => ThumbnailService.debugPosterLoader = ThumbnailService.noPoster);
  tearDown(() => ThumbnailService.debugPosterLoader = null);

  Future<void> renderAt(WidgetTester tester, Size surface) async {
    await tester.binding.setSurfaceSize(surface);
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: VideoListTile(item: _video(), onTap: () {}),
        ),
      ),
    );
    await tester.pump();
  }

  testWidgets('a wide row keeps the 16:9 box instead of stretching it', (
    WidgetTester tester,
  ) async {
    await renderAt(tester, const Size(1600, 400));

    final Size thumb = tester.getSize(find.byType(VideoCard));
    expect(thumb.height, 100);
    expect(thumb.width, closeTo(100 * 16 / 9, 0.5));
    expect(
      thumb.width / thumb.height,
      closeTo(16 / 9, 0.02),
      reason: 'the poster is 16:9; a wider box makes BoxFit.cover crop a band',
    );
  });

  testWidgets('a narrow row lets the thumbnail shrink, not the text', (
    WidgetTester tester,
  ) async {
    await renderAt(tester, const Size(360, 400));

    final Size thumb = tester.getSize(find.byType(VideoCard));
    expect(thumb.height, 100);
    expect(thumb.width, lessThan(100 * 16 / 9));
    expect(thumb.width, closeTo(360 * 0.42, 0.5));
    expect(thumb.width / thumb.height, greaterThan(1.2));
  });

  testWidgets('the text column still gets the rest of the row', (
    WidgetTester tester,
  ) async {
    await renderAt(tester, const Size(360, 400));

    final Size thumb = tester.getSize(find.byType(VideoCard));
    // 360 − thumbnail − 12dp gap, and the title must not be clipped away.
    expect(360 - thumb.width - 12, greaterThan(150));
    expect(find.text('N.mkv'), findsOneWidget);
    expect(find.text('13:00'), findsOneWidget);
  });
}
