// test/video_info_sheet_test.dart
// The item menu's Details panel for a video: the facts it shows, and the ones it
// must not invent. The container rows are a bonus — they appear when the parser
// found them and are absent (silently) when it did not, because a video without
// an author is not a fact anybody asked about.

import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:rcrm_gui/config/theme.dart';
import 'package:rcrm_gui/models/media_item.dart';
import 'package:rcrm_gui/services/media_metadata.dart';
import 'package:rcrm_gui/widgets/video_info_sheet.dart';

/// What the Rust parser replies for a phone clip with container metadata.
const _trackJson =
    '{"kind":"track","track":{"make":"Apple","model":"iPhone 15",'
    '"software":"iOS 18","author":"Ada","durationMs":83000,'
    '"width":1920,"height":1080,"createdAt":"2025-01-02 03:04:05"}}';

MediaItem _item({String? resolution}) => MediaItem(
  name: 'clip.mp4',
  path: '/Videos/clip.mp4',
  url: 'http://127.0.0.1:8080/Videos/clip.mp4',
  type: MediaType.video,
  size: 251658240, // 240.0 MB
  modified: DateTime(2026, 9, 30, 2, 24),
  durationSeconds: 83,
  resolution: resolution,
);

Future<void> _pump(
  WidgetTester tester,
  Widget sheet, {
  Size size = const Size(420, 900),
}) async {
  await tester.binding.setSurfaceSize(size);
  addTearDown(() => tester.binding.setSurfaceSize(null));
  await tester.pumpWidget(
    MaterialApp(
      theme: RCrmTheme.dark,
      home: Scaffold(
        backgroundColor: Colors.black,
        body: Align(alignment: Alignment.bottomCenter, child: sheet),
      ),
    ),
  );
  await tester.pump();
  await tester.pump(); // let the resolved metadata future land
}

void main() {
  group('VideoInfoSheet', () {
    testWidgets('leads with the file, then its technical line and facts', (
      tester,
    ) async {
      await _pump(
        tester,
        VideoInfoSheet(
          item: _item(),
          metadata: Future.value(MediaMetadata.fromJsonString(_trackJson)),
        ),
      );

      expect(find.text('clip.mp4'), findsOneWidget);
      expect(
        find.text('1920 × 1080 (1080p) • 01:23 • 240.0 MB • MP4'),
        findsOneWidget,
      );
      expect(find.text('/Videos/'), findsOneWidget);
      expect(find.text('Duration'), findsOneWidget);
      // Once in the technical line (inside the longer string above) and once as
      // the row's own value.
      expect(find.text('01:23'), findsOneWidget);
      expect(find.text('Sep 30, 2026 · 2:24 AM'), findsOneWidget);
      expect(tester.takeException(), isNull);
    });

    testWidgets('container facts appear when they exist', (tester) async {
      await _pump(
        tester,
        VideoInfoSheet(
          item: _item(),
          metadata: Future.value(MediaMetadata.fromJsonString(_trackJson)),
        ),
      );

      expect(find.text('Created'), findsOneWidget);
      expect(find.text('Jan 2, 2025 · 3:04 AM'), findsOneWidget);
      expect(find.text('Author'), findsOneWidget);
      expect(find.text('Ada'), findsOneWidget);
      expect(find.text('Software'), findsOneWidget);
      expect(find.text('iOS 18'), findsOneWidget);
      expect(find.text('Device'), findsOneWidget);
      expect(find.text('Apple iPhone 15'), findsOneWidget);
    });

    testWidgets('no answer means no container rows, not an invented absence', (
      tester,
    ) async {
      await _pump(tester, VideoInfoSheet(item: _item()));

      expect(find.text('clip.mp4'), findsOneWidget);
      expect(find.text('Created'), findsNothing);
      expect(find.text('Author'), findsNothing);
      expect(find.text('Device'), findsNothing);
      expect(find.textContaining('No '), findsNothing);
    });

    testWidgets('falls back to the scanner\'s resolution when the container '
        'has none', (tester) async {
      await _pump(
        tester,
        VideoInfoSheet(item: _item(resolution: '1280x720')),
      );
      expect(
        find.text('1280 × 720 (720p) • 01:23 • 240.0 MB • MP4'),
        findsOneWidget,
      );
    });
  });
}
