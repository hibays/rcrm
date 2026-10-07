// test/image_info_sheet_test.dart
// The viewer's info sheet: the facts it must show, the ones it must not
// invent, and the one action it offers.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/config/theme.dart';
import 'package:rcrm_gui/models/media_item.dart';
import 'package:rcrm_gui/services/media_metadata.dart';
import 'package:rcrm_gui/widgets/image_info_sheet.dart';

/// What the Rust parser replies for a phone photo with a full EXIF block.
const _exifJson =
    '{"kind":"image","exif":{"make":"vivo","model":"X100 Pro",'
    '"lens":"Vario-Test 26mm","capturedAt":"2025-01-02 03:04:05",'
    '"iso":100,"fNumber":1.8,"exposureTime":0.004,"focalLength":26.0,'
    '"pixelWidth":1440,"pixelHeight":1000,'
    '"gps":{"lat":22.5,"lon":114.05,"altitude":12.3}}}';

/// An image the parser read but that carries no camera data (the state every
/// screenshot saved from a social app is in).
const _bareImageJson = '{"kind":"image"}';

MediaItem _item({
  String name = 'Camera_XHS_1790706.JPG',
  int size = 652288, // 637 KB
  DateTime? modified,
  String album = 'DCIM',
  String path = '/DCIM/Camera/Camera_XHS_1790706.JPG',
  String? resolution,
}) => MediaItem(
  name: name,
  path: path,
  url: 'http://127.0.0.1:8080$path',
  type: MediaType.image,
  size: size,
  modified: modified ?? DateTime(2026, 9, 30, 2, 24),
  albumName: album,
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
  await tester.pump(); // let a resolved metadata future land in the sheet
}

void main() {
  group('ImageInfoSheet', () {
    testWidgets('leads with the date and the file name', (tester) async {
      await _pump(
        tester,
        ImageInfoSheet(
          item: _item(),
          index: 3,
          total: 128,
          pixelSize: const Size(1440, 1000),
        ),
      );
      expect(find.text('Sep 30, 2026 · 2:24 AM'), findsOneWidget);
      expect(find.text('Camera_XHS_1790706.JPG'), findsOneWidget);
      expect(tester.takeException(), isNull);
    });

    testWidgets('states the technical facts it actually has', (tester) async {
      await _pump(
        tester,
        ImageInfoSheet(
          item: _item(),
          index: 1,
          total: 9,
          pixelSize: const Size(1440, 1000),
        ),
      );
      expect(
        find.text('1440 × 1000 • 1.4 MP • 637.0 KB • JPG'),
        findsOneWidget,
      );
      expect(find.text('/DCIM/Camera/'), findsOneWidget);
      expect(find.text('Image 1 of 9'), findsOneWidget);
      // No camera/EXIF claim is made anywhere: we do not parse EXIF.
      expect(find.textContaining('Camera:'), findsNothing);
      expect(find.textContaining('EXIF'), findsNothing);
    });

    testWidgets('falls back to the scanned resolution while decoding', (
      tester,
    ) async {
      await _pump(
        tester,
        ImageInfoSheet(
          item: _item(resolution: '1920x1080'),
          index: 1,
          total: 2,
        ),
      );
      expect(
        find.text('1920x1080 • 637.0 KB • JPG'),
        findsOneWidget,
      );
    });

    testWidgets('without a date the name becomes the headline', (tester) async {
      await _pump(
        tester,
        ImageInfoSheet(
          item: MediaItem(
            name: 'no-exif.png',
            path: '/a/no-exif.png',
            url: 'http://x/a/no-exif.png',
            type: MediaType.image,
            size: 1024,
          ),
          index: 1,
          total: 1,
        ),
      );
      expect(find.text('no-exif.png'), findsOneWidget);
      expect(tester.takeException(), isNull);
    });

    testWidgets('mentions animation only when the file really has frames', (
      tester,
    ) async {
      await _pump(
        tester,
        ImageInfoSheet(item: _item(), index: 1, total: 2, animated: true),
      );
      expect(find.text('Animated'), findsOneWidget);
      expect(find.text('Plays on long-press'), findsOneWidget);

      await _pump(
        tester,
        ImageInfoSheet(item: _item(), index: 1, total: 2),
      );
      expect(find.text('Animated'), findsNothing);
    });

    testWidgets('the 1:1 chip appears only when it can do something', (
      tester,
    ) async {
      var taps = 0;
      await _pump(
        tester,
        ImageInfoSheet(
          item: _item(),
          index: 1,
          total: 2,
          onActualSize: () => taps++,
        ),
      );
      expect(find.text('1:1'), findsOneWidget);
      await tester.tap(find.text('1:1'));
      expect(taps, 1);

      await _pump(tester, ImageInfoSheet(item: _item(), index: 1, total: 2));
      expect(find.text('1:1'), findsNothing);
    });

    testWidgets('survives a long name on a narrow phone', (tester) async {
      await _pump(
        tester,
        ImageInfoSheet(
          item: _item(
            name:
                'Camera_XHS_1790706000_20260930_a-very-long-generative-name.png',
            album: 'a-very-long-album-name-that-keeps-going',
            path: '/a-very-long/album/path/that/keeps/going/and/going/file.png',
          ),
          index: 12,
          total: 3412,
          pixelSize: const Size(8192, 5464),
          onActualSize: () {},
        ),
        size: const Size(320, 640),
      );
      expect(tester.takeException(), isNull);
    });
  });

  group('ImageInfoSheet camera block (EXIF)', () {
    testWidgets('shows camera, lens, exposure and location', (tester) async {
      await _pump(
        tester,
        ImageInfoSheet(
          item: _item(),
          index: 1,
          total: 4,
          metadata: Future.value(MediaMetadata.fromJsonString(_exifJson)),
        ),
      );
      expect(find.text('vivo X100 Pro'), findsOneWidget);
      expect(find.text('Vario-Test 26mm'), findsOneWidget);
      expect(find.text('26 mm • f/1.8 • 1/250 s • ISO 100'), findsOneWidget);
      expect(find.text('22.5000° N, 114.0500° E'), findsOneWidget);
      expect(find.text('No camera information'), findsNothing);
      expect(tester.takeException(), isNull);
    });

    testWidgets('the capture time wins over the file timestamp', (
      tester,
    ) async {
      final item = _item(modified: DateTime(2026, 9, 30, 2, 24));
      await _pump(
        tester,
        ImageInfoSheet(
          item: item,
          index: 1,
          total: 2,
          metadata: Future.value(MediaMetadata.fromJsonString(_exifJson)),
        ),
      );
      // EXIF says 2025-01-02 03:04:05; the file says 2026-09-30 02:24.
      expect(find.text('Jan 2, 2025 · 3:04 AM'), findsOneWidget);
      expect(find.text('Sep 30, 2026 · 2:24 AM'), findsNothing);
    });

    testWidgets('EXIF dimensions fill in before the decode lands', (
      tester,
    ) async {
      await _pump(
        tester,
        ImageInfoSheet(
          item: _item(),
          index: 1,
          total: 2,
          metadata: Future.value(MediaMetadata.fromJsonString(_exifJson)),
        ),
      );
      expect(
        find.text('1440 × 1000 • 1.4 MP • 637.0 KB • JPG'),
        findsOneWidget,
      );
    });

    testWidgets('a file with no EXIF says so, and claims no location', (
      tester,
    ) async {
      await _pump(
        tester,
        ImageInfoSheet(
          item: _item(),
          index: 1,
          total: 2,
          metadata: Future.value(MediaMetadata.fromJsonString(_bareImageJson)),
        ),
      );
      expect(find.text('No camera information'), findsOneWidget);
      expect(find.text('No location information'), findsOneWidget);
      // …and still uses the file timestamp for the headline.
      expect(find.text('Sep 30, 2026 · 2:24 AM'), findsOneWidget);
    });

    testWidgets('an unreadable file claims nothing at all', (tester) async {
      await _pump(
        tester,
        ImageInfoSheet(
          item: _item(),
          index: 1,
          total: 2,
          metadata: Future.value(
            MediaMetadata.fromJsonString(
              '{"kind":"unknown","error":"unsupported format"}',
            ),
          ),
        ),
      );
      expect(find.text('No camera information'), findsNothing);
      expect(find.text('No location information'), findsNothing);
    });

    testWidgets('a FAILED parse of a known image states no absence either', (
      tester,
    ) async {
      // The container was identified as an image but the EXIF block could not
      // be read: "no camera information" would assert an absence nobody
      // established, and "no location information" is the same false claim.
      await _pump(
        tester,
        ImageInfoSheet(
          item: _item(),
          index: 1,
          total: 2,
          metadata: Future.value(
            MediaMetadata.fromJsonString('{"kind":"image","error":"bad exif"}'),
          ),
        ),
      );
      expect(find.text('No camera information'), findsNothing);
      expect(find.text('No location information'), findsNothing);
      // The headline still falls back to the file timestamp.
      expect(find.text('Sep 30, 2026 · 2:24 AM'), findsOneWidget);
    });

    testWidgets('a malformed reply is silent, not a claim', (tester) async {
      await _pump(
        tester,
        ImageInfoSheet(
          item: _item(),
          index: 1,
          total: 2,
          metadata: Future.value(MediaMetadata.fromJsonString('{"kind":"image"')),
        ),
      );
      expect(find.text('No camera information'), findsNothing);
      expect(find.text('No location information'), findsNothing);
    });

    testWidgets('dimensions alone are not "camera information"', (tester) async {
      // A camera block with nothing to render must say so instead of leaving a
      // silent gap where the design promises a statement.
      await _pump(
        tester,
        ImageInfoSheet(
          item: _item(),
          index: 1,
          total: 2,
          metadata: Future.value(
            MediaMetadata.fromJsonString(
              '{"kind":"image","exif":{"pixelWidth":4000,"pixelHeight":3000}}',
            ),
          ),
        ),
      );
      expect(find.text('No camera information'), findsOneWidget);
      // …and those dimensions still appear, in the technical line.
      expect(find.textContaining('4000 × 3000'), findsOneWidget);
    });

    testWidgets('an ISO of 0 is not reported as a setting', (tester) async {
      await _pump(
        tester,
        ImageInfoSheet(
          item: _item(),
          index: 1,
          total: 2,
          metadata: Future.value(
            MediaMetadata.fromJsonString(
              '{"kind":"image","exif":{"make":"vivo","iso":0}}',
            ),
          ),
        ),
      );
      expect(find.textContaining('ISO'), findsNothing);
    });

    testWidgets('a tiny image is not "0.0 MP"', (tester) async {
      await _pump(
        tester,
        ImageInfoSheet(
          item: _item(),
          index: 1,
          total: 2,
          pixelSize: const Size(200, 200),
        ),
      );
      expect(find.textContaining('200 × 200'), findsOneWidget);
      expect(find.textContaining('MP'), findsNothing);
    });

    testWidgets('an encrypted-style dot name does not become the extension', (
      tester,
    ) async {
      await _pump(
        tester,
        ImageInfoSheet(
          item: _item(name: '.75VcVmrMsShzt6vwLK9uTMG(hS6Eo2MWKf}KHq351d'),
          index: 1,
          total: 2,
        ),
      );
      // No " • <giant token>" tail in the technical line.
      expect(find.text('637.0 KB'), findsOneWidget);
    });

    testWidgets('a UTC file timestamp is shown as local time', (tester) async {
      // What `HttpDate.parse` returns for the server's RFC 1123 header. The
      // headline must render the same instant a local DateTime would, not the
      // UTC wall clock — off by the offset on every machine east or west of it.
      final utc = DateTime.utc(2026, 9, 30, 2, 24);
      await _pump(tester, ImageInfoSheet(item: _item(modified: utc), index: 1, total: 2));
      final fromUtc = _headline(tester);

      await _pump(
        tester,
        ImageInfoSheet(
          item: _item(modified: utc.toLocal()),
          index: 1,
          total: 2,
        ),
      );
      final fromLocal = _headline(tester);

      expect(fromUtc, fromLocal);
    });

    testWidgets('video containers get their own block', (tester) async {
      await _pump(
        tester,
        ImageInfoSheet(
          item: _item(),
          index: 1,
          total: 2,
          metadata: Future.value(
            MediaMetadata.fromJsonString(
              '{"kind":"track","track":{"make":"Apple","model":"iPhone 15",'
              '"durationMs":65000,"width":1920,"height":1080}}',
            ),
          ),
        ),
      );
      expect(find.text('Apple iPhone 15'), findsOneWidget);
      expect(find.text('1920 × 1080 • 1m 05s'), findsOneWidget);
    });

    testWidgets('a long recording reads in hours, not 185m', (tester) async {
      await _pump(
        tester,
        ImageInfoSheet(
          item: _item(),
          index: 1,
          total: 2,
          metadata: Future.value(
            MediaMetadata.fromJsonString(
              '{"kind":"track","track":{"width":1920,"height":1080,'
              '"durationMs":11100000}}',
            ),
          ),
        ),
      );
      expect(find.text('1920 × 1080 • 3h 05m'), findsOneWidget);
    });
  });
}

/// The sheet's headline: the one Text at the anchor size (21px).
String _headline(WidgetTester tester) => tester
    .widgetList<Text>(find.byType(Text))
    .firstWhere((t) => t.style?.fontSize == 21)
    .data!;
