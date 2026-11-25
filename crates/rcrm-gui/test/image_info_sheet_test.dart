// test/image_info_sheet_test.dart
// The viewer's info sheet: the facts it must show, the ones it must not
// invent, and the one action it offers.

import 'dart:async';

import 'package:material_ui/material_ui.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/config/theme.dart';
import 'package:rcrm_gui/models/media_item.dart';
import 'package:rcrm_gui/services/media_metadata.dart';
import 'package:rcrm_gui/widgets/image_info_sheet.dart';
import 'package:rcrm_gui/widgets/info_rows.dart';

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
  // The grabber must sit OUTSIDE the scrolling body: inside it, the scroll
  // view's recognizer wins the vertical-drag arena and the handle never gets
  // onVerticalDragUpdate (the same trap two_finger_pinch documents).
  testWidgets('the grabber is outside the sheet scroll view', (tester) async {
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
      find.ancestor(
        of: find.byType(InfoGrabber),
        matching: find.byType(SingleChildScrollView),
      ),
      findsNothing,
      reason: 'a drag on the handle must not be stolen by the scroll view',
    );
  });

  // The grabber LOOKS like a swipe-to-dismiss handle, so it must actually act
  // for slow drags and taps too, not only a fast flick.
  testWidgets('the sheet grabber is a real drag and tap target', (tester) async {
    await tester.pumpWidget(
      const MaterialApp(home: Scaffold(body: InfoGrabber())),
    );
    final gd = tester.widget<GestureDetector>(
      find.descendant(
        of: find.byType(InfoGrabber),
        matching: find.byType(GestureDetector),
      ),
    );
    expect(gd.onVerticalDragStart, isNotNull);
    expect(gd.onVerticalDragUpdate, isNotNull);
    expect(gd.onVerticalDragEnd, isNotNull);
    expect(gd.onTap, isNotNull, reason: 'tapping the handle must dismiss too');
    expect(
      tester.getRect(find.byType(InfoGrabber)).height,
      greaterThanOrEqualTo(44),
      reason: 'the handle hit area meets the platform touch minimum',
    );
  });

  group('ImageInfoSheet', () {
    // A bottom sheet is a reading panel, not a landscape-wide banner. The cap
    // never binds on a phone (screen narrower than it) but must hold on a wide
    // window — otherwise the facts stretch into an 800dp strip with a dead right.
    testWidgets('in landscape the sheet is a capped reading column, not full '
        'width', (tester) async {
      await _pump(
        tester,
        ImageInfoSheet(
          item: _item(),
          index: 1,
          total: 2,
          metadata: Future.value(MediaMetadata.fromJsonString(_exifJson)),
        ),
        size: const Size(800, 360),
      );

      final rect = tester.getRect(find.byType(ImageInfoSheet));
      expect(
        rect.width,
        lessThanOrEqualTo(RCrmLayout.infoSheetMaxWidth),
        reason: 'a landscape sheet must not stretch to the whole window',
      );
      expect(
        rect.center.dx,
        closeTo(400, 2),
        reason: 'the capped panel stays centred in the window',
      );
    });

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
      expect(find.text('1920x1080 • 637.0 KB • JPG'), findsOneWidget);
    });

    testWidgets('claims nothing while the parse is still in flight', (
      tester,
    ) async {
      // The answer is not in yet. Saying "No camera information" now would be a
      // claim the app cannot support — and it used to flash and then vanish,
      // shifting every row below it.
      final pending = Completer<MediaMetadata>();
      addTearDown(() {
        if (!pending.isCompleted) pending.complete(MediaMetadata.none);
      });
      await _pump(
        tester,
        ImageInfoSheet(
          item: _item(),
          index: 1,
          total: 4,
          metadata: pending.future,
        ),
      );
      expect(find.text('No camera information'), findsNothing);
      expect(find.text('No location information'), findsNothing);
      // Still a sheet, not a blank one: the facts that do not need the parse
      // are already up.
      expect(find.text('Camera_XHS_1790706.JPG'), findsOneWidget);
      expect(find.textContaining('637.0 KB'), findsOneWidget);

      // …and once the answer lands, the honest absence may be stated.
      pending.complete(MediaMetadata.fromJsonString(_bareImageJson));
      await tester.pump();
      await tester.pump();
      expect(find.text('No camera information'), findsOneWidget);
      expect(find.text('No location information'), findsOneWidget);
    });

    testWidgets('EXIF dimensions follow the orientation, not the sensor', (
      tester,
    ) async {
      // A phone held upright stores a landscape sensor frame plus an
      // orientation tag. The line must describe what is on screen (portrait),
      // or it contradicts the photo directly above it.
      const rotated =
          '{"kind":"image","exif":{"make":"Apple","pixelWidth":4032,'
          '"pixelHeight":3024,"orientation":6}}';
      await _pump(
        tester,
        ImageInfoSheet(
          item: _item(),
          index: 1,
          total: 2,
          metadata: Future.value(MediaMetadata.fromJsonString(rotated)),
        ),
      );
      expect(find.textContaining('3024 × 4032'), findsOneWidget);
      expect(find.textContaining('4032 × 3024'), findsNothing);

      // Orientation 1 (or absent) means the stored order is the on-screen one.
      const upright =
          '{"kind":"image","exif":{"make":"Apple","pixelWidth":4032,'
          '"pixelHeight":3024,"orientation":1}}';
      await _pump(
        tester,
        ImageInfoSheet(
          item: _item(),
          index: 1,
          total: 2,
          metadata: Future.value(MediaMetadata.fromJsonString(upright)),
        ),
      );
      expect(find.textContaining('4032 × 3024'), findsOneWidget);
    });

    testWidgets('a shutter speed that is not a unit fraction stays decimal', (
      tester,
    ) async {
      // 0.3 s is "0.3 s", not "1/3 s"; 1/250 s is a real fraction and stays one.
      const slow = '{"kind":"image","exif":{"exposureTime":0.3}}';
      await _pump(
        tester,
        ImageInfoSheet(
          item: _item(),
          index: 1,
          total: 2,
          metadata: Future.value(MediaMetadata.fromJsonString(slow)),
        ),
      );
      expect(find.textContaining('0.3 s'), findsOneWidget);
      expect(find.textContaining('1/3 s'), findsNothing);

      const fast = '{"kind":"image","exif":{"exposureTime":0.004}}';
      await _pump(
        tester,
        ImageInfoSheet(
          item: _item(),
          index: 1,
          total: 2,
          metadata: Future.value(MediaMetadata.fromJsonString(fast)),
        ),
      );
      expect(find.textContaining('1/250 s'), findsOneWidget);
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
      // Not "Plays on long-press": that gesture exists only on mobile; on
      // desktop the viewer's motion badge plays it. State the fact, not a
      // platform-specific promise.
      expect(find.text('Motion photo'), findsOneWidget);

      await _pump(tester, ImageInfoSheet(item: _item(), index: 1, total: 2));
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
            name: 'Camera_XHS_1790706000_20260930_a-very-long-generative-name.png',
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

    // An errored parse of a VIDEO container can still carry a half-filled
    // track object. The parsed gate must come before the track branch or the
    // camera block presents those half-facts as truth (same contract as the
    // video sheet).
    testWidgets('an errored track with half facts shows no camera block', (
      tester,
    ) async {
      const erroredTrack =
          '{"kind":"track","error":"moov truncated","parsed":false,'
          '"track":{"make":"Apple","model":"iPhone 15",'
          '"author":"Ada","width":1920,"height":1080}}';
      await _pump(
        tester,
        ImageInfoSheet(
          item: _item(),
          index: 1,
          total: 2,
          metadata: Future.value(
            MediaMetadata.fromJsonString(erroredTrack),
          ),
        ),
      );
      expect(find.text('Apple iPhone 15'), findsNothing);
      expect(find.text('No camera information'), findsNothing);
      expect(find.text('1920 × 1080'), findsNothing);
    });

    // A failed image parse can carry a half-filled EXIF block. Every exif-
    // derived fact — GPS coordinates, capture date, pixel size — must be
    // suppressed, not only the camera block. Privacy matters for coordinates.
    testWidgets('an errored exif shows no coordinates or forged capture date', (
      tester,
    ) async {
      const erroredExif =
          '{"kind":"image","error":"bad exif","exif":{'
          '"make":"Apple","model":"iPhone 15","capturedAt":"2020-01-01 00:00:00",'
          '"gps":{"lat":22.5,"lon":114.05},"pixelWidth":1920,"pixelHeight":1080}}';
      await _pump(
        tester,
        ImageInfoSheet(
          item: _item(),
          index: 1,
          total: 2,
          metadata: Future.value(MediaMetadata.fromJsonString(erroredExif)),
        ),
      );
      expect(find.textContaining('22.5000'), findsNothing);
      expect(find.textContaining('114.0500'), findsNothing);
      expect(find.text('Jan 1, 2020 · 12:00 AM'), findsNothing);
      expect(find.text('1920 × 1080'), findsNothing);
      // The file's own timestamp is still an honest anchor.
      expect(find.text('Sep 30, 2026 · 2:24 AM'), findsOneWidget);
    });

    testWidgets('a malformed reply is silent, not a claim', (tester) async {
      await _pump(
        tester,
        ImageInfoSheet(
          item: _item(),
          index: 1,
          total: 2,
          metadata: Future.value(
            MediaMetadata.fromJsonString('{"kind":"image"'),
          ),
        ),
      );
      expect(find.text('No camera information'), findsNothing);
      expect(find.text('No location information'), findsNothing);
    });

    testWidgets('dimensions alone are not "camera information"', (
      tester,
    ) async {
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
      await _pump(
        tester,
        ImageInfoSheet(item: _item(modified: utc), index: 1, total: 2),
      );
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
