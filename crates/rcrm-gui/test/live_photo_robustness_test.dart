// test/live_photo_robustness_test.dart
// Robustness of the live-photo detection:
//  - a companion is only "present" when the server reports a non-zero size
//    (a 0-byte or 404 companion is not a Live Photo);
//  - detection is idempotent: repeated calls (and the two public APIs) share
//    one network probe instead of re-running it every time.
//
// These pin the two fixes made while hardening the fetch layer: the `> 0`
// companion check and the memoisation of *every* result (previously only
// positive results were cached, so a non-live URL was re-detected on every
// call).

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/services/live_photo.dart';
import 'package:rcrm_gui/services/net.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late HttpServer server;
  // Request counts per path, to assert idempotency (a re-run would bump them).
  final Map<String, int> hits = {};

  setUp(() async {
    HttpOverrides.global = null;
    setSharedAuth(null);
    hits.clear();
    clearLivePhotoCache();
    server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  });

  tearDown(() async {
    setSharedAuth(null);
    await server.close(force: true);
  });

  // Strip a leading slash so `url('/x')` and `url('x')` both yield a single
  // slash — a double slash (`http://host//x`) would make Uri.path == `//x`,
  // which would derive the companion as `//x.mov` and miss the server hit key.
  String url(String name) =>
      'http://127.0.0.1:${server.port}/${name.startsWith('/') ? name.substring(1) : name}';

  // The companion .mov endpoint: simulate present / absent / empty companion.
  // Every *other* path (i.e. the original image file) is served as present
  // (200 + a small body with no mpvd box) so the tests exercise exactly
  // "companion missing but file present" rather than conflating a 404 on the
  // source file with one on the companion.
  void serveCompanion(String path, {int status = 200, int contentLength = 10}) {
    server.listen((req) async {
      if (req.uri.path == path) {
        hits[req.uri.path] = (hits[req.uri.path] ?? 0) + 1;
        req.response.statusCode = status;
        req.response.headers.set(
          HttpHeaders.contentLengthHeader,
          contentLength,
        );
        await req.response.close();
      } else {
        req.response.statusCode = 200;
        req.response.headers.set(HttpHeaders.contentLengthHeader, 10);
        req.response.add(List<int>.filled(10, 0x20)); // no mpvd / no XMP
        await req.response.close();
      }
    });
  }

  group('companion detection', () {
    test('a non-empty companion is detected (Apple Live Photo)', () async {
      serveCompanion('/a.mov', status: 200, contentLength: 10);
      expect(await isLivePhotoUrl(url('/a.heic')), isTrue);
      expect(hits['/a.mov'], 1, reason: 'one HEAD probe to the companion');
    });

    test('a missing companion (404) is not a live photo', () async {
      serveCompanion('/b.mov', status: 404);
      expect(await isLivePhotoUrl(url('/b.heic')), isFalse);
    });

    test('an empty companion (200, 0 bytes) is not a live photo', () async {
      // Regression: a 0-byte response used to count as a companion because the
      // check returned true for any 200.
      serveCompanion('/c.mov', status: 200, contentLength: 0);
      expect(await isLivePhotoUrl(url('/c.heic')), isFalse);
    });
  });

  group('idempotency', () {
    test(
      'phaseLivePhoto caches the result — second call hits no network',
      () async {
        serveCompanion('/d.mov', status: 200, contentLength: 10);
        await phaseLivePhoto(url('/d.heic'));
        await phaseLivePhoto(url('/d.heic'));
        expect(
          hits['/d.mov'],
          1,
          reason: 'the detection ran once; the second call is memoised',
        );
      },
    );

    test(
      'isLivePhotoUrl and phaseLivePhoto share the companion cache',
      () async {
        serveCompanion('/e.mov', status: 200, contentLength: 10);
        await isLivePhotoUrl(url('/e.heic'));
        await phaseLivePhoto(url('/e.heic'));
        expect(
          hits['/e.mov'],
          1,
          reason: 'one HEAD to the companion, shared across the two APIs',
        );
      },
    );

    test('a non-live result is also memoised (no re-detection)', () async {
      serveCompanion('/f.mov', status: 404);
      await phaseLivePhoto(url('/f.heic'));
      await phaseLivePhoto(url('/f.heic'));
      expect(
        hits['/f.mov'],
        1,
        reason: 'non-live detection is cached too, not re-run every call',
      );
    });
  });

  group('Range-ignoring servers', () {
    test(
      'an ignored Range answered with 200 still yields a LIVE badge',
      () async {
        final marker = utf8.encode(
          '<x:xmpmeta GCamera:MicroVideo="1" '
          'GCamera:MicroVideoOffset="1000">',
        );
        final bytes = Uint8List(200 * 1024);
        bytes.setRange(0, marker.length, marker);

        server.listen((req) async {
          if (req.uri.path.endsWith('.mov')) {
            req.response.statusCode = 404;
            req.response.headers.set(HttpHeaders.contentLengthHeader, 0);
            await req.response.close();
            return;
          }
          // Deliberately ignore the Range header: 200 + the whole file.
          req.response.statusCode = 200;
          req.response.headers.set(
            HttpHeaders.contentLengthHeader,
            bytes.length,
          );
          if (req.method != 'HEAD') req.response.add(bytes);
          await req.response.close();
        });

        clearLivePhotoCache();
        expect(
          await isLivePhotoUrl(url('/ignore-range.jpg')),
          isTrue,
          reason: 'the 200 whole-file body must be truncated to the head probe',
        );
      },
    );
  });
}
