// test/media_url_live_test.dart
// The live-photo and animated-image probes are two more consumers of
// `MediaItem.url`. They used to re-encode the whole URL; with a canonical URL
// they must parse it once and send a literal `%20` filename as `%2520`.

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/services/animated_detector.dart';
import 'package:rcrm_gui/services/live_photo.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late HttpServer server;
  final requests = <String>[];

  setUp(() async {
    HttpOverrides.global = null;
    clearAnimatedCache();
    requests.clear();
    server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    server.listen((req) async {
      requests.add('${req.method} ${req.uri.path}');
      if (req.method == 'HEAD' && req.uri.path.endsWith('.mov')) {
        req.response.statusCode = HttpStatus.notFound;
        await req.response.close();
        return;
      }
      req.response.statusCode = HttpStatus.ok;
      req.response.headers.set('content-length', '64');
      req.response.add(List<int>.filled(64, 0));
      await req.response.close();
    });
  });

  tearDown(() async {
    await server.close(force: true);
  });

  String url(String name) => 'http://127.0.0.1:${server.port}/$name';

  test('isAnimatedUrl sends a literal percent as %2520', () async {
    final result = await isAnimatedUrl(url('foo%2520bar.avif'));

    expect(result, isFalse);
    expect(
      requests,
      contains('GET /foo%2520bar.avif'),
      reason: 'the probe must parse the canonical URL, not decode it again',
    );
  });

  test(
    'isLivePhotoUrl keeps the canonical path for both the .mov probe and the jpg range',
    () async {
      final result = await isLivePhotoUrl(url('foo%2520bar.jpg'));

      expect(result, isFalse);
      expect(
        requests,
        contains('HEAD /foo%2520bar.mov'),
        reason: 'the companion path is derived from the canonical path',
      );
      expect(
        requests,
        contains('GET /foo%2520bar.jpg'),
        reason: 'the range probe must keep the literal %2520',
      );
    },
  );
}
