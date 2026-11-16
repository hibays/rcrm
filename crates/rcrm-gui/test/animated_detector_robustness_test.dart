// test/animated_detector_robustness_test.dart
// `isAnimatedUrl` now routes through the bounded fetch (shared client,
// deadline, range + maxBytes). Pin that it stays robust against a server that
// does not honour the Range the way rcrm does: a 200-Full (whole-file) answer
// must not hang or OOM, and a 404 must degrade to "not animated" rather than
// throw.

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/services/animated_detector.dart';
import 'package:rcrm_gui/services/net.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late HttpServer server;

  setUp(() async {
    HttpOverrides.global = null;
    setSharedAuth(null);
    server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  });

  tearDown(() async {
    setSharedAuth(null);
    await server.close(force: true);
  });

  // Strip a leading slash so `url('/x')` and `url('x')` both yield a single
  // slash — a double slash would make Uri.path == `//x` and break the server's
  // path match.
  String url(String name) =>
      'http://127.0.0.1:${server.port}/${name.startsWith('/') ? name.substring(1) : name}';

  test('isAnimatedUrl handles a 200-Full small body without hanging', () async {
    // A server that answers the 0-4095 range with 200 (whole file) instead of
    // 206 must still be handled — the fetch caps at maxBytes, not the status.
    server.listen((req) async {
      req.response.statusCode = 200;
      req.response.headers.set(HttpHeaders.contentLengthHeader, 4);
      req.response.add(const [1, 2, 3, 4]); // not a real animation marker
      await req.response.close();
    });
    expect(await isAnimatedUrl(url('/x.png')), isFalse);
  });

  test('isAnimatedUrl treats a 404 as "not animated", not a crash', () async {
    server.listen((req) async {
      req.response.statusCode = 404;
      await req.response.close();
    });
    expect(await isAnimatedUrl(url('/y.png')), isFalse);
  });
}
