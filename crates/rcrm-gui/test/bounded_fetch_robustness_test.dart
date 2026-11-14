// test/bounded_fetch_robustness_test.dart
// Robustness of the bounded fetch against servers that do NOT behave like our
// own WebDAV server. A compliant rcrm server answers a partial Range with 206,
// but other servers (cloud WebDAV, a misconfigured proxy) may answer a
// whole-file Range with 200, ignore the Range entirely and stream the full
// body, omit the Content-Length, or refuse the Range. These tests pin that
// `fetchBoundedBytes` / `fetchBoundedContentLength` cope — accept 200-Full,
// reject an oversized body at `maxBytes`, and never hand back the wrong bytes
// or go pending.
//
// This complements bounded_fetch_test.dart (which pins the stall/total deadlines
// and the production AuthImage call site); here the focus is Range handling,
// the maxBytes cap, and `fetchBoundedContentLength`.

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/services/bounded_fetch.dart';
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
  // slash — a double slash (`http://host//x`) would make Uri.path == `//x`,
  // breaking the server's path match and live_photo's companion derivation.
  String url(String name) =>
      'http://127.0.0.1:${server.port}/${name.startsWith('/') ? name.substring(1) : name}';

  // Serve [body] with [status] for [path]. HEAD requests get the headers but no
  // body. If [omitContentLength], no Content-Length is sent (chunked).
  void serve(
    String path,
    List<int> body, {
    int status = 200,
    bool omitContentLength = false,
  }) {
    server.listen((req) async {
      if (req.uri.path != path) {
        req.response.statusCode = 404;
        await req.response.close();
        return;
      }
      req.response.statusCode = status;
      if (!omitContentLength) {
        req.response.headers.set(HttpHeaders.contentLengthHeader, body.length);
      }
      if (req.method != 'HEAD') req.response.add(body);
      await req.response.close();
    });
  }

  group('Range handling', () {
    test('a 206 partial is returned whole', () async {
      serve('/partial', const [1, 2, 3, 4, 5], status: 206);
      final bytes = await fetchBoundedBytes(
        url('/partial'),
        range: 'bytes=0-4',
      );
      expect(bytes, orderedEquals(const [1, 2, 3, 4, 5]));
    });

    test('a whole-file Range answered with 200 is still accepted', () async {
      // rcrm's own server answers a Range that spans the whole file with 200
      // (RangeSpec::Full), not 206. The fetch must accept it — a 206-only guard
      // would wrongly reject every small-file range request. Regression for the
      // 206-only guard that was briefly in place.
      serve('/full', const [9, 8, 7, 6, 5], status: 200);
      final bytes = await fetchBoundedBytes(url('/full'), range: 'bytes=0-4');
      expect(bytes, orderedEquals(const [9, 8, 7, 6, 5]));
    });

    test('a range-ignoring server past maxBytes throws, not OOMs', () async {
      // The server ignores the Range and streams a 100 KB body; maxBytes=5 must
      // stop it before it is buffered into a Dart list.
      final huge = List<int>.filled(100 * 1024, 7);
      serve('/huge', huge, status: 200);
      await expectLater(
        fetchBoundedBytes(url('/huge'), range: 'bytes=0-4', maxBytes: 5),
        throwsA(isA<HttpException>()),
      );
    });

    test('a body whose length equals maxBytes is accepted', () async {
      // Boundary: a compliant 200-Full whose body length equals maxBytes must
      // not be rejected (the check is strict >, not >=).
      serve('/exact', const [1, 2, 3, 4, 5], status: 200);
      final bytes = await fetchBoundedBytes(
        url('/exact'),
        range: 'bytes=0-4',
        maxBytes: 5,
      );
      expect(bytes.length, 5);
    });

    test('truncateToMax keeps the head prefix when Range is ignored', () async {
      // A cloud WebDAV / proxy may ignore Range and stream the whole file with
      // 200. For a head probe the first maxBytes bytes ARE the answer; throwing
      // here used to make a real Motion Photo lose its LIVE badge.
      final huge = List<int>.generate(64 * 1024, (i) => i & 0xff);
      serve('/ignored-range', huge, status: 200);
      final bytes = await fetchBoundedBytes(
        url('/ignored-range'),
        range: 'bytes=0-4',
        maxBytes: 5,
        truncateToMax: true,
      );
      expect(bytes.length, 5);
      expect(bytes, orderedEquals(huge.sublist(0, 5)));
    });

    test('an unsatisfiable Range (416) is an exception', () async {
      serve('/toolong', const [1, 2, 3], status: 416);
      await expectLater(
        fetchBoundedBytes(url('/toolong'), range: 'bytes=0-2'),
        throwsA(isA<HttpException>()),
      );
    });
  });

  group('fetchBoundedContentLength', () {
    test('returns the Content-Length of a 200 response', () async {
      serve('/len5', const [0, 1, 2, 3, 4], status: 200);
      expect(await fetchBoundedContentLength(url('/len5')), 5);
    });

    test('uses HEAD, not GET', () async {
      String? method;
      server.listen((req) async {
        method = req.method;
        req.response.statusCode = 200;
        req.response.headers.set(HttpHeaders.contentLengthHeader, '5');
        await req.response.close();
      });
      await fetchBoundedContentLength(url('/head-check'));
      expect(method, 'HEAD');
    });

    test('a missing Content-Length yields 0, never a crash', () async {
      // Server answers 200 but sends no Content-Length (chunked). Callers treat
      // 0 as "cannot proceed" — it must not throw or return garbage.
      server.listen((req) async {
        req.response.statusCode = 200;
        if (req.method != 'HEAD') req.response.write('abc');
        await req.response.close();
      });
      expect(await fetchBoundedContentLength(url('/no-cl')), 0);
    });

    test('a 404 is an exception, not a silent 0', () async {
      serve('/boom', const [], status: 404);
      await expectLater(
        fetchBoundedContentLength(url('/boom')),
        throwsA(isA<HttpException>()),
      );
    });
  });
}
