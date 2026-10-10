// test/bounded_fetch_test.dart
// The Dart-bytes fetch must be bounded end to end.
//
// `sharedHttpClient` bounds only the connect phase and pooled idle sockets, so a
// server that accepts the request, sends its headers and then goes silent used to
// leave `AuthImage`/the viewer (and `DiskThumbImage`'s fallback) pending forever:
// no bytes, no error, no `PooledImage.onError` — and therefore never a
// `ImageLoadGate` token released. Two such cells wedge the whole image wall
// (mobile gate = 2). These tests pin the two things that fix depends on: a
// stalled body ends in an exception, and the production call site really raises
// it.

import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart' show consolidateHttpClientResponseBytes;
import 'package:flutter/painting.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/services/bounded_fetch.dart';
import 'package:rcrm_gui/services/image_load_gate.dart';
import 'package:rcrm_gui/services/item_cache_limit.dart';
import 'package:rcrm_gui/services/net.dart';
import 'package:rcrm_gui/widgets/auth_image.dart';

void main() {
  // Needed for the `AuthImage` case at the bottom (an ImageProvider resolves
  // through `PaintingBinding`), and the binding installs a mock `HttpClient`
  // factory that answers 400 to every request — undone per test below, because
  // these tests talk to a real loopback server.
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

  String url(String name) => 'http://127.0.0.1:${server.port}/$name';

  /// Serves [body] in one piece.
  void serve(List<int> body) {
    server.listen((req) async {
      req.response.statusCode = 200;
      req.response.contentLength = body.length;
      req.response.add(body);
      await req.response.close();
    });
  }

  /// Declares a length, sends [firstChunk] and then goes quiet forever: no more
  /// bytes and no end of body. This is the shape that used to hang.
  void serveAndStall(List<int> firstChunk, int declared) {
    server.listen((req) async {
      req.response.statusCode = 200;
      req.response.contentLength = declared;
      req.response.bufferOutput = false;
      req.response.add(firstChunk);
      await req.response.flush();
      // Never closes.
    });
  }

  test('a complete body comes back whole', () async {
    final body = List<int>.generate(64 * 1024, (i) => i % 251);
    serve(body);

    final bytes = await fetchBoundedBytes(url('whole.jpg'));
    expect(bytes.length, body.length);
    expect(bytes, orderedEquals(body));
  });

  test('a refusal is an exception, not an empty body', () async {
    server.listen((req) async {
      req.response.statusCode = 404;
      await req.response.close();
    });

    await expectLater(
      fetchBoundedBytes(url('missing.jpg')),
      throwsA(isA<HttpException>()),
    );
  });

  test('carries the shared auth header', () async {
    String? seen;
    server.listen((req) async {
      seen = req.headers.value(HttpHeaders.authorizationHeader);
      req.response.statusCode = 200;
      req.response.contentLength = 3;
      req.response.add(const [1, 2, 3]);
      await req.response.close();
    });
    setSharedAuth({'Authorization': 'Basic dGVzdDp0ZXN0'});

    expect((await fetchBoundedBytes(url('a.jpg'))).length, 3);
    expect(seen, 'Basic dGVzdDp0ZXN0');
  });

  group('deadlines', () {
    test('headers then silence gives up on the stall timeout', () async {
      const stall = Duration(milliseconds: 150);
      serveAndStall(const [1, 2, 3, 4], 1 << 20);

      final started = DateTime.now();
      await expectLater(
        fetchBoundedBytes(
          url('stalled.jpg'),
          stallTimeout: stall,
          totalTimeout: const Duration(seconds: 5),
        ),
        throwsA(isA<TimeoutException>()),
      );
      expect(
        DateTime.now().difference(started),
        lessThan(const Duration(seconds: 3)),
        reason: 'gave up on the stall timeout, not on some outer deadline',
      );
    });

    test('a body that trickles past the total deadline stops too', () async {
      // One byte at a time: never silent long enough to trip the stall timeout,
      // so only the total deadline can end this request.
      server.listen((req) async {
        req.response.statusCode = 200;
        req.response.contentLength = 1 << 20;
        req.response.bufferOutput = false;
        for (var i = 0; i < 200; i++) {
          req.response.add(const [7]);
          await req.response.flush();
          await Future<void>.delayed(const Duration(milliseconds: 5));
        }
      });

      await expectLater(
        fetchBoundedBytes(
          url('trickle.jpg'),
          stallTimeout: const Duration(seconds: 2),
          totalTimeout: const Duration(milliseconds: 150),
        ),
        throwsA(isA<TimeoutException>()),
      );
    });

    test('a slow but complete body still succeeds', () async {
      // The deadlines must not reject a legitimately slow LAN transfer.
      final body = List<int>.generate(32 * 1024, (i) => i % 241);
      server.listen((req) async {
        req.response.statusCode = 200;
        req.response.contentLength = body.length;
        req.response.bufferOutput = false;
        for (var i = 0; i < body.length; i += 4096) {
          req.response.add(body.sublist(i, i + 4096));
          await req.response.flush();
          await Future<void>.delayed(const Duration(milliseconds: 10));
        }
        await req.response.close();
      });

      final bytes = await fetchBoundedBytes(
        url('slow.jpg'),
        stallTimeout: const Duration(seconds: 5),
        totalTimeout: const Duration(seconds: 30),
      );
      expect(bytes, orderedEquals(body));
    });
  });

  group('the fixture really stalls (control for the tests above)', () {
    // Without this, "throws a TimeoutException" could pass on a server that
    // simply answered. The reproduced shape is what both call sites used before
    // the fix — `getUrl` → `close` → `consolidateHttpClientResponseBytes`, with
    // no deadline on any of the three — so this also documents what the pre-fix
    // failure looked like: it never errors and never completes.
    test('the unbounded shape is still pending after the bound fetch gave up',
        () async {
      serveAndStall(const [1, 2, 3, 4], 1 << 20);

      var oldShapeSettled = false;
      unawaited(
        () async {
          final req = await sharedHttpClient.getUrl(Uri.parse(url('old.jpg')));
          final resp = await req.close();
          if (resp.statusCode != 200) {
            throw HttpException('HTTP ${resp.statusCode}');
          }
          await consolidateHttpClientResponseBytes(resp);
        }().then(
          (_) => oldShapeSettled = true,
          onError: (Object _) => oldShapeSettled = true,
        ),
      );

      await expectLater(
        fetchBoundedBytes(
          url('old.jpg'),
          stallTimeout: const Duration(milliseconds: 150),
          totalTimeout: const Duration(seconds: 5),
        ),
        throwsA(isA<TimeoutException>()),
      );
      expect(
        oldShapeSettled,
        isFalse,
        reason: 'the unbounded fetch is still pending: a stalled body has no '
            'deadline of its own',
      );
    });
  });

  group('the production call site', () {
    // The production stall deadline is 15s and is deliberately not injectable
    // (a test hook there would be a production branch in the image path), so
    // this one test pays that deadline for real. It is worth it: it is the only
    // place that proves the *provider* a grid cell uses gives up, rather than
    // just the helper underneath it — and it is the assertion that fails on the
    // pre-fix code, where `AuthImage._load` never errors at all.
    test(
      'AuthImage turns a stalled body into an error and leaves the gate intact',
      () async {
        serveAndStall(const [1, 2, 3, 4], 1 << 20);

        Object? error;
        final got = Completer<void>();
        final listener = ImageStreamListener(
          (_, _) {},
          onError: (Object e, StackTrace? _) {
            error = e;
            if (!got.isCompleted) got.complete();
          },
        );
        final stream = AuthImage(
          url('stalled.jpg'),
          targetWidth: 64,
        ).resolve(const ImageConfiguration());
        stream.addListener(listener);
        try {
          await got.future.timeout(const Duration(seconds: 20));
        } finally {
          stream.removeListener(listener);
        }

        expect(error, isA<TimeoutException>());
        // `PooledImage.onError` is what releases the cell's token; the token is
        // the reason the hang wedged the wall, so prove the gate can still hand
        // out every slot it owns.
        final tokens = [
          for (var i = 0; i < ItemCacheLimit.imageDecodeConcurrency; i++)
            ImageLoadGate.instance.acquire(),
        ];
        expect(
          tokens.every((t) => t.isCompleted),
          isTrue,
          reason: 'a stalled fetch is holding a decode slot',
        );
        for (final t in tokens) {
          ImageLoadGate.instance.done(t);
        }
      },
      timeout: const Timeout(Duration(seconds: 45)),
    );
  });
}
