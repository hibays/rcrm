// test/webdav_head_test.dart
// `WebDavClient.getFileHead` — the doctor panel's sample check.
//
// The check has to prove the decrypt → serve → fetch path works, and it does that
// with the FIRST 64 KiB of one file. It used to call `getFile`, which reads the
// whole body: on a video library that is an entire video pulled through the
// decrypting server and into Dart memory — while the user is looking at the page
// the panel is supposed to be diagnosing (and only to print its length).
//
// The bound has to hold against a server that does not cooperate: our own server
// answers 206 to a Range request, but a cloud WebDAV may answer 200 and start
// streaming the whole file. So the read stops at N bytes and CANCELS the
// subscription, which is what stops the server's decryption too. Both halves are
// pinned here against a real loopback server, because that cancellation is the
// part a mock would not show.

import 'dart:async';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart' show IOClient;

import 'package:rcrm_gui/services/net.dart';
import 'package:rcrm_gui/services/webdav_client.dart';

/// Counts the body bytes the app actually pulls into Dart.
///
/// This is the quantity that matters: a short result would also come out of an
/// implementation that read the whole file and truncated it, and on a video
/// library "the whole file" is the freeze.
class _CountingClient extends http.BaseClient {
  _CountingClient(this._inner);
  final http.Client _inner;
  int received = 0;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final r = await _inner.send(request);
    final counted = r.stream.map((chunk) {
      received += chunk.length;
      return chunk;
    });
    return http.StreamedResponse(
      counted,
      r.statusCode,
      contentLength: r.contentLength,
      request: r.request,
      headers: r.headers,
      reasonPhrase: r.reasonPhrase,
    );
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late HttpServer server;

  setUp(() async {
    HttpOverrides.global = null;
    server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  });

  tearDown(() async {
    await server.close(force: true);
  });

  WebDavClient client() =>
      WebDavClient(baseUrl: 'http://127.0.0.1:${server.port}');

  test('pulls the head into Dart, not the file', () async {
    // 4 MiB offered as 64 chunks of 64 KiB behind a 200 (Range ignored) — a
    // cloud WebDAV's answer, and the shape that used to end up in memory.
    const chunks = 64;
    const chunkBytes = 64 * 1024;
    final serverDone = Completer<void>();
    server.listen((req) async {
      req.response.statusCode = 200;
      req.response.contentLength = chunks * chunkBytes;
      req.response.bufferOutput = false;
      final chunk = List<int>.filled(chunkBytes, 7);
      for (var i = 0; i < chunks; i++) {
        req.response.add(chunk);
        await req.response.flush();
      }
      await req.response.close();
      if (!serverDone.isCompleted) serverDone.complete();
    });

    final counting = _CountingClient(IOClient(createTrustAwareHttpClient()));
    final c = WebDavClient(
      baseUrl: 'http://127.0.0.1:${server.port}',
      client: counting,
    );

    final started = DateTime.now();
    final head = await c.getFileHead('/big.mp4', maxBytes: 64 * 1024);
    final elapsed = DateTime.now().difference(started);

    expect(head, isNotNull);
    expect(head!.length, 64 * 1024, reason: 'exactly the head, not the file');
    expect(
      counting.received,
      lessThanOrEqualTo(256 * 1024),
      reason:
          'the read stopped at the head — an implementation that read the whole '
          '4 MiB body and truncated it would show ~4 MiB here',
    );
    expect(
      elapsed,
      lessThan(const Duration(seconds: 2)),
      reason: 'the server had 4 MiB to send; the client did not wait for it',
    );
    counting.close();
    await serverDone.future.timeout(const Duration(seconds: 10));
  });

  test('a Range-honouring server is asked for exactly the head', () async {
    String? range;
    server.listen((req) async {
      range = req.headers.value(HttpHeaders.rangeHeader);
      req.response.statusCode = 206;
      req.response.contentLength = 4;
      req.response.add(const [1, 2, 3, 4]);
      await req.response.close();
    });

    final head = await client().getFileHead('/x.jpg', maxBytes: 4096);

    expect(range, 'bytes=0-4095');
    expect(head, orderedEquals(const [1, 2, 3, 4]));
  });

  test('a short file comes back whole', () async {
    server.listen((req) async {
      req.response.statusCode = 206;
      req.response.contentLength = 3;
      req.response.add(const [9, 8, 7]);
      await req.response.close();
    });

    expect(
      await client().getFileHead('/tiny.jpg', maxBytes: 64 * 1024),
      orderedEquals(const [9, 8, 7]),
    );
  });

  test('a refusal is null, not an exception to a health panel', () async {
    server.listen((req) async {
      req.response.statusCode = 404;
      await req.response.close();
    });

    expect(await client().getFileHead('/missing.mp4', maxBytes: 1024), isNull);
  });

  test('carries the client\'s own auth header', () async {
    String? seen;
    server.listen((req) async {
      seen = req.headers.value(HttpHeaders.authorizationHeader);
      req.response.statusCode = 206;
      req.response.contentLength = 1;
      req.response.add(const [1]);
      await req.response.close();
    });

    final c = WebDavClient(
      baseUrl: 'http://127.0.0.1:${server.port}',
      username: 'u',
      password: 'p',
    );
    await c.getFileHead('/a.jpg', maxBytes: 16);

    expect(seen, startsWith('Basic '));
  });
}
