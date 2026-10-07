// test/native_bytes_test.dart
// The copy-free fetch: media bytes land in NATIVE memory so the hand-off to
// Rust copies nothing. These tests read that buffer back through a view — the
// only place production never looks, because it hands the pointer straight over.

import 'dart:io';
import 'dart:math' as math;

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/services/native_bytes.dart';
import 'package:rcrm_gui/services/net.dart';

/// First index where the two differ, or -1 when they are equal.
int firstMismatch(List<int> a, List<int> b) {
  final n = math.min(a.length, b.length);
  for (var i = 0; i < n; i++) {
    if (a[i] != b[i]) return i;
  }
  return a.length == b.length ? -1 : n;
}

void main() {
  late HttpServer server;
  String? seenRange;
  String? seenAuth;

  setUp(() async {
    seenRange = null;
    seenAuth = null;
    server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  });

  tearDown(() async {
    setSharedAuth(null);
    await server.close(force: true);
  });

  /// Serves [body] in [chunks] separately-flushed pieces. With
  /// [declareLength] false the response goes out chunked (no Content-Length),
  /// which is the case the copy-free path must refuse.
  void serve(
    List<int> body, {
    int status = 200,
    int chunks = 1,
    bool declareLength = true,
  }) {
    server.listen((req) async {
      seenRange ??= req.headers.value(HttpHeaders.rangeHeader);
      seenAuth ??= req.headers.value(HttpHeaders.authorizationHeader);
      req.response.statusCode = status;
      if (status != 200) {
        await req.response.close();
        return;
      }
      if (declareLength) req.response.contentLength = body.length;
      if (body.isEmpty) {
        await req.response.close();
        return;
      }
      req.response.bufferOutput = false;
      final size = (body.length / chunks).ceil();
      for (var i = 0; i < body.length; i += size) {
        req.response.add(body.sublist(i, math.min(i + size, body.length)));
        await req.response.flush();
        await Future<void>.delayed(const Duration(milliseconds: 2));
      }
      await req.response.close();
    });
  }

  String url(String name) => 'http://127.0.0.1:${server.port}/$name';

  test('a declared length sizes the buffer exactly — no copy, no slack', () async {
    final body = List<int>.generate(256 * 1024, (i) => i % 251);
    serve(body, chunks: 6);

    final fetched = await fetchNativeBytes(url('whole.avif'));
    final bytes = fetched.bytes;
    expect(bytes, isNotNull);
    expect(fetched.retryWithCopy, isFalse);
    expect(bytes!.len, body.length);
    expect(bytes.cap, body.length, reason: 'exact sizing keeps len == cap');
    expect(firstMismatch(bytes.view, body), -1, reason: 'payload corrupted');
    bytes.free();
  });

  test('a head is capped at what was asked for', () async {
    final body = List<int>.generate(200 * 1024, (i) => i % 253);
    serve(body, chunks: 4);

    const head = 64 * 1024;
    final fetched = await fetchNativeBytes(url('head.avif'), headBytes: head);
    final bytes = fetched.bytes;
    expect(bytes, isNotNull);
    expect(bytes!.len, head);
    expect(bytes.cap, head);
    expect(firstMismatch(bytes.view, body.sublist(0, head)), -1);
    expect(seenRange, 'bytes=0-${head - 1}');
    bytes.free();
  });

  test('an unknown length is refused copy-free, not guessed', () async {
    // Chunked response: no Content-Length to size the buffer with, so the
    // caller must be told to use the copying path instead of getting a buffer
    // whose capacity disagrees with its length.
    serve(List<int>.generate(4096, (i) => i % 97), declareLength: false);

    final fetched = await fetchNativeBytes(url('chunked.avif'));
    expect(fetched.bytes, isNull);
    expect(fetched.retryWithCopy, isTrue);
  });

  test('a refused request is not retried with a copy', () async {
    serve(const [1, 2, 3], status: 404);
    final fetched = await fetchNativeBytes(url('missing.avif'));
    expect(fetched.bytes, isNull);
    expect(fetched.retryWithCopy, isFalse);
  });

  test('an empty body is an authoritative empty buffer', () async {
    serve(const []);
    final fetched = await fetchNativeBytes(url('empty.avif'));
    final bytes = fetched.bytes;
    expect(bytes, isNotNull);
    expect(bytes!.len, 0);
    bytes.free();
    bytes.free(); // idempotent
  });

  test('carries the shared auth header', () async {
    setSharedAuth({'Authorization': 'Basic dGVzdDp0ZXN0'});
    serve(const [0xff, 0xd8, 0xff, 0xd9]);

    final fetched = await fetchNativeBytes(url('auth.jpg'));
    expect(fetched.bytes, isNotNull);
    expect(seenAuth, 'Basic dGVzdDp0ZXN0');
    fetched.bytes!.free();
  });

  test('handing the buffer over stops this side freeing it', () async {
    serve(const [1, 2, 3, 4]);
    final fetched = await fetchNativeBytes(url('handover.jpg'));
    final bytes = fetched.bytes!;
    // What Rust does when it takes ownership; a later free() must be a no-op
    // rather than a double free.
    bytes.disown();
    bytes.free();
  });
}
