// test/native_bytes_test.dart
// The copy-free fetch: media bytes land in NATIVE memory so the hand-off to
// Rust copies nothing. These tests read that buffer back through a view — the
// only place production never looks, because it hands the pointer straight over.

import 'dart:ffi';
import 'dart:io';
import 'dart:math' as math;

import 'package:ffi/ffi.dart';
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
  String? seenQuery;

  setUp(() async {
    seenRange = null;
    seenAuth = null;
    seenQuery = null;
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

  test(
    'a declared length sizes the buffer exactly — no copy, no slack',
    () async {
      final body = List<int>.generate(256 * 1024, (i) => i % 251);
      serve(body, chunks: 6);

      final fetched = await fetchNativeBytes(url('whole.avif'));
      final bytes = fetched.bytes;
      expect(bytes, isNotNull);
      expect(fetched.retryWithCopy, isFalse);
      expect(bytes!.len, body.length);
      // "No slack" is now a property of the hand-off rather than of a number
      // this test can read: only a buffer whose allocation is exactly its payload
      // can produce a transfer at all.
      final transfer = bytes.transferIfWhole();
      expect(transfer, isNotNull, reason: 'len == cap, so it may go to Rust');
      expect(transfer!.len, body.length);
      expect(firstMismatch(bytes.view, body), -1, reason: 'payload corrupted');
      bytes.free();
    },
  );

  test('a head is capped at what was asked for', () async {
    final body = List<int>.generate(200 * 1024, (i) => i % 253);
    serve(body, chunks: 4);

    const head = 64 * 1024;
    final fetched = await fetchNativeBytes(url('head.avif'), headBytes: head);
    final bytes = fetched.bytes;
    expect(bytes, isNotNull);
    expect(bytes!.len, head);
    // The allocation IS the ask here, so this head happens to be whole too —
    // but a head the server fills only part way would not be (next test).
    expect(bytes.transferIfWhole(), isNotNull);
    expect(firstMismatch(bytes.view, body.sublist(0, head)), -1);
    expect(seenRange, 'bytes=0-${head - 1}');
    bytes.free();
  });

  group('the transfer shape is a whole-file buffer or nothing', () {
    // What `media_metadata.dart` fetches: a fixed-size allocation the server
    // may fill only part way. The ABI rebuilds its `Vec` from the length alone,
    // so this buffer's real size is larger than what would be sent — exactly
    // the mismatch that must be impossible to hand over.
    test('a partly filled allocation refuses to transfer', () {
      final partial = NativeBytes(calloc<Uint8>(4096), 100, 4096);
      partial.view.setAll(0, List<int>.filled(100, 7));
      expect(
        partial.transferIfWhole(),
        isNull,
        reason: 'a partial buffer has no honest length to send',
      );
      // The refusal is not a free: the buffer is still this side's to release,
      // which is the "not reusable, retry later" path, not a leak.
      partial.free();
    });

    test('a whole-file buffer transfers, and disowning seals it', () {
      final whole = NativeBytes(calloc<Uint8>(100), 100, 100);
      final transfer = whole.transferIfWhole();
      expect(transfer, isNotNull);
      expect(transfer!.len, 100);
      expect(transfer.ptr.address, whole.ptr.address);
      // Every ownership-taking export disowns before it calls, because Rust
      // frees the buffer on all of its paths. The transfer mirrors that, and a
      // later free (here, the caller's) must stay a no-op rather than be a
      // double free. Nothing frees the block after the disown — in production
      // Rust does, and this side must never race it.
      transfer.disown();
      transfer.free();
      transfer.free();
    });
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

  test('an already percent-encoded URL is not encoded a second time', () async {
    // The cast receiver's proxy hands over a URL whose query is ALREADY
    // percent-encoded (`cast_receiver.dart:637-638` builds
    // `?path=${Uri.encodeQueryComponent(path)}`), so this is the exact shape
    // every cast image arrives in. Re-encoding it (`Uri.encodeFull`) escaped
    // the `%` of every `%2F` into `%252F`; on the wire that stopped decoding as
    // `/photos/IMG_1234.avif`, the proxy's `startsWith('/')` check answered 400,
    // and the copy-free path was never taken for ANY cast image.
    const query = 'path=%2Fphotos%2FIMG_1234.avif';
    final body = List<int>.generate(4096, (i) => i % 239);
    server.listen((req) async {
      seenQuery = req.uri.query;
      req.response.statusCode = 200;
      req.response.contentLength = body.length;
      req.response.add(body);
      await req.response.close();
    });

    final fetched = await fetchNativeBytes(
      'http://127.0.0.1:${server.port}/stream?$query',
    );
    expect(
      seenQuery,
      query,
      reason: 'the wire must carry %2F, not the double-encoded %252F',
    );
    final bytes = fetched.bytes;
    expect(bytes, isNotNull, reason: 'a normal 200 must still yield bytes');
    expect(firstMismatch(bytes!.view, body), -1);
    bytes.free();
  });

  test(
    'a canonical percent sequence in the path is not decoded again',
    () async {
      // `MediaItem.url` stores a file literally named `foo%20bar.wmv` as
      // `foo%2520bar.wmv`. Parsing that URL must NOT turn it back into a
      // space before the request is sent.
      String? seenPath;
      final body = List<int>.generate(128, (i) => i);
      server.listen((req) async {
        seenPath = req.uri.path;
        req.response.statusCode = 200;
        req.response.contentLength = body.length;
        req.response.add(body);
        await req.response.close();
      });

      final fetched = await fetchNativeBytes(url('foo%2520bar.wmv'));
      expect(seenPath, '/foo%2520bar.wmv');
      final bytes = fetched.bytes;
      expect(bytes, isNotNull);
      bytes!.free();
    },
  );

  test('handing the buffer over stops this side freeing it', () async {
    serve(const [1, 2, 3, 4]);
    final fetched = await fetchNativeBytes(url('handover.jpg'));
    final bytes = fetched.bytes!;
    // What Rust does when it takes ownership; a later free() must be a no-op
    // rather than a double free.
    bytes.disown();
    bytes.free();
  });

  group('deadlines (a silent server must not pin a decode slot)', () {
    /// Accepts the request, declares a length, sends [firstChunk] bytes and then
    /// goes quiet forever — the shape that used to hang the whole thumbnail grid,
    /// because the caller holds an ImageLoadGate token across this fetch.
    void serveAndStall(List<int> firstChunk, int declared) {
      server.listen((req) async {
        req.response.statusCode = 200;
        req.response.contentLength = declared;
        req.response.bufferOutput = false;
        req.response.add(firstChunk);
        await req.response.flush();
        // Never closes: no more bytes, no end of body.
      });
    }

    test('a stalled body gives up instead of hanging', () async {
      const stall = Duration(milliseconds: 150);
      serveAndStall(const [1, 2, 3, 4], 1024);

      final started = DateTime.now();
      final fetched = await fetchNativeBytes(
        url('stalled.avif'),
        stallTimeout: stall,
        totalTimeout: const Duration(seconds: 5),
      );
      final elapsed = DateTime.now().difference(started);

      expect(fetched.bytes, isNull, reason: 'no full buffer was produced');
      // `refused` (not `unsized`): a silent server must not send the caller
      // straight into a second fetch of the same wedged URL — that used to be
      // how one stall turned into two, both holding decode slots.
      expect(fetched.retryWithCopy, isFalse);
      expect(
        elapsed,
        lessThan(const Duration(seconds: 3)),
        reason: 'gave up on the stall timeout, not on some outer deadline',
      );
    });

    test('a body that trickles past the total deadline stops too', () async {
      // One byte per tick: never silent long enough to trip the stall timeout,
      // so only the total deadline can end it.
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

      final fetched = await fetchNativeBytes(
        url('trickle.avif'),
        stallTimeout: const Duration(seconds: 2),
        totalTimeout: const Duration(milliseconds: 150),
      );
      expect(fetched.bytes, isNull);
      expect(fetched.retryWithCopy, isFalse);
    });

    test('a slow but complete body still succeeds', () async {
      // The deadlines must not reject a legitimately slow LAN transfer.
      final body = List<int>.generate(64 * 1024, (i) => i % 241);
      serve(body, chunks: 8);

      final fetched = await fetchNativeBytes(
        url('slow.avif'),
        stallTimeout: const Duration(seconds: 5),
        totalTimeout: const Duration(seconds: 30),
      );
      expect(fetched.bytes, isNotNull);
      expect(firstMismatch(fetched.bytes!.view, body), -1);
      fetched.bytes!.free();
    });
  });
}
