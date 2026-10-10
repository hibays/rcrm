// test/media_metadata_test.dart
// The JSON contract between the Rust metadata parser (nom-exif) and the UI.
// The sample below is the exact shape `rcrm_media_metadata_async` returns.

import 'dart:ffi';
import 'dart:io';
import 'dart:math' as math;

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/services/media_metadata.dart';
import 'package:rcrm_gui/services/net.dart';

const _imageJson =
    '{"kind":"image","exif":{"make":"vivo","model":"X100 Pro",'
    '"lens":"Vario-Test 26mm","software":"rcrm-test",'
    '"capturedAt":"2026-09-30 02:24:11","iso":100,"fNumber":1.8,'
    '"exposureTime":0.004,"focalLength":26.0,"focalLength35mm":24,'
    '"orientation":6,"pixelWidth":1440,"pixelHeight":1000,'
    '"gps":{"lat":22.5,"lon":114.05,"altitude":12.3}}}';

const _trackJson =
    '{"kind":"track","track":{"make":"Apple","model":"iPhone 15",'
    '"author":"hibays","durationMs":65000,"width":1920,"height":1080,'
    '"createdAt":"2026-01-02 03:04:05"}}';

void main() {
  group('MediaMetadata.fromJsonString', () {
    test('reads the image document', () {
      final meta = MediaMetadata.fromJsonString(_imageJson);
      expect(meta.isImage, isTrue);
      final exif = meta.exif!;
      expect(exif.make, 'vivo');
      expect(exif.model, 'X100 Pro');
      expect(exif.lens, 'Vario-Test 26mm');
      expect(exif.iso, 100);
      expect(exif.fNumber, closeTo(1.8, 1e-9));
      expect(exif.exposureTime, closeTo(0.004, 1e-9));
      expect(exif.focalLength, closeTo(26, 1e-9));
      expect(exif.focalLength35mm, 24);
      expect(exif.orientation, 6);
      expect(exif.hasPixelSize, isTrue);
      expect(exif.capturedAt, DateTime(2026, 9, 30, 2, 24, 11));
      expect(exif.hasLocation, isTrue);
      expect(exif.latitude, closeTo(22.5, 1e-9));
      expect(exif.longitude, closeTo(114.05, 1e-9));
      expect(exif.altitude, closeTo(12.3, 1e-9));
      expect(exif.hasCamera, isTrue);
      expect(exif.hasExposure, isTrue);
    });

    test('reads the track document', () {
      final meta = MediaMetadata.fromJsonString(_trackJson);
      expect(meta.isTrack, isTrue);
      final track = meta.track!;
      expect(track.make, 'Apple');
      expect(track.model, 'iPhone 15');
      expect(track.durationMs, 65000);
      expect(track.width, 1920);
      expect(track.createdAt, DateTime(2026, 1, 2, 3, 4, 5));
      expect(track.hasAny, isTrue);
      expect(meta.exif, isNull);
    });

    test('an image with no EXIF is not a failure', () {
      final meta = MediaMetadata.fromJsonString('{"kind":"image"}');
      expect(meta.isImage, isTrue);
      expect(meta.exif, isNull);
      expect(meta.imageWithoutCamera, isTrue);
    });

    test('unidentifiable bytes come back as unknown', () {
      final meta = MediaMetadata.fromJsonString(
        '{"kind":"unknown","error":"unsupported format"}',
      );
      expect(meta.kind, 'unknown');
      expect(meta.isImage, isFalse);
      expect(meta.imageWithoutCamera, isFalse);
      expect(meta.error, 'unsupported format');
    });

    test('garbage never throws', () {
      expect(MediaMetadata.fromJsonString('not json').kind, 'unknown');
      expect(MediaMetadata.fromJsonString('').kind, 'unknown');
      expect(MediaMetadata.fromJsonString(null).kind, 'unknown');
      // Wrong types inside a valid document must not blow up either.
      final meta = MediaMetadata.fromJsonString(
        '{"kind":"image","exif":{"make":42,"iso":"high","gps":"nope"}}',
      );
      expect(meta.kind, 'image');
      expect(meta.exif?.make, isNull);
      expect(meta.exif?.iso, isNull);
      expect(meta.exif?.hasLocation, isFalse);
    });

    test('parsed distinguishes a real answer from a failed one', () {
      // Identified and read: the UI may state absences.
      expect(MediaMetadata.fromJsonString('{"kind":"image"}').parsed, isTrue);
      expect(
        MediaMetadata.fromJsonString(
          '{"kind":"track","track":{"make":"Apple"}}',
        ).parsed,
        isTrue,
      );
      // A parse that failed, an unidentifiable container, and a fetch that
      // never produced bytes must all stay silent instead.
      expect(
        MediaMetadata.fromJsonString('{"kind":"image","error":"bad"}').parsed,
        isFalse,
      );
      expect(
        MediaMetadata.fromJsonString('{"kind":"unknown","error":"x"}').parsed,
        isFalse,
      );
      expect(MediaMetadata.none.parsed, isFalse);
    });

    test('stored dimensions alone are not camera information', () {
      final dimsOnly = MediaMetadata.fromJsonString(
        '{"kind":"image","exif":{"pixelWidth":4000,"pixelHeight":3000}}',
      ).exif!;
      expect(dimsOnly.hasPixelSize, isTrue);
      // The camera block has nothing to render, so it must not claim to have
      // something (it lives in the technical line instead).
      expect(dimsOnly.hasCamera, isFalse);
      expect(dimsOnly.hasExposure, isFalse);
    });
  });

  group('ExifInfo.cameraName', () {
    test('joins make and model', () {
      final exif = MediaMetadata.fromJsonString(
        '{"kind":"image","exif":{"make":"Xiaomi","model":"M2007J3SC"}}',
      ).exif!;
      expect(exif.cameraName, 'Xiaomi M2007J3SC');
    });

    test('does not repeat a make the model already carries', () {
      final exif = MediaMetadata.fromJsonString(
        '{"kind":"image","exif":{"make":"vivo","model":"vivo X100 Pro"}}',
      ).exif!;
      expect(exif.cameraName, 'vivo X100 Pro');
    });

    test('falls back to whichever half exists', () {
      final only = MediaMetadata.fromJsonString(
        '{"kind":"image","exif":{"model":"Pixel 8"}}',
      ).exif!;
      expect(only.cameraName, 'Pixel 8');
    });
  });

  group('MediaMetadataService', () {
    test('caches per url and kind, and clears on demand', () async {
      MediaMetadataService.clearCache();
      // No server here: the call resolves to an empty result rather than
      // throwing, and the second call must reuse the same future.
      final first = MediaMetadataService.forUrl('http://127.0.0.1:1/x.jpg');
      final second = MediaMetadataService.forUrl('http://127.0.0.1:1/x.jpg');
      expect(identical(first, second), isTrue);
      final other = MediaMetadataService.forUrl(
        'http://127.0.0.1:1/x.jpg',
        kind: MetadataKind.track,
      );
      expect(identical(first, other), isFalse);
      expect((await first).kind, 'unknown');
    });

    test('a failed fetch is not remembered as a fact', () async {
      MediaMetadataService.clearCache();
      final failed = MediaMetadataService.forUrl('http://127.0.0.1:1/y.jpg');
      expect((await failed).kind, 'unknown');
      // Nothing was learned about this file, so the next open must ask again
      // instead of serving the failure for the rest of the session.
      final retry = MediaMetadataService.forUrl('http://127.0.0.1:1/y.jpg');
      expect(identical(failed, retry), isFalse);
      expect((await retry).kind, 'unknown');
    });

    test('a new library cannot be served the previous answers', () async {
      // The doc used to promise invalidation "when the library is re-scanned" while
      // nothing ever called clearCache. The library identity is part of the cache key
      // now, so switching libraries (or re-scanning) invalidates by itself — there is
      // no hook left to forget.
      MediaMetadataService.setLibraryIdentity('serverA|/media');
      final a1 = MediaMetadataService.forUrl('http://127.0.0.1:1/z.jpg');
      expect(
        identical(a1, MediaMetadataService.forUrl('http://127.0.0.1:1/z.jpg')),
        isTrue,
        reason: 'same library, same file: one fetch',
      );

      // Re-declaring the same identity must not throw the cache away.
      MediaMetadataService.setLibraryIdentity('serverA|/media');
      expect(
        identical(a1, MediaMetadataService.forUrl('http://127.0.0.1:1/z.jpg')),
        isTrue,
      );

      // Another library: the URL means something else now, so the old answer must
      // not be served — and the old future still resolves for whoever holds it.
      MediaMetadataService.setLibraryIdentity('serverB|/media');
      expect(
        identical(a1, MediaMetadataService.forUrl('http://127.0.0.1:1/z.jpg')),
        isFalse,
      );
      expect((await a1).kind, 'unknown');
    });
  });

  group('MetadataKind', () {
    test('codes match the Rust side', () {
      expect(MetadataKind.auto.code, 0);
      expect(MetadataKind.image.code, 1);
      expect(MetadataKind.track.code, 2);
    });
  });

  group('MediaMetadataService head fetch (native memory)', () {
    // The hand-off to Rust copies nothing because the head never exists on the
    // Dart heap: the network writes it straight into the buffer Rust reads.
    // These tests can only see that buffer through the test hook, which is the
    // point — production hands it over and never looks at it again.
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

    /// Serves [body] in [chunks] separately-flushed pieces, so the client's
    /// streaming loop really does see several chunks.
    void serve(List<int> body, {int status = 200, int chunks = 1}) {
      server.listen((req) async {
        seenRange ??= req.headers.value(HttpHeaders.rangeHeader);
        seenAuth ??= req.headers.value(HttpHeaders.authorizationHeader);
        req.response.statusCode = status;
        if (status != 200 || body.isEmpty) {
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

    /// First index where the two differ, or -1.
    int firstMismatch(List<int> a, List<int> b) {
      final n = math.min(a.length, b.length);
      for (var i = 0; i < n; i++) {
        if (a[i] != b[i]) return i;
      }
      return a.length == b.length ? -1 : n;
    }

    test('a multi-chunk head lands byte-for-byte in native memory', () async {
      final body = List<int>.generate(300 * 1024, (i) => i % 251);
      serve(body, chunks: 5);

      final head = await MediaMetadataService.fetchHead(url('multi.jpg'));
      expect(head, isNotNull);
      expect(head!.len, body.length);
      final landed = head.ptr.asTypedList(head.len);
      expect(firstMismatch(landed, body), -1, reason: 'payload was corrupted');
      head.free();
    });

    test(
      'the head stops at the cap instead of buffering the whole file',
      () async {
        // The ask is 4 MiB; the file is bigger, so the Range request is what
        // bounds the transfer — and the allocation is exactly the ask, which is
        // the shape the FFI hand-off requires.
        final body = List<int>.generate(
          MediaMetadataService.maxFetchBytes + 5000,
          (i) => i % 253,
        );
        serve(body, chunks: 8);

        final head = await MediaMetadataService.fetchHead(url('huge.tif'));
        expect(head, isNotNull);
        expect(head!.len, MediaMetadataService.maxFetchBytes);
        expect(head.transferIfWhole(), isNotNull);
        final landed = head.ptr.asTypedList(head.len);
        expect(firstMismatch(landed, body.sublist(0, head.len)), -1);
        head.free();
      },
    );

    test('a refused request is a retryable non-answer', () async {
      serve(const [1, 2, 3], status: 404);
      expect(await MediaMetadataService.fetchHead(url('missing.jpg')), isNull);
    });

    test('an empty body is an authoritative empty head', () async {
      serve(const []);
      final head = await MediaMetadataService.fetchHead(url('empty.jpg'));
      expect(head, isNotNull);
      expect(head!.len, 0);
      head.free();
      head.free(); // idempotent
    });

    test('asks for a bounded range and carries the auth header', () async {
      setSharedAuth({'Authorization': 'Basic dGVzdDp0ZXN0'});
      serve(const [0xff, 0xd8, 0xff, 0xd9]);

      final head = await MediaMetadataService.fetchHead(url('auth.jpg'));
      expect(head, isNotNull);
      expect(seenRange, 'bytes=0-${MediaMetadataService.maxFetchBytes - 1}');
      expect(seenAuth, 'Basic dGVzdDp0ZXN0');
      head!.free();
    });
  });
}
