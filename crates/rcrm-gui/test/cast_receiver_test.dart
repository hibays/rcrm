// test/cast_receiver_test.dart
// End-to-end tests for the TV-side cast receiver: TLS control server,
// pair/claim handshake, session auth, and the media proxy (Range passthrough
// with certificate pinning against an upstream HTTPS server).

import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/ffi/rust_bridge.dart';
import 'package:rcrm_gui/services/cast_protocol.dart';
import 'package:rcrm_gui/services/cast_receiver.dart';

const _certDir = 'test/cert_pinning';

String _pemSha1(String pemPath) {
  final pem = File(pemPath).readAsStringSync();
  final body = pem
      .replaceAll('-----BEGIN CERTIFICATE-----', '')
      .replaceAll('-----END CERTIFICATE-----', '')
      .replaceAll(RegExp(r'\s'), '');
  return sha1.convert(base64Decode(body)).toString();
}

String _hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

class _FakePlayerHost implements CastPlayerHost {
  final List<String> log = [];
  final List<int> seeks = [];

  @override
  Future<void> play(String streamUrl, {bool isImage = false}) async =>
      log.add('play:$streamUrl${isImage ? ':image' : ''}');

  @override
  Future<void> pause() async => log.add('pause');

  @override
  Future<void> resume() async => log.add('resume');

  @override
  Future<void> seek(Duration position) async {
    log.add('seek:${position.inMilliseconds}');
    seeks.add(position.inMilliseconds);
  }

  @override
  Future<void> stopPlayback() async => log.add('stop');

  @override
  Future<void> setVolume(int level) async => log.add('volume:$level');

  @override
  Future<void> setRate(double rate) async => log.add('rate:$rate');
}

void main() {
  late Directory tmpDir;
  late CastReceiver receiver;
  late _FakePlayerHost host;
  late HttpClient trustedClient;

  setUp(() async {
    tmpDir = await Directory.systemTemp.createTemp('cast_receiver_test');
    // Reuse the pre-generated self-signed test certificates. The receiver
    // loads cert.pem/key.pem from its identity dir when both exist.
    File('$_certDir/cert1.pem').copySync('${tmpDir.path}/cast_cert.pem');
    File('$_certDir/key1.pem').copySync('${tmpDir.path}/cast_key.pem');
    host = _FakePlayerHost();
    receiver = CastReceiver(
      playerHost: host,
      rustBridge: RustBridge(), // identity files exist, so FFI is never hit
    );
    await receiver.start(tmpDir.path);
    // Client that pins cert1 (the receiver's identity) by fingerprint — the
    // test certs have CN=localhost with no IP SAN, so hostname verification
    // would fail; pinning mirrors the real phone-side policy anyway.
    final cert1Sha1 = _pemSha1('$_certDir/cert1.pem');
    final c = HttpClient();
    c.badCertificateCallback = (cert, host, port) =>
        _hex(cert.sha1) == cert1Sha1;
    c.connectionTimeout = const Duration(seconds: 5);
    trustedClient = c;
  });

  tearDown(() async {
    trustedClient.close(force: true);
    await receiver.stop();
    try {
      tmpDir.deleteSync(recursive: true);
    } catch (_) {}
  });

  Future<(int, String)> post(String path, String body, {String? bearer}) async {
    final req = await trustedClient.postUrl(
      Uri.parse('https://127.0.0.1:${receiver.port}$path'),
    );
    req.headers.contentType = ContentType.json;
    if (bearer != null) {
      req.headers.set(HttpHeaders.authorizationHeader, 'Bearer $bearer');
    }
    req.write(body);
    final res = await req.close();
    final text = await res.transform(utf8.decoder).join();
    return (res.statusCode, text);
  }

  Future<Map<String, dynamic>> postOk(
    String path,
    String body, {
    String? bearer,
  }) async {
    final (code, text) = await post(path, body, bearer: bearer);
    expect(code, HttpStatus.ok, reason: 'POST $path -> $code: $text');
    return jsonDecode(text) as Map<String, dynamic>;
  }

  group('pairing', () {
    test('rejects wrong / expired token', () async {
      final (code, _) = await post(
        CastApi.pathPair,
        CastApi.pairBody('f' * 64),
      );
      expect(code, HttpStatus.unauthorized);
    });

    test('pair consumes the token and yields a session', () async {
      final qr = receiver.currentQr();
      expect(qr, isNotNull);
      final (code, text) = await post(
        CastApi.pathPair,
        CastApi.pairBody(qr!.token),
      );
      expect(code, HttpStatus.ok);
      final session =
          (jsonDecode(text) as Map<String, dynamic>)['session'] as String;
      expect(session.length, 64);

      // Token is single-use: second attempt must fail.
      final (code2, _) = await post(
        CastApi.pathPair,
        CastApi.pairBody(qr.token),
      );
      expect(code2, HttpStatus.unauthorized);

      // Session works for authenticated endpoints.
      final status = await postOk(CastApi.pathStatus, '', bearer: session);
      expect(status['paired'], isTrue);
    });

    test('unauthenticated control requests are rejected', () async {
      final (code, _) = await post(CastApi.pathStatus, '');
      expect(code, HttpStatus.unauthorized);
      final (code2, _) = await post(CastApi.pathPlay, CastApi.playBody('/x'));
      expect(code2, HttpStatus.unauthorized);
    });

    test('claim accepts LAN http and rejects bad https fingerprint', () async {
      final qr = receiver.currentQr();
      final (code, text) = await post(
        CastApi.pathPair,
        CastApi.pairBody(qr!.token),
      );
      expect(code, HttpStatus.ok);
      final session =
          (jsonDecode(text) as Map<String, dynamic>)['session'] as String;

      // LAN http server (self-hosted) must be accepted; no TLS pin involved.
      final (codeHttp, _) = await post(
        CastApi.pathClaim,
        CastApi.claimBody(
          serverUrl: 'http://192.168.1.10:8080/',
          username: 'u',
          password: 'p',
          serverSha1: '',
        ),
        bearer: session,
      );
      expect(codeHttp, HttpStatus.ok);

      // Unsupported scheme must be refused.
      final (codeScheme, _) = await post(
        CastApi.pathClaim,
        CastApi.claimBody(
          serverUrl: 'ftp://192.168.1.10/',
          username: 'u',
          password: 'p',
          serverSha1: '',
        ),
        bearer: session,
      );
      expect(codeScheme, HttpStatus.badRequest);

      // https still requires a 40-hex fingerprint.
      final (codeFp, _) = await post(
        CastApi.pathClaim,
        CastApi.claimBody(
          serverUrl: 'https://127.0.0.1:1/',
          username: 'u',
          password: 'p',
          serverSha1: 'x' * 40,
        ),
        bearer: session,
      );
      expect(codeFp, HttpStatus.badRequest);
    });
  });

  group('control commands', () {
    late String session;

    setUp(() async {
      final qr = receiver.currentQr()!;
      final (code, text) = await post(
        CastApi.pathPair,
        CastApi.pairBody(qr.token),
      );
      expect(code, HttpStatus.ok);
      session = (jsonDecode(text) as Map<String, dynamic>)['session'] as String;
      final (claimCode, _) = await post(
        CastApi.pathClaim,
        CastApi.claimBody(
          serverUrl: 'https://127.0.0.1:1/',
          username: 'u',
          password: 'p',
          serverSha1: 'ab' * 20,
        ),
        bearer: session,
      );
      expect(claimCode, HttpStatus.ok);
    });

    test('play / pause / resume / seek / stop / volume / rate', () async {
      await postOk(
        CastApi.pathPlay,
        CastApi.playBody('/v/a.mkv'),
        bearer: session,
      );
      expect(
        host.log,
        contains(
          'play:http://127.0.0.1:${receiver.proxyPort}/stream?path=%2Fv%2Fa.mkv',
        ),
      );

      // Image casts forward the type so the receiver shows a picture.
      await postOk(
        CastApi.pathPlay,
        CastApi.playBody('/p/photo.jpg', type: 'image'),
        bearer: session,
      );
      expect(
        host.log,
        contains(
          'play:http://127.0.0.1:${receiver.proxyPort}/stream?path=%2Fp%2Fphoto.jpg:image',
        ),
      );

      await postOk(CastApi.pathPause, '', bearer: session);
      expect(host.log, contains('pause'));

      await postOk(CastApi.pathResume, '', bearer: session);
      expect(host.log, contains('resume'));

      await postOk(CastApi.pathSeek, CastApi.seekBody(12345), bearer: session);
      expect(host.seeks, [12345]);

      await postOk(CastApi.pathStop, '', bearer: session);
      expect(host.log, contains('stop'));

      await postOk(CastApi.pathVolume, CastApi.volumeBody(40), bearer: session);
      expect(host.log, contains('volume:40'));

      await postOk(
        CastApi.pathSetRate,
        CastApi.setRateBody(2.0),
        bearer: session,
      );
      expect(host.log, contains('rate:2.0'));

      // Status reflects volume.
      final status = await postOk(CastApi.pathStatus, '', bearer: session);
      expect(status['volume'], 40);
    });

    test('play rejects non-absolute path', () async {
      final (code, _) = await post(
        CastApi.pathPlay,
        CastApi.playBody('relative.mkv'),
        bearer: session,
      );
      expect(code, HttpStatus.badRequest);
    });

    test('seek rejects negative', () async {
      final (code, _) = await post(
        CastApi.pathSeek,
        CastApi.seekBody(-5),
        bearer: session,
      );
      expect(code, HttpStatus.badRequest);
    });
  });

  group('unpair', () {
    test('unpair stops playback, drops session and mints a fresh QR', () async {
      final qr = receiver.currentQr();
      final (code, text) = await post(
        CastApi.pathPair,
        CastApi.pairBody(qr!.token),
      );
      expect(code, HttpStatus.ok);
      final session =
          (jsonDecode(text) as Map<String, dynamic>)['session'] as String;

      // Unpair is an authenticated endpoint.
      final (codeAnon, _) = await post(CastApi.pathUnpair, '');
      expect(codeAnon, HttpStatus.unauthorized);

      final (codeUn, textUn) = await post(
        CastApi.pathUnpair,
        '',
        bearer: session,
      );
      expect(codeUn, HttpStatus.ok);
      expect(textUn, contains('ok'));

      // Player host told to stop, session gone (old session now rejected),
      // and a new QR with a fresh token is offered.
      expect(host.log.last, 'stop');
      final (codeStale, _) = await post(
        CastApi.pathStatus,
        '',
        bearer: session,
      );
      expect(codeStale, HttpStatus.unauthorized);

      final freshQr = receiver.currentQr();
      expect(freshQr, isNotNull);
      expect(freshQr!.token, isNot(qr.token));
      expect(receiver.isPaired, isFalse);
    });
  });

  group('media proxy', () {
    test('forwards GET with auth and Range, pinned upstream', () async {
      // Upstream HTTPS server using cert2 — the receiver must pin its sha1.
      final upCtx = SecurityContext()
        ..useCertificateChain('$_certDir/cert2.pem')
        ..usePrivateKey('$_certDir/key2.pem');
      final upstream = await HttpServer.bindSecure(
        InternetAddress.loopbackIPv4,
        0,
        upCtx,
      );
      final served = <String>[];
      upstream.listen((req) {
        served.add('${req.method} ${req.uri.path}');
        final range = req.headers.value(HttpHeaders.rangeHeader);
        final res = req.response;
        res.headers.set('content-type', 'video/x-matroska');
        if (range != null) {
          res.statusCode = HttpStatus.partialContent;
          res.headers.set('content-range', 'bytes 0-9/100');
          res.headers.set('content-length', '10');
          res.write('0123456789');
        } else {
          res.statusCode = HttpStatus.ok;
          res.headers.set('content-length', '100');
          res.write('x' * 100);
        }
        res.close();
      });

      final qr = receiver.currentQr()!;
      final (pairCode, pairText) = await post(
        CastApi.pathPair,
        CastApi.pairBody(qr.token),
      );
      expect(pairCode, HttpStatus.ok);
      final session =
          (jsonDecode(pairText) as Map<String, dynamic>)['session'] as String;
      final sha1 = _pemSha1('$_certDir/cert2.pem');
      final (claimCode, _) = await post(
        CastApi.pathClaim,
        CastApi.claimBody(
          serverUrl: 'https://127.0.0.1:${upstream.port}/',
          username: 'alice',
          password: 's3cret',
          serverSha1: sha1,
        ),
        bearer: session,
      );
      expect(claimCode, HttpStatus.ok);

      // First request: no Range.
      final r1 = await trustedClient.getUrl(
        Uri.parse(
          'http://127.0.0.1:${receiver.proxyPort}/stream?path=%2Fv%2Fbig.mkv',
        ),
      );
      final res1 = await r1.close();
      expect(res1.statusCode, HttpStatus.ok);
      expect(res1.headers.contentType?.mimeType, 'video/x-matroska');
      expect(res1.contentLength, 100);
      await res1.drain<void>();

      // Second request: Range passthrough (mpv seek).
      final r2 = await trustedClient.getUrl(
        Uri.parse(
          'http://127.0.0.1:${receiver.proxyPort}/stream?path=%2Fv%2Fbig.mkv',
        ),
      );
      r2.headers.set(HttpHeaders.rangeHeader, 'bytes=0-9');
      final res2 = await r2.close();
      expect(res2.statusCode, HttpStatus.partialContent);
      expect(res2.headers.value('content-range'), 'bytes 0-9/100');
      final body = await res2.transform(utf8.decoder).join();
      expect(body, '0123456789');

      // Proxy is localhost-only by construction (loopback bind).

      // The receiver's own 5s probe (pinned upstream client) hits GET /.
      // Wait briefly for it to run, then assert both stream requests happened.
      await Future<void>.delayed(const Duration(milliseconds: 700));
      expect(served.where((s) => s == 'GET /').length, greaterThanOrEqualTo(1));
      expect(served.where((s) => s == 'GET /v/big.mkv').length, 2);

      await upstream.close(force: true);
    });

    test('proxy refuses requests before claim', () async {
      final res = await trustedClient.getUrl(
        Uri.parse(
          'http://127.0.0.1:${receiver.proxyPort}/stream?path=%2Fv%2Fx.mkv',
        ),
      );
      final response = await res.close();
      expect(response.statusCode, HttpStatus.conflict);
      await response.drain<void>();
    });

    test('proxy rejects non-absolute path', () async {
      // Claim a dummy server so the path check (400) runs before the
      // not-claimed check (409).
      final qr = receiver.currentQr()!;
      final (pairCode, pairText) = await post(
        CastApi.pathPair,
        CastApi.pairBody(qr.token),
      );
      expect(pairCode, HttpStatus.ok);
      final session =
          (jsonDecode(pairText) as Map<String, dynamic>)['session'] as String;
      await postOk(
        CastApi.pathClaim,
        CastApi.claimBody(
          serverUrl: 'https://127.0.0.1:1/',
          username: 'u',
          password: 'p',
          serverSha1: 'ab' * 20,
        ),
        bearer: session,
      );
      final res = await trustedClient.getUrl(
        Uri.parse('http://127.0.0.1:${receiver.proxyPort}/stream?path=x'),
      );
      final response = await res.close();
      expect(response.statusCode, HttpStatus.badRequest);
      await response.drain<void>();
    });
  });
}
