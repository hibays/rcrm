// test/cast_https_relay_test.dart
// End-to-end test for the phone-side HTTPS relay: forwards media requests
// from the LAN (TLS, pinned by cert SHA-1) to a loopback HTTP server with
// the server's Basic credentials, preserving Range/206.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/ffi/rust_bridge.dart';
import 'package:rcrm_gui/services/cast_https_relay.dart';

const _certDir = 'test/cert_pinning';

String _hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

void main() {
  late HttpServer target;
  late CastHttpsRelay relay;
  late HttpClient pinnedClient;
  final servedAuth = <String?>[];
  final servedRanges = <String?>[];

  Map<String, String> testCertGen() => {
    'cert': File('$_certDir/cert1.pem').readAsStringSync(),
    'key': File('$_certDir/key1.pem').readAsStringSync(),
  };

  setUp(() async {
    // Fake loopback media server: requires Basic auth, serves Range.
    target = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    target.listen((req) async {
      final res = req.response;
      servedAuth.add(req.headers.value(HttpHeaders.authorizationHeader));
      servedRanges.add(req.headers.value(HttpHeaders.rangeHeader));
      final expected = 'Basic ${base64Encode(utf8.encode('user:pass'))}';
      if (req.headers.value(HttpHeaders.authorizationHeader) != expected) {
        res.statusCode = HttpStatus.unauthorized;
        await res.close();
        return;
      }
      if (req.uri.path == '/v/big.mkv') {
        final body = List<int>.generate(100, (i) => 48 + i % 10); // 0..9
        final range = req.headers.value(HttpHeaders.rangeHeader);
        if (range != null && range.startsWith('bytes=0-9')) {
          res.statusCode = HttpStatus.partialContent;
          res.headers.set('content-range', 'bytes 0-9/100');
          res.headers.set(HttpHeaders.contentLengthHeader, 10);
          res.add(body.sublist(0, 10));
        } else {
          res.headers.set(HttpHeaders.contentLengthHeader, body.length);
          res.add(body);
        }
      } else {
        res.statusCode = HttpStatus.notFound;
      }
      await res.close();
    });

    relay = CastHttpsRelay(
      rustBridge: RustBridge(), // cert injected, FFI never hit
      certGenerator: testCertGen,
    );
    await relay.start(
      targetBase: 'http://127.0.0.1:${target.port}',
      username: 'user',
      password: 'pass',
    );
    final c = HttpClient();
    c.badCertificateCallback = (cert, host, port) =>
        _hex(cert.sha1) == relay.certSha1;
    c.connectionTimeout = const Duration(seconds: 5);
    pinnedClient = c;
  });

  tearDown(() async {
    pinnedClient.close(force: true);
    await relay.stop();
    await target.close(force: true);
  });

  test('forwards full request with Basic auth', () async {
    final req = await pinnedClient.getUrl(
      Uri.parse('https://127.0.0.1:${relay.port}/v/big.mkv'),
    );
    final res = await req.close();
    expect(res.statusCode, HttpStatus.ok);
    expect(res.headers.value(HttpHeaders.contentLengthHeader), '100');
    final body = await res.transform(utf8.decoder).join();
    expect(body.length, 100);
    expect(servedAuth.last, contains('Basic'));
  });

  test('forwards Range and passes 206 through', () async {
    final req = await pinnedClient.getUrl(
      Uri.parse('https://127.0.0.1:${relay.port}/v/big.mkv'),
    );
    req.headers.set(HttpHeaders.rangeHeader, 'bytes=0-9');
    final res = await req.close();
    expect(res.statusCode, HttpStatus.partialContent);
    expect(res.headers.value('content-range'), 'bytes 0-9/100');
    expect(res.headers.value(HttpHeaders.contentLengthHeader), '10');
    final body = await res.transform(utf8.decoder).join();
    expect(body, '0123456789');
    expect(servedRanges.last, 'bytes=0-9');
  });

  test('rejects wrong pinned certificate', () async {
    // A client that does NOT pin the relay cert must be refused.
    final bad = HttpClient();
    bad.badCertificateCallback = (cert, host, port) =>
        _hex(cert.sha1) != relay.certSha1;
    try {
      final req = await bad.getUrl(
        Uri.parse('https://127.0.0.1:${relay.port}/v/big.mkv'),
      );
      await req.close();
      fail('expected handshake failure');
    } on HandshakeException {
      // Expected.
    } finally {
      bad.close(force: true);
    }
  });
}
