// test/cert_pinning_test.dart
// End-to-end verification of the certificate pinning policy in net.dart:
//   1. an untrusted certificate is REJECTED (no trust-all),
//   2. after the user pins the exact certificate, the SAME cert is accepted,
//   3. a DIFFERENT certificate on the same host/port is rejected again even
//      though the host was previously "trusted".
// Uses a local HTTPS server with two distinct self-signed certificates.
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/services/net.dart';

final Uint8List _cert1 = File('test/cert_pinning/cert1.pem').readAsBytesSync();
final Uint8List _key1 = File('test/cert_pinning/key1.pem').readAsBytesSync();
final Uint8List _cert2 = File('test/cert_pinning/cert2.pem').readAsBytesSync();
final Uint8List _key2 = File('test/cert_pinning/key2.pem').readAsBytesSync();

Future<HttpServer> _startServer(int port, Uint8List cert, Uint8List key) async {
  final sc = SecurityContext()
    ..useCertificateChainBytes(cert)
    ..usePrivateKeyBytes(key);
  final server = await HttpServer.bindSecure(
    InternetAddress.loopbackIPv4,
    port,
    sc,
  );
  server.listen((HttpRequest req) {
    req.response.statusCode = 200;
    req.response.headers.contentType = ContentType.text;
    req.response.write('ok');
    req.response.close();
  });
  return server;
}

void main() {
  tearDown(() => CertTrust.clear());

  test(
    'rejects untrusted cert, pins exact cert, rejects different cert',
    () async {
      CertTrust.clear();
      final server = await _startServer(0, _cert1, _key1);
      final port = server.port;

      try {
        // 1. Untrusted → must be rejected, and recorded for the dialog.
        final client1 = createTrustAwareHttpClient();
        await expectLater(
          () => client1.getUrl(Uri.parse('https://127.0.0.1:$port/')),
          throwsA(isA<HandshakeException>()),
        );
        client1.close(force: true);

        final info = CertTrust.lastRejected;
        expect(info, isNotNull, reason: 'rejected cert must be recorded');
        expect(
          CertTrust.isPinned(info!.sha1),
          isFalse,
          reason: 'rejection alone must NOT pin anything',
        );

        // 2. User confirms THAT cert → pinned → connection succeeds.
        CertTrust.pin(info);
        final client2 = createTrustAwareHttpClient();
        final req2 = await client2.getUrl(
          Uri.parse('https://127.0.0.1:$port/'),
        );
        final resp2 = await req2.close();
        expect(resp2.statusCode, 200);
        await resp2.drain<void>();
        client2.close(force: true);

        // 3. Server presents a DIFFERENT cert on the same port → rejected even
        // though the host was previously pinned.
        await server.close(force: true);
        final server2 = await _startServer(port, _cert2, _key2);
        try {
          CertTrust.lastRejected = null;
          final client3 = createTrustAwareHttpClient();
          await expectLater(
            () => client3.getUrl(Uri.parse('https://127.0.0.1:$port/')),
            throwsA(isA<HandshakeException>()),
          );
          client3.close(force: true);
          final second = CertTrust.lastRejected;
          expect(second, isNotNull);
          expect(
            second!.sha1,
            isNot(info.sha1),
            reason: 'different cert must have a different fingerprint',
          );
          expect(
            CertTrust.isPinned(second.sha1),
            isFalse,
            reason: 'only the confirmed cert may be pinned',
          );
        } finally {
          await server2.close(force: true);
        }
      } finally {
        await server.close(force: true);
      }
    },
  );

  test('pin survives across clients (session-scoped)', () async {
    CertTrust.clear();
    final server = await _startServer(0, _cert1, _key1);
    final port = server.port;
    try {
      final client1 = createTrustAwareHttpClient();
      await expectLater(
        () => client1.getUrl(Uri.parse('https://127.0.0.1:$port/')),
        throwsA(isA<HandshakeException>()),
      );
      client1.close(force: true);
      CertTrust.pin(CertTrust.lastRejected!);

      // A brand-new client (as used by animated_detector / live_photo) must
      // also accept the pinned cert.
      final client2 = createTrustAwareHttpClient();
      final req2 = await client2.getUrl(Uri.parse('https://127.0.0.1:$port/'));
      final resp2 = await req2.close();
      expect(resp2.statusCode, 200);
      await resp2.drain<void>();
      client2.close(force: true);
    } finally {
      await server.close(force: true);
    }
  });

  test('clear() drops all pins (session end)', () async {
    CertTrust.clear();
    final server = await _startServer(0, _cert1, _key1);
    final port = server.port;
    try {
      final client1 = createTrustAwareHttpClient();
      await expectLater(
        () => client1.getUrl(Uri.parse('https://127.0.0.1:$port/')),
        throwsA(isA<HandshakeException>()),
      );
      client1.close(force: true);
      CertTrust.pin(CertTrust.lastRejected!);
      expect(CertTrust.hasPinned, isTrue);

      CertTrust.clear();
      expect(CertTrust.hasPinned, isFalse);
      expect(CertTrust.lastRejected, isNull);

      final client2 = createTrustAwareHttpClient();
      await expectLater(
        () => client2.getUrl(Uri.parse('https://127.0.0.1:$port/')),
        throwsA(isA<HandshakeException>()),
      );
      client2.close(force: true);
    } finally {
      await server.close(force: true);
    }
  });
}
