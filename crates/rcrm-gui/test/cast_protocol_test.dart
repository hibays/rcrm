// test/cast_protocol_test.dart
// Unit tests for the cast QR pairing + control protocol (pure Dart layer).

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/services/cast_protocol.dart';

void main() {
  group('castRandomToken', () {
    test('produces hex of requested length', () {
      final t = castRandomToken();
      expect(t.length, 64);
      for (var i = 0; i < t.length; i++) {
        expect('0123456789abcdef'.contains(t[i]), isTrue);
      }
    });

    test('is random across calls', () {
      final a = castRandomToken();
      final b = castRandomToken();
      expect(a, isNot(equals(b)));
    });
  });

  group('castConstantEquals', () {
    test('matches equal strings', () {
      expect(castConstantEquals('abc123', 'abc123'), isTrue);
    });

    test('rejects different strings', () {
      expect(castConstantEquals('abc123', 'abc124'), isFalse);
      expect(castConstantEquals('abc123', 'abc12'), isFalse);
      expect(castConstantEquals('', 'x'), isFalse);
    });
  });

  group('CastQrPayload', () {
    CastQrPayload sample() => CastQrPayload(
      host: '192.168.1.50',
      port: 8901,
      token: 'ab12' * 16,
      certSha256: 'cd34' * 16,
      name: '客厅电视',
    );

    test('round-trips through encode/decode', () {
      final qr = sample();
      final decoded = CastQrPayload.tryDecode(qr.encode());
      expect(decoded, isNotNull);
      expect(decoded!.host, '192.168.1.50');
      expect(decoded.port, 8901);
      expect(decoded.token, qr.token);
      expect(decoded.certSha256, qr.certSha256);
      expect(decoded.name, '客厅电视');
    });

    test('round-trips without name', () {
      final qr = CastQrPayload(
        host: '10.0.0.2',
        port: 9000,
        token: 'ab12' * 16,
        certSha256: 'cd34' * 16,
      );
      final decoded = CastQrPayload.tryDecode(qr.encode());
      expect(decoded, isNotNull);
      expect(decoded!.name, isNull);
      expect(decoded.port, 9000);
    });

    test('rejects wrong scheme', () {
      expect(
        CastQrPayload.tryDecode(
          'https://v1?h=1.2.3.4&p=8901&t=${'a' * 64}&f=${'b' * 64}',
        ),
        isNull,
      );
    });

    test('rejects wrong host', () {
      expect(
        CastQrPayload.tryDecode(
          'rcrmcast://v2?h=1.2.3.4&p=8901&t=${'a' * 64}&f=${'b' * 64}',
        ),
        isNull,
      );
    });

    test('rejects malformed token / fingerprint / port', () {
      final good = sample();
      final base = good.encode();
      expect(CastQrPayload.tryDecode(base), isNotNull);
      // token too short
      expect(
        CastQrPayload.tryDecode(base.replaceAll(good.token, 'ab12' * 8)),
        isNull,
      );
      // token not hex
      expect(
        CastQrPayload.tryDecode(base.replaceAll(good.token, 'z' * 64)),
        isNull,
      );
      // fingerprint not hex
      expect(
        CastQrPayload.tryDecode(base.replaceAll(good.certSha256, 'g' * 64)),
        isNull,
      );
      // missing port
      expect(
        CastQrPayload.tryDecode(
          'rcrmcast://v1?h=1.2.3.4&t=${'a' * 64}&f=${'b' * 64}',
        ),
        isNull,
      );
      // non-numeric port
      expect(
        CastQrPayload.tryDecode(
          'rcrmcast://v1?h=1.2.3.4&p=abc&t=${'a' * 64}&f=${'b' * 64}',
        ),
        isNull,
      );
      // empty host
      expect(
        CastQrPayload.tryDecode(
          'rcrmcast://v1?h=&p=8901&t=${'a' * 64}&f=${'b' * 64}',
        ),
        isNull,
      );
    });

    test('isHex validates hex strings', () {
      expect(CastQrPayload.isHex('0123456789abcdefABCDEF', 22), isTrue);
      expect(CastQrPayload.isHex('0123456789abcdefABCDEF', 23), isFalse);
      expect(CastQrPayload.isHex('0123456789g', 11), isFalse);
      expect(CastQrPayload.isHex('', 0), isTrue);
    });

    test('baseUrl is https', () {
      expect(sample().baseUrl, 'https://192.168.1.50:8901');
    });
  });

  group('CastApi bodies', () {
    test('pairBody', () {
      expect(CastApi.pairBody('t0k3n'), contains('"token":"t0k3n"'));
    });

    test('claimBody carries server + fingerprint', () {
      final body = CastApi.claimBody(
        serverUrl: 'https://srv:443/',
        username: 'u',
        password: 'p',
        serverSha1: 'ab' * 20,
      );
      expect(body, contains('"url":"https://srv:443/"'));
      expect(body, contains('"username":"u"'));
      expect(body, contains('"password":"p"'));
      expect(body, contains('"serverSha1":"${'ab' * 20}"'));
    });

    test('playBody / seekBody / volumeBody / setRateBody', () {
      expect(CastApi.playBody('/v/x.mkv'), contains('"path":"/v/x.mkv"'));
      // Default type is video; image casts carry an explicit type.
      expect(CastApi.playBody('/v/x.mkv'), contains('"type":"video"'));
      expect(
        CastApi.playBody('/p/photo.jpg', type: 'image'),
        contains('"type":"image"'),
      );
      expect(CastApi.seekBody(12345), contains('"posMs":12345'));
      expect(CastApi.volumeBody(60), contains('"level":60'));
      expect(CastApi.setRateBody(1.5), contains('"rate":1.5'));
    });
  });

  group('CastStatus', () {
    test('parses full json', () {
      final s = CastStatus.fromJson(const {
        'paired': true,
        'playing': true,
        'posMs': 1000,
        'durMs': 60000,
        'path': '/v/x.mkv',
        'serverOk': true,
        'rate': 1.25,
        'volume': 70,
      });
      expect(s.playing, isTrue);
      expect(s.posMs, 1000);
      expect(s.durMs, 60000);
      expect(s.path, '/v/x.mkv');
      expect(s.serverOk, isTrue);
      expect(s.rate, 1.25);
      expect(s.volume, 70);
    });

    test('defaults for sparse json', () {
      final s = CastStatus.fromJson(const {});
      expect(s.playing, isFalse);
      expect(s.posMs, 0);
      expect(s.durMs, 0);
      expect(s.path, isNull);
      expect(s.serverOk, isFalse);
      expect(s.rate, 1.0);
      expect(s.volume, 50);
    });
  });
}
