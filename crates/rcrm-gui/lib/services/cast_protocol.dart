// services/cast_protocol.dart
// QR-code pairing + control protocol for the "cast to TV" feature.
//
// Pure Dart (no Flutter imports) so the whole protocol layer is unit-testable.
// Security model: the QR payload carries a one-time short-lived pair token
// plus the TV certificate fingerprint; the phone pins that exact certificate
// before anything else happens. After pairing, every control request is
// authenticated with a random session token over TLS.

import 'dart:convert';
import 'dart:math';

/// Protocol version prefix in the QR payload.
const String castQrScheme = 'rcrmcast';
const String castQrHost = 'v1';

/// Pair token validity window.
const Duration castPairTokenTtl = Duration(seconds: 30);

/// Default TLS control port on the TV.
const int castDefaultPort = 8901;

/// Generate a cryptographically random token as lowercase hex.
/// [bytes] must be positive (default 32 → 64 hex chars).
String castRandomToken([int bytes = 32]) {
  assert(bytes > 0);
  final r = Random.secure();
  final out = StringBuffer();
  for (var i = 0; i < bytes; i++) {
    final b = r.nextInt(256);
    out.write(b.toRadixString(16).padLeft(2, '0'));
  }
  return out.toString();
}

/// Constant-time hex string comparison (both sides same length).
bool castConstantEquals(String a, String b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a.codeUnitAt(i) ^ b.codeUnitAt(i);
  }
  return diff == 0;
}

/// The QR payload shown by the TV and scanned by the phone.
///
/// Wire format: `rcrmcast://v1?h=<ip>&p=<port>&t=<token>&f=<sha256>&n=<name>`
class CastQrPayload {
  /// TV LAN IPv4 address.
  final String host;

  /// TLS control port on the TV.
  final int port;

  /// One-time pair token (64 hex chars), single-use, 30s TTL.
  final String token;

  /// SHA-256 fingerprint of the TV certificate (64 hex chars, lowercase).
  final String certSha256;

  /// Optional TV display name.
  final String? name;

  const CastQrPayload({
    required this.host,
    required this.port,
    required this.token,
    required this.certSha256,
    this.name,
  });

  static bool isHex(String s, int len) {
    if (s.length != len) return false;
    for (var i = 0; i < s.length; i++) {
      final c = s.codeUnitAt(i);
      final isDigit = c >= 0x30 && c <= 0x39;
      final isLower = c >= 0x61 && c <= 0x66;
      final isUpper = c >= 0x41 && c <= 0x46;
      if (!isDigit && !isLower && !isUpper) return false;
    }
    return true;
  }

  /// Serialize to the QR payload string.
  String encode() {
    final params = <String, String>{
      'h': host,
      'p': '$port',
      't': token,
      'f': certSha256,
      if (name != null && name!.isNotEmpty) 'n': name!,
    };
    final query = params.entries
        .map((e) => '${e.key}=${Uri.encodeQueryComponent(e.value)}')
        .join('&');
    return '$castQrScheme://$castQrHost?$query';
  }

  /// Parse and validate a scanned payload. Returns null for anything that
  /// does not match the protocol exactly (wrong scheme, missing fields,
  /// malformed tokens/fingerprints, non-numeric port).
  static CastQrPayload? tryDecode(String raw) {
    final uri = Uri.tryParse(raw.trim());
    if (uri == null) return null;
    if (uri.scheme != castQrScheme) return null;
    if (uri.host != castQrHost) return null;
    final q = uri.queryParameters;
    final host = q['h'];
    final portStr = q['p'];
    final token = q['t'];
    final fp = q['f'];
    final name = q['n'];
    if (host == null || host.isEmpty) return null;
    if (token == null || !isHex(token, 64)) return null;
    if (fp == null || !isHex(fp, 64)) return null;
    final port = int.tryParse(portStr ?? '');
    if (port == null || port < 1 || port > 65535) return null;
    return CastQrPayload(
      host: host,
      port: port,
      token: token.toLowerCase(),
      certSha256: fp.toLowerCase(),
      name: (name == null || name.isEmpty) ? null : name,
    );
  }

  /// Base URL of the TV control service (https://).
  String get baseUrl => 'https://$host:$port';
}

// ── Control protocol ──────────────────────────────────────────

/// Request bodies for the cast control endpoints.
abstract final class CastApi {
  static const pathPair = '/v1/pair';
  static const pathClaim = '/v1/claim';
  static const pathUnpair = '/v1/unpair';
  static const pathStatus = '/v1/status';
  static const pathPlay = '/v1/play';
  static const pathPause = '/v1/pause';
  static const pathResume = '/v1/resume';
  static const pathSeek = '/v1/seek';
  static const pathStop = '/v1/stop';
  static const pathVolume = '/v1/volume';
  static const pathSetRate = '/v1/setrate';
  static const pathStream = '/stream';

  static String pairBody(String token) => jsonEncode({'token': token});

  static String claimBody({
    required String serverUrl,
    required String username,
    required String password,
    required String serverSha1,
  }) => jsonEncode({
    'server': {'url': serverUrl, 'username': username, 'password': password},
    'serverSha1': serverSha1,
  });

  /// `type` is 'video' (default) or 'image'. Older receivers ignore it.
  static String playBody(String path, {String type = 'video'}) =>
      jsonEncode({'path': path, 'type': type});

  static String seekBody(int posMs) => jsonEncode({'posMs': posMs});

  static String volumeBody(int level) => jsonEncode({'level': level});

  static String setRateBody(double rate) => jsonEncode({'rate': rate});
}

/// Snapshot returned by the TV's `/v1/status`.
class CastStatus {
  final bool paired;
  final bool playing;
  final int posMs;
  final int durMs;
  final String? path;
  final bool serverOk;
  final double rate;
  final int volume;

  const CastStatus({
    required this.paired,
    required this.playing,
    required this.posMs,
    required this.durMs,
    this.path,
    required this.serverOk,
    required this.rate,
    this.volume = 50,
  });

  factory CastStatus.fromJson(Map<String, dynamic> json) => CastStatus(
    paired: json['paired'] as bool? ?? false,
    playing: json['playing'] as bool? ?? false,
    posMs: (json['posMs'] as num?)?.toInt() ?? 0,
    durMs: (json['durMs'] as num?)?.toInt() ?? 0,
    path: json['path'] as String?,
    serverOk: json['serverOk'] as bool? ?? false,
    rate: (json['rate'] as num?)?.toDouble() ?? 1.0,
    volume: (json['volume'] as num?)?.toInt() ?? 50,
  );
}

/// Errors surfaced by the cast client/receiver.
class CastException implements Exception {
  final String message;
  const CastException(this.message);
  @override
  String toString() => 'CastException: $message';
}
