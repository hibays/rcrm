// services/cast_session_store.dart
// Phone-side persistence of an established cast pairing (TV address, pinned
// cert fingerprint, session token). Lets the remote resume control without
// re-scanning while the TV process keeps the session alive (TV side is
// memory-only). Server credentials are never stored here.

import 'dart:convert';

import 'package:shared_preferences/shared_preferences.dart';

import 'cast_protocol.dart';

/// Persisted remote-side cast pairing.
class CastSessionStore {
  static const _key = 'cast_session_v1';

  Future<void> save({
    required CastQrPayload qr,
    required String session,
  }) async {
    final p = await SharedPreferences.getInstance();
    await p.setString(
      _key,
      jsonEncode({
        'host': qr.host,
        'port': qr.port,
        'certSha256': qr.certSha256,
        'name': qr.name,
        'session': session,
      }),
    );
  }

  /// The stored pairing, or null when absent/corrupt. The pair token is not
  /// persisted (it is consumed during pairing); a placeholder is used so the
  /// payload can be reconstructed.
  Future<({CastQrPayload qr, String session})?> load() async {
    final p = await SharedPreferences.getInstance();
    final raw = p.getString(_key);
    if (raw == null) return null;
    try {
      final m = jsonDecode(raw) as Map<String, dynamic>;
      final host = m['host'] as String?;
      final port = (m['port'] as num?)?.toInt();
      final cert = m['certSha256'] as String?;
      final session = m['session'] as String?;
      if (host == null ||
          host.isEmpty ||
          port == null ||
          port < 1 ||
          port > 65535 ||
          cert == null ||
          !CastQrPayload.isHex(cert, 64) ||
          session == null ||
          session.isEmpty) {
        return null;
      }
      final name = m['name'] as String?;
      return (
        qr: CastQrPayload(
          host: host,
          port: port,
          token: '0' * 64, // consumed already; never used again
          certSha256: cert,
          name: (name == null || name.isEmpty) ? null : name,
        ),
        session: session,
      );
    } catch (_) {
      return null;
    }
  }

  Future<void> clear() async {
    final p = await SharedPreferences.getInstance();
    await p.remove(_key);
  }
}
