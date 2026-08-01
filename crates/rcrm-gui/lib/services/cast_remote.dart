// services/cast_remote.dart
// Phone-side cast client: pins the TV certificate (fingerprint from the QR
// payload), performs the pair/claim handshake, then sends control commands.
//
// The certificate policy mirrors net.dart: NOTHING is trusted by default.
// The only certificate ever accepted is the exact one whose SHA-256 matches
// the fingerprint the user scanned. Any other certificate — even from the
// same host — is rejected.

import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';

import 'cast_protocol.dart';

class CastRemote {
  CastRemote({required this.qr, String? session}) {
    _session = session;
  }

  final CastQrPayload qr;
  HttpClient? _client;
  String? _session;

  /// True after a successful [pair] or when constructed with a session.
  bool get isPaired => _session != null;

  /// The current session token (null before pairing).
  String? get sessionToken => _session;

  /// Restore from a previously saved session. The TV must still have this
  /// session alive (it is memory-only there); a 401 means re-scan needed.
  factory CastRemote.resume(CastQrPayload qr, String session) =>
      CastRemote(qr: qr, session: session);

  HttpClient get _http {
    final existing = _client;
    if (existing != null) return existing;
    final client = HttpClient();
    final fingerprint = qr.certSha256;
    client.badCertificateCallback = (cert, host, port) {
      // Only the exact scanned certificate is accepted.
      return sha256.convert(cert.der).toString() == fingerprint;
    };
    client.connectionTimeout = const Duration(seconds: 10);
    _client = client;
    return client;
  }

  Uri _uri(String path) => Uri.parse('${qr.baseUrl}$path');

  void _dispose() {
    _client?.close(force: true);
    _client = null;
    _session = null;
  }

  Future<Map<String, dynamic>> _post(
    String path, {
    String? body,
    bool auth = false,
  }) async {
    final req = await _http.postUrl(_uri(path));
    req.headers.contentType = ContentType.json;
    if (auth) {
      final session = _session;
      if (session == null) throw const CastException('not paired');
      req.headers.set(HttpHeaders.authorizationHeader, 'Bearer $session');
    }
    if (body != null) req.write(body);
    final res = await req.close();
    final text = await res.transform(utf8.decoder).join();
    if (res.statusCode != HttpStatus.ok) {
      throw CastException('HTTP ${res.statusCode}: $text');
    }
    try {
      final decoded = jsonDecode(text);
      if (decoded is! Map<String, dynamic>) {
        throw const CastException('invalid response');
      }
      return decoded;
    } on FormatException {
      throw const CastException('invalid response');
    }
  }

  /// Exchange the one-time QR token for a session token.
  Future<void> pair() async {
    final res = await _post(CastApi.pathPair, body: CastApi.pairBody(qr.token));
    final session = res['session'];
    if (session is! String || session.isEmpty) {
      throw const CastException('pair response missing session');
    }
    _session = session;
  }

  /// Hand the server credentials + server certificate fingerprint to the TV.
  /// Called right after [pair]. Credentials travel only over the pinned TLS
  /// channel and are held in TV memory only.
  Future<void> claim({
    required String serverUrl,
    required String username,
    required String password,
    required String serverSha1,
  }) async {
    await _post(
      CastApi.pathClaim,
      body: CastApi.claimBody(
        serverUrl: serverUrl,
        username: username,
        password: password,
        serverSha1: serverSha1,
      ),
      auth: true,
    );
  }

  Future<CastStatus> status() async {
    final res = await _post(CastApi.pathStatus, auth: true);
    return CastStatus.fromJson(res);
  }

  Future<void> play(String path, {String type = 'video'}) async {
    await _post(
      CastApi.pathPlay,
      body: CastApi.playBody(path, type: type),
      auth: true,
    );
  }

  Future<void> pause() => _post(CastApi.pathPause, auth: true);

  Future<void> resume() => _post(CastApi.pathResume, auth: true);

  Future<void> seek(int posMs) async {
    await _post(CastApi.pathSeek, body: CastApi.seekBody(posMs), auth: true);
  }

  Future<void> stop() => _post(CastApi.pathStop, auth: true);

  Future<void> setVolume(int level) async {
    await _post(
      CastApi.pathVolume,
      body: CastApi.volumeBody(level),
      auth: true,
    );
  }

  Future<void> setRate(double rate) async {
    await _post(
      CastApi.pathSetRate,
      body: CastApi.setRateBody(rate),
      auth: true,
    );
  }

  /// Explicitly end the session on the TV: stop playback and unpair so the
  /// receiver shows a fresh QR. Use when the user picks "stop casting";
  /// plain [suspend] keeps the TV playing.
  Future<void> unpair() async {
    await _post(CastApi.pathUnpair, auth: true);
    _dispose();
  }

  /// Drop the HTTP transport but keep the session token, so the pairing
  /// survives screen teardown and can be resumed without re-scanning
  /// (TV keeps playing).
  void suspend() {
    _client?.close(force: true);
    _client = null;
  }

  /// Drop the session + connection entirely. The TV keeps its state; pairing
  /// again produces a fresh session.
  void disconnect() => _dispose();
}
