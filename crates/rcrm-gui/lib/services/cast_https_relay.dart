// services/cast_https_relay.dart
// Phone-side HTTPS relay for LAN casting with a loopback-only local server.
//
// The local Rust WebDAV server usually binds 127.0.0.1 (default), which the
// TV on the LAN cannot reach. Instead of restarting it, the phone starts a
// small TLS forwarder on 0.0.0.0:<ephemeral port> that forwards media
// requests to the loopback server with the server's Basic credentials.
// The TV claims this relay like any HTTPS server (certificate SHA-1 is
// handed over during /v1/claim), so the existing pinning chain is reused
// unchanged. Certificate is regenerated per start (memory only).

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';

import '../ffi/rust_bridge.dart';
import 'cast_protocol.dart';
import 'http_forward.dart';

class CastHttpsRelay {
  /// [certGenerator] is injectable for tests; defaults to the Rust bridge
  /// TV-cert generator.
  CastHttpsRelay({required this.rustBridge, this._certGenerator});

  final RustBridge rustBridge;
  final Map<String, String> Function()? _certGenerator;
  HttpServer? _server;
  HttpClient? _upstream;
  int _port = 0;
  String? _targetBase;
  String? _authHeader;
  String _certSha1 = '';

  bool get isRunning => _server != null;

  /// TLS port on 0.0.0.0 (valid after [start]).
  int get port => _port;

  /// SHA-1 fingerprint of the relay certificate (hex, lowercase), handed to
  /// the TV as `serverSha1`.
  String get certSha1 => _certSha1;

  /// Start the TLS relay. [targetBase] is the loopback server base URL
  /// (e.g. `http://127.0.0.1:8080`). Idempotent: calling again stops the
  /// previous relay first.
  Future<void> start({
    required String targetBase,
    required String username,
    required String password,
  }) async {
    await stop();
    _targetBase = targetBase;
    _authHeader = 'Basic ${base64Encode(utf8.encode('$username:$password'))}';

    // Self-signed identity, generated fresh each start (never written to
    // disk). Reuses the Rust TV-cert generator (ECDSA P-256).
    final gen = (_certGenerator ?? rustBridge.generateTvCert)();
    final cert = gen['cert'];
    final key = gen['key'];
    if (cert == null || key == null) {
      throw CastException('relay TLS identity generation failed');
    }
    SecurityContext ctx;
    try {
      ctx = SecurityContext();
      ctx.useCertificateChainBytes(utf8.encode(cert));
      ctx.usePrivateKeyBytes(utf8.encode(key));
    } catch (_) {
      throw CastException('relay TLS identity generation failed');
    }
    _certSha1 = _pemSha1(cert);

    _server = await HttpServer.bindSecure(InternetAddress.anyIPv4, 0, ctx);
    _port = _server!.port;
    _upstream = HttpClient()..connectionTimeout = const Duration(seconds: 10);
    _server!.listen(_onRequest);
  }

  Future<void> stop() async {
    final server = _server;
    _server = null;
    final upstream = _upstream;
    _upstream = null;
    _targetBase = null;
    _authHeader = null;
    _certSha1 = '';
    await server?.close(force: true);
    upstream?.close(force: true);
  }

  static String _pemSha1(String pem) {
    final body = pem
        .replaceAll('-----BEGIN CERTIFICATE-----', '')
        .replaceAll('-----END CERTIFICATE-----', '')
        .replaceAll(RegExp(r'\s'), '');
    return sha1.convert(base64Decode(body)).toString();
  }

  Future<void> _onRequest(HttpRequest req) async {
    final res = req.response;
    try {
      final target = _targetBase;
      final upstream = _upstream;
      final auth = _authHeader;
      if (target == null || upstream == null || auth == null) {
        res.statusCode = HttpStatus.conflict;
        res.write('relay not configured');
        return;
      }
      final q = req.uri.hasQuery ? '?${req.uri.query}' : '';
      final uri = Uri.parse(target).resolve('${req.uri.path}$q');
      await forwardHttpRequest(upstream, uri, req, authHeader: auth);
    } catch (e) {
      try {
        if (res.statusCode == HttpStatus.ok) {
          res.statusCode = HttpStatus.badGateway;
        }
        res.write('relay error: $e');
      } catch (_) {}
    } finally {
      await res.close();
    }
  }
}
