// services/cast_receiver.dart
// TV-side cast receiver: TLS control server + localhost media proxy.
//
// The control server listens on 0.0.0.0:<port> with a self-signed ECDSA
// certificate generated via the Rust bridge (rcrm_generate_tv_cert) and
// persisted in the app-private directory. All requests except /v1/pair
// require a session token obtained through pairing.
//
// The media proxy listens on 127.0.0.1 only. libmpv never sees the server
// certificate: the proxy fetches through a Dart HttpClient that pins the
// server certificate (fingerprint handed over by the phone during claim).

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data' show BytesBuilder;

import 'package:crypto/crypto.dart';

import '../ffi/rust_bridge.dart';
import 'cast_protocol.dart';
import 'http_forward.dart';

/// Bridge between the receiver and the actual media player (UI layer).
abstract class CastPlayerHost {
  /// Play the given localhost proxy URL. When [isImage] is true the
  /// receiver shows the URL as a full-screen image instead of video.
  Future<void> play(String streamUrl, {bool isImage = false});

  Future<void> pause();

  Future<void> resume();

  Future<void> seek(Duration position);

  Future<void> stopPlayback();

  Future<void> setVolume(int level);

  Future<void> setRate(double rate);
}

/// Errors thrown by [CastReceiver].
class CastReceiverException implements Exception {
  final String message;
  const CastReceiverException(this.message);
  @override
  String toString() => 'CastReceiverException: $message';
}

class CastReceiver {
  CastReceiver({required this.playerHost, required this.rustBridge});

  /// UI layer that owns the actual player.
  final CastPlayerHost playerHost;

  /// Rust bridge used to generate the TLS identity on first launch.
  final RustBridge rustBridge;

  HttpServer? _server;
  HttpServer? _proxy;
  SecurityContext? _ctx;
  int _port = castDefaultPort;
  int _proxyPort = 0;

  // ── pairing / session state (all in-memory) ──────────────
  String? _pairToken;
  DateTime _pairExpiresAt = DateTime.fromMillisecondsSinceEpoch(0);
  String? _session;

  // ── server credentials, set once during claim (memory only) ──
  String? _serverUrl;
  String? _serverUsername;
  String? _serverPassword;
  String? _serverSha1;

  HttpClient? _upstreamClient;
  Timer? _serverProbe;
  bool _serverOk = false;

  // ── playback state, fed by the UI layer ──────────────────
  bool _playing = false;
  int _posMs = 0;
  int _durMs = 0;
  String? _currentPath;
  double _rate = 1.0;
  int _volume = 50;

  // ── lifecycle ────────────────────────────────────────────

  bool get isRunning => _server != null;

  /// True once a phone has completed pairing (session token exists).
  bool get isPaired => _session != null;

  /// Latest server reachability probe result (probed every 5s after claim).
  bool get serverOk => _serverOk;

  /// Discard the consumed pair token and mint a fresh one (new QR payload).
  /// Safe to call any time; the current session (if any) stays valid.
  void regeneratePairToken() => _newPairToken();

  /// Unpair: drop the session, the server credentials and the pinned
  /// upstream client, then mint a fresh pair token. Used by the receiver UI
  /// when the TV/PC owner wants to end the pairing (e.g. remote went away).
  /// The player itself is stopped by the UI layer, not here.
  void unpair() {
    _session = null;
    _serverUrl = null;
    _serverUsername = null;
    _serverPassword = null;
    _serverSha1 = null;
    _upstreamClient?.close(force: true);
    _upstreamClient = null;
    _serverOk = false;
    _playing = false;
    _posMs = 0;
    _durMs = 0;
    _currentPath = null;
    _newPairToken();
  }

  /// When the current one-time pair token expires (for countdown display).
  DateTime? get pairExpiresAt => _pairToken == null ? null : _pairExpiresAt;

  int get port => _port;

  int get proxyPort => _proxyPort;

  /// Current QR payload, or null when the receiver is not running, the token
  /// was consumed by pairing, or the token has expired (auto-destroy: an
  /// expired token is never offered again; regeneration is manual only).
  CastQrPayload? currentQr() {
    if (_server == null) return null;
    final token = _pairToken;
    // Token check first: once paired (or expired) this is called every second
    // by the QR timer and must not touch the certificate at all.
    if (token == null || !DateTime.now().isBefore(_pairExpiresAt)) return null;
    final sha = certSha256;
    if (sha == null) return null;
    return CastQrPayload(
      host: localIpv4,
      port: _port,
      token: token,
      certSha256: sha,
      name: 'rcrm-tv',
    );
  }

  static String _hexBytes(List<int> bytes) =>
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  static String _normalizePem(String pem) {
    // rcgen emits CRLF; normalize to LF for consistent parsing.
    return pem.replaceAll('\r\n', '\n').trim();
  }

  /// SHA-256 fingerprint of the current TLS certificate (hex), computed from
  /// the DER body of the PEM cert. Null when not started.
  ///
  /// Memoized: the QR timer calls this every second (via [currentQr]), and
  /// hashing on the main isolate — which also runs the control server and
  /// media proxy — is pure waste for a certificate that never changes while
  /// running.
  String? get certSha256 {
    final pem = _certPem;
    if (pem == null) return null;
    if (_certSha256CachePem == pem) return _certSha256Cache;
    final body = _normalizePem(pem)
        .replaceAll('-----BEGIN CERTIFICATE-----', '')
        .replaceAll('-----END CERTIFICATE-----', '')
        .replaceAll(RegExp(r'\s'), '');
    try {
      final sha = sha256.convert(base64Decode(body)).toString();
      _certSha256Cache = sha;
      _certSha256CachePem = pem;
      return sha;
    } catch (_) {
      return null;
    }
  }

  String? _certPem;
  String? _certSha256Cache;
  String? _certSha256CachePem;

  String _localIpv4 = '127.0.0.1';

  /// All candidate LAN IPv4 addresses found at start(), best first
  /// (real-network prefixes before virtual-NIC ranges like Hyper-V/VPN/Docker).
  final List<String> _localIpv4s = [];

  /// The IPv4 address currently baked into the QR payload.
  String get localIpv4 => _localIpv4;

  /// All candidate LAN IPv4 addresses (best first). Empty until [start].
  List<String> get localIpv4s => List.unmodifiable(_localIpv4s);

  /// Switch which local address the QR advertises (e.g. after the user picks
  /// the real NIC instead of a virtual one). Ignored if [ip] is not a known
  /// candidate.
  void selectLocalIpv4(String ip) {
    if (_localIpv4s.contains(ip)) _localIpv4 = ip;
  }

  /// Rank prefixes so real LAN NICs win over virtual ones:
  /// 192.168.x.x (most common) → 10.x.x.x → 172.16-31.x.x → anything else.
  static int _ipv4Priority(String ip) {
    final parts = ip.split('.');
    if (parts.length != 4) return 4;
    final a = int.tryParse(parts[0]) ?? -1;
    final b = int.tryParse(parts[1]) ?? -1;
    if (a == 192 && b == 168) return 0;
    if (a == 10) return 1;
    if (a == 172 && b >= 16 && b <= 31) return 2;
    return 3;
  }

  Future<List<String>> _discoverLocalIpv4s() async {
    final found = <String>{};
    try {
      final ifaces = await NetworkInterface.list(
        type: InternetAddressType.IPv4,
        includeLoopback: false,
      );
      for (final iface in ifaces) {
        for (final addr in iface.addresses) {
          if (!addr.isLoopback && !addr.isLinkLocal) {
            found.add(addr.address);
          }
        }
      }
    } catch (_) {}
    final list = found.toList()
      ..sort((a, b) => _ipv4Priority(a).compareTo(_ipv4Priority(b)));
    return list.isEmpty ? ['127.0.0.1'] : list;
  }

  /// Start the TLS control server and the localhost media proxy.
  /// [identityDir] is where cert.pem/key.pem are persisted (app-private).
  Future<void> start(String identityDir) async {
    await stop();

    _localIpv4s
      ..clear()
      ..addAll(await _discoverLocalIpv4s());
    _localIpv4 = _localIpv4s.first;
    _loadOrCreateIdentity(identityDir);

    // Bind the media proxy on an OS-assigned localhost port first.
    _proxy = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    _proxyPort = _proxy!.port;
    _proxy!.listen(_onProxyRequest);

    // Bind the TLS control server on the fixed port; if busy, fall back to
    // an OS-assigned port (the QR payload carries the actual port).
    try {
      _server = await HttpServer.bindSecure(
        InternetAddress.anyIPv4,
        _port,
        _ctx!,
      );
    } on SocketException {
      _server = await HttpServer.bindSecure(InternetAddress.anyIPv4, 0, _ctx!);
      _port = _server!.port;
    }
    _server!.listen(_onControlRequest);

    _startServerProbe();
    _newPairToken();
  }

  Future<void> stop() async {
    _serverProbe?.cancel();
    _serverProbe = null;
    final server = _server;
    _server = null;
    final proxy = _proxy;
    _proxy = null;
    await server?.close(force: true);
    await proxy?.close(force: true);
    final upstream = _upstreamClient;
    _upstreamClient = null;
    upstream?.close(force: true);
    _pairToken = null;
    _session = null;
    _serverUrl = null;
    _serverUsername = null;
    _serverPassword = null;
    _serverSha1 = null;
    _playing = false;
    _posMs = 0;
    _durMs = 0;
    _currentPath = null;
    _serverOk = false;
  }

  /// Generate a fresh one-time pair token. Call after each successful pair
  /// to keep the QR payload single-use.
  void _newPairToken() {
    _pairToken = castRandomToken();
    _pairExpiresAt = DateTime.now().add(castPairTokenTtl);
  }

  void _loadOrCreateIdentity(String dir) {
    final certFile = File('$dir/cast_cert.pem');
    final keyFile = File('$dir/cast_key.pem');
    if (certFile.existsSync() && keyFile.existsSync()) {
      try {
        final ctx = SecurityContext();
        ctx.useCertificateChain(certFile.path);
        ctx.usePrivateKey(keyFile.path);
        _ctx = ctx;
        _certPem = certFile.readAsStringSync();
        return;
      } catch (_) {
        // Fall through: regenerate.
      }
    }
    final gen = rustBridge.generateTvCert();
    final cert = gen['cert'];
    final key = gen['key'];
    if (cert == null || key == null) {
      throw CastReceiverException('TLS identity generation failed');
    }
    // Persist with restrictive permissions; reuse across restarts.
    Directory(dir).createSync(recursive: true);
    certFile.writeAsStringSync(cert);
    keyFile.writeAsStringSync(key);
    final ctx = SecurityContext();
    ctx.useCertificateChain(certFile.path);
    ctx.usePrivateKey(keyFile.path);
    _ctx = ctx;
    _certPem = cert;
  }

  // ── server reachability probe ────────────────────────────

  void _startServerProbe() {
    _serverProbe = Timer.periodic(const Duration(seconds: 5), (_) async {
      await _probeServer();
    });
  }

  Future<void> _probeServer() async {
    final url = _serverUrl;
    if (url == null) {
      _serverOk = false;
      return;
    }
    try {
      final client = await _upstream();
      final req = await client.getUrl(Uri.parse(url));
      _applyAuth(req);
      final res = await req.close();
      await res.drain<void>();
      _serverOk = res.statusCode < 500;
    } catch (_) {
      _serverOk = false;
    }
  }

  HttpClient _newPinnedClient() {
    final client = HttpClient();
    final sha = _serverSha1;
    client.badCertificateCallback = (cert, host, port) {
      if (sha == null) return false;
      return _hexBytes(cert.sha1) == sha;
    };
    client.connectionTimeout = const Duration(seconds: 10);
    return client;
  }

  Future<HttpClient> _upstream() async {
    final existing = _upstreamClient;
    if (existing != null) return existing;
    final client = _newPinnedClient();
    _upstreamClient = client;
    return client;
  }

  String? get _basicAuthHeader {
    final user = _serverUsername;
    final pass = _serverPassword;
    if (user == null || pass == null) return null;
    return 'Basic ${base64Encode(utf8.encode('$user:$pass'))}';
  }

  void _applyAuth(HttpClientRequest req) {
    final header = _basicAuthHeader;
    if (header != null) {
      req.headers.set(HttpHeaders.authorizationHeader, header);
    }
  }

  // ── playback state (fed by UI layer) ─────────────────────

  void updatePlayback({
    required bool playing,
    required int posMs,
    required int durMs,
  }) {
    _playing = playing;
    _posMs = posMs;
    _durMs = durMs;
  }

  /// The path currently playing (server-relative), or null.
  String? get currentPath => _currentPath;

  // ── control handlers ─────────────────────────────────────

  Future<void> _onControlRequest(HttpRequest req) async {
    final res = req.response;
    try {
      final path = req.uri.path;
      if (path == CastApi.pathPair) {
        await _handlePair(req, res);
        return;
      }
      if (!_authorized(req)) {
        res.statusCode = HttpStatus.unauthorized;
        res.write('unauthorized');
        return;
      }
      switch (path) {
        case CastApi.pathClaim:
          await _handleClaim(req, res);
        case CastApi.pathUnpair:
          await _handleUnpair(res);
        case CastApi.pathStatus:
          await _handleStatus(res);
        case CastApi.pathPlay:
          await _handlePlay(req, res);
        case CastApi.pathPause:
          await _handlePause(res);
        case CastApi.pathResume:
          await _handleResume(res);
        case CastApi.pathSeek:
          await _handleSeek(req, res);
        case CastApi.pathStop:
          await _handleStop(res);
        case CastApi.pathVolume:
          await _handleVolume(req, res);
        case CastApi.pathSetRate:
          await _handleSetRate(req, res);
        default:
          res.statusCode = HttpStatus.notFound;
          res.write('not found');
      }
    } catch (e) {
      // Only bump the status when nothing has been written yet (no
      // content-type set). The inner try/catch stops the fallback itself
      // from throwing after headers were already flushed.
      try {
        if (res.headers.contentType == null) {
          res.statusCode = HttpStatus.badRequest;
        }
        res.write('error: $e');
      } catch (_) {}
    } finally {
      await res.close();
    }
  }

  bool _authorized(HttpRequest req) {
    final session = _session;
    if (session == null) return false;
    final header = req.headers.value(HttpHeaders.authorizationHeader);
    if (header == null) return false;
    final parts = header.split(' ');
    return parts.length == 2 &&
        parts[0] == 'Bearer' &&
        castConstantEquals(parts[1], session);
  }

  /// Control requests carry tiny JSON bodies; anything beyond this is a
  /// broken or hostile client. Cap the accumulation so the TV's main isolate
  /// (which serves this TLS endpoint) can't be ballooned by an unbounded
  /// upload.
  static const int _maxBodyBytes = 64 * 1024;

  Future<String> _readBody(HttpRequest req) async {
    final bytes = BytesBuilder(copy: false);
    var total = 0;
    await for (final chunk in req) {
      total += chunk.length;
      if (total > _maxBodyBytes) {
        throw const CastReceiverException('request body too large');
      }
      bytes.add(chunk);
    }
    return utf8.decode(bytes.takeBytes());
  }

  Future<Map<String, dynamic>> _readJson(HttpRequest req) async {
    final text = await _readBody(req);
    final decoded = jsonDecode(text);
    if (decoded is! Map<String, dynamic>) {
      throw const CastReceiverException('expected JSON object');
    }
    return decoded;
  }

  Future<void> _handlePair(HttpRequest req, HttpResponse res) async {
    if (req.method != 'POST') {
      res.statusCode = HttpStatus.methodNotAllowed;
      return;
    }
    Map<String, dynamic> body;
    try {
      body = await _readJson(req);
    } catch (_) {
      res.statusCode = HttpStatus.badRequest;
      return;
    }
    final token = body['token'];
    final now = DateTime.now();
    final pairToken = _pairToken;
    final ok =
        token is String &&
        pairToken != null &&
        now.isBefore(_pairExpiresAt) &&
        castConstantEquals(token, pairToken);
    if (!ok) {
      res.statusCode = HttpStatus.unauthorized;
      res.write('invalid or expired pair token');
      return;
    }
    // Consume the token atomically (no await between check and consume).
    _pairToken = null;
    _session = castRandomToken();
    res.headers.contentType = ContentType.json;
    res.write(jsonEncode({'session': _session}));
  }

  Future<void> _handleClaim(HttpRequest req, HttpResponse res) async {
    Map<String, dynamic> body;
    try {
      body = await _readJson(req);
    } catch (_) {
      res.statusCode = HttpStatus.badRequest;
      return;
    }
    final server = body['server'];
    if (server is! Map<String, dynamic>) {
      res.statusCode = HttpStatus.badRequest;
      return;
    }
    final url = server['url'];
    final username = server['username'];
    final password = server['password'];
    final sha1 = body['serverSha1'];
    if (url is! String || username is! String || password is! String) {
      res.statusCode = HttpStatus.badRequest;
      return;
    }
    final parsed = Uri.tryParse(url);
    if (parsed == null ||
        (parsed.scheme != 'http' && parsed.scheme != 'https')) {
      res.statusCode = HttpStatus.badRequest;
      res.write('server URL must be http:// or https://');
      return;
    }
    final isHttps = parsed.scheme == 'https';
    if (isHttps && (sha1 is! String || !CastQrPayload.isHex(sha1, 40))) {
      res.statusCode = HttpStatus.badRequest;
      res.write('serverSha1 must be 40 hex chars for https');
      return;
    }
    // LAN (http) servers have no TLS certificate to pin; sha1 is optional.
    if (!isHttps && sha1 is! String) {
      res.statusCode = HttpStatus.badRequest;
      res.write('serverSha1 must be a string');
      return;
    }
    // Replace credentials; drop the pinned client so the next fetch uses the
    // new fingerprint.
    _serverUrl = url;
    _serverUsername = username;
    _serverPassword = password;
    _serverSha1 = isHttps ? sha1.toLowerCase() : null;
    _upstreamClient?.close(force: true);
    _upstreamClient = null;
    _serverOk = false;
    unawaited(_probeServer());
    res.headers.contentType = ContentType.json;
    res.write(jsonEncode({'ok': true}));
  }

  Future<void> _handleUnpair(HttpResponse res) async {
    // The phone-side "disconnect" may choose to keep playing; this endpoint
    // is how the phone explicitly ends the session (stop + unpair).
    await playerHost.stopPlayback();
    unpair();
    _writeOk(res);
  }

  Future<void> _handleStatus(HttpResponse res) async {
    res.headers.contentType = ContentType.json;
    res.write(
      jsonEncode({
        'paired': _session != null,
        'playing': _playing,
        'posMs': _posMs,
        'durMs': _durMs,
        'path': _currentPath,
        'serverOk': _serverOk,
        'rate': _rate,
        'volume': _volume,
      }),
    );
  }

  Future<void> _handlePlay(HttpRequest req, HttpResponse res) async {
    Map<String, dynamic> body;
    try {
      body = await _readJson(req);
    } catch (_) {
      res.statusCode = HttpStatus.badRequest;
      return;
    }
    final path = body['path'];
    if (path is! String || !path.startsWith('/')) {
      res.statusCode = HttpStatus.badRequest;
      return;
    }
    final type = body['type'];
    final isImage = type == 'image';
    final serverUrl = _serverUrl;
    if (serverUrl == null) {
      res.statusCode = HttpStatus.conflict;
      res.write('server not claimed');
      return;
    }
    _currentPath = path;
    final streamUrl =
        'http://127.0.0.1:$_proxyPort${CastApi.pathStream}?path=${Uri.encodeQueryComponent(path)}';
    // Opening a network stream can take seconds (format probe over the
    // relay). Don't block the control response on it: the phone UI would
    // feel dead and invite double taps. Playback proceeds asynchronously;
    // a failed open surfaces via status (playing=false, path=null).
    unawaited(
      playerHost
          .play(streamUrl, isImage: isImage)
          .then((_) {
            _rate = 1.0;
          })
          .catchError((Object _) {
            _currentPath = null;
            _playing = false;
          }),
    );
    res.headers.contentType = ContentType.json;
    res.write(jsonEncode({'ok': true}));
  }

  Future<void> _handlePause(HttpResponse res) async {
    await playerHost.pause();
    _writeOk(res);
  }

  Future<void> _handleResume(HttpResponse res) async {
    await playerHost.resume();
    _writeOk(res);
  }

  Future<void> _handleSeek(HttpRequest req, HttpResponse res) async {
    Map<String, dynamic> body;
    try {
      body = await _readJson(req);
    } catch (_) {
      res.statusCode = HttpStatus.badRequest;
      return;
    }
    final posMs = body['posMs'];
    if (posMs is! num || posMs < 0) {
      res.statusCode = HttpStatus.badRequest;
      return;
    }
    await playerHost.seek(Duration(milliseconds: posMs.toInt()));
    _writeOk(res);
  }

  Future<void> _handleStop(HttpResponse res) async {
    await playerHost.stopPlayback();
    _currentPath = null;
    _playing = false;
    _writeOk(res);
  }

  Future<void> _handleVolume(HttpRequest req, HttpResponse res) async {
    Map<String, dynamic> body;
    try {
      body = await _readJson(req);
    } catch (_) {
      res.statusCode = HttpStatus.badRequest;
      return;
    }
    final level = body['level'];
    if (level is! num || level < 0 || level > 100) {
      res.statusCode = HttpStatus.badRequest;
      return;
    }
    _volume = level.toInt();
    await playerHost.setVolume(level.toInt());
    _writeOk(res);
  }

  Future<void> _handleSetRate(HttpRequest req, HttpResponse res) async {
    Map<String, dynamic> body;
    try {
      body = await _readJson(req);
    } catch (_) {
      res.statusCode = HttpStatus.badRequest;
      return;
    }
    final rate = body['rate'];
    if (rate is! num || rate <= 0 || rate > 4) {
      res.statusCode = HttpStatus.badRequest;
      return;
    }
    _rate = rate.toDouble();
    await playerHost.setRate(rate.toDouble());
    _writeOk(res);
  }

  void _writeOk(HttpResponse res) {
    res.headers.contentType = ContentType.json;
    res.write(jsonEncode({'ok': true}));
  }

  // ── media proxy ──────────────────────────────────────────

  Future<void> _onProxyRequest(HttpRequest req) async {
    final res = req.response;
    try {
      final serverUrl = _serverUrl;
      if (serverUrl == null) {
        res.statusCode = HttpStatus.conflict;
        res.write('server not claimed');
        return;
      }
      final path = req.uri.queryParameters['path'];
      if (path == null || !path.startsWith('/')) {
        res.statusCode = HttpStatus.badRequest;
        return;
      }
      final client = await _upstream();
      final upstreamUri = Uri.parse(serverUrl).resolve(path);
      await forwardHttpRequest(
        client,
        upstreamUri,
        req,
        authHeader: _basicAuthHeader,
      );
    } catch (e) {
      try {
        if (res.statusCode == HttpStatus.ok) {
          res.statusCode = HttpStatus.badGateway;
        }
        res.write('proxy error: $e');
      } catch (_) {}
    } finally {
      await res.close();
    }
  }
}
