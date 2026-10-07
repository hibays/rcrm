// services/live_media_server.dart
// Loopback HTTP server that lets mpv play an in-memory media payload.
//
// Android live photos carry their video appended to (or embedded in) the
// image file. mpv needs a seekable URL, and media_kit's Media.memory() gets
// there by writing the bytes to a temp file — which would put decrypted
// plaintext on disk (see AGENTS.md, "Zero disk writes"). Instead the payload
// stays in RAM and mpv is handed a 127.0.0.1 URL that answers Range/206, so
// it streams and seeks exactly as it would against the server itself.
//
// Deliberately NOT built on http_forward.dart, which the two casting hops
// (CastReceiver's media proxy, CastHttpsRelay) share. Those are forwarders:
// they copy the client's Range header onto an upstream request and relay the
// upstream's Content-Range back untouched, because the Rust WebDAV server is
// what actually satisfies the range. Here there is no upstream — this class
// IS the origin, so it has to parse ranges, build Content-Range and answer
// 416 itself. Renaming it "proxy" would suggest a shared shape that does not
// exist.

import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

/// Serves registered byte buffers over loopback HTTP for mpv.
class LiveMediaServer {
  LiveMediaServer._();
  static final LiveMediaServer instance = LiveMediaServer._();

  /// How many payloads may be alive at once. The viewer plays one live photo
  /// at a time; the spare slot covers the hand-off while the previous player
  /// is still tearing down. Oldest entry is evicted first.
  static const int _maxPayloads = 2;

  /// Returned by [_parseRange] for a syntactically valid but unsatisfiable
  /// range, so the caller answers 416 instead of silently serving 200.
  static const (int, int) _unsatisfiable = (-1, -1);

  final Map<String, Uint8List> _payloads = {};
  final Random _rng = Random.secure();
  HttpServer? _server;
  Future<HttpServer>? _starting;

  /// Registers [bytes] and returns a loopback URL that serves them.
  ///
  /// Pass the returned URL to [release] once the player consuming it is
  /// disposed. The server itself is started lazily and kept for the process
  /// lifetime: closing it on release would race in-flight range requests.
  Future<String> register(Uint8List bytes) async {
    final server = await _ensureServer();
    final token = _newToken();
    _payloads[token] = bytes;
    while (_payloads.length > _maxPayloads) {
      _payloads.remove(_payloads.keys.first);
    }
    return 'http://${InternetAddress.loopbackIPv4.address}:'
        '${server.port}/$token';
  }

  /// Forgets the payload served at [url]. Safe to call repeatedly, and with
  /// `null`.
  void release(String? url) {
    if (url == null) return;
    final uri = Uri.tryParse(url);
    if (uri == null) return;
    final token = _tokenFromPath(uri.path);
    if (token != null) _payloads.remove(token);
  }

  // ── Server ──────────────────────────────────────────────────

  Future<HttpServer> _ensureServer() async {
    final running = _server;
    if (running != null) return running;
    final pending = _starting;
    if (pending != null) return pending;
    final future = HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    _starting = future;
    try {
      final server = await future;
      server.listen(_onRequest, onError: (_) {});
      _server = server;
      return server;
    } finally {
      _starting = null;
    }
  }

  Future<void> _onRequest(HttpRequest req) async {
    final res = req.response;
    try {
      final token = _tokenFromPath(req.uri.path);
      final bytes = token == null ? null : _payloads[token];
      if (bytes == null) {
        res.statusCode = HttpStatus.notFound;
        return;
      }

      final total = bytes.length;
      final range = _parseRange(
        req.headers.value(HttpHeaders.rangeHeader),
        total,
      );
      res.headers.set(HttpHeaders.acceptRangesHeader, 'bytes');
      res.headers.set(HttpHeaders.contentTypeHeader, 'video/mp4');

      if (range == _unsatisfiable) {
        res.statusCode = HttpStatus.requestedRangeNotSatisfiable;
        res.headers.set(HttpHeaders.contentRangeHeader, 'bytes */$total');
        return;
      }

      final start = range?.$1 ?? 0;
      final end = range?.$2 ?? total - 1;
      if (range == null) {
        res.statusCode = HttpStatus.ok;
      } else {
        res.statusCode = HttpStatus.partialContent;
        res.headers.set(
          HttpHeaders.contentRangeHeader,
          'bytes $start-$end/$total',
        );
      }
      res.headers.contentLength = end - start + 1;
      if (req.method != 'HEAD') {
        // sublistView is a view, not a copy — no per-request buffering.
        res.add(Uint8List.sublistView(bytes, start, end + 1));
      }
    } catch (_) {
      try {
        res.statusCode = HttpStatus.internalServerError;
      } catch (_) {}
    } finally {
      await res.close();
    }
  }

  // ── Helpers ─────────────────────────────────────────────────

  String _newToken() {
    final b = List<int>.generate(16, (_) => _rng.nextInt(256));
    return b.map((v) => v.toRadixString(16).padLeft(2, '0')).join();
  }

  /// `/abc…` -> `abc…`; null for anything that cannot be a token.
  static String? _tokenFromPath(String path) {
    final token = path.startsWith('/') ? path.substring(1) : path;
    return token.isEmpty || token.contains('/') ? null : token;
  }

  /// Parses a single-range `Range` header into inclusive `(start, end)`.
  ///
  /// Returns null when there is no usable range — serving the whole body with
  /// 200 is a legal answer to any request, so that is the fallback. Returns
  /// [_unsatisfiable] when the client asked for a range past the end.
  static (int, int)? _parseRange(String? header, int total) {
    if (header == null || !header.startsWith('bytes=')) return null;
    final spec = header.substring('bytes='.length).trim();
    // Multi-range requests are legal but mpv does not send them; a 200 with
    // the full body is an allowed response, so treat them as "no range".
    if (spec.contains(',')) return null;
    final dash = spec.indexOf('-');
    if (dash < 0) return null;

    final rawStart = spec.substring(0, dash).trim();
    final rawEnd = spec.substring(dash + 1).trim();

    if (rawStart.isEmpty) {
      // Suffix form: the last N bytes.
      final n = int.tryParse(rawEnd);
      if (n == null || n <= 0) return null;
      return (n >= total ? 0 : total - n, total - 1);
    }

    final start = int.tryParse(rawStart);
    if (start == null || start < 0) return null;
    if (start >= total) return _unsatisfiable;
    if (rawEnd.isEmpty) return (start, total - 1);

    final parsedEnd = int.tryParse(rawEnd);
    if (parsedEnd == null || parsedEnd < start) return _unsatisfiable;
    return (start, parsedEnd >= total ? total - 1 : parsedEnd);
  }
}
