// services/webdav_client.dart
import 'dart:async';
import 'dart:convert';
import 'dart:io' show HandshakeException, HttpDate, TlsException;
import 'dart:typed_data';
import 'bounded_fetch.dart' show kBoundedFetchDeadline, kBoundedFetchStall;
import 'net.dart';
import 'package:flutter/foundation.dart' show compute;
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart' show IOClient;
import 'package:xml/xml.dart';
import '../models/media_item.dart';

String _safeDecode(String s) {
  try {
    return Uri.decodeFull(s);
  } catch (_) {}
  final bytes = <int>[];
  int i = 0;
  while (i < s.length) {
    if (s.codeUnitAt(i) == 0x25 && i + 2 < s.length) {
      final b = int.tryParse(s.substring(i + 1, i + 3), radix: 16);
      if (b != null) {
        bytes.add(b);
        i += 3;
        continue;
      }
    }
    bytes.addAll(utf8.encode(s[i]));
    i++;
  }
  return utf8.decode(bytes);
}

class WebDavClient {
  final String baseUrl;
  final String? username;
  final String? password;
  final http.Client _client;
  String? _authHeader;

  /// Clean base URL never containing credentials.
  String get authenticatedBaseUrl => baseUrl;

  /// HTTP headers for Basic Auth, or null if no credentials.
  Map<String, String>? get authHeader =>
      _authHeader != null ? {'Authorization': _authHeader!} : null;

  /// Construct a URL with embedded Basic Auth for tools that need it
  /// (e.g. ffmpeg CLI which only supports URLs).
  String authenticatedUrl(String path) {
    if (username == null || password == null) return '$baseUrl$path';
    final uri = Uri.parse(baseUrl);
    final port = uri.hasPort ? ':${uri.port}' : '';
    return '${uri.scheme}://$username:$password@${uri.host}$port$path';
  }

  WebDavClient({
    required this.baseUrl,
    this.username,
    this.password,
    http.Client? client,
  }) : _client = client ?? IOClient(createTrustAwareHttpClient()) {
    if (username != null && password != null) {
      _authHeader = 'Basic ${base64Encode(utf8.encode('$username:$password'))}';
    }
  }

  void _addAuth(http.BaseRequest request) {
    if (_authHeader != null) request.headers['Authorization'] = _authHeader!;
  }

  String _normPath(String path) {
    var p = path.startsWith('/') ? path : '/$path';
    if (p.length > 1 && p.endsWith('/')) p = p.substring(0, p.length - 1);
    return p;
  }

  Uri _url(String path) {
    final base = baseUrl.endsWith('/') ? baseUrl : '$baseUrl/';
    final p = path.startsWith('/') ? path.substring(1) : path;
    return Uri.parse(Uri.encodeFull('$base$p'));
  }

  Future<List<MediaItem>> listDirectory(String path) async {
    final normPath = _normPath(path);
    final url = _url(normPath);
    const body =
        '<d:propfind xmlns:d="DAV:"><d:prop><d:displayname/><d:getcontentlength/><d:getlastmodified/><d:resourcetype/><d:getcontenttype/></d:prop></d:propfind>';
    try {
      final request = http.Request('PROPFIND', url)
        ..headers['Depth'] = '1'
        ..headers['Content-Type'] = 'application/xml; charset=utf-8'
        ..bodyBytes = utf8.encode(body);
      _addAuth(request);
      final r = await _client.send(request);
      if (r.statusCode == 207) {
        final xml = await r.stream.bytesToString();
        return _parsePropfind(xml, normPath, authenticatedBaseUrl);
      }
      return [];
    } catch (_) {
      // Server might not be running
      return [];
    }
  }

  /// Single PROPFIND returning both files and subdirectories.
  Future<ListAllResult> listAll(String path) async {
    final normPath = _normPath(path);
    final url = _url(normPath);
    const body =
        '<d:propfind xmlns:d="DAV:"><d:prop><d:displayname/><d:getcontentlength/><d:getlastmodified/><d:resourcetype/><d:getcontenttype/></d:prop></d:propfind>';
    try {
      final request = http.Request('PROPFIND', url)
        ..headers['Depth'] = '1'
        ..headers['Content-Type'] = 'application/xml; charset=utf-8'
        ..bodyBytes = utf8.encode(body);
      _addAuth(request);
      final r = await _client.send(request);
      if (r.statusCode == 207) {
        final xml = await r.stream.bytesToString();
        return await compute(
          _parseAllCompute,
          _ParseAllArgs(xml, normPath, authenticatedBaseUrl),
        );
      }
    } catch (_) {}
    return const ListAllResult([], []);
  }

  Future<List<String>> listSubdirectories(String path) async {
    final normPath = _normPath(path);
    final url = _url(normPath);
    const body =
        '<d:propfind xmlns:d="DAV:"><d:prop><d:displayname/><d:resourcetype/></d:prop></d:propfind>';
    try {
      final request = http.Request('PROPFIND', url)
        ..headers['Depth'] = '1'
        ..headers['Content-Type'] = 'application/xml; charset=utf-8'
        ..bodyBytes = utf8.encode(body);
      _addAuth(request);
      final r = await _client.send(request);
      if (r.statusCode == 207) {
        final xml = await r.stream.bytesToString();
        return _parseDirectories(xml, normPath);
      }
    } catch (_) {}
    return [];
  }

  List<String> _parseDirectories(String xml, String currentPath) {
    final dirs = <String>[];
    try {
      final doc = XmlDocument.parse(xml);
      for (final resp in doc.findAllElements('D:response')) {
        final href = resp.findElements('D:href').firstOrNull?.innerText ?? '';
        if (href.isEmpty) continue;
        final d = _safeDecode(href);
        if (d == currentPath || d == '$currentPath/') continue;
        bool coll = false;
        for (final ps in resp.findElements('D:propstat')) {
          if (ps
                  .findElements('D:status')
                  .firstOrNull
                  ?.innerText
                  .contains('200') ==
              true) {
            final c = ps
                .findElements('D:prop')
                .firstOrNull
                ?.findElements('D:resourcetype')
                .firstOrNull
                ?.findElements('D:collection');
            if (c != null && c.isNotEmpty) {
              coll = true;
              break;
            }
          }
        }
        if (coll) dirs.add(d);
      }
    } catch (_) {}
    return dirs;
  }

  /// Reads the FIRST [maxBytes] of [path] and no more.
  ///
  /// This is a health probe, not a download: the only caller
  /// (`widgets/doctor_panel.dart`) has to prove the decrypt → serve → fetch path
  /// works, which the first chunk of an encrypted file already does. Asking for
  /// the whole file — which is what this replaced — means pulling an entire
  /// video through the decrypting server and into Dart memory just to print its
  /// length, and doing it while the user is looking at the page.
  ///
  /// Bounded twice over, because a bound that can be ignored is not one:
  ///
  ///  * the request carries `Range: bytes=0-N-1`, so a server that honours it
  ///    never decrypts more than the head;
  ///  * the loop stops at N bytes and BREAKS, which cancels the subscription and
  ///    stops the app reading — so a server that ignores `Range` and starts
  ///    streaming the whole file (our own server answers 206, but a cloud WebDAV
  ///    may answer 200) is read for one head and no more.
  ///
  /// What the PEER does next is the socket's business, not this function's: its
  /// further writes block once the buffers fill, but it can still push a few MiB
  /// into them before that (measured — a paced 4 MiB body finished writing after
  /// the client had stopped reading). The guarantee here is about the app's
  /// memory and its read loop, and that is the half that was missing.
  ///
  /// The deadlines are `bounded_fetch.dart`'s, so "how long a fetch may take" has
  /// one answer in this app rather than one per call site.
  Future<Uint8List?> getFileHead(String path, {required int maxBytes}) async {
    if (maxBytes <= 0) return null;
    final uri = _url(_normPath(path));
    final deadline = DateTime.now().add(kBoundedFetchDeadline);
    try {
      final request = http.Request('GET', uri)
        ..headers['Range'] = 'bytes=0-${maxBytes - 1}';
      _addAuth(request);
      final response = await _client.send(request).timeout(kBoundedFetchStall);
      if (response.statusCode != 200 && response.statusCode != 206) {
        // Read the (small, in practice) error body off the socket so the
        // connection can return to the pool — but only for as long as one stall,
        // because the caller is waiting for this answer, not for a body it will
        // discard.
        await response.stream
            .drain<void>()
            .timeout(kBoundedFetchStall)
            .catchError((_) {});
        return null;
      }
      final head = BytesBuilder(copy: false);
      await for (final chunk in response.stream.timeout(
        kBoundedFetchStall,
        onTimeout: (sink) => sink.addError(
          TimeoutException('stalled for $kBoundedFetchStall reading $uri'),
        ),
      )) {
        if (DateTime.now().isAfter(deadline)) {
          throw TimeoutException(
            'head exceeded $kBoundedFetchDeadline from $uri',
          );
        }
        head.add(chunk);
        if (head.length >= maxBytes) {
          break; // stops reading; the app holds a head, not the file
        }
      }
      final bytes = head.takeBytes();
      return bytes.length > maxBytes
          ? Uint8List.sublistView(bytes, 0, maxBytes)
          : bytes;
    } catch (_) {
      return null;
    }
  }

  Future<bool> ping() async => await pingStatusCode() == 200;

  Future<int?> pingStatusCode() async {
    try {
      final r = http.Request('OPTIONS', Uri.parse('$baseUrl/'));
      _addAuth(r);
      final resp = await _client.send(r);
      return resp.statusCode;
    } on HandshakeException {
      rethrow;
    } on TlsException {
      rethrow;
    } catch (_) {
      return null;
    }
  }

  void dispose() {
    scheduleMicrotask(() => _client.close());
  }
}

List<MediaItem> _parsePropfind(String xml, String currentPath, String baseUrl) {
  final items = <MediaItem>[];
  try {
    final doc = XmlDocument.parse(xml);
    for (final resp in doc.findAllElements('D:response')) {
      final href = resp.findElements('D:href').firstOrNull?.innerText ?? '';
      if (href.isEmpty) continue;
      final d = _safeDecode(href);
      if (d == currentPath || d == '$currentPath/') continue;
      XmlElement? okProp;
      for (final ps in resp.findElements('D:propstat')) {
        if (ps
                .findElements('D:status')
                .firstOrNull
                ?.innerText
                .contains('200') ==
            true) {
          okProp = ps.findElements('D:prop').firstOrNull;
          if (okProp != null) break;
        }
      }
      if (okProp == null) continue;
      if (okProp
              .findElements('D:resourcetype')
              .firstOrNull
              ?.findElements('D:collection')
              .isNotEmpty ==
          true) {
        continue;
      }
      final displayName =
          okProp.findElements('D:displayname').firstOrNull?.innerText ??
          _fileName(d);
      final contentLength =
          int.tryParse(
            okProp.findElements('D:getcontentlength').firstOrNull?.innerText ??
                '0',
          ) ??
          0;
      final ts = okProp
          .findElements('D:getlastmodified')
          .firstOrNull
          ?.innerText;
      final lastModified = _parseLastModified(ts);
      items.add(
        MediaItem.fromWebDavProps(
          name: displayName,
          path: d,
          baseUrl: baseUrl,
          size: contentLength,
          modified: lastModified,
          albumName: _albumName(d, currentPath),
        ),
      );
    }
  } catch (_) {}
  return items;
}

String _fileName(String p) {
  final s = p.split('/').where((x) => x.isNotEmpty).toList();
  return s.isNotEmpty ? s.last : p;
}

/// `getlastmodified` may be either RFC 1123 ("Wed, 30 Sep 2026 02:24:11 GMT",
/// which is what rcrm's own server writes and what RFC 4918 asks for) or
/// ISO-8601 — and `DateTime.tryParse` only understands the latter. Losing this
/// silently cost the viewer's info sheet its "file timestamp" fallback and
/// left date sorting with nothing to sort by.
///
/// **Every value comes back on one clock (UTC).** RFC 1123 carries a zone and
/// `HttpDate.parse` honours it; an ISO-8601 value *without* a zone is read as
/// UTC rather than as local time (`DateTime.parse` would otherwise interpret
/// it locally, which would make two entries in the same listing disagree by the
/// UTC offset — sorting and "newest first" both depend on a single clock).
/// Callers that *display* it convert with `.toLocal()`.
DateTime? _parseLastModified(String? raw) {
  if (raw == null) return null;
  final iso = DateTime.tryParse(raw);
  if (iso != null) {
    if (iso.isUtc) return iso;
    // Naive: the wall-clock fields are the server's, but they are the only
    // thing on offer, so treat them as UTC (same reading as the RFC 1123
    // branch) instead of mixing the local zone into the comparison.
    return DateTime.utc(
      iso.year,
      iso.month,
      iso.day,
      iso.hour,
      iso.minute,
      iso.second,
      iso.millisecond,
      iso.microsecond,
    );
  }
  try {
    return HttpDate.parse(raw);
  } catch (_) {
    return null;
  }
}

String _albumName(String fp, String cp) {
  final f = fp.split('/').where((x) => x.isNotEmpty).toList();
  final c = cp.split('/').where((x) => x.isNotEmpty).toList();
  if (f.length > c.length + 1) return f[c.length];
  if (f.length == c.length + 1 && c.isNotEmpty) return c.last;
  return '';
}

class ListAllResult {
  final List<MediaItem> files;
  final List<String> subdirs;
  const ListAllResult(this.files, this.subdirs);
}

class _ParseAllArgs {
  final String xml;
  final String currentPath;
  final String baseUrl;
  const _ParseAllArgs(this.xml, this.currentPath, this.baseUrl);
}

ListAllResult _parseAllCompute(_ParseAllArgs args) {
  return _parseAll(args.xml, args.currentPath, args.baseUrl);
}

ListAllResult _parseAll(String xml, String currentPath, String baseUrl) {
  final files = <MediaItem>[];
  final subdirs = <String>[];
  try {
    final doc = XmlDocument.parse(xml);
    for (final resp in doc.findAllElements('D:response')) {
      final href = resp.findElements('D:href').firstOrNull?.innerText ?? '';
      if (href.isEmpty) continue;
      final d = _safeDecode(href);
      if (d == currentPath || d == '$currentPath/') continue;
      XmlElement? okProp;
      for (final ps in resp.findElements('D:propstat')) {
        if (ps
                .findElements('D:status')
                .firstOrNull
                ?.innerText
                .contains('200') ==
            true) {
          okProp = ps.findElements('D:prop').firstOrNull;
          if (okProp != null) break;
        }
      }
      if (okProp == null) continue;
      final isDir =
          okProp
              .findElements('D:resourcetype')
              .firstOrNull
              ?.findElements('D:collection')
              .isNotEmpty ==
          true;
      if (isDir) {
        subdirs.add(d);
      } else {
        final displayName =
            okProp.findElements('D:displayname').firstOrNull?.innerText ??
            _fileName(d);
        final contentLength =
            int.tryParse(
              okProp
                      .findElements('D:getcontentlength')
                      .firstOrNull
                      ?.innerText ??
                  '0',
            ) ??
            0;
        final ts = okProp
            .findElements('D:getlastmodified')
            .firstOrNull
            ?.innerText;
        final lm = _parseLastModified(ts);
        files.add(
          MediaItem.fromWebDavProps(
            name: displayName,
            path: d,
            baseUrl: baseUrl,
            size: contentLength,
            modified: lm,
            albumName: _albumName(d, currentPath),
          ),
        );
      }
    }
  } catch (_) {}
  return ListAllResult(files, subdirs);
}
