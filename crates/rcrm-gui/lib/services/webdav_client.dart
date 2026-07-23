// services/webdav_client.dart
import 'dart:async';
import 'dart:convert';
import 'dart:io' show HandshakeException, HttpClient, TlsException;
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
    bool allowBadCert = false,
    http.Client? client,
  }) : _client =
           client ??
           (allowBadCert
               ? IOClient(
                   HttpClient()..badCertificateCallback = (_, _, _) => true,
                 )
               : http.Client()) {
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

  Future<List<int>?> getFile(String path) async {
    try {
      final r = http.Request('GET', _url(_normPath(path)));
      _addAuth(r);
      final resp = await _client.send(r);
      if (resp.statusCode == 200) return await resp.stream.toBytes();
    } catch (_) {}
    return null;
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
      DateTime? lastModified;
      final ts = okProp
          .findElements('D:getlastmodified')
          .firstOrNull
          ?.innerText;
      if (ts != null) lastModified = DateTime.tryParse(ts);
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
        DateTime? lm;
        final ts = okProp
            .findElements('D:getlastmodified')
            .firstOrNull
            ?.innerText;
        if (ts != null) lm = DateTime.tryParse(ts);
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
