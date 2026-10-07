// test/live_media_server_test.dart
// Live photos hand mpv an in-memory payload over loopback HTTP instead of
// letting media_kit's Media.memory write it to a temp file. mpv seeks by
// issuing Range requests, so this pins the HTTP contract it depends on.

import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/services/live_media_server.dart';

Uint8List _payload(int length) =>
    Uint8List.fromList(List<int>.generate(length, (i) => i % 256));

Future<HttpClientResponse> _request(
  String url, {
  String? range,
  String method = 'GET',
}) async {
  final req = await HttpClient().openUrl(method, Uri.parse(url));
  if (range != null) req.headers.set(HttpHeaders.rangeHeader, range);
  return req.close();
}

Future<List<int>> _body(HttpClientResponse res) =>
    res.fold<List<int>>([], (acc, chunk) => acc..addAll(chunk));

void main() {
  test(
    'serves the whole payload with 200 and advertises range support',
    () async {
      final bytes = _payload(1000);
      final url = await LiveMediaServer.instance.register(bytes);

      final res = await _request(url);
      expect(res.statusCode, HttpStatus.ok);
      expect(res.headers.value(HttpHeaders.acceptRangesHeader), 'bytes');
      expect(res.contentLength, 1000);
      expect(await _body(res), bytes);

      LiveMediaServer.instance.release(url);
    },
  );

  test('serves a bounded range as 206 with a correct Content-Range', () async {
    final bytes = _payload(1000);
    final url = await LiveMediaServer.instance.register(bytes);

    final res = await _request(url, range: 'bytes=10-19');
    expect(res.statusCode, HttpStatus.partialContent);
    expect(
      res.headers.value(HttpHeaders.contentRangeHeader),
      'bytes 10-19/1000',
    );
    expect(res.contentLength, 10);
    expect(await _body(res), bytes.sublist(10, 20));

    LiveMediaServer.instance.release(url);
  });

  test('open-ended and suffix ranges resolve to the right slices', () async {
    final bytes = _payload(500);
    final url = await LiveMediaServer.instance.register(bytes);

    final open = await _request(url, range: 'bytes=490-');
    expect(open.statusCode, HttpStatus.partialContent);
    expect(
      open.headers.value(HttpHeaders.contentRangeHeader),
      'bytes 490-499/500',
    );
    expect(await _body(open), bytes.sublist(490));

    // Suffix form: the LAST n bytes, not bytes 0..n.
    final suffix = await _request(url, range: 'bytes=-5');
    expect(suffix.statusCode, HttpStatus.partialContent);
    expect(
      suffix.headers.value(HttpHeaders.contentRangeHeader),
      'bytes 495-499/500',
    );
    expect(await _body(suffix), bytes.sublist(495));

    LiveMediaServer.instance.release(url);
  });

  test('clamps an end past the payload and rejects a start past it', () async {
    final bytes = _payload(100);
    final url = await LiveMediaServer.instance.register(bytes);

    final clamped = await _request(url, range: 'bytes=90-9999');
    expect(clamped.statusCode, HttpStatus.partialContent);
    expect(
      clamped.headers.value(HttpHeaders.contentRangeHeader),
      'bytes 90-99/100',
    );
    expect(await _body(clamped), bytes.sublist(90));

    final past = await _request(url, range: 'bytes=100-');
    expect(past.statusCode, HttpStatus.requestedRangeNotSatisfiable);
    expect(past.headers.value(HttpHeaders.contentRangeHeader), 'bytes */100');

    LiveMediaServer.instance.release(url);
  });

  test('HEAD answers headers without a body', () async {
    final bytes = _payload(64);
    final url = await LiveMediaServer.instance.register(bytes);

    final res = await _request(url, method: 'HEAD');
    expect(res.statusCode, HttpStatus.ok);
    expect(res.contentLength, 64);
    expect(await _body(res), isEmpty);

    LiveMediaServer.instance.release(url);
  });

  test(
    'an unknown token is 404, and release makes the URL stop working',
    () async {
      final url = await LiveMediaServer.instance.register(_payload(32));

      final unknown = await _request(
        url.replaceFirst(RegExp(r'/[^/]+$'), '/deadbeef'),
      );
      expect(unknown.statusCode, HttpStatus.notFound);

      LiveMediaServer.instance.release(url);
      final after = await _request(url);
      expect(after.statusCode, HttpStatus.notFound);

      // Idempotent, and null-tolerant.
      LiveMediaServer.instance.release(url);
      LiveMediaServer.instance.release(null);
    },
  );
}
