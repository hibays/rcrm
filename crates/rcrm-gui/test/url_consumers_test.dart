// test/url_consumers_test.dart
// The URL util is only useful if every consumer hands it the same canonical
// string. These tests pin the two Dart consumers that are easy to regress:
// PROPFIND URL construction, the ffmpeg URL, and the thumbnail URL helper.

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:rcrm_gui/services/thumbnail_service.dart';
import 'package:rcrm_gui/services/webdav_client.dart';
import 'package:rcrm_gui/utils/ffmpeg_thumb_args.dart';

class _CaptureClient extends http.BaseClient {
  Uri? last;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    last = request.url;
    return http.StreamedResponse(
      Stream.value(
        utf8.encode('<D:multistatus xmlns:D="DAV:"></D:multistatus>'),
      ),
      207,
    );
  }
}

void main() {
  group('WebDavClient', () {
    test('PROPFIND encodes a literal percent exactly once', () async {
      final capture = _CaptureClient();
      final client = WebDavClient(baseUrl: 'http://h:9', client: capture);

      await client.listDirectory('/foo%20bar');

      expect(capture.last.toString(), 'http://h:9/foo%2520bar');
    });

    test('authenticatedUrl encodes the path and the credentials', () {
      final client = WebDavClient(
        baseUrl: 'http://h:9',
        username: 'u@x',
        password: 'p:w',
      );

      expect(
        client.authenticatedUrl('/foo%20bar.wmv'),
        'http://u%40x:p%3Aw@h:9/foo%2520bar.wmv',
      );
    });
  });

  group('ffmpeg URL', () {
    test('safeUrl drops credentials but keeps the canonical path', () {
      expect(
        ThumbnailService.safeUrl('http://u:p@h:9/a%2520b.mkv?x=1'),
        'http://h:9/a%2520b.mkv?x=1',
      );
    });

    test('ffmpegThumbArgs passes the canonical path through unchanged', () {
      final args = ffmpegThumbArgs(
        url: 'http://h:9/a%2520b.mkv',
        headers: const {'Authorization': 'Basic dTpw'},
        seekSeconds: 0,
        frames: 1,
        width: 320,
        inputSeek: true,
      );
      expect(args[args.indexOf('-i') + 1], 'http://h:9/a%2520b.mkv');
    });
  });
}
