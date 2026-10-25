// test/media_url_test.dart
// The one URL-encoding rule: a decoded WebDAV path becomes a canonical URL
// exactly once, and a literal `%20` in a file name is not a space.
//
// The regression this pins is real and was visible on Android: a synthetic file
// `【x】foo%20bar%20-%20baz%20qux.wmv` was listed by PROPFIND, its
// poster/metadata paths failed, and media_kit requested `foo%20bar...` — which
// rcrm's server decoded to a space and answered 404, leaving the player on its
// buffering spinner forever.

import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/models/media_item.dart';
import 'package:rcrm_gui/utils/media_url.dart';

void main() {
  group('encodeMediaPath', () {
    test('a literal percent sequence is escaped once', () {
      expect(encodeMediaPath('/foo%20bar.wmv'), '/foo%2520bar.wmv');
    });

    test('a real space becomes %20', () {
      expect(encodeMediaPath('/foo bar.wmv'), '/foo%20bar.wmv');
    });

    test('reserved characters stay inside one path segment', () {
      expect(encodeMediaPath('/a#b?c&d+e'), '/a%23b%3Fc%26d%2Be');
    });

    test('non-ASCII is UTF-8 percent-encoded', () {
      expect(
        encodeMediaPath('/【x】/файл.mkv'),
        '/%E3%80%90x%E3%80%91/%D1%84%D0%B0%D0%B9%D0%BB.mkv',
      );
    });

    test('empty segments and the leading slash are preserved', () {
      expect(encodeMediaPath('/a//b/'), '/a//b/');
    });
  });

  group('mediaUrl', () {
    test('a base ending in / is not doubled', () {
      expect(mediaUrl('http://h:9/', '/v/a.mkv'), 'http://h:9/v/a.mkv');
      expect(mediaUrl('http://h:9/dav/', '/v/a.mkv'), 'http://h:9/dav/v/a.mkv');
    });

    test('a path without a leading slash still lands under the base', () {
      expect(mediaUrl('http://h:9', 'v/a.mkv'), 'http://h:9/v/a.mkv');
    });

    test('root path keeps the base as a directory', () {
      expect(mediaUrl('http://h:9/', '/'), 'http://h:9/');
    });

    test('a non-ASCII path with literal percents is encoded exactly once', () {
      expect(
        mediaUrl(
          'http://192.168.1.5:8080',
          '/【x】foo%20bar%20-%20baz%20qux.wmv',
        ),
        'http://192.168.1.5:8080/'
        '%E3%80%90x%E3%80%91'
        'foo%2520bar%2520-%2520baz%2520qux.wmv',
      );
    });

    test('MediaItem keeps the decoded path for display and the URL encoded', () {
      final item = MediaItem.fromWebDavProps(
        name: 'foo%20bar - baz qux.wmv',
        path: '/【x】foo%20bar%20-%20baz%20qux.wmv',
        baseUrl: 'http://h:9',
        size: 1,
        modified: null,
      );
      expect(
        item.path,
        '/【x】foo%20bar%20-%20baz%20qux.wmv',
        reason: 'the path is what the UI and the cast protocol show',
      );
      expect(
        item.url,
        'http://h:9/'
        '%E3%80%90x%E3%80%91'
        'foo%2520bar%2520-%2520baz%2520qux.wmv',
        reason:
            'the literal % must reach the server as %25, so it survives one '
            'server-side decode as the three characters the file is named with',
      );
    });

    test('MediaItem canonicalises a name with real spaces', () {
      final item = MediaItem.fromWebDavProps(
        name: 'foo bar.wmv',
        path: '/a/foo bar.wmv',
        baseUrl: 'http://h:9/',
        size: 1,
        modified: null,
      );
      expect(item.url, 'http://h:9/a/foo%20bar.wmv');
    });

    test(
      'MediaItem keeps every reserved path character inside its segment',
      () {
        final item = MediaItem.fromWebDavProps(
          name: 'a#b?c&d+e.mkv',
          path: '/a/a#b?c&d+e.mkv',
          baseUrl: 'http://h:9',
          size: 1,
          modified: null,
        );
        expect(item.url, 'http://h:9/a/a%23b%3Fc%26d%2Be.mkv');
      },
    );

    test('MediaItem preserves a base path prefix', () {
      final item = MediaItem.fromWebDavProps(
        name: 'a b.mkv',
        path: '/a b.mkv',
        baseUrl: 'https://h/dav/',
        size: 1,
        modified: null,
      );
      expect(item.url, 'https://h/dav/a%20b.mkv');
    });
  });

  group('withoutUrlCredentials', () {
    test('removes userInfo and keeps the canonical path and query', () {
      expect(
        withoutUrlCredentials('http://u:p@h:9/a%2520b.mkv?x=1'),
        'http://h:9/a%2520b.mkv?x=1',
      );
    });

    test('an uncredentialed URL is unchanged', () {
      expect(
        withoutUrlCredentials('https://h:8443/a%20b.mkv'),
        'https://h:8443/a%20b.mkv',
      );
    });

    test('credentials are removed from an IPv6 authority too', () {
      expect(
        withoutUrlCredentials('http://u:p@[::1]:8080/a'),
        'http://[::1]:8080/a',
      );
    });
  });
}
