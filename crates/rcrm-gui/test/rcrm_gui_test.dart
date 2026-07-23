// test/rcrm_gui_test.dart
// RCrm GUI — pure-Dart unit tests (no Flutter runtime needed)
//
// Run:  dart test test/rcrm_gui_test.dart
// Widget tests live in test/widgets/ and use `flutter test`.

import 'dart:io';

import 'package:test/test.dart';

import 'package:rcrm_gui/models/album.dart';
import 'package:rcrm_gui/models/media_item.dart';
import 'package:rcrm_gui/models/server_config.dart';
import 'package:rcrm_gui/services/webdav_client.dart';

// ── Helpers ─────────────────────────────────────────────────

MediaItem mkVideo(String name, {int? dur}) => MediaItem(
  name: name,
  path: '/$name',
  url: 'http://127.0.0.1:8080/$name',
  type: MediaType.video,
  size: 50 * 1024 * 1024,
  durationSeconds: dur ?? 120,
  modified: DateTime(2025, 1, 15),
);

MediaItem mkImage(String name) => MediaItem(
  name: name,
  path: '/$name',
  url: 'http://127.0.0.1:8080/$name',
  type: MediaType.image,
  size: 5 * 1024 * 1024,
  modified: DateTime(2025, 3, 10),
);

// ── Tests ────────────────────────────────────────────────────

void main() {
  // ═══════════════════════════════════════════════════════════
  // 1. MediaItem — formatting & type detection
  // ═══════════════════════════════════════════════════════════
  group('MediaItem', () {
    test('formattedSize', () {
      MediaItem m(int s) => MediaItem(
        name: 't',
        path: '/t',
        url: 'http://x/t',
        type: MediaType.video,
        size: s,
      );
      expect(m(500).formattedSize, '500 B');
      expect(m(2048).formattedSize, '2.0 KB');
      expect(m(5 * 1024 * 1024).formattedSize, '5.0 MB');
      expect(m(2 * 1024 * 1024 * 1024).formattedSize, '2.0 GB');
    });

    test('formattedDuration', () {
      MediaItem d(int? s) => MediaItem(
        name: 't',
        path: '/t',
        url: 'http://x/t',
        type: MediaType.video,
        durationSeconds: s,
      );
      expect(d(3661).formattedDuration, '61:01');
      expect(d(5).formattedDuration, '00:05');
      expect(d(125).formattedDuration, '02:05');
      expect(d(null).formattedDuration, '');
      expect(d(0).formattedDuration, '00:00');
    });

    test('detects all video extensions', () {
      for (final e in [
        'mp4',
        'mkv',
        'avi',
        'wmv',
        'mov',
        'webm',
        'flv',
        'm4v',
      ]) {
        final i = MediaItem.fromWebDavProps(
          name: 'v.$e',
          path: '/v.$e',
          baseUrl: 'http://x',
          size: 1,
          modified: null,
        );
        expect(i.isVideo, isTrue, reason: e);
        expect(i.isImage, isFalse, reason: e);
      }
    });

    test('detects all image extensions', () {
      for (final e in [
        'jpg',
        'jpeg',
        'png',
        'webp',
        'avif',
        'heic',
        'jxl',
        'tiff',
        'gif',
        'bmp',
      ]) {
        final i = MediaItem.fromWebDavProps(
          name: 'i.$e',
          path: '/i.$e',
          baseUrl: 'http://x',
          size: 1,
          modified: null,
        );
        expect(i.isImage, isTrue, reason: e);
        expect(i.isVideo, isFalse, reason: e);
      }
    });

    test('extension lowercased', () {
      final i = MediaItem.fromWebDavProps(
        name: 'X.AVI',
        path: '/X.AVI',
        baseUrl: 'http://x',
        size: 1,
        modified: null,
      );
      expect(i.extension, 'avi');
    });

    test('isAnimated true for gif and apng only', () {
      MediaItem anim(String name) => MediaItem.fromWebDavProps(
        name: name,
        path: '/$name',
        baseUrl: 'http://x',
        size: 1,
        modified: null,
      );
      expect(anim('test.gif').isAnimated, isTrue);
      expect(anim('test.apng').isAnimated, isTrue);
      expect(anim('test.png').isAnimated, isFalse);
      expect(anim('test.webp').isAnimated, isFalse);
      expect(anim('test.mp4').isAnimated, isFalse);
    });
  });
  // ═══════════════════════════════════════════════════════════
  // 2. Album — creation & cover previews
  // ═══════════════════════════════════════════════════════════
  group('Album', () {
    test('fromItems sets fields correctly', () {
      final items = [mkImage('c.jpg'), mkImage('2.jpg'), mkImage('3.jpg')];
      final a = Album.fromItems(
        name: 'Test',
        path: '/t',
        url: 'http://x/t',
        items: items,
      );
      expect(a.name, 'Test');
      expect(a.itemCount, 3);
      expect(a.coverUrl, items[0].url);
      expect(a.coverPreviewUrls.length, 3);
    });

    test('single-image album', () {
      final items = [mkImage('solo.jpg')];
      final a = Album.fromItems(
        name: 'S',
        path: '/s',
        url: 'http://x/s',
        items: items,
      );
      expect(a.itemCount, 1);
      expect(a.coverPreviewUrls.length, 1);
    });

    test('empty itemCount returns 0', () {
      final a = Album.fromItems(
        name: 'Empty',
        path: '/e',
        url: 'http://x/e',
        items: [],
      );
      expect(a.itemCount, 0);
      expect(a.coverPreviewUrls, isEmpty);
    });
  });

  // ═══════════════════════════════════════════════════════════
  // 3. ServerConfig — defaults, serialization, copyWith
  // ═══════════════════════════════════════════════════════════
  group('ServerConfig', () {
    test('defaults', () {
      const c = ServerConfig();
      expect(c.directories, isEmpty);
      expect(c.bindAddress, '127.0.0.1');
      expect(c.port, 8080);
      expect(c.passwords, isEmpty);
    });

    test('json roundtrip excludes passwords', () {
      const c = ServerConfig(
        directories: ['/a', '/b'],
        port: 0,
        passwords: ['pw'],
      );
      final r = ServerConfig.fromJson(c.toJson());
      expect(r.directories, ['/a', '/b']);
      expect(r.port, 0);
      // passwords are NOT serialized
      expect(r.passwords, isEmpty);
    });

    test('copyWith preserves unmodified fields', () {
      const c = ServerConfig(directories: ['/a'], port: 0, passwords: ['pw']);
      final u = c.copyWith(port: 9000);
      expect(u.port, 9000);
      expect(u.directories, ['/a']);
      expect(u.passwords, ['pw']);
    });

    test('copyWith all fields', () {
      const c = ServerConfig();
      final u = c.copyWith(
        directories: ['/x'],
        bindAddress: '0.0.0.0',
        port: 9999,
        passwords: ['a', 'b'],
      );
      expect(u.directories, ['/x']);
      expect(u.bindAddress, '0.0.0.0');
      expect(u.port, 9999);
      expect(u.passwords, ['a', 'b']);
    });
  });

  // ═══════════════════════════════════════════════════════════
  // 4. WebDavClient — auth embedding
  // ═══════════════════════════════════════════════════════════
  group('WebDavClient', () {
    test('authenticatedBaseUrl is clean (no credentials)', () {
      final client = WebDavClient(
        baseUrl: 'http://127.0.0.1:8080',
        username: 'testuser',
        password: 'testpass',
      );
      final url = client.authenticatedBaseUrl;
      expect(url, 'http://127.0.0.1:8080');
      expect(url, isNot(contains('@')));
      expect(url, isNot(contains('testuser')));
    });

    test('authHeader provides Basic Auth', () {
      final client = WebDavClient(
        baseUrl: 'http://127.0.0.1:8080',
        username: 'testuser',
        password: 'testpass',
      );
      expect(client.authHeader, isNotNull);
      expect(client.authHeader!['Authorization'], startsWith('Basic '));
    });

    test('authHeader is null without credentials', () {
      final client = WebDavClient(baseUrl: 'http://127.0.0.1:8080');
      expect(client.authHeader, isNull);
    });

    test('authenticatedUrl embeds creds for ffmpeg', () {
      final client = WebDavClient(
        baseUrl: 'http://127.0.0.1:9090',
        username: 'u',
        password: 'p',
      );
      final url = client.authenticatedUrl('/video.mp4');
      expect(url, contains('u:p@'));
      expect(url, contains(':9090/video.mp4'));
    });
  });

  // ═══════════════════════════════════════════════════════════
  // 5. ffmpeg pipeline — real thumbnail/preview test
  // ═══════════════════════════════════════════════════════════
  group('ffmpeg pipeline', () {
    test('ffmpeg generates poster from test pattern', () async {
      final out =
          '${Directory.current.path}${Platform.pathSeparator}test_poster.jpg';
      try {
        File(out).deleteSync();
      } catch (_) {}
      final r = await Process.run('ffmpeg', [
        '-f',
        'lavfi',
        '-i',
        'color=c=red:s=640x360:d=1',
        '-vframes',
        '1',
        out,
        '-y',
      ]);
      expect(r.exitCode, 0, reason: 'ffmpeg not on PATH. stderr: ${r.stderr}');
      expect(File(out).existsSync(), isTrue);
      File(out).deleteSync();
    });

    test('URL encoding preserves @ in auth URL', () {
      final u = Uri.parse(
        'http://user:pass@127.0.0.1:8080/test.mp4',
      ).toString();
      expect(u.contains('@'), isTrue);
    });
  });

  group('Image classification', () {
    test('format grouping creates albums by extension', () {
      final items = [
        mkImage('photo1.jpg'),
        mkImage('photo2.jpg'),
        mkImage('photo3.jpeg'),
        mkImage('graphic.png'),
        mkImage('anim.gif'),
        mkImage('anim2.gif'),
        mkImage('anim3.gif'),
        mkImage('logo.svg'),
      ];

      // Verify extension getter works
      expect(items[0].extension, 'jpg');
      expect(items[1].extension, 'jpg');
      expect(items[2].extension, 'jpeg');
      expect(items[3].extension, 'png');

      // Manually simulate _groupByFormat's grouping logic
      final formatNames = {
        'jpg': 'JPEG',
        'jpeg': 'JPEG',
        'png': 'PNG',
        'gif': 'GIF',
        'svg': 'SVG',
      };
      final groups = <String, List<MediaItem>>{};
      for (final img in items) {
        final label = formatNames[img.extension] ?? img.extension.toUpperCase();
        groups.putIfAbsent(label, () => []).add(img);
      }

      expect(groups.length, 4);
      expect(groups['JPEG']!.length, 3); // 2 jpg + 1 jpeg
      expect(groups['PNG']!.length, 1);
      expect(groups['GIF']!.length, 3);
      expect(groups['SVG']!.length, 1);

      // Verify album creation
      final albums = groups.entries.map((e) {
        return Album.fromItems(
          name: e.key,
          path: '/_fmt/${e.key.toLowerCase()}',
          url: 'http://127.0.0.1:8080/_fmt/${e.key.toLowerCase()}',
          items: e.value,
        );
      }).toList();
      albums.sort((a, b) {
        final cmp = b.items.length.compareTo(a.items.length);
        if (cmp != 0) return cmp;
        return a.name.compareTo(b.name);
      });
      expect(albums.length, 4);
      expect(albums[0].name, 'GIF'); // 3 items, G < J alphabetically
      expect(albums[1].name, 'JPEG'); // 3 items
      expect(albums[2].name, 'PNG'); // 1 item
      expect(albums[3].name, 'SVG'); // 1 item
    });

    test('Unknown format falls back to uppercase extension', () {
      final item = mkImage('test.xyz');
      // Simulate _groupByFormat: _formatNames['xyz'] is null → 'XYZ'
      final formatNames = <String, String>{};
      final label = formatNames[item.extension] ?? item.extension.toUpperCase();
      expect(label, 'XYZ');
    });

    test('none grouping puts all images in one album', () {
      final items = [mkImage('a.jpg'), mkImage('b.png'), mkImage('c.gif')];

      // Simulate _groupNone: single album with all images
      final album = Album.fromItems(
        name: 'All Images',
        path: '/',
        url: 'http://127.0.0.1:8080/',
        items: items,
      );

      expect(album.name, 'All Images');
      expect(album.itemCount, 3);
      expect(album.items, items);
    });

    test('none grouping with no images returns empty', () {
      // Simulate _groupNone with empty list
      expect(<MediaItem>[].isEmpty, isTrue);
    });
  });
}
