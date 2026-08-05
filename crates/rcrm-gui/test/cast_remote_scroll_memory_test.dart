// test/cast_remote_scroll_memory_test.dart
// CastRemoteScreen scroll-position memory: browsing into a subdirectory and
// back restores the previous scroll offset (per-directory PageStorageKey),
// positions never leak across directories, image/video tabs keep their own
// position, and returning to a directory reuses cached folder thumbnails
// (no second round of thumbnail probes).

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:rcrm_gui/models/media_item.dart';
import 'package:rcrm_gui/providers/server_provider.dart';
import 'package:rcrm_gui/screens/cast_remote_screen.dart';
import 'package:rcrm_gui/services/cast_protocol.dart';
import 'package:rcrm_gui/services/cast_remote.dart';
import 'package:rcrm_gui/services/thumb_cache.dart';
import 'package:rcrm_gui/services/thumbnail_service.dart';
import 'package:rcrm_gui/services/webdav_client.dart';

/// Network-free PROPFIND stub. Counts probes so tests can assert that folder
/// thumbnails are NOT re-fetched after a directory round trip.
class _FakeDavClient extends WebDavClient {
  _FakeDavClient() : super(baseUrl: 'http://127.0.0.1:18443');

  final Map<String, List<String>> dirs = {};
  final Map<String, List<MediaItem>> files = {};
  int listAllCalls = 0;

  @override
  Future<ListAllResult> listAll(String path) async {
    listAllCalls++;
    final subs = dirs[path];
    final fls = files[path];
    if (subs == null && fls == null) return const ListAllResult([], []);
    return ListAllResult(fls ?? const [], List.of(subs ?? const []));
  }
}

MediaItem _video(String path, String name) => MediaItem(
  path: path,
  url: 'http://127.0.0.1:18443$path',
  name: name,
  type: MediaType.video,
  size: 1024,
  modified: DateTime(2024, 1, 1),
);

/// The offset of the single browser ListView (folder/file rows).
double _listOffset(WidgetTester tester) {
  final scrollable = find.descendant(
    of: find.byType(ListView),
    matching: find.byType(Scrollable),
  );
  return tester.state<ScrollableState>(scrollable).position.pixels;
}

void main() {
  setUp(() {
    ThumbnailService.suppressPosterGeneration = true;
    // The folder-thumbnail reuse assertions must hold WITHOUT the on-disk
    // ThumbCache: everything here is served from in-memory caches only.
    ThumbCache.enabled = false;
  });
  tearDown(() {
    ThumbnailService.suppressPosterGeneration = false;
    ThumbCache.enabled = false;
  });

  late ProviderContainer container;
  late _FakeDavClient client;

  setUp(() {
    client = _FakeDavClient();
    container = ProviderContainer();
    addTearDown(container.dispose);
    container.read(serverProvider.notifier).state = ServerState(
      status: ServerStatus.running,
      url: 'http://127.0.0.1:18443',
      client: client,
    );
  });

  Future<void> pumpScreen(WidgetTester tester) async {
    await tester.pumpWidget(
      UncontrolledProviderScope(
        container: container,
        child: MaterialApp(
          home: CastRemoteScreen(
            remote: CastRemote(
              qr: const CastQrPayload(
                host: '192.168.1.10',
                port: 18443,
                token:
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                certSha256:
                    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
              ),
            ),
          ),
        ),
      ),
    );
    // Let _loadDir('/') complete and the list build. Total pumped time stays
    // under 1s so the poll timer never fires.
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 50));
  }

  testWidgets('scroll position is remembered per directory', (tester) async {
    client.dirs['/'] = [
      for (var i = 0; i < 30; i++) '/d${i.toString().padLeft(2, '0')}',
    ];
    client.dirs['/d05'] = [
      for (var i = 0; i < 30; i++) '/d05/s${i.toString().padLeft(2, '0')}',
    ];
    await pumpScreen(tester);

    expect(find.text('d05'), findsOneWidget);
    expect(_listOffset(tester), 0);

    // Scroll the root list down.
    await tester.drag(find.byType(ListView), const Offset(0, -300));
    await tester.pump();
    final rootOffset = _listOffset(tester);
    expect(rootOffset, greaterThan(0));

    // Enter d05 (still visible after scrolling): the new directory must
    // start at the TOP (position never leaks across directories).
    await tester.tap(find.text('d05'));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 50));
    expect(_listOffset(tester), 0);

    // Scroll inside the subdirectory, then go back up.
    await tester.drag(find.byType(ListView), const Offset(0, -200));
    await tester.pump();
    final subOffset = _listOffset(tester);
    expect(subOffset, greaterThan(0));

    await tester.tap(find.byTooltip('Up'));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 50));
    expect(_listOffset(tester), closeTo(rootOffset, 1));

    // Re-entering the subdirectory restores ITS offset.
    await tester.tap(find.text('d05'));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 50));
    expect(_listOffset(tester), closeTo(subOffset, 1));

    // Unmount so the poll timer is cancelled before the test ends.
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('returning to a directory reuses cached folder thumbnails', (
    tester,
  ) async {
    client.dirs['/'] = [
      for (var i = 0; i < 30; i++) '/d${i.toString().padLeft(2, '0')}',
    ];
    client.dirs['/d03'] = [
      for (var i = 0; i < 30; i++) '/d03/s${i.toString().padLeft(2, '0')}',
    ];
    await pumpScreen(tester);

    // Baseline: root listing + one probe per visible folder row.
    final callsBefore = client.listAllCalls;

    await tester.tap(find.text('d03'));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 50));
    final callsInSub = client.listAllCalls;
    // Entering adds the directory listing + the subdirectory's own probes.
    expect(callsInSub, greaterThan(callsBefore));

    // Go back up. The root rows rebuild, but their folder thumbnails are
    // served from the in-memory cache: only the listing itself is refetched.
    await tester.tap(find.byTooltip('Up'));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 50));
    expect(client.listAllCalls, callsInSub + 1);

    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('image and video tabs keep separate scroll positions', (
    tester,
  ) async {
    client.dirs['/'] = [
      for (var i = 0; i < 30; i++) '/d${i.toString().padLeft(2, '0')}',
    ];
    client.files['/'] = [
      for (var i = 0; i < 30; i++) _video('/v$i.mp4', 'v$i.mp4'),
    ];
    await pumpScreen(tester);

    // Videos tab (default): scroll down.
    await tester.drag(find.byType(ListView), const Offset(0, -300));
    await tester.pump();
    final videoOffset = _listOffset(tester);
    expect(videoOffset, greaterThan(0));

    // Switch to images: fresh key -> starts at the top.
    await tester.tap(find.byTooltip('Show images'));
    await tester.pump();
    expect(_listOffset(tester), 0);

    // Switch back to videos: position restored.
    await tester.tap(find.byTooltip('Show videos'));
    await tester.pump();
    expect(_listOffset(tester), closeTo(videoOffset, 1));

    await tester.pumpWidget(const SizedBox());
  });
}
