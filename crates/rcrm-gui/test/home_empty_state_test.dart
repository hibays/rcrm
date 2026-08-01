// test/home_empty_state_test.dart
// Verifies the "server stopped → library cache cleared" consistency:
// after stop(), the Home tab must show the empty state and MUST NOT render a
// Recommended row, and the Videos tab must show "No videos found".
import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:rcrm_gui/models/media_item.dart';
import 'package:rcrm_gui/providers/library_provider.dart';
import 'package:rcrm_gui/providers/server_provider.dart';
import 'package:rcrm_gui/screens/home_screen.dart';
import 'package:rcrm_gui/services/media_library.dart';
import 'package:rcrm_gui/services/thumbnail_service.dart';
import 'package:rcrm_gui/services/webdav_client.dart';

MediaItem _video(String path, String name) => MediaItem(
  path: path,
  url: 'http://127.0.0.1:18443$path',
  name: name,
  type: MediaType.video,
  size: 1024,
  modified: DateTime(2024, 1, 1),
);

void main() {
  setUp(() => ThumbnailService.suppressPosterGeneration = true);
  tearDown(() => ThumbnailService.suppressPosterGeneration = false);
  testWidgets(
    'stopping the server clears library caches and shows consistent empty UI',
    (tester) async {
      final container = ProviderContainer();
      addTearDown(container.dispose);

      // Server running with scanned media.
      container.read(serverProvider.notifier).state = const ServerState(
        status: ServerStatus.running,
        url: 'http://127.0.0.1:18443',
      );
      final videos = container.read(videosMapProvider.notifier);
      videos.addAll([_video('/a.mp4', 'a.mp4'), _video('/b.mp4', 'b.mp4')]);
      container.read(recentVideosProvider.notifier).addBatch([
        _video('/a.mp4', 'a.mp4'),
        _video('/b.mp4', 'b.mp4'),
      ]);
      container.read(recentVideosProvider.notifier).sort();
      container.read(scanStateProvider.notifier).state = const ScanState(
        isLoading: false,
        hasCompletedOnce: true,
      );

      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: container,
          child: const MaterialApp(home: HomeScreen()),
        ),
      );
      await tester.pump();

      // Before stop: Recommended row present, no empty state.
      expect(find.text('Recommended'), findsOneWidget);
      expect(find.text('No media found'), findsNothing);

      // Stop the server.
      container.read(serverProvider.notifier).state = const ServerState();
      await tester.pump();
      await tester.pump();

      // Home: empty state shown, Recommended gone, recent gone.
      expect(find.text('No media found'), findsOneWidget);
      expect(find.text('Recommended'), findsNothing);
      expect(find.text('Recent Videos'), findsNothing);

      // Videos tab: no stale items.
      await tester.tap(find.text('Videos'));
      await tester.pump();
      expect(find.text('No videos found'), findsOneWidget);

      // Data stores are actually empty (not just hidden).
      expect(container.read(videosMapProvider), isEmpty);
      expect(container.read(recentVideosProvider), isEmpty);
    },
  );

  testWidgets('empty state requires ALL sources empty (recommended included)', (
    tester,
  ) async {
    final container = ProviderContainer();
    addTearDown(container.dispose);
    container.read(serverProvider.notifier).state = const ServerState(
      status: ServerStatus.running,
    );
    // Videos present (recommended will be non-empty) but recent list empty —
    // the pathological split the old condition missed.
    container.read(videosMapProvider.notifier).addAll([
      _video('/a.mp4', 'a.mp4'),
    ]);
    container.read(scanStateProvider.notifier).state = const ScanState(
      isLoading: false,
      hasCompletedOnce: true,
    );

    await tester.pumpWidget(
      UncontrolledProviderScope(
        container: container,
        child: const MaterialApp(home: HomeScreen()),
      ),
    );
    await tester.pump();

    // Recommended must render, and "No media found" must NOT appear next to it.
    expect(find.text('Recommended'), findsOneWidget);
    expect(find.text('No media found'), findsNothing);
  });

  testWidgets('stop during an in-flight scan does not re-populate the stores', (
    tester,
  ) async {
    final container = ProviderContainer();
    addTearDown(container.dispose);
    container.read(serverProvider.notifier).state = const ServerState(
      status: ServerStatus.running,
    );

    // Fake WebDAV server: root listing returns one video + a subdir whose
    // listing is blocked until we release it — so the scan is still in
    // flight when stop() happens.
    final gate = Completer<void>();
    final fake = _GateWebDav(gate);
    final lib = MediaLibrary(fake);

    final scanFuture = container.read(scanStateProvider.notifier).scan(lib);
    await tester.pump(); // root batch processed
    expect(
      container.read(videosMapProvider),
      isNotEmpty,
      reason: 'root batch lands before stop',
    );

    // Stop the server while the scan is blocked in the subdir.
    container.read(serverProvider.notifier).state = const ServerState();
    await tester.pump();
    expect(
      container.read(videosMapProvider),
      isEmpty,
      reason: 'stop clears the stores',
    );

    // Release the blocked subdir: its batch must be DISCARDED (gen bumped),
    // not re-added. The scan's internal Future.delayed(Duration.zero) timers
    // only fire when the fake clock advances — pump() with no duration does
    // NOT flush them, so pump(duration) is required here.
    gate.complete();
    await tester.pump(const Duration(milliseconds: 1));
    await tester.pump(const Duration(milliseconds: 1));
    await scanFuture;
    await tester.pump();

    expect(
      container.read(videosMapProvider),
      isEmpty,
      reason: 'stale in-flight batch must not repopulate after stop',
    );
    expect(container.read(recentVideosProvider), isEmpty);
  });
}

/// WebDAV client whose subdirectory listing hangs until [gate] completes.
class _GateWebDav extends WebDavClient {
  final Completer<void> gate;
  _GateWebDav(this.gate)
    : super(baseUrl: 'http://127.0.0.1:1', username: '', password: '');

  @override
  Future<ListAllResult> listAll(String path) async {
    if (path == '/') {
      return ListAllResult([_video('/a.mp4', 'a.mp4')], ['/sub']);
    }
    await gate.future;
    return const ListAllResult([], []);
  }
}
