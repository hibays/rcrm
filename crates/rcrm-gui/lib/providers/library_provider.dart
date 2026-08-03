// providers/library_provider.dart
// RCrm GUI — reactive incremental media library state
//
// Data stores (videosMapProvider / imagesMapProvider) accumulate scan
// batches incrementally. Derived providers (sortedVideos, albums, etc.)
// recompose reactively when their inputs change.

import 'dart:async';
import 'dart:math';

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../models/album.dart';
import '../models/media_item.dart';
import '../services/media_library.dart';
import '../utils/natural_sort.dart';
import 'server_provider.dart';
import 'settings_provider.dart';

// ── Scan state ────────────────────────────────────────────────

class ScanState {
  final bool isLoading;
  final String? error;

  /// True after at least one scan has completed successfully.
  final bool hasCompletedOnce;

  /// Monotonically increasing scan generation, incremented on every scan() call.
  /// Used by consumers to invalidate caches that depend on library content.
  final int scanGen;

  const ScanState({
    this.isLoading = false,
    this.error,
    this.hasCompletedOnce = false,
    this.scanGen = 0,
  });

  ScanState copyWith({
    bool? isLoading,
    String? error,
    bool? hasCompletedOnce,
    int? scanGen,
  }) {
    return ScanState(
      isLoading: isLoading ?? this.isLoading,
      error: error,
      hasCompletedOnce: hasCompletedOnce ?? this.hasCompletedOnce,
      scanGen: scanGen ?? this.scanGen,
    );
  }
}

class ScanCoordinator extends Notifier<ScanState> {
  @override
  ScanState build() {
    // When the server stops, ALL cached library data is dropped so the UI
    // can't show stale media next to a "no media found" empty state. The
    // maps are plain NotifierProviders (kept alive), so without this they
    // would retain the last scan's items after stop().
    ref.listen(serverProvider, (prev, next) {
      if ((prev?.isRunning ?? false) && !next.isRunning) {
        // Invalidate any scan still in flight: its onBatch/completion
        // callbacks check _scanGen and would otherwise re-populate the
        // stores AFTER the clear below (stop during a scan).
        _scanGen++;
        _clearAll();
        state = const ScanState();
      }
    });
    return const ScanState();
  }

  void _clearAll() {
    ref.read(videosMapProvider.notifier).clear();
    ref.read(imagesMapProvider.notifier).clear();
    ref.read(recentVideosProvider.notifier).clear();
  }

  int _scanGen = 0;

  Future<void> scan(MediaLibrary library) async {
    final myGen = ++_scanGen;
    state = ScanState(scanGen: _scanGen, isLoading: true);
    ref.read(videosMapProvider.notifier).clear();
    ref.read(imagesMapProvider.notifier).clear();
    ref.read(recentVideosProvider.notifier).clear();
    try {
      await library
          .scanAll(
            onBatch: (batchVideos, batchImages) {
              if (myGen != _scanGen) return;
              ref.read(videosMapProvider.notifier).addAll(batchVideos);
              ref.read(imagesMapProvider.notifier).addAll(batchImages);
              ref.read(recentVideosProvider.notifier).addBatch(batchVideos);
            },
          )
          .timeout(const Duration(seconds: 120));
      if (myGen != _scanGen) return;
      ref.read(recentVideosProvider.notifier).sort();
      state = state.copyWith(
        isLoading: false,
        hasCompletedOnce: true,
        scanGen: _scanGen,
      );
    } on TimeoutException {
      if (myGen != _scanGen) return;
      state = state.copyWith(
        isLoading: false,
        error: 'Scan timed out. Large libraries may need more time.',
        scanGen: _scanGen,
      );
    } catch (e) {
      if (myGen != _scanGen) return;
      state = state.copyWith(
        isLoading: false,
        error: 'Failed to scan library: $e. Check server connection.',
        scanGen: _scanGen,
      );
    }
  }
}

final scanStateProvider = NotifierProvider<ScanCoordinator, ScanState>(
  ScanCoordinator.new,
);

// ── Data stores (incremental, keyed by path) ──────────────────

class VideosNotifier extends Notifier<Map<String, MediaItem>> {
  @override
  Map<String, MediaItem> build() => {};

  void clear() => state = {};

  void addAll(List<MediaItem> items) {
    if (items.isEmpty) return;
    final map = Map<String, MediaItem>.of(state);
    for (final item in items) {
      map[item.path] = item;
    }
    state = map;
  }
}

final videosMapProvider =
    NotifierProvider<VideosNotifier, Map<String, MediaItem>>(
      VideosNotifier.new,
    );

class ImagesNotifier extends Notifier<Map<String, MediaItem>> {
  @override
  Map<String, MediaItem> build() => {};

  void clear() => state = {};

  void addAll(List<MediaItem> items) {
    if (items.isEmpty) return;
    final map = Map<String, MediaItem>.of(state);
    for (final item in items) {
      map[item.path] = item;
    }
    state = map;
  }
}

final imagesMapProvider =
    NotifierProvider<ImagesNotifier, Map<String, MediaItem>>(
      ImagesNotifier.new,
    );

// ── Helpers ───────────────────────────────────────────────────

/// Reusable MediaLibrary instance that follows the current server + settings.
final mediaLibraryProvider = Provider<MediaLibrary?>((ref) {
  final serverState = ref.watch(serverProvider);
  final client = serverState.client;
  if (client == null) return null;
  final imageClass = ref.watch(
    uiSettingsProvider.select((s) => s.imageClassification),
  );
  return MediaLibrary(
    client,
    imageClassification: switch (imageClass) {
      'format' => ImageClassification.format,
      'none' => ImageClassification.none,
      _ => ImageClassification.folder,
    },
  );
});

// ── Video settings (standalone, persisted) ────────────────────

class SettingNotifier<T> extends Notifier<T> {
  SettingNotifier(this.defaultValue);
  final T defaultValue;

  @override
  T build() => defaultValue;

  void set(T value) => state = value;
}

class _SortNotifier extends Notifier<String> {
  @override
  String build() => 'name';

  void set(String value) {
    state = value;
    unawaited(ref.read(settingsServiceProvider).setVideoSort(value));
  }
}

final videoSortProvider = NotifierProvider<_SortNotifier, String>(
  _SortNotifier.new,
);

class _SortAscNotifier extends Notifier<bool> {
  @override
  bool build() => true;

  void set(bool value) {
    state = value;
    unawaited(ref.read(settingsServiceProvider).setVideoSortAsc(value));
  }
}

final videoSortAscProvider = NotifierProvider<_SortAscNotifier, bool>(
  _SortAscNotifier.new,
);
final videoFilterProvider = NotifierProvider<SettingNotifier<String>, String>(
  () => SettingNotifier(''),
);

class _GridColumnsNotifier extends Notifier<int> {
  @override
  int build() => 4;

  void set(int value) {
    state = value;
    unawaited(ref.read(settingsServiceProvider).setVideoGridColumns(value));
  }
}

final videoGridColumnsProvider = NotifierProvider<_GridColumnsNotifier, int>(
  _GridColumnsNotifier.new,
);

// ── Derived providers ─────────────────────────────────────────

final sortedVideosProvider = Provider<List<MediaItem>>((ref) {
  final videos = ref.watch(videosMapProvider).values;
  final sort = ref.watch(videoSortProvider);
  final asc = ref.watch(videoSortAscProvider);
  final filter = ref.watch(videoFilterProvider);

  var list = videos.toList();

  if (filter.isNotEmpty) {
    final f = filter.toLowerCase();
    list.retainWhere((v) => v.extension.toLowerCase() == f);
  }

  list.sort((a, b) {
    int c;
    switch (sort) {
      case 'name':
        c = naturalCompare(a.name, b.name);
        break;
      case 'date':
        c = (a.modified ?? DateTime(2000)).compareTo(
          b.modified ?? DateTime(2000),
        );
        break;
      case 'size':
        c = a.size.compareTo(b.size);
        break;
      case 'duration':
        c = (a.durationSeconds ?? 0).compareTo(b.durationSeconds ?? 0);
        break;
      default:
        return 0;
    }
    return asc ? c : -c;
  });

  return list;
});

List<MediaItem> _shuffleWithSeed(List<MediaItem> items, int seed) {
  if (items.length < 2) return items;
  final list = List<MediaItem>.of(items);
  final rng = Random(seed);
  for (var i = list.length - 1; i > 0; i--) {
    final j = rng.nextInt(i + 1);
    final tmp = list[i];
    list[i] = list[j];
    list[j] = tmp;
  }
  return list;
}

/// Recommended videos: Fisher-Yates shuffle seeded by day number, take 10.
/// Rotates daily so the set stays fresh during browsing.
final recommendedProvider = Provider.autoDispose.family<List<MediaItem>, int>((
  ref,
  daySeed,
) {
  final videos = ref.watch(videosMapProvider).values.toList();
  if (videos.isEmpty) return const [];
  final shuffled = _shuffleWithSeed(videos, daySeed);
  return shuffled.take(10).toList();
});

final videoExtensionsProvider = Provider<Set<String>>((ref) {
  return ref
      .watch(videosMapProvider)
      .values
      .map((v) => v.extension)
      .where((e) => e.isNotEmpty)
      .toSet();
});

final albumsProvider = Provider<List<Album>>((ref) {
  final images = ref.watch(imagesMapProvider).values.toList();
  final lib = ref.watch(mediaLibraryProvider);
  if (lib == null) return const [];
  return lib.buildAlbums(images);
});

final videosListProvider = Provider<List<MediaItem>>(
  (ref) => ref.watch(videosMapProvider).values.toList(),
);

/// Accumulates videos during scan (append-only, no sort).
/// After scan completes, call [sort] once for O(n log n) recency order.
class RecentVideosNotifier extends Notifier<List<MediaItem>> {
  @override
  List<MediaItem> build() => const [];

  void clear() => state = const [];

  void addBatch(List<MediaItem> batch) {
    if (batch.isEmpty) return;
    state = [...state, ...batch];
  }

  void sort() {
    final sorted = List<MediaItem>.of(state)
      ..sort((a, b) {
        final da = a.modified ?? DateTime(2000);
        final db = b.modified ?? DateTime(2000);
        return db.compareTo(da);
      });
    sorted.length = min(sorted.length, 200);
    state = sorted;
  }
}

final recentVideosProvider =
    NotifierProvider<RecentVideosNotifier, List<MediaItem>>(
      RecentVideosNotifier.new,
    );
