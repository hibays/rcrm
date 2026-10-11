// providers/settings_provider.dart
// RCrm GUI — UI settings state management
//
// Manages display preferences: image layout, preview settings, etc.

import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../services/media_library.dart';
import '../services/settings_service.dart';
import '../services/thumb_cache.dart';
import '../services/preview_player.dart';
import 'library_provider.dart';
import 'server_provider.dart'; // for settingsServiceProvider

// ── State ────────────────────────────────────────────────────

class SettingsState {
  final String imageLayout; // 'masonry' or 'uniform'
  final int imageColumns;
  final String imageSort; // 'name', 'date', 'size'
  final bool imageSortAsc;
  final bool previewEnabled;
  final bool thumbCacheEnabled;
  final String videoLayout; // 'grid' or 'list'
  final String imageClassification; // 'folder' or 'format'
  final bool pipEnabled;
  final String pipSize; // 'normal' or 'small'
  final String playbackMode; // 'loopAll' | 'loopOne' | 'pauseAfter'
  final bool autoRotate;
  final bool castAutoNext;

  /// How many previous videos the video player's jump stack keeps — the entries
  /// `Back` returns to and the Related list excludes
  /// (`providers/video_jump_stack.dart`). Persisted; the stack itself is not.
  final int videoJumpHistoryLimit;
  const SettingsState({
    this.imageLayout = 'masonry',
    this.imageColumns = 3,
    this.imageSort = 'name',
    this.imageSortAsc = true,
    this.previewEnabled = true,
    this.thumbCacheEnabled = true,
    this.videoLayout = 'grid',
    this.imageClassification = 'folder',
    this.pipEnabled = true,
    this.playbackMode = 'pauseAfter',
    this.autoRotate = false,
    this.castAutoNext = true,
    this.pipSize = 'normal',
    this.videoJumpHistoryLimit = kVideoJumpHistoryDefault,
  });

  SettingsState copyWith({
    String? imageLayout,
    int? imageColumns,
    String? imageSort,
    bool? imageSortAsc,
    bool? previewEnabled,
    bool? thumbCacheEnabled,
    String? videoLayout,
    String? imageClassification,
    bool? pipEnabled,
    String? playbackMode,
    bool? autoRotate,
    bool? castAutoNext,
    String? pipSize,
    int? videoJumpHistoryLimit,
  }) {
    return SettingsState(
      imageLayout: imageLayout ?? this.imageLayout,
      imageColumns: imageColumns ?? this.imageColumns,
      imageSort: imageSort ?? this.imageSort,
      imageSortAsc: imageSortAsc ?? this.imageSortAsc,
      previewEnabled: previewEnabled ?? this.previewEnabled,
      thumbCacheEnabled: thumbCacheEnabled ?? this.thumbCacheEnabled,
      videoLayout: videoLayout ?? this.videoLayout,
      imageClassification: imageClassification ?? this.imageClassification,
      playbackMode: playbackMode ?? this.playbackMode,
      pipEnabled: pipEnabled ?? this.pipEnabled,
      autoRotate: autoRotate ?? this.autoRotate,
      castAutoNext: castAutoNext ?? this.castAutoNext,
      pipSize: pipSize ?? this.pipSize,
      videoJumpHistoryLimit:
          videoJumpHistoryLimit ?? this.videoJumpHistoryLimit,
    );
  }
}

// ── Notifier ─────────────────────────────────────────────────

class SettingsNotifier extends Notifier<SettingsState> {
  @override
  SettingsState build() => const SettingsState();

  SettingsService get _service => ref.read(settingsServiceProvider);

  Future<void> load() async {
    final imageLayout = await _service.getImageLayout();
    final imageColumns = await _service.getImageColumns();
    final imageSort = await _service.getImageSort();
    final imageSortAsc = await _service.getImageSortAsc();
    final previewEnabled = await _service.getPreviewEnabled();
    PreviewPlayer.enabled = previewEnabled;
    final thumbCacheEnabled = await _service.getThumbCacheEnabled();
    ThumbCache.enabled = thumbCacheEnabled;
    final videoLayout = await _service.getVideoLayout();
    final imageClassification = await _service.getImageClassification();
    final pipEnabled = await _service.getPipEnabled();
    final pipSize = await _service.getPipSize();
    final playbackMode = await _service.getPlaybackMode();
    final autoRotate = await _service.getAutoRotate();
    final castAutoNext = await _service.getCastAutoNext();
    final videoJumpHistoryLimit = await _service.getVideoJumpHistoryLimit();

    // Restore video sort/grid columns from persistence. The video sort field
    // goes through `restore`, not `set`: `set` carries the re-pick rule below,
    // and a restored field that matches the default would read as a re-pick.
    ref.read(videoSortProvider.notifier).restore(await _service.getVideoSort());
    ref
        .read(videoSortAscProvider.notifier)
        .set(await _service.getVideoSortAsc());
    ref
        .read(videoGridColumnsProvider.notifier)
        .set(await _service.getVideoGridColumns());

    state = SettingsState(
      imageLayout: imageLayout,
      imageColumns: imageColumns,
      imageSort: imageSort,
      imageSortAsc: imageSortAsc,
      previewEnabled: previewEnabled,
      thumbCacheEnabled: thumbCacheEnabled,
      videoLayout: videoLayout,
      imageClassification: imageClassification,
      pipEnabled: pipEnabled,
      playbackMode: playbackMode,
      autoRotate: autoRotate,
      castAutoNext: castAutoNext,
      pipSize: pipSize,
      videoJumpHistoryLimit: videoJumpHistoryLimit,
    );
  }

  Future<void> setImageLayout(String layout) async {
    state = state.copyWith(imageLayout: layout);
    await _service.setImageLayout(layout);
  }

  Future<void> setImageColumns(int cols) async {
    final c = cols.clamp(2, 8);
    state = state.copyWith(imageColumns: c);
    await _service.setImageColumns(c);
  }

  /// The image page's album sort committed [sort] — the one entry point both
  /// the image screen (`screens/image_screen.dart`) and any future caller use.
  ///
  /// Re-picking the field already in effect reverses the direction instead of
  /// doing nothing; picking a different field starts that field ascending, and
  /// either way the direction now in effect is persisted and restored by
  /// [load]. The video page's `_SortNotifier.set` (library_provider.dart)
  /// carries this same rule, so the video and image screens answer a re-pick
  /// identically — keep the two in step.
  Future<void> setImageSort(String sort) async {
    final asc = state.imageSort == sort ? !state.imageSortAsc : true;
    state = state.copyWith(imageSort: sort, imageSortAsc: asc);
    await _service.setImageSort(sort);
    await _service.setImageSortAsc(asc);
  }

  Future<void> setVideoLayout(String layout) async {
    state = state.copyWith(videoLayout: layout);
    await _service.setVideoLayout(layout);
  }

  Future<void> setImageClassification(String method) async {
    state = state.copyWith(imageClassification: method);
    await _service.setImageClassification(method);

    // Trigger a re-scan so the new grouping takes effect immediately.
    final serverState = ref.read(serverProvider);
    if (serverState.isRunning && serverState.client != null) {
      final mediaLib = MediaLibrary(
        serverState.client!,
        imageClassification: switch (method) {
          'format' => ImageClassification.format,
          'none' => ImageClassification.none,
          _ => ImageClassification.folder,
        },
      );
      unawaited(ref.read(scanStateProvider.notifier).scan(mediaLib));
    }
  }

  Future<void> setPreviewEnabled(bool enabled) async {
    state = state.copyWith(previewEnabled: enabled);
    PreviewPlayer.enabled = enabled;
    await _service.setPreviewEnabled(enabled);
  }

  Future<void> setThumbCacheEnabled(bool enabled) async {
    state = state.copyWith(thumbCacheEnabled: enabled);
    ThumbCache.enabled = enabled;
    await _service.setThumbCacheEnabled(enabled);
  }

  Future<void> setPipSize(String size) async {
    state = state.copyWith(pipSize: size);
    await _service.setPipSize(size);
  }

  Future<void> setPipEnabled(bool enabled) async {
    state = state.copyWith(pipEnabled: enabled);
    await _service.setPipEnabled(enabled);
  }

  Future<void> setPlaybackMode(String mode) async {
    state = state.copyWith(playbackMode: mode);
    await _service.setPlaybackMode(mode);
  }

  Future<void> setAutoRotate(bool enabled) async {
    state = state.copyWith(autoRotate: enabled);
    await _service.setAutoRotate(enabled);
  }

  Future<void> setCastAutoNext(bool enabled) async {
    state = state.copyWith(castAutoNext: enabled);
    await _service.setCastAutoNext(enabled);
  }

  /// The settings slider (`screens/settings_screen.dart`) committed [limit] —
  /// the size of the video jump stack.
  ///
  /// A drag reports a value per frame: writing every one of them would queue a
  /// platform write per frame, and consecutive frames usually round to the same
  /// entry anyway, so only a real change is applied and persisted. The stack's
  /// own re-trim follows from this state change
  /// (`VideoJumpStackNotifier.build` listens to it).
  Future<void> setVideoJumpHistoryLimit(int limit) async {
    final v = limit.clamp(kVideoJumpHistoryMin, kVideoJumpHistoryMax);
    if (v == state.videoJumpHistoryLimit) return;
    state = state.copyWith(videoJumpHistoryLimit: v);
    await _service.setVideoJumpHistoryLimit(v);
  }
}

// ── Provider ─────────────────────────────────────────────────

final uiSettingsProvider = NotifierProvider<SettingsNotifier, SettingsState>(
  SettingsNotifier.new,
);
