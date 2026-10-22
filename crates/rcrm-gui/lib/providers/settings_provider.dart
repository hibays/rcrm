// providers/settings_provider.dart
// RCrm GUI — UI settings state management
//
// Manages display preferences: image layout, preview settings, etc.

import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../services/media_library.dart';
import '../services/screen_capture.dart';
import '../services/settings_service.dart';
import '../services/thumb_cache.dart';
import '../services/preview_player.dart';
import '../services/system_volume.dart';
import 'library_provider.dart';
import 'server_provider.dart'; // for settingsServiceProvider
import '../utils/player_orientation.dart';

// ── State ────────────────────────────────────────────────────

class SettingsState {
  final String imageLayout; // 'masonry' or 'uniform'
  final int imageColumns;
  final String imageSort; // 'name', 'date', 'size'
  final bool imageSortAsc;
  final bool previewEnabled;
  final bool thumbCacheEnabled;

  /// See `SettingsService.getThumbCacheLimitMb`: `0` platform default, `>0` that
  /// many MB — the size the manual clean-up trims to. Mirrored into
  /// `ThumbCache.limitMb`.
  final int thumbCacheLimitMb;
  final String videoLayout; // 'grid' or 'list'
  final String imageClassification; // 'folder' or 'format'

  /// How the video tab organizes its list: 'none' (flat grid, the default and
  /// the tab's historical behaviour), 'folder' or 'format'. Persisted; the
  /// folders themselves are derived, not stored (`videoFoldersProvider`).
  final String videoClassification; // 'none' | 'folder' | 'format'
  final bool pipEnabled;
  final String pipSize; // 'normal' or 'small'
  /// What the player does when a file ends, in `PlaybackMode.key`'s vocabulary
  /// (`utils/player_playback_mode.dart`): 'loopAll' | 'shuffle' | 'loopOne' |
  /// 'pauseAfter'. Kept as the stored string rather than the enum so this
  /// provider stays free of the player's own types; the screen converts once, at
  /// the two places that read it.
  final String playbackMode;

  /// How the FULLSCREEN mobile player chooses which way up it is
  /// (`utils/player_orientation.dart`): fit the video (the default), follow the
  /// system's own preference, follow the phone's real posture even against the
  /// system's rotation lock, or stay in one orientation. Replaces the old
  /// `autoRotate` boolean, whose switch promised the rotation-lock override and
  /// could not deliver it.
  final PlayerOrientation playerOrientation;
  final bool castAutoNext;

  /// Whether the system may capture the app's pixels — screenshots, screen
  /// recording, the recent-apps preview. Mobile only, and **off by default**:
  /// the library is decrypted media and a capture of it outlives the session.
  /// The platform window is what enforces it, so every write here leaves Dart
  /// (`services/screen_capture.dart`).
  final bool allowScreenshots;

  /// Whether the player's volume control moves the DEVICE's media volume
  /// instead of the player's own gain. Mobile only, **on by default there**:
  /// the phone's hardware keys and every other media app move that one stream,
  /// so a video holding a private volume above it disagrees with the phone.
  /// The platform is not told — the player reads this when it opens, and only
  /// binds when the device can really be set (`shouldBindSystemVolume`).
  final bool useSystemVolume;

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
    this.thumbCacheLimitMb = 0,
    this.videoLayout = 'grid',
    this.imageClassification = 'folder',
    this.videoClassification = 'none',
    this.pipEnabled = true,
    this.playbackMode = 'pauseAfter',
    this.playerOrientation = defaultOrientation,
    this.castAutoNext = true,
    this.pipSize = 'normal',
    this.videoJumpHistoryLimit = kVideoJumpHistoryDefault,
    this.allowScreenshots = false,
    this.useSystemVolume = true,
  });

  SettingsState copyWith({
    String? imageLayout,
    int? imageColumns,
    String? imageSort,
    bool? imageSortAsc,
    bool? previewEnabled,
    bool? thumbCacheEnabled,
    int? thumbCacheLimitMb,
    String? videoLayout,
    String? imageClassification,
    String? videoClassification,
    bool? pipEnabled,
    String? playbackMode,
    PlayerOrientation? playerOrientation,
    bool? castAutoNext,
    String? pipSize,
    int? videoJumpHistoryLimit,
    bool? allowScreenshots,
    bool? useSystemVolume,
  }) {
    return SettingsState(
      imageLayout: imageLayout ?? this.imageLayout,
      imageColumns: imageColumns ?? this.imageColumns,
      imageSort: imageSort ?? this.imageSort,
      imageSortAsc: imageSortAsc ?? this.imageSortAsc,
      previewEnabled: previewEnabled ?? this.previewEnabled,
      thumbCacheEnabled: thumbCacheEnabled ?? this.thumbCacheEnabled,
      thumbCacheLimitMb: thumbCacheLimitMb ?? this.thumbCacheLimitMb,
      videoLayout: videoLayout ?? this.videoLayout,
      imageClassification: imageClassification ?? this.imageClassification,
      videoClassification: videoClassification ?? this.videoClassification,
      playbackMode: playbackMode ?? this.playbackMode,
      pipEnabled: pipEnabled ?? this.pipEnabled,
      playerOrientation: playerOrientation ?? this.playerOrientation,
      castAutoNext: castAutoNext ?? this.castAutoNext,
      pipSize: pipSize ?? this.pipSize,
      videoJumpHistoryLimit:
          videoJumpHistoryLimit ?? this.videoJumpHistoryLimit,
      allowScreenshots: allowScreenshots ?? this.allowScreenshots,
      useSystemVolume: useSystemVolume ?? this.useSystemVolume,
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
    final thumbCacheLimitMb = await _service.getThumbCacheLimitMb();
    ThumbCache.limitMb = thumbCacheLimitMb;
    final videoLayout = await _service.getVideoLayout();
    final imageClassification = await _service.getImageClassification();
    final videoClassification = await _service.getVideoClassification();
    final pipEnabled = await _service.getPipEnabled();
    final pipSize = await _service.getPipSize();
    final playbackMode = await _service.getPlaybackMode();
    final playerOrientation = await _service.getPlayerOrientation();
    final castAutoNext = await _service.getCastAutoNext();
    final videoJumpHistoryLimit = await _service.getVideoJumpHistoryLimit();
    final allowScreenshots = await _service.getAllowScreenshots();
    final useSystemVolume = await _service.getUseSystemVolume();
    // The one reading taken at APP start, for the volume binding: a player
    // opened later seeds its bar from this before it asks again, so the bar
    // never opens on 100 while a platform round trip is in flight. Unawaited
    // for the same reason the capture policy below is: restoring the settings
    // must not depend on a platform answering.
    if (SystemVolume.supported) {
      SystemVolume.watch();
      unawaited(SystemVolume.read());
    }
    // Mirrored onto the platform, not just remembered: the window that is
    // capturable or not belongs to the OS, and the Android half starts SECURE
    // (`MainActivity.onCreate`, before Dart exists) — so this is what lifts it
    // when the stored choice says capture is allowed.
    //
    // Deliberately NOT awaited: restoring the settings must not depend on a
    // platform answering, and nothing here reads the result. (Awaiting a channel
    // round-trip inside `testWidgets` also never resolves — the fake clock does
    // not advance the engine's reply — which stalled every existing test that
    // calls `load()` until this was unawaited.)
    unawaited(ScreenCapture.setAllowed(allowScreenshots));

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
      thumbCacheLimitMb: thumbCacheLimitMb,
      videoLayout: videoLayout,
      imageClassification: imageClassification,
      videoClassification: videoClassification,
      pipEnabled: pipEnabled,
      playbackMode: playbackMode,
      playerOrientation: playerOrientation,
      castAutoNext: castAutoNext,
      pipSize: pipSize,
      videoJumpHistoryLimit: videoJumpHistoryLimit,
      allowScreenshots: allowScreenshots,
      useSystemVolume: useSystemVolume,
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
          'format' => MediaClassification.format,
          'none' => MediaClassification.none,
          _ => MediaClassification.folder,
        },
      );
      unawaited(ref.read(scanStateProvider.notifier).scan(mediaLib));
    }
  }

  /// The video tab's grouping — the toolbar's grouping button commits here.
  ///
  /// Unlike [setImageClassification] this needs no re-scan: the video folders are
  /// DERIVED from the already-scanned list (`videoFoldersProvider`), so a new
  /// grouping is in the next frame. The photo path re-scans because its albums
  /// are built inside the [MediaLibrary] it was constructed with, which makes the
  /// classification a property of the library rather than of the view.
  Future<void> setVideoClassification(String method) async {
    state = state.copyWith(videoClassification: method);
    await _service.setVideoClassification(method);
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

  Future<void> setThumbCacheLimitMb(int mb) async {
    state = state.copyWith(thumbCacheLimitMb: mb);
    ThumbCache.limitMb = mb;
    await _service.setThumbCacheLimitMb(mb);
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

  /// The fullscreen orientation strategy — the player's settings panel, mobile
  /// only.
  ///
  /// The player applies it immediately (it is watching the panel), so this only
  /// remembers the choice; the screen's `_applyOrientation` is what the platform
  /// hears.
  Future<void> setPlayerOrientation(PlayerOrientation mode) async {
    state = state.copyWith(playerOrientation: mode);
    await _service.setPlayerOrientation(mode);
  }

  Future<void> setCastAutoNext(bool enabled) async {
    state = state.copyWith(castAutoNext: enabled);
    await _service.setCastAutoNext(enabled);
  }

  /// The screenshots policy — Settings → Privacy, mobile only.
  ///
  /// The platform is told FIRST and the choice is persisted second: the switch
  /// is the user saying "stop capturing this window now", and a write to disk
  /// that fails afterwards must not leave the window capturable.
  Future<void> setAllowScreenshots(bool allowed) async {
    state = state.copyWith(allowScreenshots: allowed);
    await ScreenCapture.setAllowed(allowed);
    await _service.setAllowScreenshots(allowed);
  }

  /// The volume binding — Settings → Display, mobile only.
  ///
  /// Nothing is pushed to the platform: the choice is read when a player opens,
  /// and the player is the only thing that acts on it. A player that is already
  /// open keeps the choice it started with, which is the same rule the rest of
  /// the player's own settings follow.
  Future<void> setUseSystemVolume(bool enabled) async {
    state = state.copyWith(useSystemVolume: enabled);
    await _service.setUseSystemVolume(enabled);
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
