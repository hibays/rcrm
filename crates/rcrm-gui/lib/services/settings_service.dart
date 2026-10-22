// services/settings_service.dart
// RCrm GUI — persistent user settings service
//
// Stores display preferences, library configuration, and UI state
// using SharedPreferences.

import 'dart:convert';
import 'dart:io' show Platform;

import 'package:shared_preferences/shared_preferences.dart';

import '../models/server_config.dart';
import '../utils/player_orientation.dart';

/// Bounds and default of the video jump-history limit — how many previous
/// videos `Back` can return to (`providers/video_jump_stack.dart`) and how many
/// are kept out of the Related list. The range lives here, next to the key that
/// persists it, so the service's clamp and the settings slider's travel cannot
/// drift apart.
///
/// 1 is the floor because one remembered video is the smallest useful history;
/// 50 is the ceiling because past that the exclusion set swallows whole small
/// libraries' Related lists for no gain.
const int kVideoJumpHistoryMin = 1;
const int kVideoJumpHistoryMax = 50;
const int kVideoJumpHistoryDefault = 10;

/// The default of the mobile volume binding (`use_system_volume`).
///
/// A pure function of the platform family rather than a read of `Platform`, so
/// both branches are assertable on any host — the tests run the desktop VM,
/// where the mobile answer is unreachable. On a phone the hardware keys and
/// every other media app move the same media stream, so the player follows it
/// unless told otherwise; a desktop's mixer is the user's own business, and its
/// own slider is the behaviour expected there (where the row is not offered at
/// all — see `SystemVolume.supported`).
bool useSystemVolumeDefault({required bool isDesktop}) => !isDesktop;

class SettingsService {
  static const _keyServerConfig = 'server_config';
  static const _keyVideoLayout = 'video_layout'; // 'grid' or 'list'
  static const _keyVideoGridColumns = 'video_grid_columns';
  static const _keyVideoSort = 'video_sort';
  static const _keyVideoSortAsc = 'video_sort_asc';
  static const _keyImageLayout = 'image_layout'; // 'masonry' or 'uniform'
  static const _keyImageColumns = 'image_columns';
  static const _keyImageSort = 'image_sort'; // 'name', 'date', 'size'
  static const _keyImageSortAsc = 'image_sort_asc';
  static const _keyImageClassification =
      'image_classification'; // 'folder' | 'format'
  static const _keyVideoClassification =
      'video_classification'; // 'none' | 'folder' | 'format'
  static const _keyPreviewEnabled = 'preview_enabled';
  static const _keyThumbCache = 'thumb_cache_enabled';
  static const _keyThumbCacheLimit = 'thumb_cache_limit_mb';
  static const _keyPipEnabled = 'pip_enabled';
  static const _keyPipSize = 'pip_size'; // 'normal' or 'small'
  static const _keyPlaybackMode =
      'playback_mode'; // 'loopAll' | 'loopOne' | 'pauseAfter'
  static const _keyAutoRotate = 'auto_rotate'; // bool, legacy -- read once, never written
  static const _keyPlayerOrientation = 'player_orientation'; // PlayerOrientation.key
  static const _keyCastAutoNext = 'cast_auto_next'; // bool
  static const _keyVideoJumpHistory = 'video_jump_history_limit'; // int, 1..50
  static const _keyAllowScreenshots = 'allow_screenshots'; // bool, mobile only
  static const _keyUseSystemVolume = 'use_system_volume'; // bool, mobile only

  SharedPreferences? _prefs;

  Future<SharedPreferences> get prefs async {
    _prefs ??= await SharedPreferences.getInstance();
    return _prefs!;
  }

  // ── Server config ───────────────────────────────────────────

  Future<ServerConfig> getServerConfig() async {
    final p = await prefs;
    final json = p.getString(_keyServerConfig);
    if (json == null) return const ServerConfig();
    try {
      // fromJson ignores any password field, so the loaded config is
      // always password-free; the user re-enters it each session.
      return ServerConfig.fromJson(jsonDecode(json));
    } catch (_) {
      return const ServerConfig();
    }
  }

  Future<void> saveServerConfig(ServerConfig config) async {
    final p = await prefs;
    await p.setString(_keyServerConfig, jsonEncode(config.toJson()));
  }

  Future<DeployMode> getDeployMode() async {
    final config = await getServerConfig();
    return config.deployMode;
  }

  Future<void> setDeployMode(DeployMode mode) async {
    final config = await getServerConfig();
    await saveServerConfig(config.copyWith(deployMode: mode));
  }

  Future<void> saveCloudServerConfig(String url, String username) async {
    final config = await getServerConfig();
    await saveServerConfig(
      config.copyWith(remoteUrl: url, remoteUsername: username),
    );
  }

  // ── Video display settings ─────────────────────────────────

  Future<String> getVideoLayout() async {
    final p = await prefs;
    return p.getString(_keyVideoLayout) ?? 'grid';
  }

  Future<void> setVideoLayout(String layout) async {
    final p = await prefs;
    await p.setString(_keyVideoLayout, layout);
  }

  Future<int> getVideoGridColumns() async {
    final p = await prefs;
    return p.getInt(_keyVideoGridColumns) ?? 4;
  }

  Future<void> setVideoGridColumns(int cols) async {
    final p = await prefs;
    await p.setInt(_keyVideoGridColumns, cols.clamp(1, 8));
  }

  Future<String> getVideoSort() async {
    final p = await prefs;
    return p.getString(_keyVideoSort) ?? 'name';
  }

  Future<void> setVideoSort(String sort) async {
    final p = await prefs;
    await p.setString(_keyVideoSort, sort);
  }

  Future<bool> getVideoSortAsc() async {
    final p = await prefs;
    return p.getBool(_keyVideoSortAsc) ?? true;
  }

  Future<void> setVideoSortAsc(bool asc) async {
    final p = await prefs;
    await p.setBool(_keyVideoSortAsc, asc);
  }

  // ── Image display settings ─────────────────────────────────

  Future<String> getImageLayout() async {
    final p = await prefs;
    return p.getString(_keyImageLayout) ?? 'masonry';
  }

  Future<void> setImageLayout(String layout) async {
    final p = await prefs;
    await p.setString(_keyImageLayout, layout);
  }

  Future<int> getImageColumns() async {
    final p = await prefs;
    return p.getInt(_keyImageColumns) ?? 3;
  }

  Future<void> setImageColumns(int cols) async {
    final p = await prefs;
    await p.setInt(_keyImageColumns, cols.clamp(2, 8));
  }

  Future<String> getImageSort() async {
    final p = await prefs;
    return p.getString(_keyImageSort) ?? 'name';
  }

  Future<void> setImageSort(String sort) async {
    final p = await prefs;
    await p.setString(_keyImageSort, sort);
  }

  /// Direction of [getImageSort], persisted exactly like the video one
  /// (`getVideoSortAsc`) so a re-pick of the active field survives a relaunch.
  Future<bool> getImageSortAsc() async {
    final p = await prefs;
    return p.getBool(_keyImageSortAsc) ?? true;
  }

  Future<void> setImageSortAsc(bool asc) async {
    final p = await prefs;
    await p.setBool(_keyImageSortAsc, asc);
  }
  // ── Image classification ─────────────────────────────────

  Future<String> getImageClassification() async {
    final p = await prefs;
    return p.getString(_keyImageClassification) ?? 'folder';
  }

  Future<void> setImageClassification(String method) async {
    final p = await prefs;
    await p.setString(_keyImageClassification, method);
  }

  // ── Video classification ─────────────────────────────────
  // How the video tab organizes its list: 'none' (the flat grid of every video,
  // which is what the tab has always shown, and the default), 'folder' (by
  // parent folder) or 'format' (by extension). Read back unvalidated on purpose:
  // an unknown value means "no grouping", the same as an absent one, so the
  // reader maps it in one place (`videoFoldersProvider`).
  Future<String> getVideoClassification() async {
    final p = await prefs;
    return p.getString(_keyVideoClassification) ?? 'none';
  }

  Future<void> setVideoClassification(String method) async {
    final p = await prefs;
    await p.setString(_keyVideoClassification, method);
  }

  // ── Preview settings ──────────────────────────────────────

  Future<bool> getPreviewEnabled() async {
    final p = await prefs;
    return p.getBool(_keyPreviewEnabled) ?? true;
  }

  Future<void> setPreviewEnabled(bool enabled) async {
    final p = await prefs;
    await p.setBool(_keyPreviewEnabled, enabled);
  }

  // ── Thumbnail cache ──────────────────────────────
  // Default: ON for mobile (slow to regenerate), OFF for desktop.
  Future<bool> getThumbCacheEnabled() async {
    final p = await prefs;
    final isDesktop =
        Platform.isWindows || Platform.isLinux || Platform.isMacOS;
    return p.getBool(_keyThumbCache) ?? !isDesktop;
  }

  Future<void> setThumbCacheEnabled(bool enabled) async {
    final p = await prefs;
    await p.setBool(_keyThumbCache, enabled);
  }

  /// The size the MANUAL clean-up trims the thumbnail cache to, in MB.
  ///
  ///   * `0`  — the platform default (`thumbCacheBudgetBytes`: 96 MB mobile /
  ///            512 MB desktop), which is what an untouched install does;
  ///   * `>0` — that limit, whatever the platform.
  ///
  /// One number rather than a switch plus a size, because they are the same
  /// decision — how much disk this app may spend on thumbnails. Nothing is
  /// automatic: the cache grows until the user opens the cache row and chooses
  /// Auto trim, which then trims it to this.
  Future<int> getThumbCacheLimitMb() async {
    final p = await prefs;
    return p.getInt(_keyThumbCacheLimit) ?? 0; // 0 = platform default
  }

  Future<void> setThumbCacheLimitMb(int mb) async {
    final p = await prefs;
    await p.setInt(_keyThumbCacheLimit, mb);
  }

  // ── PiP settings ──────────────────────────────────────────
  // Default: enabled, normal size.
  Future<bool> getPipEnabled() async {
    final p = await prefs;
    return p.getBool(_keyPipEnabled) ?? true;
  }

  Future<void> setPipEnabled(bool enabled) async {
    final p = await prefs;
    await p.setBool(_keyPipEnabled, enabled);
  }

  Future<String> getPipSize() async {
    final p = await prefs;
    final v = p.getString(_keyPipSize);
    return v == 'small' ? 'small' : 'normal';
  }

  Future<void> setPipSize(String size) async {
    final p = await prefs;
    await p.setString(_keyPipSize, size == 'small' ? 'small' : 'normal');
  }

  // ── Playback settings ─────────────────────────────────────
  // Default: 'pauseAfter' — stop when the current video ends.
  //
  // The whitelist is the read-side guard for a preference file this build did
  // not write (an older version's value, a hand-edited one): an unknown string
  // reads as the default rather than as a mode. `PlaybackMode.key` is the
  // vocabulary (`utils/player_playback_mode.dart`).
  Future<String> getPlaybackMode() async {
    final p = await prefs;
    final v = p.getString(_keyPlaybackMode);
    if (v == 'loopAll' || v == 'shuffle' || v == 'loopOne' || v == 'pauseAfter') {
      return v!;
    }
    return 'pauseAfter';
  }

  Future<void> setPlaybackMode(String mode) async {
    final p = await prefs;
    await p.setString(_keyPlaybackMode, mode);
  }

  // ── Cast auto-next ────────────────────────────────────────
  // Default: true — when the TV is unresponsive (video ended, or a picked
  // video never started) for 5s, the phone plays the next one by itself.
  Future<bool> getCastAutoNext() async {
    final p = await prefs;
    return p.getBool(_keyCastAutoNext) ?? true;
  }

  Future<void> setCastAutoNext(bool enabled) async {
    final p = await prefs;
    await p.setBool(_keyCastAutoNext, enabled);
  }

  // ── Screenshot policy ─────────────────────────────────────
  // Mobile only (`services/screen_capture.dart`). Default: NOT allowed — the
  // library shown here is decrypted media, and a screenshot of it outlives the
  // session, the app and the password. The platform enforces it; this is the
  // choice it is told.
  Future<bool> getAllowScreenshots() async {
    final p = await prefs;
    return p.getBool(_keyAllowScreenshots) ?? false;
  }

  Future<void> setAllowScreenshots(bool allowed) async {
    final p = await prefs;
    await p.setBool(_keyAllowScreenshots, allowed);
  }

  // ── System volume binding ─────────────────────────────────
  // Mobile only (`services/system_volume.dart`). Default: ON for mobile, OFF for
  // desktop -- on a phone the hardware keys and every other media app move the
  // same media stream, so an app-local volume stacked on top of it is the odd
  // one out; a desktop's mixer is the user's own business and the app's slider
  // is the behaviour expected there (where the row is not offered at all). The
  // binding itself needs more than this flag (`shouldBindSystemVolume`).
  Future<bool> getUseSystemVolume() async {
    final p = await prefs;
    final isDesktop =
        Platform.isWindows || Platform.isLinux || Platform.isMacOS;
    return p.getBool(_keyUseSystemVolume) ??
        useSystemVolumeDefault(isDesktop: isDesktop);
  }

  Future<void> setUseSystemVolume(bool enabled) async {
    final p = await prefs;
    await p.setBool(_keyUseSystemVolume, enabled);
  }

  // ── Fullscreen orientation ────────────────────────────────
  // Mobile only, and only while the player is fullscreen
  // (`utils/player_orientation.dart`).
  //
  // `player_orientation` replaced an `auto_rotate` boolean: the switch said
  // "ignore the system rotation lock; follow device orientation", and the request
  // it made was `FULL_USER`, which the platform documents as respecting that very
  // lock -- so the one thing it existed for was the one thing it could not do.
  //
  // The old key is still READ here, once, so a choice made before the upgrade
  // keeps its meaning (`true` was asking for `device`, `false` was the
  // fit-the-video default). Nothing writes it any more: the accessors the old
  // boolean had are gone with the switch, which is what makes this really
  // read-only rather than read-mostly.
  Future<PlayerOrientation> getPlayerOrientation() async {
    final p = await prefs;
    final stored = p.getString(_keyPlayerOrientation);
    if (stored != null) return PlayerOrientation.fromKey(stored);
    final legacy = p.getBool(_keyAutoRotate);
    if (legacy != null) return orientationFromLegacyAutoRotate(legacy);
    return defaultOrientation;
  }

  Future<void> setPlayerOrientation(PlayerOrientation mode) async {
    final p = await prefs;
    await p.setString(_keyPlayerOrientation, mode.key);
  }

  // ── Video jump history ────────────────────────────────────
  // The size of the jump stack whose entries `Back` returns to and the Related
  // list excludes. The stack itself is session state and is never persisted —
  // only this limit is. Read back clamped, so a hand-edited or legacy value can
  // never leave the range the slider (and the stack) is built on.
  Future<int> getVideoJumpHistoryLimit() async {
    final p = await prefs;
    return (p.getInt(_keyVideoJumpHistory) ?? kVideoJumpHistoryDefault).clamp(
      kVideoJumpHistoryMin,
      kVideoJumpHistoryMax,
    );
  }

  Future<void> setVideoJumpHistoryLimit(int limit) async {
    final p = await prefs;
    await p.setInt(
      _keyVideoJumpHistory,
      limit.clamp(kVideoJumpHistoryMin, kVideoJumpHistoryMax),
    );
  }
}
