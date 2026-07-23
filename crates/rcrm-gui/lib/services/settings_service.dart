// services/settings_service.dart
// RCrm GUI — persistent user settings service
//
// Stores display preferences, library configuration, and UI state
// using SharedPreferences.

import 'dart:convert';
import 'dart:io' show Platform;

import 'package:shared_preferences/shared_preferences.dart';

import '../models/server_config.dart';

class SettingsService {
  static const _keyServerConfig = 'server_config';
  static const _keyVideoLayout = 'video_layout'; // 'grid' or 'list'
  static const _keyVideoGridColumns = 'video_grid_columns';
  static const _keyVideoSort = 'video_sort';
  static const _keyVideoSortAsc = 'video_sort_asc';
  static const _keyImageLayout = 'image_layout'; // 'masonry' or 'uniform'
  static const _keyImageColumns = 'image_columns';
  static const _keyImageSort = 'image_sort'; // 'name', 'date', 'size'
  static const _keyImageClassification =
      'image_classification'; // 'folder' | 'format'
  static const _keyPreviewEnabled = 'preview_enabled';
  static const _keyThumbCache = 'thumb_cache_enabled';
  static const _keyPipEnabled = 'pip_enabled';
  static const _keyPipSize = 'pip_size'; // 'normal' or 'small'
  static const _keyPlaybackMode =
      'playback_mode'; // 'loopAll' | 'loopOne' | 'pauseAfter'
  static const _keyAutoRotate = 'auto_rotate'; // bool

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
  // ── Image classification ─────────────────────────────────

  Future<String> getImageClassification() async {
    final p = await prefs;
    return p.getString(_keyImageClassification) ?? 'folder';
  }

  Future<void> setImageClassification(String method) async {
    final p = await prefs;
    await p.setString(_keyImageClassification, method);
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
  Future<String> getPlaybackMode() async {
    final p = await prefs;
    final v = p.getString(_keyPlaybackMode);
    if (v == 'loopAll' || v == 'loopOne' || v == 'pauseAfter') return v!;
    return 'pauseAfter';
  }

  Future<void> setPlaybackMode(String mode) async {
    final p = await prefs;
    await p.setString(_keyPlaybackMode, mode);
  }

  // ── Auto-rotate ───────────────────────────────────────────
  // Default: false (respect system rotation lock).
  Future<bool> getAutoRotate() async {
    final p = await prefs;
    return p.getBool(_keyAutoRotate) ?? false;
  }

  Future<void> setAutoRotate(bool enabled) async {
    final p = await prefs;
    await p.setBool(_keyAutoRotate, enabled);
  }
}
