// services/item_cache_limit.dart
// Centralised immutable resource limits for thumbnails & image decoding.

import 'dart:io' show Platform;

bool get _isMobile => Platform.isAndroid || Platform.isIOS;

final isMobile = _isMobile;

class ItemCacheLimit {
  ItemCacheLimit._();

  // ── Video poster (ThumbnailService) ──────────────────────────

  /// How many poster generation slots run concurrently.
  static final int videoPosterConcurrency = _isMobile ? 1 : 11;

  /// Maximum queued poster requests. Oldest evicted when exceeded.
  static final int videoPosterQueueMax = _isMobile ? 50 : 200;

  /// In-memory LRU poster cache entry count.
  static final int videoPosterMemoryCacheMax = _isMobile ? 32 : 512;

  // ── Image decode gate (ImageLoadGate) ────────────────────────

  /// How many image decodes run concurrently.
  static final int imageDecodeConcurrency = _isMobile ? 2 : 6;

  /// Maximum queued decode waiters. Oldest evicted when exceeded.
  static final int imageDecodeQueueMax = _isMobile ? 12 : 40;

  // ── Flutter global ImageCache (main.dart) ────────────────────

  /// Global ImageCache byte limit.
  static final int flutterImageCacheMaxBytes = _isMobile ? 84 << 20 : 384 << 20;

  /// Global ImageCache entry limit.
  static final int flutterImageCacheMaxEntries = _isMobile ? 384 : 896;

  // ── Full-res viewer ImageCache (image_viewer_screen.dart) ────

  /// Private full-resolution ImageCache byte limit.
  static final int fullResImageCacheMaxBytes = _isMobile ? 64 << 20 : 384 << 20;

  // ── Scroll cache extent (image_grid.dart) ────────────────────

  /// How many pixels off-screen the image grid pre-builds cells.
  static final double imageScrollCacheExtent = _isMobile ? 100 : 800;
}
