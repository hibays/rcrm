// services/item_cache_limit.dart
// Centralised immutable resource limits for thumbnails & image decoding.

import 'dart:io' show Platform;

bool get _isMobile => Platform.isAndroid || Platform.isIOS;

final isMobile = _isMobile;

class ItemCacheLimit {
  ItemCacheLimit._();

  // ── Video poster (ThumbnailService) ──────────────────────────

  /// How many poster generation slots run concurrently.
  ///
  /// One on a phone. Four on a desktop rather than the eleven the ffmpeg-era
  /// pipeline used: each slot is now a whole mpv context (libmpv path) or a
  /// media_kit Player, decoding a full-resolution frame, so eleven of them at
  /// once cost a 4K film's decoder each — and the eval that measured the libmpv
  /// backend recommended starting at 2-4 workers (docs/MPV_POSTER_EVAL.md §8).
  static final int videoPosterConcurrency = _isMobile ? 1 : 4;

  /// Maximum queued poster requests — the depth of the waiting stack. Oldest
  /// (the bottom) evicted when exceeded, newest served first.
  ///
  /// Kept BELOW [videoPosterMemoryCacheMax] on both platforms (24 < 32,
  /// 128 < 512): an evicted request is answered with null and never retried, so
  /// a queue deeper than the cache it feeds would spend slots on work whose
  /// results the cache could not even hold.
  static final int videoPosterQueueMax = _isMobile ? 24 : 128;

  /// In-memory LRU poster cache entry count.
  static final int videoPosterMemoryCacheMax = _isMobile ? 32 : 512;

  // ── Image decode gate (ImageLoadGate) ────────────────────────

  /// How many image decodes run concurrently.
  static final int imageDecodeConcurrency = _isMobile ? 2 : 6;

  /// Depth of the decode waiting stack (`ImageLoadGate`, LIFO). A full stack
  /// drops its OLDEST entry — the picture least likely still to be on screen.
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
