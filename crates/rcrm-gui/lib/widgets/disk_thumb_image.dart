// widgets/disk_thumb_image.dart
// A small-thumbnail ImageProvider with a STABLE cache key (file-path + width)
// so Flutter's in-memory imageCache still dedups across rebuilds/scroll (no
// re-decode). Only a DOWNSCALED thumbnail (WebP at the target width) is stored
// on disk — never the original full-size image. The on-disk ThumbCache is read
// first (cross-session); the server is hit only on a cold miss.
//
// Used only when thumbnail caching is enabled; otherwise PooledImage keeps
// using ResizeImage(NetworkImage(...)).
//
// Generation is a static, shared, deduplicated service: concurrent callers
// (grid cells, the viewer's thumbnail layer) asking for the same key share
// one fetch/decode/encode instead of duplicating it.

import 'dart:async';
import 'dart:ui' as ui;
import 'package:flutter/foundation.dart';
import 'package:flutter/painting.dart';
import '../ffi/rust_bridge.dart';
import '../services/bounded_fetch.dart';
import '../services/image_load_gate.dart';
import '../services/thumb_cache.dart';
import '../services/thumb_webp_worker.dart';
import '../services/mobile_image_decoder.dart';

@immutable
class DiskThumbImage extends ImageProvider<DiskThumbImage> {
  final String url;
  final int width;
  const DiskThumbImage(this.url, this.width);

  // ── Shared miss-path generation ─────────────────────────────

  /// In-flight generation by disk key, so concurrent callers share one
  /// fetch/decode/encode instead of stampeding the server.
  static final Map<String, Future<Uint8List?>> _inflight = {};

  /// Key for the on-disk thumbnail of [url] at [width]: path + width, nothing else.
  /// `ThumbCache.pathId` keeps only the URL path and `ThumbCache._key` hashes the
  /// whole id (FNV-1a → hex) into the file name, so nothing in here has to be
  /// disc-safe.
  ///
  /// Consequence, accepted deliberately: two origins serving the same path share
  /// one cached thumbnail.
  static String _diskKey(String url, int width) =>
      '${ThumbCache.pathId(url)}|w${width}wp';

  static Future<Uint8List?> _make(String url, int width) {
    final key = _diskKey(url, width);
    final existing = _inflight[key];
    if (existing != null) return existing;
    final future = _generate(url, width, key);
    _inflight[key] = future;
    // `ignore()` is load-bearing: this derived future is discarded, and if it
    // completed with an error that error would be re-reported as an unhandled
    // exception even though the caller awaiting `future` already handles it.
    future.whenComplete(() => _inflight.remove(key)).ignore();
    return future;
  }

  static Future<Uint8List?> _generate(
    String url,
    int width,
    String diskKey,
  ) async {
    // The gate throttles the expensive cold-miss work (network fetch +
    // decode + WebP encode) so a cold wall can't stampede the CPU. The
    // cheap disk-hit decode path never reaches here — and no longer waits
    // on the gate at all (PooledImage skips it for DiskThumbImage).
    final token = ImageLoadGate.instance.acquire();
    try {
      await token.future;
      final thumb = await _makeThumb(url, width);
      if (thumb != null && thumb.isNotEmpty) {
        ThumbCache.write(diskKey, thumb); // persist the SMALL thumbnail only
      }
      return thumb;
    } finally {
      ImageLoadGate.instance.done(token);
    }
  }

  /// Fetch the original, downscale to [width] during decode, and re-encode the
  /// small frame as lossy WebP (Rust FFI). Returns the small thumbnail bytes
  /// (never the original).
  ///
  /// The pixel path: something already decoded the original (the engine, or the
  /// Rust software decoder via [MobileImageDecoder]) and the pixels exist in
  /// Dart, so they are copied into native memory once for the encoder.
  /// [_makeThumbInRust] short-circuits this for the formats Rust decodes itself.
  static Future<Uint8List?> _makeThumb(String u, int width) async {
    final (inRust, fetchAnswered) = await _makeThumbInRust(u, width);
    if (inRust != null) return inRust;
    // What must not happen here is a second download of an answer the network
    // already gave (a refused request, an empty body) — that is what
    // `fetchAnswered` rules out. "Rust produced no thumbnail from bytes it did
    // receive" is a different answer, and it is not final: the pixel path below
    // decodes with Flutter's engine, a *different* decoder that reads what our
    // `heic`/`rav1d`/`jxl-oxide` builds refuse (an AV1- or uncompressed-HEIF
    // file, a `.heic` that is really a JPEG, a frame past the shared 64 MP
    // ceiling). `AuthImage._load` falls back to that same engine for exactly this
    // reason, so a file the viewer displays must not lose its thumbnail. The
    // cost — the original fetched once more, only when our own decoder said no —
    // is unavoidable rather than lazy: Rust borrowed those bytes and the worker
    // frees them when it replies, so they cannot be reused here.
    if (fetchAnswered) return null;
    final orig = await _fetch(u);
    if (orig == null || orig.isEmpty) return null;
    try {
      // On mobile, route AVIF/JXL/HEIC originals through the software decoder
      // so the cached thumbnail has correct colors.
      final swCodec = await MobileImageDecoder.tryDecode(
        orig,
        u,
        targetWidth: width,
      );
      // `instantiateImageCodec` hands back a codec with native resources of its
      // own: disposing the frame's image is not enough, so it is disposed too
      // (once per cold thumbnail, which is exactly when this path runs).
      final codec =
          swCodec ?? await ui.instantiateImageCodec(orig, targetWidth: width);
      ui.Codec? owned = swCodec == null ? codec : null;
      try {
        final frame = await codec.getNextFrame();
        final rgba = await frame.image.toByteData(
          format: ui.ImageByteFormat.rawRgba,
        );
        final w = frame.image.width;
        final h = frame.image.height;
        frame.image.dispose();
        if (rgba == null) return null;
        return await ThumbWebpWorker.instance.encodeRgba(
          rgba.buffer.asUint8List(),
          w,
          h,
        );
      } finally {
        // Only the codec this file created: a codec from `tryDecode` belongs to
        // the decoder service and may be cached there.
        owned?.dispose();
      }
    } catch (_) {
      return null;
    }
  }

  /// Thumbnail straight from the **encoded** original, for the formats Rust can
  /// decode itself: fetch the bytes into native memory and let
  /// `rcrm_generate_thumb_webp_from_image` decode → downscale → WebP-encode (on
  /// the worker isolate), so the pixels never enter the Dart heap — the pixel
  /// path above copies them twice instead.
  ///
  /// Returns `(bytes, fetchAnswered)`: `fetchAnswered` says whether the network
  /// already gave this URL its final answer — a refused response, or an empty
  /// body — which is what makes a second download of the same original pointless
  /// (see [_makeThumb], which is the only caller and the only place that acts on
  /// it). Every recoverable outcome reports false, so the engine still gets its
  /// turn: a format this build has no decoder for, a response the copy-free path
  /// could not size exactly (nothing was read, so nothing was spent), and bytes
  /// that arrived but that Rust would not decode.
  static Future<(Uint8List?, bool)> _makeThumbInRust(
    String url,
    int width,
  ) async {
    if (RustBridge.generateThumbWebpFromImageAddr == 0) return (null, false);
    final kind = MobileImageDecoder.kindHintFor(url);
    if (kind == 0) return (null, false);
    final (head, retryByFetching) = await MobileImageDecoder.fetchForThumb(url);
    if (head == null) return (null, !retryByFetching);
    if (head.len == 0) {
      head.free();
      return (null, true);
    }
    // Ownership passes to the worker, which frees it once Rust is done.
    final bytes = await ThumbWebpWorker.instance.generateThumbFromImage(
      head,
      targetWidth: width,
      kindHint: kind,
    );
    // A refusal here is not the network's answer, it is one decoder's: report it
    // as unsettled so the engine is still asked (and, for a HEIC this build
    // cannot read, the thumbnail is not silently lost).
    if (bytes == null) return (null, false);
    return (bytes, true);
  }

  /// The Dart-bytes fallback fetch, bounded end to end by [fetchBoundedBytes]
  /// for the reason that helper documents: the caller holds an `ImageLoadGate`
  /// token across it, and a server that goes silent mid-body would otherwise pin
  /// a decode slot forever (and the grid would stop loading thumbnails).
  ///
  /// That helper reports failure by throwing, while this path only cares whether
  /// bytes came back — "no thumbnail from these bytes" is one answer here, not
  /// three — so every outcome is flattened to null. Dart bytes need no free, so
  /// abandoning the read on a timeout is safe.
  static Future<Uint8List?> _fetch(String u) async {
    try {
      return await fetchBoundedBytes(u);
    } catch (_) {
      return null;
    }
  }

  @override
  Future<DiskThumbImage> obtainKey(ImageConfiguration configuration) =>
      SynchronousFuture<DiskThumbImage>(this);

  @override
  ImageStreamCompleter loadImage(
    DiskThumbImage key,
    ImageDecoderCallback decode,
  ) {
    return MultiFrameImageStreamCompleter(
      codec: _load(decode),
      scale: 1.0,
      debugLabel: url,
    );
  }

  Future<ui.Codec> _load(ImageDecoderCallback decode) async {
    // Stable key: file path only (no random host/port/credentials) + width.
    // `wp` marks the WebP-encoded format so old PNG caches are not misread.
    final diskKey = _diskKey(url, width);
    // Hit path: let the engine read the file directly (no Dart-side copy, no
    // exists()/readAsBytes round trip). Any failure — including a corrupt or
    // truncated cache entry rejected by the codec — deletes the entry and
    // falls through to regeneration below (self-heal, no permanent error
    // cell). The decode future is awaited so codec errors land in this catch.
    try {
      final file = await ThumbCache.fileFor(diskKey);
      if (file != null) {
        final buffer = await ui.ImmutableBuffer.fromFilePath(file.path);
        return await decode(buffer);
      }
    } catch (_) {
      await ThumbCache.remove(diskKey); // heal: drop the bad cache entry
    }
    // Cold miss: shared generation (deduped across concurrent callers), then
    // decode the just-persisted bytes.
    final thumb = await _make(url, width);
    if (thumb == null || thumb.isEmpty) {
      throw StateError('DiskThumbImage: empty bytes for $url');
    }
    final buffer = await ui.ImmutableBuffer.fromUint8List(thumb);
    try {
      return await decode(buffer);
    } catch (_) {
      // Symmetric with the hit path: a corrupt freshly-generated entry is
      // dropped so a retry (PooledImage backoff) regenerates instead of
      // failing forever.
      await ThumbCache.remove(diskKey);
      rethrow;
    }
  }

  @override
  bool operator ==(Object other) =>
      other is DiskThumbImage && other.url == url && other.width == width;

  @override
  int get hashCode => Object.hash(url, width);
}
