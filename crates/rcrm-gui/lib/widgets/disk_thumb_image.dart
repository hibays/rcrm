// widgets/disk_thumb_image.dart
// A small-thumbnail ImageProvider with a STABLE cache key (file-path + width)
// so Flutter's in-memory imageCache still dedups across rebuilds/scroll (no
// re-decode). Only a DOWNSCALED thumbnail (PNG at the target width) is stored
// on disk — never the original full-size image. The on-disk ThumbCache is read
// first (cross-session); the server is hit only on a cold miss.
//
// Used only when thumbnail caching is enabled; otherwise PooledImage keeps
// using ResizeImage(NetworkImage(...)).

import 'dart:ffi';
import 'dart:ui' as ui;
import 'dart:async';
import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/painting.dart';
import '../ffi/rust_bridge.dart';
import '../services/thumb_cache.dart';
import '../services/mobile_image_decoder.dart';

import '../services/net.dart';

/// Mirrors Rust `webp::WebpBuf { data_len: usize, data: *mut u8 }`.
final class _WebpBuf extends Struct {
  @IntPtr()
  external int dataLen;
  external Pointer<Uint8> data;
}

/// Auto-frees Rust WebP output buffers when the Dart view is GC'd, so the
/// encoded bytes are returned to Dart with ZERO copies (native memory is
/// read in place; the finalizer releases it later).
Pointer<NativeFunction<RcrmFreeWebpBufC>>? _webpFreeFn;

void _ensureWebpFinalizer() {
  if (_webpFreeFn != null) return;
  final addr = RustBridge.freeWebpBufAddr;
  if (addr == 0) return;
  _webpFreeFn = Pointer<NativeFunction<RcrmFreeWebpBufC>>.fromAddress(addr);
}

@immutable
class DiskThumbImage extends ImageProvider<DiskThumbImage> {
  final String url;
  final int width;
  const DiskThumbImage(this.url, this.width);

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
    final diskKey = '${ThumbCache.pathId(url)}|w${width}wp';
    Uint8List? thumb = await ThumbCache.read(diskKey);
    if (thumb == null || thumb.isEmpty) {
      thumb = await _makeThumb(url); // fetch original, downscale, WebP-encode
      if (thumb != null && thumb.isNotEmpty) {
        ThumbCache.write(diskKey, thumb); // persist the SMALL thumbnail only
      }
    }
    if (thumb == null || thumb.isEmpty) {
      throw StateError('DiskThumbImage: empty bytes for $url');
    }
    // The stored bytes are already the downscaled thumbnail — decode as-is.
    final buffer = await ui.ImmutableBuffer.fromUint8List(thumb);
    return decode(buffer);
  }

  /// Fetch the original, downscale to [width] during decode, and re-encode the
  /// small frame as lossy WebP (Rust FFI). Returns the small thumbnail bytes
  /// (never the original).
  Future<Uint8List?> _makeThumb(String u) async {
    final orig = await _fetch(u);
    if (orig == null || orig.isEmpty) return null;
    try {
      // On mobile, route AVIF/JXL originals through the software decoder
      // so the cached thumbnail has correct colors.
      final swCodec = await MobileImageDecoder.tryDecode(
        orig,
        u,
        targetWidth: width,
      );
      final codec =
          swCodec ?? await ui.instantiateImageCodec(orig, targetWidth: width);
      final frame = await codec.getNextFrame();
      final rgba = await frame.image.toByteData(
        format: ui.ImageByteFormat.rawRgba,
      );
      final w = frame.image.width;
      final h = frame.image.height;
      frame.image.dispose();
      if (rgba == null) return null;
      return _encodeWebp(rgba.buffer.asUint8List(), w, h);
    } catch (_) {
      return null;
    }
  }

  /// Encode RGBA pixels as lossy WebP via the Rust bridge (zenwebp).
  /// Returns null if the bridge is unavailable or encoding fails.
  static Uint8List? _encodeWebp(
    Uint8List rgba,
    int w,
    int h, {
    int quality = 78,
  }) {
    final bridge = RustBridge();
    if (!bridge.isLoaded) {
      try {
        bridge.load();
      } catch (_) {
        return null;
      }
    }
    final data = calloc<Uint8>(rgba.length);
    data.asTypedList(rgba.length).setAll(0, rgba);
    final ptr = bridge.encodeThumbWebp(data, rgba.length, w, h, quality);
    calloc.free(data);
    if (ptr == nullptr) return null;
    final buf = ptr.cast<_WebpBuf>().ref;
    final len = buf.dataLen;
    if (buf.data == nullptr || len <= 0) {
      bridge.freeWebpBuf(ptr);
      return null;
    }
    _ensureWebpFinalizer();
    final fin = _webpFreeFn;
    if (fin != null) {
      // Zero-copy view over the native WebP bytes. When this Uint8List is
      // GC'd, the finalizer calls rcrm_free_webp_buf(token) with token=ptr.
      return buf.data.asTypedList(len, finalizer: fin, token: ptr);
    }
    // Fallback (finalizer unavailable): copy + free immediately.
    final bytes = Uint8List.fromList(buf.data.asTypedList(len));
    bridge.freeWebpBuf(ptr);
    return bytes;
  }

  Future<Uint8List?> _fetch(String u) async {
    try {
      final uri = Uri.parse(Uri.encodeFull(u));
      final req = await sharedHttpClient.getUrl(uri);
      if (sharedAuthHeader != null) {
        req.headers.set('Authorization', sharedAuthHeader!['Authorization']!);
      }
      final resp = await req.close();
      if (resp.statusCode != 200) return null;
      return await consolidateHttpClientResponseBytes(resp);
    } catch (_) {
      return null;
    }
  }

  @override
  bool operator ==(Object other) =>
      other is DiskThumbImage && other.url == url && other.width == width;

  @override
  int get hashCode => Object.hash(url, width);
}
