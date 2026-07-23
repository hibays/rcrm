// widgets/disk_thumb_image.dart
// A small-thumbnail ImageProvider with a STABLE cache key (file-path + width)
// so Flutter's in-memory imageCache still dedups across rebuilds/scroll (no
// re-decode). Only a DOWNSCALED thumbnail (PNG at the target width) is stored
// on disk — never the original full-size image. The on-disk ThumbCache is read
// first (cross-session); the server is hit only on a cold miss.
//
// Used only when thumbnail caching is enabled; otherwise PooledImage keeps
// using ResizeImage(NetworkImage(...)).

import 'dart:ui' as ui;
import 'dart:async';
import 'package:flutter/foundation.dart';
import 'package:flutter/painting.dart';
import '../services/thumb_cache.dart';
import '../services/mobile_image_decoder.dart';

import '../services/net.dart';

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
    final diskKey = '${ThumbCache.pathId(url)}|w$width';
    Uint8List? thumb = await ThumbCache.read(diskKey);
    if (thumb == null || thumb.isEmpty) {
      thumb = await _makeThumb(url); // fetch original, downscale, PNG-encode
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
  /// small frame as PNG. Returns the small thumbnail bytes (never the original).
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
      final png = await frame.image.toByteData(format: ui.ImageByteFormat.png);
      frame.image.dispose();
      return png?.buffer.asUint8List();
    } catch (_) {
      return null;
    }
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
