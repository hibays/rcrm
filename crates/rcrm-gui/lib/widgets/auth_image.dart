// widgets/auth_image.dart
// An ImageProvider that fetches via sharedHttpClient with auth headers.
// Used as a drop-in replacement for NetworkImage/Image.network.

import 'dart:ui' as ui;

import 'package:flutter/foundation.dart';
import 'package:flutter/painting.dart';

import '../services/bounded_fetch.dart';
import '../services/mobile_image_decoder.dart';

class AuthImage extends ImageProvider<AuthImage> {
  final String url;
  final int? targetWidth;
  const AuthImage(this.url, {this.targetWidth});

  @override
  Future<AuthImage> obtainKey(ImageConfiguration _) =>
      SynchronousFuture<AuthImage>(this);

  @override
  ImageStreamCompleter loadImage(AuthImage key, ImageDecoderCallback decode) {
    return MultiFrameImageStreamCompleter(
      codec: _load(),
      scale: 1.0,
      debugLabel: url,
    );
  }

  Future<ui.Codec> _load() async {
    // Software-decoded formats first, copy-free: the compressed bytes land in
    // native memory and go straight to Rust, so they never become a Dart list.
    //
    // When Rust refuses, the fetch below happens AGAIN — deliberately: this
    // fallback is a *different decoder*. The engine can decode what our build of the
    // Rust decoders cannot (a HEIF the `heic` crate refuses because it is built
    // without `av1`/`unci`, a container that is really JPEG/PNG, or a file past
    // Rust's shared 64 MP ceiling), so skipping it would turn "our decoder said no"
    // into "nothing is shown". The disk-thumbnail cache follows the same rule for
    // the same reason (its fallback is the engine too). The cost is one extra
    // download on that path only, and those bytes cannot be reused because the
    // native attempt already transferred ownership of them to Rust.
    final soft = await MobileImageDecoder.fetchForDecode(url);
    if (soft != null) {
      final codec = await MobileImageDecoder.tryDecodeNative(
        soft,
        url,
        targetWidth: targetWidth ?? 0,
      );
      if (codec != null) return codec;
    }

    // Bounded end to end (see [fetchBoundedBytes]): a server that accepts the
    // request and then stalls mid-body must end in an exception here, because
    // this codec future's error is what fires `PooledImage.onError` — the
    // handler that releases the cell's ImageLoadGate token and paints the error
    // tile. `sharedHttpClient` bounds only connect and idle time, never an
    // in-flight body, so an unbounded fetch here pins a decode slot forever.
    final bytes = await fetchBoundedBytes(url);

    // On mobile, route AVIF/JXL through the Rust software decoder
    // to avoid platform decoder color bugs.
    final codec = await MobileImageDecoder.tryDecode(
      bytes,
      url,
      targetWidth: targetWidth ?? 0,
    );
    if (codec != null) return codec;
    final buffer = await ui.ImmutableBuffer.fromUint8List(bytes);
    if (targetWidth != null) {
      return await ui.instantiateImageCodecFromBuffer(
        buffer,
        targetWidth: targetWidth,
      );
    }
    return await ui.instantiateImageCodecFromBuffer(buffer);
  }

  @override
  bool operator ==(Object other) =>
      other is AuthImage &&
      other.url == url &&
      other.targetWidth == targetWidth;

  @override
  int get hashCode => Object.hash(url, targetWidth);
}
