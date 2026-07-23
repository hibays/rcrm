// widgets/auth_image.dart
// An ImageProvider that fetches via sharedHttpClient with auth headers.
// Used as a drop-in replacement for NetworkImage/Image.network.

import 'dart:io';
import 'dart:ui' as ui;

import 'package:flutter/foundation.dart';
import 'package:flutter/painting.dart';

import '../services/mobile_image_decoder.dart';
import '../services/net.dart';

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
    final uri = Uri.parse(Uri.encodeFull(url));
    final req = await sharedHttpClient.getUrl(uri);
    if (sharedAuthHeader != null) {
      req.headers.set('Authorization', sharedAuthHeader!['Authorization']!);
    }
    final resp = await req.close();
    if (resp.statusCode != 200) {
      throw HttpException('HTTP ${resp.statusCode} fetching $url');
    }
    final bytes = await consolidateHttpClientResponseBytes(resp);

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
