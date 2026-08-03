// widgets/pooled_image.dart
// Image loader backed by Flutter's default LRU imageCache, with a concurrency
// gate so a freshly-opened grid never kicks off dozens of decodes at once.

import 'dart:async';
import 'package:flutter/material.dart';
import '../services/image_load_gate.dart';
import 'auth_image.dart';
import 'disk_thumb_image.dart';
import '../services/thumb_cache.dart';

class PooledImage extends StatefulWidget {
  final String url;
  final BoxFit fit;
  final bool useIntrinsicRatio;
  final double defaultAspectRatio;

  /// Physical-pixel width to decode at (downscale). Null = full resolution
  /// (used by the viewer). Grids/strips pass a small width.
  final int? decodeWidth;
  final Widget? placeholder;
  final Widget? errorWidget;

  const PooledImage({
    super.key,
    required this.url,
    this.fit = BoxFit.cover,
    this.useIntrinsicRatio = false,
    this.defaultAspectRatio = 1.0,
    this.decodeWidth = 400,
    this.placeholder,
    this.errorWidget,
  });

  @override
  State<PooledImage> createState() => _PooledImageState();
}

class _PooledImageState extends State<PooledImage> {
  // URL → aspect ratio; tiny entries, near-unbounded; for instant masonry sizing.
  static final Map<String, double> _ratioCache = {};
  static const int _ratioCacheCap = 50000;
  static void _putRatio(String url, double r) {
    _ratioCache[url] = r;
    if (_ratioCache.length >= _ratioCacheCap) {
      _ratioCache.remove(_ratioCache.keys.first);
    }
  }

  // URLs that have decoded at least once → don't flash a spinner on re-show.
  // Stores url HASHES (few bytes each), so a huge library can't grow this
  // set out of memory. A rare hash collision only suppresses a spinner for
  // a never-seen image — cosmetic, harmless.
  static final Set<int> _seenLoaded = {};

  ImageProvider? _provider;
  bool _ready = false;
  bool _error = false;
  double? _ratio;
  Completer<void>? _token;
  ImageStream? _stream;
  ImageStreamListener? _listener;
  Object? _key;
  int _retryCount = 0;
  Timer? _retryTimer;

  @override
  void initState() {
    super.initState();
    _ratio = _ratioCache[widget.url];
    _load();
  }

  @override
  void didUpdateWidget(PooledImage old) {
    super.didUpdateWidget(old);
    if (old.url != widget.url || old.decodeWidth != widget.decodeWidth) {
      _key = null;
      _teardown();
      _provider = null;
      _ready = false;
      _error = false;
      _ratio = _ratioCache[widget.url];
      _load();
    }
  }

  ImageProvider _makeProvider() {
    final w = widget.decodeWidth;
    if (w == null) return AuthImage(widget.url);
    if (ThumbCache.enabled) return DiskThumbImage(widget.url, w);
    return AuthImage(widget.url, targetWidth: w);
  }

  Future<void> _load() async {
    final provider = _makeProvider();
    _provider = provider;

    // Cache-warm fast path: if this key is already decoded & resident in the
    // LRU, render immediately — no gate, no decode. The gate only throttles
    // DECODES (bytes→RAM bitmap); a resident image does none. The RAM→VRAM
    // texture upload happens on first paint either way and was never gated, so
    // this adds no IO. Guarded so an intrinsic-ratio cell never renders before
    // its aspect ratio is known.
    final key = await provider.obtainKey(const ImageConfiguration());
    _key = key;
    if (!mounted) return;
    final warm = PaintingBinding.instance.imageCache
        .statusForKey(key)
        .keepAlive;
    final ratioKnown =
        !widget.useIntrinsicRatio || _ratioCache.containsKey(widget.url);
    if (warm && ratioKnown) {
      _seenLoaded.add(widget.url.hashCode);
      setState(() {
        _ready = true;
        _ratio = _ratioCache[widget.url] ?? _ratio;
      });
      return;
    }
    // Disk thumbnails skip the decode gate: a disk hit is a tiny engine
    // decode that must not queue behind cold misses (or the full-res
    // viewer). The expensive cold-miss generation is still throttled by
    // the same gate inside DiskThumbImage._make.
    final gated = _provider is! DiskThumbImage;
    final token = gated ? ImageLoadGate.instance.acquire() : null;
    _token = token;
    if (token != null) {
      await token.future;
      if (!mounted) {
        // _teardown() may have already released the token via done().
        // Only release if _token still points to us.
        if (_token == token) {
          ImageLoadGate.instance.done(token);
          _token = null;
        }
        return;
      }
    }

    final stream = provider.resolve(const ImageConfiguration());
    final listener = ImageStreamListener(
      (info, sync) {
        final h = info.image.height;
        if (h > 0) _putRatio(widget.url, info.image.width / h);
        _seenLoaded.add(widget.url.hashCode);
        _teardown(); // remove listener + release slot
        if (mounted) {
          setState(() {
            _ready = true;
            _ratio = _ratioCache[widget.url] ?? _ratio;
          });
        }
      },
      onError: (e, st) {
        _teardown();
        if (_key != null) {
          PaintingBinding.instance.imageCache.evict(_key!);
          _key = null;
        }
        const maxRetries = 2;
        if (_retryCount < maxRetries) {
          _retryCount++;
          _retryTimer = Timer(Duration(seconds: 2 << (_retryCount - 1)), () {
            if (mounted) {
              setState(() {
                _error = false;
                _ready = false;
              });
              _load();
            }
          });
        } else {
          if (mounted) setState(() => _error = true);
        }
      },
    );
    _stream = stream;
    _listener = listener;
    stream.addListener(listener);
  }

  void _retry() {
    if (!mounted) return;
    _retryTimer?.cancel();
    _retryTimer = null;
    _retryCount = 0;
    _teardown();
    if (_key != null) {
      PaintingBinding.instance.imageCache.evict(_key!);
      _key = null;
    }
    setState(() {
      _error = false;
      _ready = false;
    });
    _load();
  }

  // Remove the stream listener and release/drop the gate token.
  void _teardown() {
    _retryTimer?.cancel();
    _retryTimer = null;
    if (_stream != null && _listener != null) {
      _stream!.removeListener(_listener!);
    }
    _stream = null;
    _listener = null;
    if (_token != null) {
      ImageLoadGate.instance.done(_token!);
      _token = null;
    }
  }

  @override
  void dispose() {
    _retryTimer?.cancel();
    _teardown();
    super.dispose();
  }

  Widget _spinner() => Container(
    color: const Color(0xFF2A2A2A),
    child: const Center(
      child: SizedBox(
        width: 18,
        height: 18,
        child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white24),
      ),
    ),
  );

  Widget _dark() => Container(color: const Color(0xFF2A2A2A));

  Widget _defaultError() => Container(
    color: const Color(0xFF2A2A2A),
    child: const Center(
      child: Icon(Icons.broken_image, color: Colors.white24, size: 28),
    ),
  );

  @override
  Widget build(BuildContext context) {
    Widget content;
    if (_error) {
      // A full-surface GestureDetector here would WIN the gesture arena over
      // the card's own onTap (leaf recognizers beat ancestors), so tapping a
      // card whose image failed to load would silently "retry" instead of
      // opening the album/image. Keep the tap surface transparent: the error
      // tile itself is inert, and retry lives on a small corner button.
      content = Stack(
        children: [
          widget.errorWidget ?? _defaultError(),
          Positioned(
            top: 4,
            right: 4,
            child: Material(
              color: Colors.black45,
              shape: const CircleBorder(),
              child: InkWell(
                customBorder: const CircleBorder(),
                onTap: _retry,
                child: const Padding(
                  padding: EdgeInsets.all(4),
                  child: Icon(Icons.refresh, size: 14, color: Colors.white70),
                ),
              ),
            ),
          ),
        ],
      );
    } else if (_ready && _provider != null) {
      content = Image(
        image: _provider!,
        fit: widget.fit,
        gaplessPlayback: true,
        errorBuilder: (_, _, _) => widget.errorWidget ?? _defaultError(),
      );
    } else {
      // While the gated decode is pending: spinner the first time, plain dark
      // on re-show (seen before) to avoid spinner flashing on return.
      content =
          widget.placeholder ??
          (_seenLoaded.contains(widget.url.hashCode) ? _dark() : _spinner());
    }
    if (widget.useIntrinsicRatio) {
      return AspectRatio(
        aspectRatio: _ratio ?? widget.defaultAspectRatio,
        child: content,
      );
    }
    return content;
  }
}
