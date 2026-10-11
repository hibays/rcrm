// widgets/video_poster.dart
// RCrm GUI — the poster tile for ONE video, and nothing else.
//
// Extracted from `VideoCard`, which is this poster plus the hover/finger preview
// and the info overlay. The video tab's folder cards need four posters each and
// no preview at all, and a second copy of the poster path is exactly what the
// list row already drifted on once — see the note on `VideoListTile` in
// `video_card.dart`: the placeholder, the crop, the decode width and the
// generation guard have to agree, so they live in one widget and every caller
// uses it.
//
// The two states it cannot invent for its callers are the loading one and the
// "no poster" one — a grid card wants a spinner and an extension label, a folder
// preview wants a flat grey cell — so both are passed in, and `VideoCard` passes
// the widgets it always drew.

import 'dart:typed_data';

import 'package:flutter/material.dart';

import '../models/media_item.dart';
import '../services/thumbnail_service.dart';

class VideoPoster extends StatefulWidget {
  final MediaItem item;

  /// How the poster fills its box. Everything here crops (`BoxFit.cover`), but a
  /// caller that letterboxes a poster passes its own.
  final BoxFit fit;

  /// Painted while the poster is being generated.
  final Widget? loading;

  /// Painted when there is no poster to show — generation failed, or the server
  /// has not answered yet.
  final Widget? fallback;

  const VideoPoster({
    super.key,
    required this.item,
    this.fit = BoxFit.cover,
    this.loading,
    this.fallback,
  });

  @override
  State<VideoPoster> createState() => _VideoPosterState();
}

class _VideoPosterState extends State<VideoPoster> {
  final ThumbnailService _ts = ThumbnailService();
  Uint8List? _poster;
  bool _loading = true;

  /// Guards the async answer: a poster that arrives after the element was
  /// recycled onto another item, or after the widget went away, must not paint.
  int _gen = 0;

  @override
  void initState() {
    super.initState();
    // After the frame, like `VideoCard` did: a wall of cards must not all start
    // generating posters inside the build that creates them.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) _load();
    });
  }

  @override
  void didUpdateWidget(VideoPoster old) {
    super.didUpdateWidget(old);
    // The element was recycled onto a different video (a grid re-sort, a folder
    // card that now stands for another folder): drop the old poster instead of
    // showing it under the new name for a frame.
    if (old.item.url != widget.item.url) {
      setState(() {
        _poster = null;
        _loading = true;
      });
      _load();
    }
  }

  Future<void> _load() async {
    final gen = ++_gen;
    Uint8List? poster;
    try {
      poster = await _ts.generatePoster(widget.item.url);
    } catch (_) {
      poster = null;
    }
    if (!mounted || _gen != gen) return;
    setState(() {
      _poster = poster;
      _loading = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    final poster = _poster;
    if (poster != null) {
      return Image.memory(
        poster,
        fit: widget.fit,
        cacheWidth: 640,
        gaplessPlayback: true,
        errorBuilder: (_, _, _) => _fallback(),
      );
    }
    if (_loading) {
      return widget.loading ?? const ColoredBox(color: Color(0xFF2A2A2A));
    }
    return _fallback();
  }

  Widget _fallback() =>
      widget.fallback ??
      const ColoredBox(
        color: Color(0xFF2A2A2A),
        child: Center(
          child: Icon(
            Icons.play_circle_outline,
            size: 32,
            color: Colors.white38,
          ),
        ),
      );
}
