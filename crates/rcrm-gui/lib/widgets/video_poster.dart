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

import '../config/theme.dart';
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

  /// Reports whether a real poster (not the placeholder) is being painted.
  /// A parent that draws an overlay on top of the poster needs this: the dark
  /// ink layer belongs over unknown media pixels, NOT over a light placeholder.
  final ValueChanged<bool>? onPosterChanged;

  const VideoPoster({
    super.key,
    required this.item,
    this.fit = BoxFit.cover,
    this.loading,
    this.fallback,
    this.onPosterChanged,
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

  /// One self-heal per item. A disk entry that decodes badly is dropped and
  /// regenerated once; without the guard a genuinely undecodable frame would
  /// spin errorBuilder → reload → errorBuilder forever.
  bool _retried = false;

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
      _retried = false;
      // _load() bumps `_gen` synchronously, so this `false` and the answer
      // that follows both belong to the NEW item. A stale `true` from the
      // previous item can never land on the recycled element.
      _load();
      _notify(false);
    }
  }

  /// Deferred: a parent's setState must never run inside this widget's build
  /// (didUpdateWidget) or inside its own setState.
  void _notify(bool hasPoster) {
    final gen = _gen;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      // The element may have been recycled onto another video before this
      // frame lands; a generation mismatch means the answer is about a poster
      // that is no longer ours.
      if (!mounted || _gen != gen) return;
      widget.onPosterChanged?.call(hasPoster);
    });
  }

  Future<void> _load({bool refresh = false}) async {
    final gen = ++_gen;
    Uint8List? poster;
    try {
      poster = await _ts.generatePoster(widget.item.url, refresh: refresh);
    } catch (_) {
      poster = null;
    }
    if (!mounted || _gen != gen) return;
    setState(() {
      _poster = poster;
      _loading = false;
    });
    _notify(poster != null);
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
        errorBuilder: (_, _, _) {
          // The image path heals a corrupt disk entry in DiskThumbImage._load;
          // the poster path has to do the same here, because ThumbnailService
          // only returns bytes and cannot know whether the engine decoded them.
          // Deferred: errorBuilder runs inside build, so setState is illegal.
          if (!_retried) {
            _retried = true;
            WidgetsBinding.instance.addPostFrameCallback((_) {
              if (mounted) _load(refresh: true);
            });
          }
          return _fallback();
        },
      );
    }
    if (_loading) {
      return widget.loading ?? ColoredBox(color: RCrmColors.coal);
    }
    return _fallback();
  }

  Widget _fallback() =>
      widget.fallback ??
      ColoredBox(
        color: RCrmColors.coal,
        child: Center(
          child: Icon(
            Icons.play_circle_outline,
            size: 32,
            color: RCrmColors.textFaint,
          ),
        ),
      );
}
