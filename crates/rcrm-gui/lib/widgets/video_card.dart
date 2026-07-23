// widgets/video_card.dart
// Video card: poster thumbnail + inline preview via a SHARED preview Player.
// Desktop: hover preview (200ms delay). Mobile: preview controlled
// externally by finger position (sticky). Only one card previews at a time,
// so all cards share one Player (PreviewPlayer) — no per-hover Player init.

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:media_kit_video/media_kit_video.dart';
import '../models/media_item.dart';
import '../widgets/marquee_text.dart';
import '../services/thumbnail_service.dart';
import '../services/preview_player.dart';

class VideoCard extends StatefulWidget {
  final MediaItem item;
  final VoidCallback? onTap;
  final bool compact;

  /// When true (mobile), show preview video. External controller toggles this.
  final bool preview;
  const VideoCard({
    super.key,
    required this.item,
    this.onTap,
    this.compact = false,
    this.preview = false,
  });
  @override
  State<VideoCard> createState() => _VideoCardState();
}

class _VideoCardState extends State<VideoCard> {
  static final _isMobile = Platform.isAndroid || Platform.isIOS;
  final ThumbnailService _ts = ThumbnailService();
  Uint8List? _poster;
  bool _posterLoading = true;
  Timer? _ht;
  bool _disposing = false;
  int _hoverGen = 0;
  int _posterGen = 0;

  // Shared-preview claim state
  int? _claimToken;
  VideoController? _previewController;
  StreamSubscription? _playSub;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) _loadPoster();
    });
  }

  @override
  void dispose() {
    _ht?.cancel();
    _disposing = true;
    _stopPreview();
    super.dispose();
  }

  @override
  void didUpdateWidget(VideoCard old) {
    super.didUpdateWidget(old);
    // Item changed under a recycled element (e.g. grid re-sort with null keys):
    if (old.item.url != widget.item.url) {
      _hoverGen++;
      _stopPreview();
      _ht?.cancel();
      setState(() {
        _poster = null;
        _posterLoading = true;
      });
      _loadPoster();
      return;
    }
    if (widget.preview != old.preview) {
      if (widget.preview) {
        _startPreview();
      } else {
        _stopPreview();
      }
    }
  }

  Future<void> _loadPoster() async {
    final gen = ++_posterGen;
    try {
      final p = await _ts.generatePoster(widget.item.url);
      if (!mounted || _posterGen != gen) return;
      setState(() {
        _poster = p;
        _posterLoading = false;
      });
    } catch (_) {
      if (!mounted || _posterGen != gen) return;
      setState(() {
        _poster = null;
        _posterLoading = false;
      });
    }
  }

  // ── Desktop hover ──────────────────────────────────────
  void _enter(_) {
    if (_isMobile) return;
    _ht?.cancel();
    final gen = _hoverGen;
    _ht = Timer(const Duration(milliseconds: 200), () {
      if (!mounted || _disposing) return;
      if (_hoverGen != gen) return;
      _startPreview();
    });
  }

  void _exit(_) {
    if (_isMobile) return;
    _ht?.cancel();
    _stopPreview();
  }

  // ── Shared preview start/stop ──────────────────────────
  void _startPreview() {
    if (!mounted || _disposing) return;
    if (!PreviewPlayer.enabled) return; // "Video Hover Preview" setting off
    final claim = PreviewPlayer.instance.claim(widget.item.url);
    if (claim == null) return; // MediaKit unavailable on this device
    _claimToken = claim.token;
    _previewController = claim.controller;
    final player = claim.player;
    // Seek long videos to 1/3 once playback starts (guarded by ownership).
    _playSub?.cancel();
    _playSub = player.stream.playing.listen((p) {
      if (!p || !mounted || _disposing) return;
      if (!PreviewPlayer.instance.owns(_claimToken ?? -1)) return;
      final dur = player.state.duration.inMilliseconds;
      if (dur > 0) {
        final isLong = (widget.item.durationSeconds ?? 0) > 180;
        player.seek(Duration(milliseconds: isLong ? dur ~/ 4 : 0));
      }
      // Video widget handles its own rendering — no need to rebuild card.
      // if (mounted) setState(() {});
    });
    if (mounted) setState(() {});
  }

  void _stopPreview() {
    _playSub?.cancel();
    _playSub = null;
    if (_claimToken != null) PreviewPlayer.instance.release(_claimToken!);
    _claimToken = null;
    _previewController = null;
    if (!_disposing && mounted) setState(() {});
  }

  bool get _showingPreview =>
      _previewController != null &&
      _claimToken != null &&
      PreviewPlayer.instance.owns(_claimToken!);

  // ── Build ──────────────────────────────────────────────
  @override
  Widget build(BuildContext c) {
    final showDur = widget.item.durationSeconds != null && !widget.compact;
    final card = Card(
      clipBehavior: Clip.antiAlias,
      child: Stack(
        fit: StackFit.expand,
        children: [_thumb(), if (showDur) _dur(), _info()],
      ),
    );

    if (_isMobile) {
      return GestureDetector(onTap: widget.onTap, child: card);
    }
    return MouseRegion(
      onEnter: _enter,
      onExit: _exit,
      child: GestureDetector(onTap: widget.onTap, child: card),
    );
  }

  Widget _thumb() {
    if (_showingPreview) {
      // Desktop: top 2/3 overlay captures taps for navigation;
      // bottom 1/3 lets native Video controls through.
      // Mobile: full-card overlay (no native controls on touch).
      return Stack(
        fit: StackFit.expand,
        children: [
          Video(controller: _previewController!, fit: BoxFit.cover),
          Positioned.fill(
            child: FractionallySizedBox(
              alignment: Alignment.topCenter,
              heightFactor: _isMobile ? 1.0 : 2 / 3,
              child: GestureDetector(
                behavior: HitTestBehavior.translucent,
                onTap: widget.onTap,
              ),
            ),
          ),
        ],
      );
    }
    if (_poster != null) {
      return Image.memory(
        _poster!,
        fit: BoxFit.cover,
        cacheWidth: 640,
        gaplessPlayback: true,
        errorBuilder: (_, _, _) => _ph(),
      );
    }
    if (_posterLoading) {
      return Container(
        color: const Color(0xFF2A2A2A),
        child: const Center(
          child: SizedBox(
            width: 20,
            height: 20,
            child: CircularProgressIndicator(
              strokeWidth: 2,
              color: Colors.white24,
            ),
          ),
        ),
      );
    }
    return _ph();
  }

  Widget _dur() => Positioned(
    bottom: 36,
    right: 4,
    child: Container(
      padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 2),
      decoration: BoxDecoration(
        color: Colors.black87,
        borderRadius: BorderRadius.circular(4),
      ),
      child: Text(
        widget.item.formattedDuration,
        style: const TextStyle(color: Colors.white, fontSize: 11),
      ),
    ),
  );

  Widget _info() {
    if (widget.compact) return const SizedBox.shrink();
    return Positioned(
      bottom: 0,
      left: 0,
      right: 0,
      child: Container(
        padding: const EdgeInsets.all(6),
        decoration: BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.bottomCenter,
            end: Alignment.topCenter,
            colors: [
              Colors.black.withValues(alpha: 0.9),
              Colors.black.withValues(alpha: 0.3),
              Colors.transparent,
            ],
          ),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
            MarqueeText(
              text: widget.item.name,
              style: TextStyle(
                color: Colors.white,
                fontSize: widget.compact ? 11 : 13,
                fontWeight: FontWeight.w500,
              ),
            ),
            if (!widget.compact)
              Text(
                '${widget.item.formattedSize} • ${widget.item.extension.toUpperCase()}',
                style: const TextStyle(color: Colors.white60, fontSize: 10),
              ),
          ],
        ),
      ),
    );
  }

  Widget _ph() => Container(
    color: const Color(0xFF2A2A2A),
    child: Column(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        const Icon(Icons.play_circle_outline, size: 48, color: Colors.white38),
        const SizedBox(height: 4),
        Text(
          widget.item.extension.toUpperCase(),
          style: const TextStyle(color: Colors.white38, fontSize: 11),
        ),
      ],
    ),
  );
}
