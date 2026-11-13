// widgets/video_card.dart
// Video card: poster thumbnail + inline preview via a SHARED preview Player.
// Desktop: hover preview (200ms delay). Mobile: preview controlled
// externally by finger position (sticky). Only one card previews at a time,
// so all cards share one Player (PreviewPlayer) — no per-hover Player init.

import 'dart:async';
import 'dart:io';
import 'dart:math' as math;
import 'package:material_ui/material_ui.dart';
import 'package:media_kit_video/media_kit_video.dart';
import '../config/theme.dart';
import '../models/media_item.dart';
import '../widgets/marquee_text.dart';
import '../services/preview_player.dart';
import 'video_poster.dart';

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
  Timer? _ht;
  bool _disposing = false;
  int _hoverGen = 0;

  /// Whether a real poster is behind the info layer. The dark gradient and
  /// white labels are an ink layer over MEDIA pixels; on a bare placeholder
  /// (Day especially) they would read as an unthemed black band, so the
  /// placeholder gets the page's semantic colours instead.
  bool _hasPoster = false;

  // Shared-preview claim state
  int? _claimToken;
  VideoController? _previewController;
  StreamSubscription? _playSub;

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
      // The poster reloads itself (`VideoPoster.didUpdateWidget`); what this
      // widget owns is the preview, which must not go on playing the video that
      // has just left the card.
      _hoverGen++;
      _stopPreview();
      _ht?.cancel();
      _hasPoster = false;
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
      color: RCrmColors.char,
      clipBehavior: Clip.antiAlias,
      child: Stack(
        fit: StackFit.expand,
        children: [
          // 1px black edge at the card's bottom: the thumbnail region stops
          // 1px short, so no thumbnail pixel ever paints the bottom row —
          // nothing left to leak through the anti-aliased clip boundary.
          Positioned(top: 0, left: 0, right: 0, bottom: 1, child: _thumb()),
          if (showDur) _dur(),
          _info(),
        ],
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
    // Not previewing: the poster, with the two states this card has always
    // drawn — a spinner while it is being generated, and the extension
    // placeholder when there is none.
    return VideoPoster(
      item: widget.item,
      onPosterChanged: (has) {
        if (mounted && _hasPoster != has) {
          setState(() => _hasPoster = has);
        }
      },
      loading: Container(
        color: RCrmColors.coal,
        child: Center(
          child: SizedBox(
            width: 20,
            height: 20,
            child: CircularProgressIndicator(
              strokeWidth: 2,
              color: RCrmColors.textFaint,
            ),
          ),
        ),
      ),
      fallback: _ph(),
    );
  }

  Widget _dur() {
    final onMedia = _hasPoster;
    return Positioned(
      bottom: 36,
      right: 4,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 2),
        decoration: BoxDecoration(
          color: onMedia ? Colors.black87 : RCrmColors.char,
          borderRadius: BorderRadius.circular(4),
        ),
        child: Text(
          widget.item.formattedDuration,
          style: TextStyle(
            color: onMedia ? Colors.white : RCrmColors.textPrimary,
            fontSize: 11,
          ),
        ),
      ),
    );
  }

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
            colors: _hasPoster
                ? [
                    Colors.black.withValues(alpha: 0.9),
                    Colors.black.withValues(alpha: 0.3),
                    Colors.transparent,
                  ]
                : [
                    RCrmColors.coal,
                    RCrmColors.coal.withValues(alpha: 0.55),
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
                color: _hasPoster ? Colors.white : RCrmColors.textPrimary,
                fontSize: widget.compact ? 11 : 13,
                fontWeight: FontWeight.w500,
              ),
            ),
            if (!widget.compact)
              Text(
                '${widget.item.formattedSize} • ${widget.item.extension.toUpperCase()}',
                style: TextStyle(
                  color: _hasPoster
                      ? Colors.white60
                      : RCrmColors.textSecondary,
                  fontSize: 10,
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _ph() => Container(
    color: RCrmColors.coal,
    child: Column(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        Icon(Icons.play_circle_outline, size: 48, color: RCrmColors.textFaint),
        const SizedBox(height: 4),
        Text(
          widget.item.extension.toUpperCase(),
          style: TextStyle(color: RCrmColors.textSecondary, fontSize: 11),
        ),
      ],
    ),
  );
}

/// One row of the list layout: compact poster on the left, metadata on the
/// right.
///
/// Shared by the video screen and the search screen. They previously each
/// carried their own copy of this row and drifted apart — 100 px vs 140 px
/// tall, and a flexed vs a fixed-width poster — so the same video looked
/// different depending on where it was listed. Keeping one widget is what
/// stops that from happening again.
class VideoListTile extends StatelessWidget {
  final MediaItem item;
  final VoidCallback? onTap;
  final bool preview;

  /// Key handed to the inner [VideoCard]. Mobile finger-preview hit-tests the
  /// card's render box through it, so it must land on the card, not the row.
  final Key? cardKey;

  const VideoListTile({
    super.key,
    required this.item,
    this.onTap,
    this.preview = false,
    this.cardKey,
  });

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (BuildContext context, BoxConstraints constraints) {
        // A 16:9 poster, and it stays one. This used to be
        // `Expanded(flex: 2)`, so the thumbnail grew with the window: a 1600px
        // list drew a 630 × 100 strip and `BoxFit.cover` cropped the poster
        // into a band. On a phone that same 16:9 box would eat the text
        // column, so it may shrink below the ideal width — never above it.
        final double thumbWidth = math.min(
          100 * 16 / 9,
          constraints.maxWidth * 0.42,
        );
        return SizedBox(
          height: 100,
          child: Row(
            children: [
              SizedBox(
                width: thumbWidth,
                child: VideoCard(
                  key: cardKey,
                  item: item,
                  preview: preview,
                  compact: true,
                  onTap: onTap,
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: GestureDetector(
                  behavior: HitTestBehavior.opaque,
                  onTap: onTap,
                  child: _info(context),
                ),
              ),
            ],
          ),
        );
      },
    );
  }

  Widget _info(BuildContext c) => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    mainAxisAlignment: MainAxisAlignment.center,
    children: [
      Text(
        item.name,
        maxLines: 2,
        overflow: TextOverflow.ellipsis,
        style: Theme.of(c).textTheme.titleMedium,
      ),
      const SizedBox(height: 4),
      if (item.durationSeconds != null)
        Text(item.formattedDuration, style: Theme.of(c).textTheme.bodyMedium),
      const SizedBox(height: 2),
      Text(
        '${item.formattedSize} • ${item.extension.toUpperCase()}',
        style: Theme.of(c).textTheme.bodyMedium,
      ),
    ],
  );
}
