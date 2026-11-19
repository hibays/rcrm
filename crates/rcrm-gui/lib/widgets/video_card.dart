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
import '../utils/frame_ready_gate.dart';
import '../widgets/marquee_text.dart';
import '../services/preview_player.dart';
import 'media_item_menu.dart';
import 'preview_surface.dart';
import 'video_poster.dart';

class VideoCard extends StatefulWidget {
  final MediaItem item;
  final VoidCallback? onTap;

  /// Long-press (touch) / right-click (desktop) on the card: where the pointer
  /// was, so the item's menu opens there. Null on surfaces with no menu.
  final void Function(Offset globalPosition)? onMenuRequested;
  final bool compact;

  /// When true (mobile), show preview video. External controller toggles this.
  final bool preview;

  /// Whether a desktop pointer may start the shared hover preview. False where
  /// the card is already about to play by itself — the end card's countdown
  /// tile — because a second moving picture under the ring is noise.
  final bool hoverPreview;

  /// Overrides the duration chip's default, which is `!compact`. The end card's
  /// grid wants the chip on a compact card; the list rows do not.
  final bool? showDuration;

  /// Card's own margin. The grids and list rows keep the Card default of 4;
  /// the end card wants the poster to fill its 16:9 box exactly.
  final EdgeInsetsGeometry margin;

  /// This card floats on MEDIA — over a picture, not on the page.
  ///
  /// The page's own colours belong to the page: in the Day appearance the
  /// card surface and the poster placeholder turn cream, and a cream tile
  /// sitting on the player's fixed dark surface is a light patch on a dark
  /// picture. A card on media therefore reads the FIXED dark tokens instead
  /// (docs/DESIGN.md §2A: "Media overlays deliberately do not follow the page
  /// appearance").
  final bool mediaSurface;

  const VideoCard({
    super.key,
    required this.item,
    this.onTap,
    this.onMenuRequested,
    this.compact = false,
    this.preview = false,
    this.hoverPreview = true,
    this.showDuration,
    this.margin = const EdgeInsets.all(4),
    this.mediaSurface = false,
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

  /// Whether the freshly-opened preview has a decoded frame. Drives the video's
  /// fade-in over the persistent poster. The gate opens on the NEW video's
  /// positive width event (not an FFI property read of the current frame —
  /// that could be the previous video's, flashing it on hover).
  bool _frameReady = false;
  StreamSubscription<int?>? _widthSub;
  late final FrameReadyGate _frameGate = FrameReadyGate(() {
    if (!mounted || _disposing) return;
    if (!PreviewPlayer.instance.owns(_claimToken ?? -1)) return;
    setState(() => _frameReady = true);
  });

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
    // A card that becomes the countdown tile must drop a preview a pointer is
    // already holding; hoverPreview is the gate, not a hint.
    if (old.hoverPreview && !widget.hoverPreview) {
      _ht?.cancel();
      _stopPreview();
    }
  }

  // ── Desktop hover ──────────────────────────────────────
  void _enter(_) {
    if (_isMobile || !widget.hoverPreview) return;
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

    // Wait for the NEW video's positive width before revealing the video.
    // open() resets width=null first, so a positive event can only come from
    // the new file — no stale-frame flash. The 220ms fade covers the small gap
    // between width (decoder config) and the first composited frame.
    _frameReady = false;
    _frameGate.arm();
    _widthSub?.cancel();
    _widthSub = player.stream.width.listen((w) => _frameGate.onWidth(w));

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
    _widthSub?.cancel();
    _widthSub = null;
    _frameGate.cancel();
    _frameReady = false;
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
    final showDur =
        (widget.showDuration ?? !widget.compact) &&
        widget.item.durationSeconds != null;
    // A card on media reads the FIXED dark tokens, never the page's: the page
    // turns cream in the Day appearance, and a cream tile on the player's
    // dark surface is a light patch on a picture.
    final surface = widget.mediaSurface
        ? RCrmColors.playerSurface
        : RCrmColors.char;
    final card = Card(
      color: surface,
      margin: widget.margin,
      clipBehavior: Clip.antiAlias,
      child: Stack(
        fit: StackFit.expand,
        children: [
          // 1px black edge at the card's bottom: the thumbnail region stops
          // 1px short, so no thumbnail pixel ever paints the bottom row —
          // nothing left to leak through the anti-aliased clip boundary.
          Positioned(top: 0, left: 0, right: 0, bottom: 1, child: _thumb()),
          if (showDur)
            _dur(
              bottom: _showingPreview
                  ? (widget.compact ? 0 : 36) + kPreviewStripHeight + 4
                  : null,
            ),
          _info(),
        ],
      ),
    );

    final menu = widget.onMenuRequested;
    final longPress = menu == null
        ? null
        : (LongPressStartDetails d) =>
              requestItemMenu(menu, d.globalPosition, haptic: true);
    final secondary = menu == null
        ? null
        : (TapDownDetails d) => requestItemMenu(menu, d.globalPosition);
    if (_isMobile) {
      return GestureDetector(
        onTap: widget.onTap,
        onLongPressStart: longPress,
        onSecondaryTapDown: secondary,
        child: card,
      );
    }
    return MouseRegion(
      onEnter: _enter,
      onExit: _exit,
      child: GestureDetector(
        onTap: widget.onTap,
        onLongPressStart: longPress,
        onSecondaryTapDown: secondary,
        child: card,
      ),
    );
  }

  Widget _thumb() {
    // ONE stack, fixed indices, so nothing remounts when a preview starts/stops.
    // The poster is the persistent BOTTOM layer; the Video sits above it and
    // fades in only once a frame is ready. Until then the viewer sees the poster
    // (the same image as the video's first frame) - never the card background.
    // fill:transparent removes media_kit's own opaque black, so letterboxing
    // also shows the poster. PreviewSurface is a pure view; the frame gate here
    // feeds it the frameReady boolean.
    return PreviewSurface(
      frameReady: _frameReady,
      active: _showingPreview,
      poster: _poster(),
      video: _showingPreview
          ? Video(
              // A preview clip is a few seconds under a finger or a cursor, and
              // the engine's wakelock is a PROCESS-WIDE count: a preview that
              // ends calls WakelockPlus.disable() at zero, clearing the player's
              // own hold. No preview needs the screen held awake.
              controller: _previewController!,
              fit: BoxFit.cover,
              wakelock: false,
              // media_kit's default controls need ~150dp and overflow an 81dp
              // card, and their churn desyncs the Windows AXTree. The preview
              // keeps the one useful affordance via PreviewControls.
              controls: NoVideoControls,
              // No opaque black rectangle before the first frame.
              fill: Colors.transparent,
            )
          : const SizedBox.shrink(),
      player: _showingPreview ? _previewController!.player : null,
      stripBottom: widget.compact ? 0 : 36,
      onTap: widget.onTap,
      onMenu: widget.onMenuRequested,
    );
  }

  /// The poster, with the two states this card has always drawn — a spinner
  /// while it is being generated, and the extension placeholder when there is
  /// none. Mounted exactly once per card (see _thumb) so its decoded thumbnail
  /// survives the preview transition instead of being reloaded on every hover.
  Widget _poster() => VideoPoster(
    item: widget.item,
    onPosterChanged: (has) {
      if (mounted && _hasPoster != has) {
        setState(() => _hasPoster = has);
      }
    },
    loading: Container(
      color: widget.mediaSurface ? RCrmColors.playerSurface : RCrmColors.coal,
      child: Center(
        child: SizedBox(
          width: 20,
          height: 20,
          child: CircularProgressIndicator(
            strokeWidth: 2,
            color: widget.mediaSurface
                ? RCrmColors.playerTextFaint
                : RCrmColors.textFaint,
          ),
        ),
      ),
    ),
    fallback: _ph(),
  );

  Widget _dur({double? bottom}) {
    final onMedia = _hasPoster;
    // The chip sits on the poster: over a real picture it is black with
    // white ink, and over the placeholder it takes the card's own surface so
    // it does not become a second rectangle inside the tile.
    final Color chipBg = onMedia
        ? Colors.black87
        : (widget.mediaSurface ? RCrmColors.playerSurface : RCrmColors.char);
    final Color chipFg = onMedia
        ? Colors.white
        : (widget.mediaSurface
              ? RCrmColors.playerText
              : RCrmColors.textPrimary);
    return Positioned(
      // Clear of the info strip when there is one. A compact card has no
      // strip, and the end card asks for the chip there — bottom 36 would
      // float it in the middle of the poster.
      bottom: bottom ?? (widget.compact ? 4 : 36),
      right: 4,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 2),
        decoration: BoxDecoration(
          color: chipBg,
          borderRadius: BorderRadius.circular(4),
        ),
        child: Text(
          widget.item.formattedDuration,
          style: TextStyle(color: chipFg, fontSize: 11),
        ),
      ),
    );
  }

  Widget _info() {
    if (widget.compact) return const SizedBox.shrink();
    // The no-poster strip is a media overlay of its own: on media it stays
    // dark in both appearances, so it never becomes a cream band on a card
    // floating over the picture.
    final Color strip = _hasPoster
        ? Colors.transparent
        : (widget.mediaSurface ? RCrmColors.playerSurface : RCrmColors.coal);
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
                : [strip, strip.withValues(alpha: 0.55), Colors.transparent],
          ),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
            MarqueeText(
              text: widget.item.name,
              style: TextStyle(
                color: _hasPoster || widget.mediaSurface
                    ? Colors.white
                    : RCrmColors.textPrimary,
                fontSize: widget.compact ? 11 : 13,
                fontWeight: FontWeight.w500,
              ),
            ),
            if (!widget.compact)
              Text(
                '${widget.item.formattedSize} • ${widget.item.extension.toUpperCase()}',
                style: TextStyle(
                  color: _hasPoster || widget.mediaSurface
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
    // The placeholder is a media overlay too: on the picture it stays dark in
    // both appearances, so a card on media never turns into a cream block.
    color: widget.mediaSurface ? RCrmColors.playerSurface : RCrmColors.coal,
    child: Column(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        Icon(
          Icons.play_circle_outline,
          size: 48,
          color: widget.mediaSurface
              ? RCrmColors.playerTextFaint
              : RCrmColors.textFaint,
        ),
        const SizedBox(height: 4),
        Text(
          widget.item.extension.toUpperCase(),
          style: TextStyle(
            color: widget.mediaSurface
                ? RCrmColors.playerTextSecondary
                : RCrmColors.textSecondary,
            fontSize: 11,
          ),
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

  /// Long-press / right-click anywhere on the row (poster or text) asks for the
  /// item's menu. Both halves carry it: a row whose text ignores a right-click
  /// while its thumbnail answers one is a row with two personalities.
  final void Function(Offset globalPosition)? onMenuRequested;
  final bool preview;

  /// Key handed to the inner [VideoCard]. Mobile finger-preview hit-tests the
  /// card's render box through it, so it must land on the card, not the row.
  final Key? cardKey;

  /// The row's height, and the number the 16:9 poster is sized from.
  ///
  /// The content is a two-line title + duration + `size • extension`. 100dp is
  /// the established full-width row (the text column is wide enough there at
  /// 1.0x); a narrower cell or a larger text scale needs more, which is why the
  /// caller passes `videoListRowHeight` instead of a literal. The default keeps
  /// every other surface (search rows) exactly as it was.
  final double height;

  const VideoListTile({
    super.key,
    required this.item,
    this.onTap,
    this.onMenuRequested,
    this.preview = false,
    this.cardKey,
    this.height = 100,
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
          height * 16 / 9,
          constraints.maxWidth * 0.42,
        );
        return SizedBox(
          height: height,
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
                  onMenuRequested: onMenuRequested,
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: GestureDetector(
                  behavior: HitTestBehavior.opaque,
                  onTap: onTap,
                  onLongPressStart: onMenuRequested == null
                      ? null
                      : (d) => requestItemMenu(
                          onMenuRequested,
                          d.globalPosition,
                          haptic: true,
                        ),
                  onSecondaryTapDown: onMenuRequested == null
                      ? null
                      : (d) =>
                            requestItemMenu(onMenuRequested, d.globalPosition),
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
