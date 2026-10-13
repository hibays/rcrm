// widgets/episode_picker_panel.dart
// Fullscreen episode picker: a bottom sheet (at most half the screen) listing
// the same "Related" videos shown under the player — poster thumbnail + name
// per row — so episodes can be switched without leaving fullscreen.

import 'package:flutter/material.dart';

import '../models/media_item.dart';
import '../widgets/finger_preview_listener.dart';
import '../widgets/video_card.dart';

/// How long the sheet takes to arrive, and to leave again.
///
/// One number for both directions: the appearance is a single value run
/// forwards, so the entrance and the exit are the same motion and cannot drift
/// apart.
///
/// 130ms. It was 200ms — matching the up-next card's entrance, on the theory
/// that anything that appears once and stays should take the same time — and a
/// full-screen sheet on an 800px-wide panel is a lot of travel for 200ms: it
/// read as the sheet hesitating rather than arriving. Faster than the card, and
/// deliberately not the platform's route transition, which the sheet must not
/// borrow from.
const kEpisodeSheetDuration = Duration(milliseconds: 130);

/// How far the sheet travels, from the edge it is anchored to.
const _kSheetSlide = 28.0;

class EpisodePickerPanel extends StatefulWidget {
  final List<MediaItem> items;
  final ValueChanged<MediaItem> onPick;

  /// The sheet has finished closing; the caller unmounts it.
  ///
  /// Also what a dismissal means: the ✕ and the backdrop start the exit with
  /// this widget and report through here when it is over, rather than the screen
  /// unmounting on the tap — an unmounted widget cannot animate out.
  final VoidCallback onDismiss;

  /// Shared mobile sticky-preview state (the same one the related list uses).
  final FingerPreviewState? fingerPreview;

  /// The screen is closing the sheet and is holding it mounted for
  /// [kEpisodeSheetDuration] so the exit can play.
  ///
  /// The screen owns WHEN the sheet goes and this widget owns HOW it looks while
  /// it goes, which is what lets Back and the gear animate exactly as the ✕
  /// does. Picking an episode never sets it: that is a navigation, and the route
  /// is the motion there.
  final bool closing;

  const EpisodePickerPanel({
    super.key,
    required this.items,
    required this.onPick,
    required this.onDismiss,
    this.fingerPreview,
    this.closing = false,
  });

  @override
  State<EpisodePickerPanel> createState() => _EpisodePickerPanelState();
}

class _EpisodePickerPanelState extends State<EpisodePickerPanel>
    with SingleTickerProviderStateMixin {
  /// The one value both directions read: 1 is arrived, 0 is gone.
  late final AnimationController _ctrl = AnimationController(
    vsync: this,
    duration: kEpisodeSheetDuration,
  );

  /// Mirrors [EpisodePickerPanel.closing] as a latch, so a dismissal cannot be
  /// started twice (a ✕ press followed by a backdrop tap on the way out).
  bool _closing = false;

  /// True when the platform was asked for less motion. Read in build for the
  /// value, and by [_startClosing] to decide whether there is anything to play.
  bool get _instant => MediaQuery.maybeOf(context)?.disableAnimations ?? false;

  @override
  void initState() {
    super.initState();
    _ctrl.addStatusListener(_onStatus);
    if (widget.closing) {
      // Asked to close the instant it appeared: there is nothing to arrive.
      _closing = true;
      _ctrl.value = 1;
    } else {
      _ctrl.forward();
    }
  }

  @override
  void didUpdateWidget(EpisodePickerPanel old) {
    super.didUpdateWidget(old);
    if (widget.closing && !old.closing) _startClosing();
  }

  @override
  void dispose() {
    _ctrl.dispose();
    super.dispose();
  }

  void _onStatus(AnimationStatus s) {
    if (!_closing) return;
    // BOTH ends, because the two directions land on different ones: `forward()`
    // finishes at `completed` (the upper bound) and `reverse()` at `dismissed`
    // (the lower bound). Watching only the former meant the exit ran to the end
    // and the screen was never told — the sheet animated away and stayed
    // mounted.
    if (s == AnimationStatus.completed || s == AnimationStatus.dismissed) {
      widget.onDismiss();
    }
  }

  /// Starts the exit, from a ✕ press, a backdrop tap, or the screen flipping
  /// [EpisodePickerPanel.closing]. Whoever asked, [EpisodePickerPanel.onDismiss]
  /// is what unmounts the sheet.
  void _startClosing() {
    if (_closing) return;
    _closing = true;
    if (_instant) {
      widget.onDismiss();
      return;
    }
    _ctrl.reverse();
  }

  Widget _row(MediaItem item) {
    final fp = widget.fingerPreview;
    return InkWell(
      onTap: () => widget.onPick(item),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
        child: Row(
          children: [
            SizedBox(
              width: 132,
              height: 74,
              child: ClipRRect(
                borderRadius: BorderRadius.circular(6),
                child: VideoCard(
                  key: fp?.keyFor(item.path),
                  item: item,
                  preview: fp?.isActive(item.path) ?? false,
                  compact: true,
                ),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Text(
                    item.name,
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(color: Colors.white, fontSize: 13),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    [
                      if (item.durationSeconds != null) item.formattedDuration,
                      item.formattedSize,
                      item.extension.toUpperCase(),
                    ].join(' • '),
                    style: const TextStyle(color: Colors.white54, fontSize: 11),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final fp = widget.fingerPreview;
    final size = MediaQuery.of(context).size;
    // Landscape fullscreen: a right-side panel (half the width, full height).
    // Portrait fullscreen: a bottom sheet (half the height at most).
    final landscape = size.width > size.height;

    // One value for the whole appearance, so the entrance and the exit are the
    // same motion in reverse; see the `AnimatedBuilder` below for where it is
    // read.
    //
    // The sheet travels from the edge it is anchored to — the right in
    // landscape, the bottom in portrait.
    final from = landscape
        ? const Offset(_kSheetSlide, 0)
        : const Offset(0, _kSheetSlide);

    final listBody = Listener(
      onPointerDown: fp == null ? null : (e) => fp.onPointerDown(e, setState),
      child: ListView.builder(
        padding: EdgeInsets.only(top: 4, bottom: landscape ? 16 : 12),
        itemCount: widget.items.length,
        itemBuilder: (_, i) => _row(widget.items[i]),
      ),
    );

    final sheet = Container(
      width: landscape ? (size.width / 2).clamp(280.0, 560.0) : double.infinity,
      height: landscape ? double.infinity : null,
      constraints: landscape
          ? null
          : BoxConstraints(maxHeight: size.height / 2),
      decoration: BoxDecoration(
        color: const Color(0xFF1A1A1A),
        borderRadius: landscape
            ? const BorderRadius.horizontal(left: Radius.circular(14))
            : const BorderRadius.vertical(top: Radius.circular(14)),
        border: landscape
            ? const Border(left: BorderSide(color: Color(0x14FFFFFF)))
            : const Border(top: BorderSide(color: Color(0x14FFFFFF))),
      ),
      clipBehavior: Clip.antiAlias,
      child: Column(
        mainAxisSize: landscape ? MainAxisSize.max : MainAxisSize.min,
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(20, 14, 8, 6),
            child: Row(
              children: [
                const Icon(
                  Icons.playlist_play,
                  color: Colors.white54,
                  size: 20,
                ),
                const SizedBox(width: 8),
                const Text(
                  'Episodes',
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 15,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const SizedBox(width: 8),
                Text(
                  '${widget.items.length}',
                  style: const TextStyle(color: Colors.white38, fontSize: 13),
                ),
                const Spacer(),
                IconButton(
                  icon: const Icon(
                    Icons.close,
                    color: Colors.white38,
                    size: 18,
                  ),
                  onPressed: _startClosing,
                  visualDensity: VisualDensity.compact,
                  padding: EdgeInsets.zero,
                  constraints: const BoxConstraints(),
                ),
              ],
            ),
          ),
          const Divider(height: 1, color: Color(0x10FFFFFF)),
          if (landscape) Expanded(child: listBody) else Flexible(child: listBody),
        ],
      ),
    );

    return GestureDetector(
      // A tap on the dimmed backdrop dismisses, through the same exit as the ✕.
      onTap: _startClosing,
      behavior: HitTestBehavior.opaque,
      // The controller drives this: reading `_ctrl.value` in build on its own
      // rebuilds nothing, so the value would never move. Only the wrappers are
      // rebuilt per frame — the sheet is passed as the builder's `child`, so its
      // list is built once.
      child: AnimatedBuilder(
        animation: _ctrl,
        builder: (_, child) {
          final t = _instant ? 1.0 : Curves.easeOutCubic.transform(_ctrl.value);
          return Container(
            // The scrim FADES IN PLACE. It is a full-bleed dimming layer, so
            // moving it with the sheet left an uncovered strip along the edge it
            // travelled away from — and a backdrop that slides is a backdrop
            // with an edge.
            color: Colors.black.withValues(alpha: 0.45 * t),
            alignment: landscape
                ? Alignment.centerRight
                : Alignment.bottomCenter,
            child: GestureDetector(
              onTap: () {}, // absorb taps inside the sheet
              child: Opacity(
                opacity: t,
                child: Transform.translate(
                  offset: from * (1 - t),
                  child: child,
                ),
              ),
            ),
          );
        },
        child: sheet,
      ),
    );
  }
}