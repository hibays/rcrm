// widgets/player_end_card.dart
// What the player shows when a file has finished and NOTHING is about to play.
//
// Before this existed the default mode (`Pause After`) left the viewer on a
// static last frame with the controls fading out: no replay, no next video, no
// way back into the library without knowing where the chrome went. The end of
// a file is a decision moment, and a decision needs its options on the picture
// rather than on a side panel that fullscreen has already hidden.
//
// The reference a viewer would recognise is a streaming site's end screen: a
// row of actions, then a grid of things to watch next. The parts that belong
// to a social platform (creator, follow, coins, likes, danmaku, ad rails) do
// not exist in a private local library and are not copied. Neither is the
// blurred backdrop: docs/DESIGN.md bans glass/blur, so this dims the last
// frame with a flat scrim instead and keeps it visible behind the card.
//
// Everything here floats ON the picture, so it reads the fixed `player*`
// tokens in both appearances (docs/DESIGN.md §2A). Orange is spent on one
// action and one dot, nowhere else. Pure presentation: the screen owns the
// Related list, the EOF latch and what playing a pick means.

import 'package:material_ui/material_ui.dart';

import '../config/theme.dart';
import '../models/media_item.dart';
import 'video_poster.dart';

/// How long the card takes to arrive and to leave. A moment, not a place —
/// the same 200ms rise the up-next card uses; the exit is a shade quicker.
const Duration kEndCardEntrance = Duration(milliseconds: 200);
const Duration kEndCardExit = Duration(milliseconds: 140);

class PlayerEndCard extends StatefulWidget {
  const PlayerEndCard({
    super.key,
    required this.title,
    required this.related,
    required this.onReplay,
    required this.onPick,
    required this.onShowAll,
    required this.onDismiss,
    this.autoPlayItem,
    this.autoPlayShuffled = false,
    this.countdown = const Duration(seconds: 8),
    this.onAutoPlay,
    this.onCancelAutoPlay,
  });

  /// The file that just ended. Naming it is the only "you are here" the card
  /// needs; it is not an eyebrow over the heading.
  final String title;

  /// The same Related list the page sidebar and the Next button read. Already
  /// excludes this file and the jump history.
  final List<MediaItem> related;

  final VoidCallback onReplay;
  final ValueChanged<MediaItem> onPick;

  /// Opens the player's existing episode sheet — one list, one door, rather
  /// than a second copy of it drawn inside this card. Null where that sheet is
  /// not reachable (the windowed player shows its full Related list beside the
  /// picture): a control that cannot act is not shown at all.
  final VoidCallback? onShowAll;

  /// Called after the exit has played, so the screen unmounts a widget that is
  /// still visible. An unmounted widget cannot be seen leaving.
  final VoidCallback onDismiss;

  /// The video `Loop All`/`Shuffle` is counting down to, or null when nothing
  /// is about to play. It is hoisted to the FIRST tile: that tile is the
  /// autoplay, so the ring and the thing it will play cannot disagree — the
  /// reference's end screen marks its first card the same way, with a ring and
  /// a way to cancel the autoplay.
  final MediaItem? autoPlayItem;

  /// True when [autoPlayItem] was drawn at random — the line above the grid
  /// has to say where it came from, because the viewer was not looking at a
  /// list when it was chosen.
  final bool autoPlayShuffled;

  /// How long [autoPlayItem] waits before it plays on its own.
  final Duration countdown;

  /// The countdown ran out. Fires once per card.
  final VoidCallback? onAutoPlay;

  /// Stop the countdown but KEEP the card: the viewer is still choosing, and
  /// closing the whole surface is the ✕'s job.
  final VoidCallback? onCancelAutoPlay;

  @override
  State<PlayerEndCard> createState() => _PlayerEndCardState();
}

class _PlayerEndCardState extends State<PlayerEndCard>
    with TickerProviderStateMixin {
  late final AnimationController _ctrl = AnimationController(
    vsync: this,
    duration: kEndCardEntrance,
    reverseDuration: kEndCardExit,
  );

  /// The ONE clock behind the autoplay: the ring drains from this and the
  /// advance fires from this, so the picture and the moment cannot disagree.
  late final AnimationController _count = AnimationController(
    vsync: this,
    duration: widget.countdown,
  );

  bool get _instant => MediaQuery.disableAnimationsOf(context);
  bool _started = false;

  @override
  void initState() {
    super.initState();
    _count.addStatusListener(_onCountDone);
    if (widget.autoPlayItem != null) _count.forward();
  }

  void _onCountDone(AnimationStatus status) {
    if (status != AnimationStatus.completed) return;
    // The controller finishes inside a frame; the screen is about to replace
    // the media, so hand it over once the frame is done rather than during it.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted && widget.autoPlayItem != null) widget.onAutoPlay?.call();
    });
  }

  @override
  void didUpdateWidget(PlayerEndCard old) {
    super.didUpdateWidget(old);
    final bool had = old.autoPlayItem != null;
    final bool has = widget.autoPlayItem != null;
    if (!has && had) {
      // Cancelled: the ring goes and nothing plays. The card stays.
      _count.stop();
      _count.value = 0;
    } else if (has && (!had || old.autoPlayItem!.path != widget.autoPlayItem!.path)) {
      // A fresh offer (the mode changed, a new ending): one clock, from zero.
      _count.forward(from: 0);
    }
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    // MediaQuery is an InheritedWidget: reading it here rather than in
    // initState is what makes the reduced-motion choice real on the first
    // frame, and the latch keeps a later dependency change from replaying the
    // arrival.
    if (_started) return;
    _started = true;
    if (_instant) {
      _ctrl.value = 1;
    } else {
      _ctrl.forward();
    }
  }

  @override
  void dispose() {
    _count.removeStatusListener(_onCountDone);
    _count.dispose();
    _ctrl.dispose();
    super.dispose();
  }

  Future<void> _dismiss() async {
    if (_ctrl.isAnimating && _ctrl.status == AnimationStatus.reverse) return;
    // Closing is a refusal too: a countdown that fired during the exit would
    // start a video the viewer has just waved away.
    _count.stop();
    if (_instant) {
      widget.onDismiss();
      return;
    }
    await _ctrl.reverse();
    if (mounted) widget.onDismiss();
  }

  @override
  Widget build(BuildContext context) {
    final card = Center(
      child: Padding(
        padding: const EdgeInsets.all(RCrmSpacing.md),
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 720),
          child: DecoratedBox(
            decoration: BoxDecoration(
              color: RCrmColors.playerSurface.withValues(alpha: 0.97),
              borderRadius: BorderRadius.circular(RCrmRadii.md),
              // The surface appears over a frame of unknown brightness, so it
              // must read as a card rather than a patch of the picture. This is
              // the same exception the up-next card takes — never at rest.
              boxShadow: const [
                BoxShadow(
                  color: Color(0x59000000),
                  blurRadius: 16,
                  offset: Offset(0, 4),
                ),
              ],
            ),
            child: LayoutBuilder(
              builder: (context, bounds) {
                // A 420dp-tall landscape phone cannot hold six posters and the
                // action row. The column count follows the width; the ROW
                // count follows the height, because a second row that has to
                // be scrolled to is a row nobody knows is there.
                final columns = bounds.maxWidth >= 560 ? 3 : 2;
                final tileWidth =
                    (bounds.maxWidth - 40 - (columns - 1) * 8) / columns;
                final tileHeight = tileWidth * 9 / 16 + 46;
                const chrome = 175.0;
                final rows = bounds.maxHeight >= chrome + tileHeight * 2 + 16
                    ? 2
                    : 1;
                return ConstrainedBox(
                  constraints: BoxConstraints(
                    // The height this card really has, not the screen's: the
                    // windowed player mounts it inside a 16:9 picture box, and
                    // a screen-sized cap would let the card run past the frame
                    // it is drawn on.
                    maxHeight: bounds.maxHeight.clamp(160.0, 620.0),
                  ),
                  child: SingleChildScrollView(
                    padding: const EdgeInsets.fromLTRB(20, 16, 20, 18),
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        _heading(),
                        const SizedBox(height: RCrmSpacing.md),
                        _actions(),
                        const SizedBox(height: RCrmSpacing.lg),
                        _gridHeading(),
                        const SizedBox(height: RCrmSpacing.sm),
                        _grid(columns, columns * rows),
                      ],
                    ),
                  ),
                );
              },
            ),
          ),
        ),
      ),
    );

    return Stack(
      children: [
        Positioned.fill(
          child: GestureDetector(
            behavior: HitTestBehavior.opaque,
            onTap: _dismiss,
            child: ColoredBox(
              color: RCrmColors.playerScrim.withValues(alpha: 0.78),
            ),
          ),
        ),
        AnimatedBuilder(
          animation: _ctrl,
          builder: (_, child) => Opacity(
            opacity: _instant ? 1.0 : _ctrl.value,
            child: Transform.translate(
              offset: Offset(0, 8 * (1 - (_instant ? 1.0 : _ctrl.value))),
              child: child,
            ),
          ),
          child: card,
        ),
      ],
    );
  }

  Widget _heading() => Row(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Expanded(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              'Playback finished',
              style: TextStyle(
                color: RCrmColors.playerText,
                fontSize: 17,
                fontWeight: FontWeight.w600,
              ),
            ),
            const SizedBox(height: 4),
            Text(
              widget.title,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(
                color: RCrmColors.playerTextSecondary,
                fontSize: 12,
              ),
            ),
            if (widget.autoPlayItem != null) ...[
              const SizedBox(height: 6),
              Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(
                    Icons.play_circle_outline,
                    size: 13,
                    color: RCrmColors.playerTextSecondary,
                  ),
                  const SizedBox(width: 4),
                  Flexible(
                    child: Text(
                      widget.autoPlayShuffled
                          ? 'Random pick · auto-plays in '
                                '${widget.countdown.inSeconds}s'
                          : 'Auto-plays in ${widget.countdown.inSeconds}s',
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: TextStyle(
                        color: RCrmColors.playerTextSecondary,
                        fontSize: 11,
                      ),
                    ),
                  ),
                ],
              ),
            ],
          ],
        ),
      ),
      const SizedBox(width: RCrmSpacing.sm),
      Semantics(
        button: true,
        label: 'Close end card',
        child: InkResponse(
          onTap: _dismiss,
          radius: 22,
          child: Padding(
            padding: const EdgeInsets.all(6),
            child: Icon(
              Icons.close,
              size: 20,
              color: RCrmColors.playerTextSecondary,
            ),
          ),
        ),
      ),
    ],
  );

  Widget _actions() {
    final hasRelated = widget.related.isNotEmpty;
    return Wrap(
      spacing: RCrmSpacing.sm,
      runSpacing: RCrmSpacing.sm,
      children: [
        _Action(
          icon: Icons.replay,
          label: 'Replay',
          onTap: widget.onReplay,
        ),
        // There is deliberately no "Play next" here: the FIRST tile is the
        // next video, and it is already the thing the ring counts down to.
        // Two doors to one video is one too many, and the reference's end
        // screen has the same shape.
        if (hasRelated && widget.onShowAll != null)
          _Action(
            icon: Icons.list_alt,
            label: 'All ${widget.related.length}',
            onTap: widget.onShowAll!,
          ),
      ],
    );
  }

  Widget _gridHeading() => Row(
    children: [
      Container(
        width: 4,
        height: 4,
        decoration: BoxDecoration(
          color: RCrmColors.playerAccent,
          shape: BoxShape.circle,
        ),
      ),
      const SizedBox(width: RCrmSpacing.sm),
      Text(
        'Related',
        style: TextStyle(
          color: RCrmColors.playerText,
          fontSize: 14,
          fontWeight: FontWeight.w600,
        ),
      ),
    ],
  );

  Widget _grid(int columns, int maxTiles) {
    final MediaItem? auto = widget.autoPlayItem;
    // The autoplay is FIRST, whatever position it had in Related: the ring is
    // drawn on the first tile, and a ring on something else than the video it
    // is counting down to would be a lie. Shuffle's random pick is therefore
    // hoisted to the same slot the reference puts its countdown in.
    final List<MediaItem> ordered = <MediaItem>[
      ?auto,
      ...widget.related.where(
        (MediaItem item) => auto == null || item.path != auto.path,
      ),
    ];
    if (ordered.isEmpty) {
      return Padding(
        padding: const EdgeInsets.symmetric(vertical: RCrmSpacing.md),
        child: Text(
          'No related videos',
          style: TextStyle(
            color: RCrmColors.playerTextSecondary,
            fontSize: 12,
          ),
        ),
      );
    }
    final shown = ordered.take(maxTiles).toList();
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        for (var row = 0; row < shown.length; row += columns) ...[
          if (row > 0) const SizedBox(height: RCrmSpacing.md),
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              for (var col = 0; col < columns; col++) ...[
                if (col > 0) const SizedBox(width: RCrmSpacing.sm),
                Expanded(
                  child: row + col < shown.length
                      ? _Tile(
                          item: shown[row + col],
                          onTap: () => widget.onPick(shown[row + col]),
                          autoOverlay:
                              auto != null && shown[row + col].path == auto.path
                              ? _autoOverlay()
                              : null,
                        )
                      : const SizedBox(),
                ),
              ],
            ],
          ),
        ],
      ],
    );
  }

  /// What the first tile wears while the autoplay is counting down: the last
  /// frame dimmed, the ring draining, and a way out that does not close the
  /// whole card. The reference's end screen marks its first card this way, and
  /// it is the honest place for it — the ring is on the video it will play.
  Widget _autoOverlay() => Stack(
    fit: StackFit.expand,
    children: [
      const ColoredBox(color: Color(0x73000000)),
      Center(
        child: AnimatedBuilder(
          animation: _count,
          builder: (_, _) => SizedBox(
            width: 40,
            height: 40,
            child: Stack(
              alignment: Alignment.center,
              children: [
                SizedBox(
                  width: 40,
                  height: 40,
                  child: CircularProgressIndicator(
                    // Drains: full at the moment the card appeared.
                    value: 1 - _count.value,
                    strokeWidth: 2.5,
                    valueColor: AlwaysStoppedAnimation<Color>(
                      RCrmColors.playerAccent,
                    ),
                    backgroundColor: RCrmColors.playerText.withValues(
                      alpha: 0.12,
                    ),
                  ),
                ),
                Icon(
                  Icons.skip_next,
                  size: 17,
                  color: RCrmColors.playerText,
                ),
              ],
            ),
          ),
        ),
      ),
      Positioned(
        top: 4,
        left: 4,
        child: Semantics(
          button: true,
          label: 'Cancel auto-play',
          child: GestureDetector(
            behavior: HitTestBehavior.opaque,
            onTap: widget.onCancelAutoPlay,
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 3),
              decoration: BoxDecoration(
                color: const Color(0x99000000),
                borderRadius: BorderRadius.circular(RCrmRadii.sm),
              ),
              child: Text(
                'Cancel',
                style: TextStyle(
                  color: RCrmColors.playerText,
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ),
          ),
        ),
      ),
    ],
  );
}

/// One action: an icon and its word, on a flat tonal chip. No border, no
/// circle badge — the player's chrome is flat and the word is the label.
class _Action extends StatelessWidget {
  const _Action({
    required this.icon,
    required this.label,
    required this.onTap,
  });

  final IconData icon;
  final String label;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final Color color = RCrmColors.playerText;
    return Semantics(
      button: true,
      label: label,
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(RCrmRadii.sm),
        hoverColor: RCrmColors.playerHairline,
        focusColor: RCrmColors.playerHairline,
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(icon, size: 18, color: color),
              const SizedBox(width: RCrmSpacing.sm),
              Text(
                label,
                style: TextStyle(
                  color: color,
                  fontSize: 13,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

/// One Related tile: a poster, its duration in the corner, and a name under
/// it. The poster and its two states are the shared `VideoPoster`, but the
/// placeholder is drawn in fixed dark tokens because this tile floats on the
/// picture and must not turn cream in the Day appearance.
class _Tile extends StatelessWidget {
  const _Tile({
    required this.item,
    required this.onTap,
    this.autoOverlay,
  });

  final MediaItem item;
  final VoidCallback onTap;

  /// Painted over the poster when this tile is the autoplay: the dim, the
  /// ring and the cancel chip live above the image and below the duration.
  final Widget? autoOverlay;

  @override
  Widget build(BuildContext context) {
    return Semantics(
      button: true,
      label: item.name,
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(RCrmRadii.sm),
        hoverColor: RCrmColors.playerHairline,
        focusColor: RCrmColors.playerHairline,
        child: Padding(
          padding: const EdgeInsets.all(4),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              AspectRatio(
                aspectRatio: 16 / 9,
                child: ClipRRect(
                  borderRadius: BorderRadius.circular(RCrmRadii.sm),
                  child: Stack(
                    fit: StackFit.expand,
                    children: [
                      VideoPoster(
                        item: item,
                        loading: const _PosterPlaceholder(),
                        fallback: const _PosterPlaceholder(),
                      ),
                      ?autoOverlay,
                      if (item.durationSeconds != null)
                        Positioned(
                          right: 4,
                          bottom: 4,
                          child: Container(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 4,
                              vertical: 2,
                            ),
                            decoration: BoxDecoration(
                              color: const Color(0xCC000000),
                              borderRadius: BorderRadius.circular(
                                RCrmRadii.sm,
                              ),
                            ),
                            child: Text(
                              item.formattedDuration,
                              style: TextStyle(
                                color: RCrmColors.playerText,
                                fontSize: 11,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                          ),
                        ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 6),
              Text(
                item.name,
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                  color: RCrmColors.playerText,
                  fontSize: 12,
                  fontWeight: FontWeight.w500,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _PosterPlaceholder extends StatelessWidget {
  const _PosterPlaceholder();

  @override
  Widget build(BuildContext context) => Container(
    color: RCrmColors.darkCoal,
    alignment: Alignment.center,
    child: Icon(
      Icons.play_circle_outline,
      size: 26,
      color: RCrmColors.playerTextFaint,
    ),
  );
}
