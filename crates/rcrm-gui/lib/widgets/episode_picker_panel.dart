// widgets/episode_picker_panel.dart
// Fullscreen episode picker: a bottom sheet (at most half the screen) listing
// the same "Related" videos shown under the player — poster thumbnail + name
// per row — so episodes can be switched without leaving fullscreen.

import 'package:flutter/material.dart';

import '../models/media_item.dart';
import '../widgets/finger_preview_listener.dart';
import '../widgets/video_card.dart';

class EpisodePickerPanel extends StatefulWidget {
  final List<MediaItem> items;
  final ValueChanged<MediaItem> onPick;
  final VoidCallback onDismiss;

  /// Shared mobile sticky-preview state (the same one the related list uses).
  final FingerPreviewState? fingerPreview;

  const EpisodePickerPanel({
    super.key,
    required this.items,
    required this.onPick,
    required this.onDismiss,
    this.fingerPreview,
  });

  @override
  State<EpisodePickerPanel> createState() => _EpisodePickerPanelState();
}

class _EpisodePickerPanelState extends State<EpisodePickerPanel> {
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
    final listBody = Listener(
      onPointerDown: fp == null ? null : (e) => fp.onPointerDown(e, setState),
      child: ListView.builder(
        padding: EdgeInsets.only(top: 4, bottom: landscape ? 16 : 12),
        itemCount: widget.items.length,
        itemBuilder: (_, i) => _row(widget.items[i]),
      ),
    );
    return GestureDetector(
      // Tap on the dimmed backdrop dismisses.
      onTap: widget.onDismiss,
      behavior: HitTestBehavior.opaque,
      child: Container(
        color: Colors.black.withValues(alpha: 0.45),
        alignment: landscape ? Alignment.centerRight : Alignment.bottomCenter,
        child: GestureDetector(
          onTap: () {}, // absorb taps inside the panel
          child: Container(
            width: landscape
                ? (size.width / 2).clamp(280.0, 560.0)
                : double.infinity,
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
                        style: const TextStyle(
                          color: Colors.white38,
                          fontSize: 13,
                        ),
                      ),
                      const Spacer(),
                      IconButton(
                        icon: const Icon(
                          Icons.close,
                          color: Colors.white38,
                          size: 18,
                        ),
                        onPressed: widget.onDismiss,
                        visualDensity: VisualDensity.compact,
                        padding: EdgeInsets.zero,
                        constraints: const BoxConstraints(),
                      ),
                    ],
                  ),
                ),
                const Divider(height: 1, color: Color(0x10FFFFFF)),
                if (landscape)
                  Expanded(child: listBody)
                else
                  Flexible(child: listBody),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
