// widgets/media_item_menu.dart
//
// The context menu of a LIBRARY ITEM — one long press on a phone, one right-click
// on a desktop — and the actions it offers.
//
// One entry point (`showMediaItemMenu`) serves every surface that shows items
// (the video tab's grid/list, the photo tab's grid, search results), because the
// alternative is three menus that disagree about what "Details" means. The menu
// itself is the app's one menu panel (`showSmartMenu`, the same geometry as
// `SmartPopupMenu`), anchored at the POINT that was pressed rather than at the
// card: a card is a large target and a menu that appears at its bottom-left on a
// wide desktop row is nowhere near the pointer.
//
// What is in the menu is what this app can honestly DO. The library is read-only
// (the server is a decrypted view of an encrypted folder), so there is no Rename,
// Delete, Move or Share: every one of those would be a row that has to explain
// why it is greyed out. What remains is navigation (open / play), the facts
// panel, revealing a video in its folder, and the two clipboard hand-offs that
// desktop users reach for.

import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_smart_dialog/flutter_smart_dialog.dart';
import 'package:material_ui/material_ui.dart';

import '../models/media_item.dart';
import '../services/item_cache_limit.dart';
import '../services/media_metadata.dart';
import '../utils/menu_placement.dart';
import 'image_info_sheet.dart';
import 'smart_popup_menu.dart';
import 'video_info_sheet.dart';
import '../config/theme.dart';

/// What a row of an item's menu does.
enum MediaItemMenuAction { open, details, reveal, copyName, copyPath }

/// One row: the action, the label the user reads, and the glyph beside it.
@immutable
class MediaItemMenuEntry {
  final MediaItemMenuAction action;
  final String label;
  final IconData icon;

  const MediaItemMenuEntry({
    required this.action,
    required this.label,
    required this.icon,
  });
}

/// The rows an item's menu offers.
///
/// [canReveal] is the caller's answer to "is there a folder view this item can
/// be shown in?". The photo tab has none that is worth the cost of reaching (its
/// folder view needs a re-scan, which is a heavy side effect for one menu row),
/// while the video tab's folders are derived and free — so a video offers
/// "Show in folder" and a photo does not.
List<MediaItemMenuEntry> mediaItemMenuEntries({
  required bool isVideo,
  bool canReveal = false,
}) {
  return [
    MediaItemMenuEntry(
      action: MediaItemMenuAction.open,
      label: isVideo ? 'Play' : 'Open',
      // A literal at a use site: the release icon tree-shaker keeps a glyph only
      // when its IconData reaches it as a constant here, and this list is the
      // only place these three are chosen.
      icon: isVideo ? Icons.play_arrow : Icons.open_in_full,
    ),
    const MediaItemMenuEntry(
      action: MediaItemMenuAction.details,
      label: 'Details',
      icon: Icons.info_outline,
    ),
    if (canReveal)
      const MediaItemMenuEntry(
        action: MediaItemMenuAction.reveal,
        label: 'Show in folder',
        icon: Icons.folder_open,
      ),
    const MediaItemMenuEntry(
      action: MediaItemMenuAction.copyName,
      label: 'Copy name',
      icon: Icons.copy,
    ),
    const MediaItemMenuEntry(
      action: MediaItemMenuAction.copyPath,
      label: 'Copy path',
      icon: Icons.link,
    ),
  ];
}

/// The card-side trigger: a long press or a secondary click asking for the
/// item's menu at [at].
///
/// A long press on a TOUCH screen is confirmed with a haptic — it is the one
/// gesture that gives no immediate visual answer before the menu appears. A
/// mouse long-press and a right-click are not, and neither is anything on a
/// desktop, where the haptic channel has nothing to move.
void requestItemMenu(
  void Function(Offset globalPosition)? onMenuRequested,
  Offset at, {
  bool haptic = false,
}) {
  final request = onMenuRequested;
  if (request == null) return;
  if (haptic && isMobile) unawaited(HapticFeedback.mediumImpact());
  request(at);
}

/// Opens the item menu at [at] (a global position) and runs what was chosen.
///
/// [index]/[total] position the item in the list it was opened from; the photo
/// details sheet states that position, and it is the only row that needs them.
Future<void> showMediaItemMenu({
  required BuildContext context,
  required MediaItem item,
  required Offset at,
  required bool isVideo,
  required VoidCallback onOpen,
  VoidCallback? onReveal,
  int index = 1,
  int total = 1,
  List<String>? keywords,
}) async {
  final entries = mediaItemMenuEntries(
    isVideo: isVideo,
    canReveal: onReveal != null,
  );
  final up = menuOpensUpward(
    anchorY: at.dy,
    screenHeight: MediaQuery.sizeOf(context).height,
    rows: entries.length,
    textScale: MediaQuery.textScalerOf(context).scale(1),
  );
  final action = await showSmartMenu<MediaItemMenuAction>(
    anchor: at,
    openUpward: up,
    items: [
      for (final entry in entries)
        SmartPopupMenuItem<MediaItemMenuAction>(
          value: entry.action,
          child: Row(
            children: [
              Icon(entry.icon, size: 20, color: RCrmColors.textSecondary),
              const SizedBox(width: 14),
              Text(entry.label),
            ],
          ),
        ),
    ],
  );
  if (action == null) return;
  switch (action) {
    case MediaItemMenuAction.open:
      onOpen();
    case MediaItemMenuAction.reveal:
      onReveal?.call();
    case MediaItemMenuAction.details:
      _showDetails(
        item,
        isVideo: isVideo,
        index: index,
        total: total,
        keywords: keywords,
      );
    case MediaItemMenuAction.copyName:
      unawaited(_copy(item.name, 'Name'));
    case MediaItemMenuAction.copyPath:
      unawaited(_copy(item.path, 'Path'));
  }
}

/// The facts panel, in the same bottom-anchored sheet the viewer's info button
/// opens — one panel per media kind, reachable from the item itself instead of
/// only from inside the viewer.
void _showDetails(
  MediaItem item, {
  required bool isVideo,
  required int index,
  required int total,
  List<String>? keywords,
}) {
  final metadata = MediaMetadataService.forUrl(
    item.url,
    kind: isVideo ? MetadataKind.track : MetadataKind.image,
  );
  unawaited(
    SmartDialog.show<void>(
      // A light scrim, the photo/video stays the subject (same as the viewer).
      alignment: Alignment.bottomCenter,
      maskColor: Colors.black.withValues(alpha: 0.35),
      clickMaskDismiss: true,
      builder: (_) => ConstrainedBox(
        // A bottom sheet is a reading panel, not a full-width banner: in
        // landscape an infinity-width sheet reads as a stretched strip with a
        // long empty right side. The cap never binds on a phone (screen < cap).
        constraints: const BoxConstraints(maxWidth: RCrmLayout.infoSheetMaxWidth),
        child: isVideo
            ? VideoInfoSheet(
                item: item,
                metadata: metadata,
                keywords: keywords ?? const [],
              )
            : ImageInfoSheet(
                item: item,
                index: index,
                total: total,
                metadata: metadata,
                // The extension-level verdict only: the grid's badge may also
                // probe a webp/avif header, and a sheet opened from the grid has
                // not done that probe. The row therefore never claims animation
                // the badge has not shown; it may stay silent about frames the
                // viewer's own probe would have found.
                animated: item.isAnimated,
              ),
      ),
    ),
  );
}

/// Copies [text] and says so.
///
/// On Android/iOS the OS already shows its own "Copied" confirmation above the
/// content (Android 13+ draws an overlay that the app cannot match), so the app
/// adds nothing there; on a desktop nothing acknowledges the copy, and a silent
/// clipboard write reads as a dead menu row.
Future<void> _copy(String text, String what) async {
  await Clipboard.setData(ClipboardData(text: text));
  if (isMobile) return;
  unawaited(
    SmartDialog.showNotify(msg: '$what copied', notifyType: NotifyType.success),
  );
}
