// widgets/image_grid.dart
// RCrm GUI — image grid with two layouts:
//   uniform  — fixed-aspect GridView (Google Photos style)
//   masonry  — variable-height MasonryGridView (Pinterest style),
//              each cell sized to its image's real aspect ratio.
// Both are lazy (only visible cells build) and use PooledImage
// (throttled decode + LRU) so large albums don't OOM/freeze.

import 'package:material_ui/material_ui.dart';
import 'package:flutter_staggered_grid_view/flutter_staggered_grid_view.dart';

import '../services/item_cache_limit.dart';
import '../models/media_item.dart';
import 'image_card.dart';

class ImageGrid extends StatelessWidget {
  final List<MediaItem> items;
  final String layout;
  final ValueChanged<MediaItem>? onTap;

  /// Long-press / right-click on a cell, with the pointer's global position.
  final void Function(MediaItem item, Offset globalPosition)? onMenuRequested;
  final int crossAxisCount;

  /// Overrides the scroll physics — a two-finger pinch hands the grid
  /// `NeverScrollableScrollPhysics` for the length of the gesture so the grid
  /// does not scroll under the fingers sizing it (see `two_finger_pinch.dart`).
  final ScrollPhysics? physics;

  const ImageGrid({
    super.key,
    required this.items,
    this.layout = 'uniform',
    this.onTap,
    this.onMenuRequested,
    this.crossAxisCount = 3,
    this.physics,
  });

  @override
  Widget build(BuildContext context) {
    if (items.isEmpty) {
      return const Center(child: Text('No images'));
    }

    // Mobile keeps a tight ring (RAM-bound — a wide ring pre-decodes too much
    // and stutters); desktop pre-builds far more so a fast fling never
    // out-runs the gated decode.
    final double cacheExt = ItemCacheLimit.imageScrollCacheExtent;

    if (layout == 'masonry') {
      return MasonryGridView.builder(
        padding: const EdgeInsets.all(4),
        physics: physics,
        // Only build cells in/near the viewport so off-screen images don't
        // pre-decode (which stampedes the CPU on a freshly-opened grid).
        cacheExtent: cacheExt,
        gridDelegate: SliverSimpleGridDelegateWithFixedCrossAxisCount(
          crossAxisCount: crossAxisCount,
        ),
        mainAxisSpacing: 4,
        crossAxisSpacing: 4,
        itemCount: items.length,
        addAutomaticKeepAlives: false,
        addRepaintBoundaries: true,
        itemBuilder: (context, index) {
          return ImageCard(
            key: ValueKey(items[index].path),
            item: items[index],
            intrinsicRatio: true,
            onTap: () => onTap?.call(items[index]),
            onMenuRequested: onMenuRequested == null
                ? null
                : (at) => onMenuRequested!(items[index], at),
          );
        },
      );
    }

    // uniform
    return GridView.builder(
      padding: const EdgeInsets.all(4),
      physics: physics,
      scrollCacheExtent: ScrollCacheExtent.pixels(cacheExt),
      gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: crossAxisCount,
        crossAxisSpacing: 4,
        mainAxisSpacing: 4,
        childAspectRatio: 0.85,
      ),
      itemCount: items.length,
      addAutomaticKeepAlives: false,
      addRepaintBoundaries: true,
      itemBuilder: (context, index) {
        return ImageCard(
          key: ValueKey(items[index].path),
          item: items[index],
          onTap: () => onTap?.call(items[index]),
          onMenuRequested: onMenuRequested == null
              ? null
              : (at) => onMenuRequested!(items[index], at),
        );
      },
    );
  }
}
