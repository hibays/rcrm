// widgets/image_grid.dart
// RCrm GUI — image grid with two layouts:
//   uniform  — fixed-aspect GridView (Google Photos style)
//   masonry  — variable-height MasonryGridView (Pinterest style),
//              each cell sized to its image's real aspect ratio.
// Both are lazy (only visible cells build) and use PooledImage
// (throttled decode + LRU) so large albums don't OOM/freeze.

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart' show ScrollCacheExtent;
import 'package:flutter_staggered_grid_view/flutter_staggered_grid_view.dart';
import '../services/item_cache_limit.dart';
import '../models/media_item.dart';
import 'image_card.dart';

class ImageGrid extends StatelessWidget {
  final List<MediaItem> items;
  final String layout;
  final ValueChanged<MediaItem>? onTap;
  final int crossAxisCount;

  const ImageGrid({
    super.key,
    required this.items,
    this.layout = 'uniform',
    this.onTap,
    this.crossAxisCount = 3,
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
          );
        },
      );
    }

    // uniform
    return GridView.builder(
      padding: const EdgeInsets.all(4),
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
        );
      },
    );
  }
}
