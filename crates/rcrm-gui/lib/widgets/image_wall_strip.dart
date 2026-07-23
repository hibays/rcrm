// widgets/image_wall_strip.dart
// RCrm GUI — bottom image wall strip for quick navigation
//
// Shows a thumbnail strip at the bottom of the image viewer for quick jumping
// between images. The current image is highlighted, and the strip auto-scrolls
// to keep the focused thumbnail centered when the page changes.

import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';

import '../models/media_item.dart';
import 'pooled_image.dart';

class ImageWallStrip extends StatefulWidget {
  final List<MediaItem> items;
  final int currentIndex;
  final ValueChanged<int> onTap;

  const ImageWallStrip({
    super.key,
    required this.items,
    required this.currentIndex,
    required this.onTap,
  });

  @override
  State<ImageWallStrip> createState() => _ImageWallStripState();
}

class _ImageWallStripState extends State<ImageWallStrip> {
  final ScrollController _controller = ScrollController();

  // 56 (tile) + 2*2 (margin) = 60px per item.
  static const double _itemExtent = 60;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback(
      (_) => _centerCurrent(animate: false),
    );
  }

  @override
  void didUpdateWidget(ImageWallStrip old) {
    super.didUpdateWidget(old);
    if (old.currentIndex != widget.currentIndex) _centerCurrent(animate: true);
  }

  void _centerCurrent({required bool animate}) {
    if (!_controller.hasClients) return;
    final viewport = _controller.position.viewportDimension;
    final target =
        (widget.currentIndex * _itemExtent) -
        (viewport / 2) +
        (_itemExtent / 2);
    final clamped = target.clamp(0.0, _controller.position.maxScrollExtent);
    if (animate) {
      _controller.animateTo(
        clamped,
        duration: const Duration(milliseconds: 300),
        curve: Curves.easeInOut,
      );
    } else {
      _controller.jumpTo(clamped);
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      height: 80,
      decoration: BoxDecoration(color: Colors.black.withValues(alpha: 0.7)),
      child: Listener(
        // Map a vertical mouse wheel onto this horizontal strip (desktop).
        onPointerSignal: (signal) {
          if (signal is PointerScrollEvent && _controller.hasClients) {
            final delta = signal.scrollDelta.dy != 0
                ? signal.scrollDelta.dy
                : signal.scrollDelta.dx;
            final target = (_controller.offset + delta).clamp(
              0.0,
              _controller.position.maxScrollExtent,
            );
            _controller.jumpTo(target);
          }
        },
        child: ListView.builder(
          controller: _controller,
          scrollDirection: Axis.horizontal,
          padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 8),
          itemCount: widget.items.length,
          itemBuilder: (context, index) {
            final isSelected = index == widget.currentIndex;
            return GestureDetector(
              onTap: () => widget.onTap(index),
              child: Container(
                width: 56,
                margin: const EdgeInsets.symmetric(horizontal: 2),
                decoration: BoxDecoration(
                  border: Border.all(
                    color: isSelected
                        ? Theme.of(context).colorScheme.primary
                        : Colors.white24,
                    width: isSelected ? 2 : 1,
                  ),
                  borderRadius: BorderRadius.circular(4),
                ),
                child: ClipRRect(
                  borderRadius: BorderRadius.circular(3),
                  child: PooledImage(
                    url: widget.items[index].url,
                    fit: BoxFit.cover,
                    errorWidget: Container(
                      color: const Color(0xFF2A2A2A),
                      child: const Icon(
                        Icons.image,
                        size: 16,
                        color: Colors.white24,
                      ),
                    ),
                  ),
                ),
              ),
            );
          },
        ),
      ),
    );
  }
}
