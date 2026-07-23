// widgets/image_card.dart
// RCrm GUI — image card: PooledImage (throttled+LRU), placeholder on failure,
// format badge, animated indicator, live-photo badge.

import 'package:flutter/material.dart';
import '../models/media_item.dart';
import '../services/animated_detector.dart';
import '../services/live_photo.dart';
import '../services/net.dart';
import 'pooled_image.dart';

class ImageCard extends StatelessWidget {
  final MediaItem item;
  final VoidCallback? onTap;

  /// Masonry: size the cell to the image's real aspect ratio.
  final bool intrinsicRatio;

  const ImageCard({
    super.key,
    required this.item,
    this.onTap,
    this.intrinsicRatio = false,
  });

  static bool _couldBeLiveExt(String ext) =>
      ext == 'jpg' || ext == 'jpeg' || ext == 'heic' || ext == 'heif';

  /// Formats that could be animated but aren't always (need header check).
  /// Excludes gif/apng (always animated → covered by MediaItem.isAnimated).
  /// Excludes heic/heif (covered by live photo badge).
  static bool _checkableAnimatedExt(String ext) =>
      ext == 'webp' || ext == 'avif';

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Card(
        clipBehavior: Clip.antiAliasWithSaveLayer,
        child: Stack(
          fit: intrinsicRatio ? StackFit.loose : StackFit.expand,
          children: [
            PooledImage(
              url: item.url,
              fit: BoxFit.cover,
              useIntrinsicRatio: intrinsicRatio,
              defaultAspectRatio: 0.85,
            ),
            // Format badge
            Positioned(
              top: 4,
              right: 4,
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 2),
                decoration: BoxDecoration(
                  color: Colors.black54,
                  borderRadius: BorderRadius.circular(4),
                ),
                child: Text(
                  item.extension.toUpperCase(),
                  style: const TextStyle(
                    color: Colors.white70,
                    fontSize: 9,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
            ),
            // Animated formats (gif/apng): motion-circle badge so the user
            // knows it's long-pressable to play.
            if (item.isAnimated)
              const Positioned(
                left: 4,
                bottom: 4,
                child: DecoratedBox(
                  decoration: BoxDecoration(
                    color: Colors.black54,
                    shape: BoxShape.circle,
                  ),
                  child: Padding(
                    padding: EdgeInsets.all(3),
                    child: Icon(
                      Icons.motion_photos_on,
                      size: 14,
                      color: Colors.white,
                    ),
                  ),
                ),
              ),

            // Checkable animated formats (webp/avif): header-based detection
            // to determine if the file actually contains animation frames.
            if (_checkableAnimatedExt(item.extension))
              Positioned(
                left: 4,
                bottom: 4,
                child: FutureBuilder<bool>(
                  future: isAnimatedUrl(item.url, headers: sharedAuthHeader),
                  builder: (_, snap) => snap.data == true
                      ? const DecoratedBox(
                          decoration: BoxDecoration(
                            color: Colors.black54,
                            shape: BoxShape.circle,
                          ),
                          child: Padding(
                            padding: EdgeInsets.all(3),
                            child: Icon(
                              Icons.motion_photos_on,
                              size: 14,
                              color: Colors.white,
                            ),
                          ),
                        )
                      : const SizedBox.shrink(),
                ),
              ),
            if (_couldBeLiveExt(item.extension))
              Positioned(
                left: 4,
                bottom: 4,
                child: FutureBuilder<bool>(
                  future: isLivePhotoUrl(item.url, headers: sharedAuthHeader),
                  builder: (_, snap) => snap.data == true
                      ? const DecoratedBox(
                          decoration: BoxDecoration(
                            color: Colors.black54,
                            shape: BoxShape.circle,
                          ),
                          child: Padding(
                            padding: EdgeInsets.all(3),
                            child: Icon(
                              Icons.motion_photos_on,
                              size: 14,
                              color: Colors.white,
                            ),
                          ),
                        )
                      : const SizedBox.shrink(),
                ),
              ),
          ],
        ),
      ),
    );
  }
}
