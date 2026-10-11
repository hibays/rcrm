// widgets/video_folder_card.dart
// RCrm GUI — a folder of videos as a card: four posters, the folder's name, and
// how many videos are in it.
//
// The photo tab's `AlbumCard` is the same card for images, down to the 2×2
// preview and the count line. It cannot be reused directly because its preview
// loads IMAGE thumbnails from a URL (`AlbumPreview` → `PooledImage`), while a
// video's cover is a poster the thumbnail service generates from the video
// itself — so this card pairs the same layout with `VideoPoster`, which is also
// what a grid card draws.
//
// Four posters per folder, and a folder holds more than four videos: that is
// deliberate and cheaper than it looks — the flat grid requests one poster per
// video it shows, so a folder list asks for fewer posters in total than the
// ungrouped view of the same library, and the service dedups and caches them
// either way (`ThumbnailService._posterInflight`, `ThumbCache`).

import 'package:flutter/material.dart';

import '../models/album.dart';
import '../models/media_item.dart';
import 'video_poster.dart';

class VideoFolderCard extends StatelessWidget {
  /// An `Album` here IS a folder: the app groups both tabs with
  /// `MediaLibrary.buildAlbums`, and an album is a folder of media items.
  final Album folder;
  final VoidCallback? onTap;

  const VideoFolderCard({super.key, required this.folder, this.onTap});

  @override
  Widget build(BuildContext context) {
    final covers = folder.items.take(4).toList();
    return GestureDetector(
      onTap: onTap,
      child: Card(
        color: Colors.black,
        clipBehavior: Clip.antiAlias,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Expanded(child: _preview(covers)),
            Padding(
              padding: const EdgeInsets.all(8),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(
                    folder.name,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                  const SizedBox(height: 2),
                  Text(
                    folder.itemCount == 1
                        ? '1 video'
                        : '${folder.itemCount} videos',
                    style: Theme.of(context).textTheme.bodyMedium,
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  /// One poster, or up to four in a 2×2 — the same shape `AlbumPreview` gives a
  /// photo album, so the two tabs read as the same idea.
  Widget _preview(List<MediaItem> covers) {
    if (covers.isEmpty) return _empty();
    if (covers.length == 1) return _cell(covers[0]);
    return Column(
      children: [
        Expanded(
          child: Row(
            children: [
              Expanded(child: _cell(covers[0])),
              Expanded(child: _cell(covers[1])),
            ],
          ),
        ),
        if (covers.length > 2)
          Expanded(
            child: Row(
              children: [
                Expanded(child: _cell(covers[2])),
                if (covers.length > 3)
                  Expanded(child: _cell(covers[3]))
                else
                  Expanded(child: _empty()),
              ],
            ),
          ),
      ],
    );
  }

  Widget _cell(MediaItem item) =>
      VideoPoster(item: item, loading: _empty(), fallback: _empty(icon: true));

  /// A poster that is not there yet, and one that will never arrive, are the
  /// same flat cell at this size — the folder's name and count are what the card
  /// is read for.
  Widget _empty({bool icon = false}) => ColoredBox(
    color: const Color(0xFF2A2A2A),
    child: icon
        ? const Center(
            child: Icon(
              Icons.play_circle_outline,
              size: 20,
              color: Colors.white24,
            ),
          )
        : const SizedBox.expand(),
  );
}
