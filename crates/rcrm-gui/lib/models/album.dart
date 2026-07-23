// models/album.dart
// RCrm GUI — album (folder) model for image galleries

import 'media_item.dart';

class Album {
  final String name;
  final String path; // WebDAV path
  final String url; // Base URL for this folder
  final List<MediaItem> items;
  final int itemCount;
  final String? coverUrl; // First image thumbnail as cover

  const Album({
    required this.name,
    required this.path,
    required this.url,
    required this.items,
    this.coverUrl,
    this.itemCount = 0,
  });

  factory Album.fromItems({
    required String name,
    required String path,
    required String url,
    required List<MediaItem> items,
  }) {
    return Album(
      name: name,
      path: path,
      url: url,
      items: items,
      itemCount: items.length,
      coverUrl: items.isNotEmpty ? items.first.url : null,
    );
  }

  /// Create cover preview URLs — up to 4 thumbnails from the album
  List<String> get coverPreviewUrls => items.take(4).map((e) => e.url).toList();
}
