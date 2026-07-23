// services/media_library.dart
// RCrm GUI — media library scanning and organization service
//
// Scans the WebDAV server for media files, organizes them into videos
// and albums. Image grouping strategy is configurable: by folder or by format.

import '../models/album.dart';
import '../models/media_item.dart';
import 'webdav_client.dart';

/// How images are grouped into albums.
enum ImageClassification { folder, format, none }

class MediaLibrary {
  final WebDavClient _client;
  final ImageClassification imageClassification;

  MediaLibrary(
    this._client, {
    this.imageClassification = ImageClassification.folder,
  });

  /// Scan the entire media library starting from root (/).
  ///
  /// Calls [onBatch] after each directory is scanned with the videos and images
  /// found in that single directory (the batch, not the accumulated total).
  /// The caller should accumulate state itself. The callback enables the caller
  /// to incrementally update the UI during scanning.
  ///
  /// Returns the final (videos, albums) tuple.
  Future<({List<MediaItem> videos, List<Album> albums})> scanAll({
    void Function(List<MediaItem> videos, List<MediaItem> images)? onBatch,
  }) async {
    final allVideos = <MediaItem>[];
    final allImages = <MediaItem>[];
    await _scanRecursive('/', allVideos, allImages, onBatch: onBatch);
    final albumList = switch (imageClassification) {
      ImageClassification.folder => _groupByFolder(allImages),
      ImageClassification.format => _groupByFormat(allImages),
      ImageClassification.none => _groupNone(allImages),
    };
    return (videos: allVideos, albums: albumList);
  }

  /// Build albums from the given images using the current classification.
  /// Used by callers to incrementally reconstruct albums during a batch scan.
  List<Album> buildAlbums(List<MediaItem> images) {
    return switch (imageClassification) {
      ImageClassification.folder => _groupByFolder(images),
      ImageClassification.format => _groupByFormat(images),
      ImageClassification.none => _groupNone(images),
    };
  }

  /// Group images by parent folder (original behavior).
  List<Album> _groupByFolder(List<MediaItem> allImages) {
    final albums = <String, List<MediaItem>>{};
    for (final img in allImages) {
      final key = img.albumName.isNotEmpty ? img.albumName : '_root';
      albums.putIfAbsent(key, () => []).add(img);
    }

    final albumList = albums.entries.map((e) {
      final path = e.key == '_root' ? '/' : '/${e.key}';
      return Album.fromItems(
        name: e.key == '_root' ? 'Unorganized' : e.key,
        path: path,
        url: '${_client.authenticatedBaseUrl}$path',
        items: e.value,
      );
    }).toList();

    albumList.sort((a, b) => a.name.compareTo(b.name));
    return albumList;
  }

  /// Group all images into a single flat album.
  List<Album> _groupNone(List<MediaItem> allImages) {
    if (allImages.isEmpty) return [];
    return [
      Album.fromItems(
        name: 'All Images',
        path: '/',
        url: _client.authenticatedBaseUrl,
        items: allImages,
      ),
    ];
  }

  /// Human-readable names for common image formats.
  static const Map<String, String> _formatNames = {
    'jpg': 'JPEG',
    'jpeg': 'JPEG',
    'png': 'PNG',
    'gif': 'GIF',
    'apng': 'APNG',
    'webp': 'WebP',
    'avif': 'AVIF',
    'heic': 'HEIC',
    'heif': 'HEIF',
    'bmp': 'BMP',
    'svg': 'SVG',
    'ico': 'ICO',
    'tiff': 'TIFF',
    'tif': 'TIFF',
    'jxl': 'JPEG XL',
    'psd': 'Photoshop',
    'raw': 'RAW',
    'cr2': 'CR2',
    'nef': 'NEF',
    'dng': 'DNG',
    'orf': 'ORF',
  };

  /// Group images by file format (extension).
  List<Album> _groupByFormat(List<MediaItem> allImages) {
    final groups = <String, List<MediaItem>>{};
    for (final img in allImages) {
      final ext = img.extension;
      final label = _formatNames[ext] ?? ext.toUpperCase();
      groups.putIfAbsent(label, () => []).add(img);
    }

    final albumList = groups.entries.map((e) {
      return Album.fromItems(
        name: e.key,
        path: '/_fmt/${e.key.toLowerCase()}',
        url: '${_client.authenticatedBaseUrl}/_fmt/${e.key.toLowerCase()}',
        items: e.value,
      );
    }).toList();

    albumList.sort((a, b) {
      final cmp = b.items.length.compareTo(a.items.length);
      if (cmp != 0) return cmp;
      return a.name.compareTo(b.name);
    });
    return albumList;
  }

  static const _maxRecurseDepth = 128;

  Future<void> _scanRecursive(
    String path,
    List<MediaItem> allVideos,
    List<MediaItem> allImages, {
    int depth = 0,
    void Function(List<MediaItem> videos, List<MediaItem> images)? onBatch,
  }) async {
    if (depth >= _maxRecurseDepth) return;
    final result = await _client.listAll(path);
    final batchVideos = <MediaItem>[];
    final batchImages = <MediaItem>[];
    for (final item in result.files) {
      if (item.isVideo) {
        allVideos.add(item);
        batchVideos.add(item);
      } else if (item.isImage) {
        allImages.add(item);
        batchImages.add(item);
      }
    }
    onBatch?.call(batchVideos, batchImages);
    // Yield to event loop so XML parsing doesn't freeze the UI
    await Future.delayed(Duration.zero);
    for (final subdir in result.subdirs) {
      await _scanRecursive(
        subdir,
        allVideos,
        allImages,
        depth: depth + 1,
        onBatch: onBatch,
      );
    }
  }

  /// Scan only videos from a specific path.
  Future<List<MediaItem>> scanVideos(String path) async {
    final items = await _client.listDirectory(path);
    return items.where((item) => item.isVideo).toList();
  }

  /// Scan images organized by album (folder).
  Future<List<Album>> scanAlbums() async {
    final result = await scanAll();
    return result.albums;
  }
}
