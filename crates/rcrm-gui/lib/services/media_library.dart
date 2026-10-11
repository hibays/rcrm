// services/media_library.dart
// RCrm GUI — media library scanning and organization service
//
// Scans the WebDAV server for media files, organizes them into videos
// and albums. Image grouping strategy is configurable: by folder or by format.

import '../models/album.dart';
import '../models/media_item.dart';
import '../utils/natural_sort.dart';
import 'webdav_client.dart';

/// How media items are grouped into albums/folders.
///
/// The photo tab uses it for its albums (the classification lives on the library
/// instance it was built with); the video tab uses the same rule for its folder
/// view, passed in explicitly (`videoFoldersProvider`). One enum because the
/// grouping is identical — only what is being grouped differs.
enum MediaClassification { folder, format, none }

/// The name of the one album the home page offers for media that is NOT grouped.
///
/// The tabs show ungrouped items flat — there is nothing to open — but a home
/// page has only albums to offer, so it offers this one, and opening it lands on
/// that same flat view. One string, so the album and the view it opens are named
/// alike.
const String kUngroupedAlbumName = 'Ungrouped';

class MediaLibrary {
  final WebDavClient _client;

  /// How IMAGES are grouped for the photo tab. The video side keeps its own
  /// setting and passes it to [buildAlbums], so one tab's choice can never
  /// rewrite the other's grouping.
  final MediaClassification imageClassification;

  MediaLibrary(
    this._client, {
    this.imageClassification = MediaClassification.folder,
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
    final albumList = _group(allImages, imageClassification);
    return (videos: allVideos, albums: albumList);
  }

  /// Group [items] into albums/folders by [classification], defaulting to this
  /// library's own image classification.
  ///
  /// Used by callers to incrementally reconstruct albums during a batch scan,
  /// and — with an explicit classification — by the video tab, whose folder view
  /// is this same grouping applied to videos.
  List<Album> buildAlbums(
    List<MediaItem> items, {
    MediaClassification? classification,
  }) => _group(items, classification ?? imageClassification);

  /// The one place the classification is turned into albums — the scan above and
  /// [buildAlbums] both come through here, so the three branches cannot drift
  /// apart (they did: `none` was spelled out at both call sites).
  ///
  /// `none` yields NOTHING, on purpose. "Ungrouped" is the caller showing the
  /// items themselves in one flat grid (both tabs do); a single group holding
  /// them all — which is what an "All Images" album used to be here — is exactly
  /// what the setting says not to do. That is why this branch is an empty list
  /// and not a call like the other two: there is no grouping work to do, and a
  /// method whose whole body is `const []`, ignoring its argument, would claim
  /// otherwise.
  List<Album> _group(List<MediaItem> items, MediaClassification by) =>
      switch (by) {
        MediaClassification.folder => _groupByFolder(items),
        MediaClassification.format => _groupByFormat(items),
        MediaClassification.none => const <Album>[],
      };

  /// Group by parent folder — the original behaviour, and what the video tab's
  /// folder view uses.
  List<Album> _groupByFolder(List<MediaItem> items) {
    final albums = <String, List<MediaItem>>{};
    for (final img in items) {
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

    albumList.sort((a, b) => naturalCompare(a.name, b.name));
    return albumList;
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

  /// The single album the HOME page shows when the classification is `none`.
  ///
  /// [buildAlbums] deliberately returns nothing for `none`: the tabs show those
  /// items flat, and one group holding everything is exactly what "ungrouped"
  /// must not be. A home page has no flat view of its own, so it offers this
  /// album, and tapping it opens that same flat grid — `ImageScreen` branches on
  /// the setting, not on this album, so the tab does not gain a folder from it.
  Album flatAlbum(List<MediaItem> items) => Album.fromItems(
    name: kUngroupedAlbumName,
    path: '/',
    url: _client.authenticatedBaseUrl,
    items: items,
  );

  /// Group by file format (extension). `_formatNames` covers the image
  /// extensions; a video extension falls back to its uppercase form (MKV, MP4),
  /// which is already the name a user would give it.
  List<Album> _groupByFormat(List<MediaItem> items) {
    final groups = <String, List<MediaItem>>{};
    for (final img in items) {
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
      return naturalCompare(a.name, b.name);
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

  /// Scan images organized by album (folder).
  Future<List<Album>> scanAlbums() async {
    final result = await scanAll();
    return result.albums;
  }
}
