// models/media_item.dart
// RCrm GUI — media file model (video or image)

enum MediaType { video, image, unknown }

class MediaItem {
  final String name;
  final String path; // WebDAV path
  final String url; // Full WebDAV URL
  final MediaType type;
  final int size; // bytes
  final DateTime? modified;
  final String? posterUrl; // Thumbnail/poster URL
  final List<String>? previewClipUrls; // Hover preview clips
  final int? durationSeconds; // Video duration
  final String? resolution; // e.g. "1920x1080"
  final String albumName; // Parent folder name

  const MediaItem({
    required this.name,
    required this.path,
    required this.url,
    required this.type,
    this.size = 0,
    this.modified,
    this.posterUrl,
    this.previewClipUrls,
    this.durationSeconds,
    this.resolution,
    this.albumName = '',
  });

  String get extension =>
      name.contains('.') ? name.split('.').last.toLowerCase() : '';

  bool get isVideo => type == MediaType.video;
  bool get isImage => type == MediaType.image;

  /// gif/webp/apng carry animation frames → marked with a motion badge in the
  /// grid and long-pressable to play in the viewer.
  /// Animation-capable formats (container-level). gif/webp/apng are always
  /// animated. avif/heic/heif NATIVELY support image sequences (AVIF by spec,
  /// HEIC as the Live Photos container), but a specific file may be still —
  /// the viewer long-press will attempt playback and fall back to a still.
  /// Only marks formats ALWAYS animated: gif, apng.
  /// webp/avif/heic/heif can be still or animated — the viewer detects
  /// actual frame count after full decode and shows a badge then.
  // Formats where a specific file MAY be animated (container supports it).
  // gif/apng are always animated. webp/avif/heic/heif are detected by the
  // viewer after frame count decode.
  bool get isAnimated {
    final e = extension;
    return e == 'gif' || e == 'apng';
  }

  String get formattedSize {
    if (size < 1024) return '$size B';
    if (size < 1024 * 1024) return '${(size / 1024).toStringAsFixed(1)} KB';
    if (size < 1024 * 1024 * 1024) {
      return '${(size / (1024 * 1024)).toStringAsFixed(1)} MB';
    }
    return '${(size / (1024 * 1024 * 1024)).toStringAsFixed(1)} GB';
  }

  String get formattedDuration {
    if (durationSeconds == null) return '';
    final m = durationSeconds! ~/ 60;
    final s = durationSeconds! % 60;
    return '${m.toString().padLeft(2, '0')}:${s.toString().padLeft(2, '0')}';
  }

  factory MediaItem.fromWebDavProps({
    required String name,
    required String path,
    required String baseUrl,
    required int size,
    required DateTime? modified,
    String? albumName,
  }) {
    final ext = name.contains('.') ? name.split('.').last.toLowerCase() : '';
    final type = _detectType(ext);

    return MediaItem(
      name: name,
      path: path,
      url: '$baseUrl$path',
      type: type,
      size: size,
      modified: modified,
      albumName: albumName ?? '',
    );
  }

  static MediaType _detectType(String ext) {
    const videoExts = {
      'mp4',
      'mkv',
      'avi',
      'wmv',
      'mov',
      'webm',
      'flv',
      'm4v',
      'mpeg',
      'mpg',
      '3gp',
      'ogv',
      'ts',
      'm2ts',
      'vob',
      'rmvb',
      'rm',
      'asf',
      'divx',
      'xvid',
    };
    const imageExts = {
      'jpg',
      'jpeg',
      'apng',
      'png',
      'gif',
      'bmp',
      'webp',
      'avif',
      'heic',
      'heif',
      'jxl',
      'tiff',
      'tif',
      'ico',
      'svg',
      'psd',
      'raw',
      'cr2',
      'nef',
      'dng',
      'orf',
    };

    if (videoExts.contains(ext)) return MediaType.video;
    if (imageExts.contains(ext)) return MediaType.image;
    return MediaType.unknown;
  }

  MediaItem copyWith({
    String? posterUrl,
    List<String>? previewClipUrls,
    int? durationSeconds,
    String? resolution,
  }) {
    return MediaItem(
      name: name,
      path: path,
      url: url,
      type: type,
      size: size,
      modified: modified,
      posterUrl: posterUrl ?? this.posterUrl,
      previewClipUrls: previewClipUrls ?? this.previewClipUrls,
      durationSeconds: durationSeconds ?? this.durationSeconds,
      resolution: resolution ?? this.resolution,
      albumName: albumName,
    );
  }
}
