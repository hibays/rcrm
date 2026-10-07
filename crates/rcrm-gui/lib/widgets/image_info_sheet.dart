// widgets/image_info_sheet.dart
// The image viewer's info sheet: what this file is, at a glance.
//
// Reference: the gallery info panels people already know — one large
// human-readable date as the anchor, the file name under it, the location
// line, then a camera block over a compact technical line, then labelled
// rows. Rendered in RCrm's world: flat tonal layering (ash sheet over a
// dimmed photo), hairline dividers, silver for secondary text, and Marquee
// Orange only on the one thing that acts.
//
// The camera block is fed by the Rust EXIF parser (services/media_metadata.dart).
// When the file carries none, the sheet says so instead of inventing fields.

import 'package:flutter/material.dart';

import '../config/theme.dart';
import '../models/media_item.dart';
import '../services/media_metadata.dart';

class ImageInfoSheet extends StatelessWidget {
  final MediaItem item;

  /// Decoded pixel size, when the viewer has it (null while loading). Preferred
  /// over EXIF dimensions, which describe the stored pixels rather than the
  /// picture as displayed after orientation.
  final Size? pixelSize;

  /// 1-based position in the viewer's list.
  final int index;
  final int total;

  /// True when the file really carries animation frames: gif/apng by extension,
  /// or a multi-frame png/webp/avif/heic confirmed by the container-header
  /// probe the viewer also badges with.
  final bool animated;

  /// EXIF / track metadata, parsed on demand. Null = not requested.
  final Future<MediaMetadata>? metadata;

  /// Shown as the accent chip when non-null — jumps the viewer to 1:1.
  final VoidCallback? onActualSize;

  const ImageInfoSheet({
    super.key,
    required this.item,
    required this.index,
    required this.total,
    this.pixelSize,
    this.animated = false,
    this.metadata,
    this.onActualSize,
  });

  static const _hairline = Color(0x14FFFFFF);

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: const BoxDecoration(
        color: RCrmColors.ash,
        borderRadius: BorderRadius.vertical(top: Radius.circular(14)),
        border: Border(top: BorderSide(color: _hairline)),
      ),
      // Never taller than the screen: the body scrolls if a huge text scale
      // ever makes it so.
      constraints: BoxConstraints(
        maxHeight: MediaQuery.sizeOf(context).height * 0.9,
      ),
      child: SafeArea(
        top: false,
        child: FutureBuilder<MediaMetadata>(
          future: metadata,
          builder: (_, snapshot) => _body(snapshot.data ?? MediaMetadata.none),
        ),
      ),
    );
  }

  Widget _body(MediaMetadata meta) {
    final exif = meta.exif;
    // EXIF knows when the picture was taken; the WebDAV timestamp only knows
    // when the file was last written. An RFC 1123 header parses to UTC, so the
    // fallback is converted for display — while `capturedAt` is deliberately
    // left alone: EXIF stores the camera's wall clock, and shifting it would
    // show a time the photographer never saw.
    final captured = exif?.capturedAt ?? item.modified?.toLocal();
    return SingleChildScrollView(
      padding: const EdgeInsets.fromLTRB(20, 10, 20, 20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: [
          Center(
            child: Container(
              width: 36,
              height: 4,
              decoration: BoxDecoration(
                color: Colors.white24,
                borderRadius: BorderRadius.circular(2),
              ),
            ),
          ),
          const SizedBox(height: RCrmSpacing.md),

          // ── The anchor: when the picture is from ──────────────
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Expanded(
                child: Text(
                  captured == null ? item.name : _formatDate(captured),
                  style: TextStyle(
                    color: RCrmColors.white,
                    fontSize: captured == null ? 18 : 21,
                    fontWeight: FontWeight.w600,
                    height: 1.2,
                  ),
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              if (onActualSize != null) ...[
                const SizedBox(width: RCrmSpacing.sm),
                _Chip(label: '1:1', onTap: onActualSize!),
              ],
            ],
          ),
          if (captured != null) ...[
            const SizedBox(height: 6),
            Text(
              item.name,
              style: const TextStyle(
                color: RCrmColors.silver,
                fontSize: 13,
                height: 1.35,
              ),
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
            ),
          ],

          const SizedBox(height: 10),
          _LocationLine(exif: exif, known: meta.parsed),

          const _Rule(),
          ..._cameraBlock(meta),
          Text(
            _technicalLine(exif),
            style: const TextStyle(
              color: RCrmColors.silver,
              fontSize: 13,
              height: 1.4,
            ),
          ),
          const _Rule(),

          _Row(icon: Icons.folder_outlined, label: _folderLabel()),
          _Row(
            icon: Icons.photo_library_outlined,
            label: 'Image $index of $total',
          ),
          if (animated)
            const _Row(
              icon: Icons.motion_photos_on_outlined,
              label: 'Animated',
              value: 'Plays on long-press',
            ),
        ],
      ),
    );
  }

  /// Camera name, lens and exposure — or the honest admission that the file
  /// has none (the state every phone-saved picture is in).
  List<Widget> _cameraBlock(MediaMetadata meta) {
    final exif = meta.exif;
    if (meta.isTrack) {
      return meta.track == null ? const [] : _trackBlock(meta.track!);
    }
    // A parse that failed (corrupt EXIF, an unreadable container) or a fetch
    // that never produced bytes is NOT the same fact as "this file has no
    // camera": stay silent rather than assert an absence that was never
    // established.
    if (!meta.parsed) return const [];
    if (exif == null || !exif.hasCamera) {
      return const [
        Text(
          'No camera information',
          style: TextStyle(color: RCrmColors.silver, fontSize: 13),
        ),
        SizedBox(height: 6),
      ];
    }
    final exposure = _exposureLine(exif);
    return [
      if (exif.cameraName != null)
        Text(
          exif.cameraName!,
          style: const TextStyle(
            color: RCrmColors.white,
            fontSize: 14,
            fontWeight: FontWeight.w500,
            height: 1.3,
          ),
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
        ),
      if (exif.lens != null) ...[
        const SizedBox(height: 3),
        Text(
          exif.lens!,
          style: const TextStyle(
            color: RCrmColors.silver,
            fontSize: 13,
            height: 1.3,
          ),
          maxLines: 2,
          overflow: TextOverflow.ellipsis,
        ),
      ],
      if (exposure.isNotEmpty) ...[
        const SizedBox(height: 3),
        Text(
          exposure,
          style: const TextStyle(
            color: RCrmColors.silver,
            fontSize: 13,
            height: 1.3,
          ),
        ),
      ],
      const SizedBox(height: 6),
    ];
  }

  List<Widget> _trackBlock(TrackInfo track) {
    final parts = <String>[
      if (track.width != null && track.height != null)
        '${track.width} × ${track.height}',
      if (track.durationMs != null) _duration(track.durationMs!),
      if (track.author != null) track.author!,
    ];
    return [
      if (track.make != null || track.model != null)
        Text(
          [track.make, track.model].whereType<String>().join(' '),
          style: const TextStyle(
            color: RCrmColors.white,
            fontSize: 14,
            fontWeight: FontWeight.w500,
          ),
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
        ),
      if (parts.isNotEmpty) ...[
        const SizedBox(height: 3),
        Text(
          parts.join(' • '),
          style: const TextStyle(color: RCrmColors.silver, fontSize: 13),
        ),
      ],
      const SizedBox(height: 6),
    ];
  }

  /// "1440 × 1000 • 1.4 MP • 637 KB • JPG" — only what is actually known.
  String _technicalLine(ExifInfo? exif) {
    final parts = <String>[];
    // Decoded size first (that is the picture you are looking at), EXIF
    // dimensions second, the scanner's guess last.
    final stored = exif != null && exif.hasPixelSize
        ? Size(exif.pixelWidth!.toDouble(), exif.pixelHeight!.toDouble())
        : null;
    final px = pixelSize ?? stored;
    if (px != null && px.width > 0 && px.height > 0) {
      parts.add('${px.width.round()} × ${px.height.round()}');
      final mp = (px.width * px.height) / 1000000;
      // Below a tenth of a megapixel "0.0 MP" would be a claim, not a size.
      if (mp >= 0.1) {
        parts.add(mp >= 10 ? '${mp.round()} MP' : '${mp.toStringAsFixed(1)} MP');
      }
    } else if (item.resolution != null) {
      parts.add(item.resolution!);
    }
    parts.add(item.formattedSize);
    // A dot-leading name (the encrypted on-disk form) makes `extension` the
    // whole name, so only a plausible token is shown.
    final ext = item.extension.toUpperCase();
    if (ext.isNotEmpty && ext.length <= 5) parts.add(ext);
    return parts.join(' • ');
  }

  String _folderLabel() {
    final path = item.path;
    final cut = path.lastIndexOf('/');
    if (cut <= 0) return '/';
    return path.substring(0, cut + 1);
  }

  /// "26 mm • f/1.8 • 1/250 s • ISO 100" — the compact line every camera app
  /// shows, with whatever the file actually had.
  static String _exposureLine(ExifInfo exif) {
    final parts = <String>[];
    final focal = exif.focalLength;
    if (focal != null && focal > 0) {
      parts.add(
        focal >= 10
            ? '${focal.round()} mm'
            : '${focal.toStringAsFixed(1)} mm',
      );
    }
    final f = exif.fNumber;
    if (f != null && f > 0) {
      parts.add('f/${f == f.roundToDouble() ? f.round() : f.toStringAsFixed(1)}');
    }
    final t = exif.exposureTime;
    if (t != null && t > 0) {
      parts.add(t >= 1 ? '${_trim(t)} s' : '1/${(1 / t).round()} s');
    }
    if (exif.iso != null && exif.iso! > 0) parts.add('ISO ${exif.iso}');
    final bias = exif.exposureBias;
    if (bias != null && bias.abs() >= 0.05) {
      parts.add('${bias > 0 ? '+' : ''}${_trim(bias)} EV');
    }
    return parts.join(' • ');
  }

  static String _trim(double v) {
    final s = v.toStringAsFixed(2);
    return s.replaceFirst(RegExp(r'\.?0+$'), '');
  }

  static String _duration(int ms) {
    if (ms <= 0) return '0s';
    final total = (ms / 1000).round();
    final h = total ~/ 3600;
    final m = (total % 3600) ~/ 60;
    final s = total % 60;
    // Hours, so a two-hour recording does not read as "125m 30s".
    if (h > 0) return '${h}h ${m.toString().padLeft(2, '0')}m';
    return m > 0 ? '${m}m ${s.toString().padLeft(2, '0')}s' : '${s}s';
  }

  static const _months = [
    'Jan',
    'Feb',
    'Mar',
    'Apr',
    'May',
    'Jun',
    'Jul',
    'Aug',
    'Sep',
    'Oct',
    'Nov',
    'Dec',
  ];

  /// "Sep 30, 2026 · 2:24 AM" — locale-free, unambiguous, and the one line a
  /// person actually reads first.
  static String _formatDate(DateTime d) {
    final hour12 = d.hour % 12 == 0 ? 12 : d.hour % 12;
    final minute = d.minute.toString().padLeft(2, '0');
    final period = d.hour < 12 ? 'AM' : 'PM';
    return '${_months[d.month - 1]} ${d.day}, ${d.year}'
        ' · $hour12:$minute $period';
  }
}

/// Where the picture was taken. A missing location is stated, not hidden —
/// that is the difference between "no GPS" and "not looked up yet".
class _LocationLine extends StatelessWidget {
  final ExifInfo? exif;
  final bool known;

  const _LocationLine({required this.exif, required this.known});

  @override
  Widget build(BuildContext context) {
    final lat = exif?.latitude;
    final lon = exif?.longitude;
    if (lat != null && lon != null) {
      return Row(
        children: [
          const Icon(Icons.place_outlined, size: 16, color: RCrmColors.silver),
          const SizedBox(width: 6),
          Expanded(
            child: Text(
              '${lat.abs().toStringAsFixed(4)}° ${lat >= 0 ? 'N' : 'S'}, '
              '${lon.abs().toStringAsFixed(4)}° ${lon >= 0 ? 'E' : 'W'}',
              style: const TextStyle(
                color: RCrmColors.white,
                fontSize: 13,
              ),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      );
    }
    if (!known) return const SizedBox.shrink();
    return const Text(
      'No location information',
      style: TextStyle(color: Colors.white38, fontSize: 13),
    );
  }
}

class _Rule extends StatelessWidget {
  const _Rule();

  @override
  Widget build(BuildContext context) => const Padding(
    padding: EdgeInsets.symmetric(vertical: 14),
    child: Divider(height: 1, thickness: 1, color: ImageInfoSheet._hairline),
  );
}

class _Row extends StatelessWidget {
  final IconData icon;
  final String label;
  final String? value;

  const _Row({required this.icon, required this.label, this.value});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 7),
      child: Row(
        children: [
          Icon(icon, size: 19, color: Colors.white54),
          const SizedBox(width: 14),
          Expanded(
            child: Text(
              label,
              style: const TextStyle(
                color: RCrmColors.white,
                fontSize: 14,
                height: 1.3,
              ),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
          ),
          if (value != null) ...[
            const SizedBox(width: 12),
            // Both sides are long in practice (folder path, album name), so
            // the trailing value must be able to give way — never overflow.
            Flexible(
              child: Text(
                value!,
                style: const TextStyle(color: RCrmColors.silver, fontSize: 13),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                textAlign: TextAlign.end,
              ),
            ),
          ],
        ],
      ),
    );
  }
}

/// The accent chip: the only element in the sheet that does something.
class _Chip extends StatelessWidget {
  final String label;
  final VoidCallback onTap;

  const _Chip({required this.label, required this.onTap});

  @override
  Widget build(BuildContext context) {
    return Material(
      color: RCrmColors.primary.withValues(alpha: 0.14),
      borderRadius: BorderRadius.circular(RCrmRadii.sm + 2),
      child: InkWell(
        borderRadius: BorderRadius.circular(RCrmRadii.sm + 2),
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 7),
          child: Text(
            label,
            style: const TextStyle(
              color: RCrmColors.primary,
              fontSize: 13,
              fontWeight: FontWeight.w600,
            ),
          ),
        ),
      ),
    );
  }
}
