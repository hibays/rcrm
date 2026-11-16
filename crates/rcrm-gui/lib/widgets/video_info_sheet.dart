// widgets/video_info_sheet.dart
//
// The item menu's **Details** panel for a video: what this file is, in the same
// gallery-panel shape as the image viewer's sheet (drag handle, the file's name,
// a compact technical line, labelled rows, hairline rules).
//
// It says only what was established. The rows that come from the container
// (created time, author, software, device, location) appear when the Rust parser
// found them and are ABSENT when it did not — there is deliberately no "No
// container information" line and no skeleton standing in for one. The image
// sheet's absences are facts about a photo (a camera, a GPS fix) that a viewer
// asks about; a video's container metadata is a bonus, and a bonus that is not
// there needs no announcement.

import 'package:material_ui/material_ui.dart';

import '../config/theme.dart';
import '../models/media_item.dart';
import '../services/media_metadata.dart';
import '../utils/format.dart';
import 'info_rows.dart';

class VideoInfoSheet extends StatelessWidget {
  final MediaItem item;

  /// Track/container metadata, parsed on demand. Null = not requested.
  final Future<MediaMetadata>? metadata;

  const VideoInfoSheet({super.key, required this.item, this.metadata});

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        color: RCrmColors.ash,
        borderRadius: const BorderRadius.vertical(top: Radius.circular(14)),
        border: Border(top: BorderSide(color: RCrmColors.hairline)),
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
          // A failed or unfinished parse simply contributes no rows; the ones
          // the item already carries are drawn either way.
          builder: (_, snapshot) => _body(snapshot.data?.track),
        ),
      ),
    );
  }

  Widget _body(TrackInfo? track) {
    final technical = _technicalLine(track);
    final folder = _folderLabel();
    final createdAt = track?.createdAt;
    final device = [track?.make, track?.model]
        .whereType<String>()
        .where((s) => s.trim().isNotEmpty)
        .join(' ');
    final extraRows = <Widget>[
      if (createdAt != null)
        InfoRow(icon: Icons.event_outlined, label: 'Created', value: formatStamp(createdAt)),
      if (track?.author != null)
        InfoRow(icon: Icons.person_outline, label: 'Author', value: track!.author),
      if (track?.software != null)
        InfoRow(icon: Icons.memory, label: 'Software', value: track!.software),
      if (device.isNotEmpty)
        InfoRow(icon: Icons.devices_other, label: 'Device', value: device),
      if (track?.gpsIso6709 != null)
        InfoRow(icon: Icons.place_outlined, label: 'Location', value: track!.gpsIso6709),
    ];
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
                color: RCrmColors.textFaint,
                borderRadius: BorderRadius.circular(2),
              ),
            ),
          ),
          const SizedBox(height: RCrmSpacing.md),

          Text(
            item.name,
            style: TextStyle(
              color: RCrmColors.textPrimary,
              fontSize: 18,
              fontWeight: FontWeight.w600,
              height: 1.25,
            ),
            maxLines: 2,
            overflow: TextOverflow.ellipsis,
          ),
          if (technical.isNotEmpty) ...[
            const SizedBox(height: 8),
            Text(
              technical,
              style: TextStyle(
                color: RCrmColors.textSecondary,
                fontSize: 13,
                height: 1.4,
              ),
            ),
          ],
          const InfoRule(),

          InfoRow(icon: Icons.folder_outlined, label: folder),
          if (item.durationSeconds != null)
            InfoRow(
              icon: Icons.schedule,
              label: 'Duration',
              value: formatMs(item.durationSeconds! * 1000),
            ),
          if (item.modified != null)
            InfoRow(
              icon: Icons.update,
              label: 'Modified',
              value: formatStamp(item.modified!.toLocal()),
            ),
          if (extraRows.isNotEmpty) ...[
            const InfoRule(),
            ...extraRows,
          ],
        ],
      ),
    );
  }

  /// "1920 × 1080 (1080p) • 01:23 • 240 MB • MP4" — only what is actually known,
  /// in the order a viewer reads it: the picture, the length, the weight, the
  /// container.
  String _technicalLine(TrackInfo? track) {
    final parts = <String>[];
    final resolution = _resolution(track);
    if (resolution != null) parts.add(resolution);
    final durationMs = track?.durationMs;
    if (item.durationSeconds != null) {
      parts.add(formatMs(item.durationSeconds! * 1000));
    } else if (durationMs != null && durationMs > 0) {
      parts.add(formatMs(durationMs));
    }
    parts.add(item.formattedSize);
    // A dot-leading name (the encrypted on-disk form) makes `extension` the
    // whole name, so only a plausible token is shown.
    final ext = item.extension.toUpperCase();
    if (ext.isNotEmpty && ext.length <= 5) parts.add(ext);
    return parts.join(' • ');
  }

  String? _resolution(TrackInfo? track) {
    if (track?.width != null &&
        track?.height != null &&
        track!.width! > 0 &&
        track.height! > 0) {
      return resolutionLabel(track.width!, track.height!);
    }
    final raw = item.resolution;
    if (raw == null) return null;
    final m = RegExp(r'^(\d+)\s*[x×]\s*(\d+)$').firstMatch(raw.trim());
    if (m != null) {
      return resolutionLabel(int.parse(m[1]!), int.parse(m[2]!));
    }
    return raw;
  }

  String _folderLabel() {
    final path = item.path;
    final cut = path.lastIndexOf('/');
    if (cut <= 0) return '/';
    return path.substring(0, cut + 1);
  }
}
