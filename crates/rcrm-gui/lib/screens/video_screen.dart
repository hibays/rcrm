// screens/video_screen.dart
// Video browsing screen (grid/list). Mobile: finger-touch preview.

import 'package:flutter/material.dart';
import 'dart:io' show Platform;
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../models/media_item.dart';
import '../providers/library_provider.dart';
import '../providers/settings_provider.dart';
import '../widgets/media_toolbar.dart';
import '../widgets/video_card.dart';
import '../widgets/finger_preview_listener.dart';
import 'video_player_screen.dart';

class VideoScreen extends ConsumerWidget {
  const VideoScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final videos = ref.watch(sortedVideosProvider);
    final columns = ref.watch(videoGridColumnsProvider);
    final sort = ref.watch(videoSortProvider);
    final asc = ref.watch(videoSortAscProvider);
    final extensions = ref.watch(videoExtensionsProvider);
    final filter = ref.watch(videoFilterProvider);
    final uiSettings = ref.watch(uiSettingsProvider);
    final isGrid = uiSettings.videoLayout == 'grid';
    // Calculate max columns from available width (min 160 px per card).
    // This adapts naturally to portrait/landscape rotation on mobile
    // instead of a single hard 600 px cutoff.
    final width = MediaQuery.of(context).size.width;
    const minCardWidth = 160;
    final maxByWidth = (width / minCardWidth).floor().clamp(1, 6);
    final isMobile = Platform.isAndroid || Platform.isIOS;
    final colMin = isMobile ? 1 : (maxByWidth < 2 ? 1 : 2);
    final colMax = maxByWidth;
    final effectiveColumns = columns.clamp(colMin, colMax);

    return Column(
      children: [
        MediaToolbar(
          sortOptions: const ['name', 'date', 'size', 'duration'],
          currentSort: sort,
          isAscending: asc,
          onSortChanged: (s) => ref.read(videoSortProvider.notifier).set(s),
          extensions: extensions.toList(),
          currentFilter: filter,
          onFilterChanged: (f) => ref.read(videoFilterProvider.notifier).set(f),
          onColumnsChanged: isGrid
              ? (c) => ref.read(videoGridColumnsProvider.notifier).set(c)
              : null,
          currentColumns: isGrid ? effectiveColumns : null,
          minColumns: colMin,
          maxColumns: colMax,
          isGrid: isGrid,
          onLayoutToggle: () => ref
              .read(uiSettingsProvider.notifier)
              .setVideoLayout(isGrid ? 'list' : 'grid'),
        ),
        Expanded(
          child: _VideoGrid(
            videos: videos,
            columns: effectiveColumns,
            isGrid: isGrid,
            onOpen: (item) {
              Future.microtask(() {
                if (context.mounted) {
                  Navigator.push(
                    context,
                    MaterialPageRoute(
                      builder: (_) => VideoPlayerScreen(item: item),
                    ),
                  );
                }
              });
            },
          ),
        ),
      ],
    );
  }
}

class _VideoGrid extends StatefulWidget {
  final List<MediaItem> videos;
  final int columns;
  final bool isGrid;
  final void Function(MediaItem) onOpen;
  const _VideoGrid({
    required this.videos,
    required this.columns,
    required this.isGrid,
    required this.onOpen,
  });
  @override
  State<_VideoGrid> createState() => _VideoGridState();
}

class _VideoGridState extends State<_VideoGrid> {
  final _fp = FingerPreviewState();

  @override
  Widget build(BuildContext c) {
    final videos = widget.videos;
    if (videos.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              Icons.videocam_off,
              size: 64,
              color: Theme.of(c).colorScheme.primary.withValues(alpha: 0.5),
            ),
            const SizedBox(height: 16),
            Text('No videos found', style: Theme.of(c).textTheme.titleLarge),
            const SizedBox(height: 8),
            Text(
              'Add folders with video files in Settings',
              style: Theme.of(c).textTheme.bodyMedium,
            ),
          ],
        ),
      );
    }

    final child = widget.isGrid ? _grid(c, videos) : _list(c, videos);
    if (!FingerPreviewState.isMobile) return child;
    return Listener(
      onPointerDown: (e) => _fp.onPointerDown(e, setState),
      child: child,
    );
  }

  Widget _grid(BuildContext c, List<MediaItem> videos) {
    final cols = widget.columns;
    return LayoutBuilder(
      builder: (_, constraints) {
        final cardWidth = (constraints.maxWidth - 16) / cols - 8;
        final cardHeight = cardWidth / 16 * 9 + 60;
        return GridView.builder(
          padding: const EdgeInsets.all(8),
          gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
            crossAxisCount: cols,
            childAspectRatio: cardWidth / cardHeight,
            crossAxisSpacing: 8,
            mainAxisSpacing: 8,
          ),
          itemCount: videos.length,
          addRepaintBoundaries: true,
          itemBuilder: (_, i) {
            final v = videos[i];
            return VideoCard(
              key: FingerPreviewState.isMobile ? _fp.keyFor(v.path) : null,
              item: v,
              preview: _fp.isActive(v.path),
              onTap: () => widget.onOpen(v),
            );
          },
        );
      },
    );
  }

  Widget _list(BuildContext c, List<MediaItem> videos) {
    return ListView.builder(
      padding: const EdgeInsets.all(8),
      itemCount: videos.length,
      addRepaintBoundaries: true,
      itemBuilder: (_, i) {
        final v = videos[i];
        return Padding(
          padding: const EdgeInsets.only(bottom: 8),
          child: SizedBox(
            height: 100,
            child: Row(
              children: [
                Expanded(
                  flex: 2,
                  child: VideoCard(
                    key: _fp.keyFor(v.path),
                    item: v,
                    preview: _fp.isActive(v.path),
                    compact: true,
                    onTap: () => widget.onOpen(v),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  flex: 3,
                  child: GestureDetector(
                    behavior: HitTestBehavior.opaque,
                    onTap: () => widget.onOpen(v),
                    child: _listInfo(c, v),
                  ),
                ),
              ],
            ),
          ),
        );
      },
    );
  }

  Widget _listInfo(BuildContext c, MediaItem item) => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    mainAxisAlignment: MainAxisAlignment.center,
    children: [
      Text(
        item.name,
        maxLines: 2,
        overflow: TextOverflow.ellipsis,
        style: Theme.of(c).textTheme.titleMedium,
      ),
      const SizedBox(height: 4),
      if (item.durationSeconds != null)
        Text(item.formattedDuration, style: Theme.of(c).textTheme.bodyMedium),
      const SizedBox(height: 2),
      Text(
        '${item.formattedSize} • ${item.extension.toUpperCase()}',
        style: Theme.of(c).textTheme.bodyMedium,
      ),
    ],
  );
}
