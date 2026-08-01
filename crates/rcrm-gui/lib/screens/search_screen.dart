// screens/search_screen.dart
// RCrm GUI — full-screen search as a regular route (not SearchDelegate),
// so nested navigation works: tap result → player → back returns to search.
//
// Video cards match the home screen's Recent Videos proportions (280×180).

import 'dart:io' show Platform;
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../models/album.dart';
import '../models/media_item.dart';
import '../providers/library_provider.dart';
import '../widgets/album_card.dart';
import '../widgets/image_card.dart';
import '../widgets/video_card.dart';
import 'image_screen.dart'; // selectedAlbumProvider
import 'image_viewer_screen.dart';
import 'video_player_screen.dart';

class SearchScreen extends ConsumerStatefulWidget {
  final MediaType? tabFilter;

  const SearchScreen({super.key, this.tabFilter});

  @override
  ConsumerState<SearchScreen> createState() => _SearchScreenState();
}

class _SearchScreenState extends ConsumerState<SearchScreen> {
  final _controller = TextEditingController();
  final _focusNode = FocusNode();
  final _isGrid = ValueNotifier<bool>(true);
  String _query = '';

  @override
  void initState() {
    super.initState();
    _controller.addListener(_onQueryChanged);
    // Auto-focus after first frame so the keyboard opens.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) _focusNode.requestFocus();
    });
  }

  @override
  void dispose() {
    _controller.removeListener(_onQueryChanged);
    _controller.dispose();
    _focusNode.dispose();
    _isGrid.dispose();
    super.dispose();
  }

  void _onQueryChanged() {
    setState(() => _query = _controller.text);
  }

  void _clear() {
    _controller.clear();
  }

  // ── Navigation ─────────────────────────────────────────

  void _openVideo(MediaItem item) {
    Future.microtask(() {
      if (mounted) {
        Navigator.of(context).push(
          MaterialPageRoute(builder: (_) => VideoPlayerScreen(item: item)),
        );
      }
    });
  }

  void _openImage(List<MediaItem> images, int index) {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => ImageViewerScreen(items: images, initialIndex: index),
      ),
    );
  }

  void _openAlbum(Album album) {
    ref.read(selectedAlbumProvider.notifier).select(album);
    // Pop back to home — the image tab will pick up the selection.
    Navigator.of(context).pop();
  }

  // ── Build ──────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    final scanState = ref.watch(scanStateProvider);
    final videos = ref.watch(videosListProvider);
    final albums = ref.watch(albumsProvider);
    final q = _query.toLowerCase().trim();
    final isMobile = Platform.isAndroid || Platform.isIOS;

    return PopScope(
      canPop: true,
      child: Scaffold(
        appBar: AppBar(
          backgroundColor: const Color(0xFF1A1A1A),
          foregroundColor: Colors.white,
          elevation: 0,
          leading: IconButton(
            icon: const Icon(Icons.arrow_back),
            onPressed: () => Navigator.pop(context),
          ),
          title: TextField(
            controller: _controller,
            focusNode: _focusNode,
            style: const TextStyle(color: Colors.white),
            decoration: const InputDecoration(
              hintText: 'Search name or type (mp4, jpg...)',
              hintStyle: TextStyle(color: Color(0xFFAAAAAA)),
              border: InputBorder.none,
            ),
          ),
          actions: [
            if (q.isNotEmpty)
              IconButton(
                icon: const Icon(Icons.clear),
                onPressed: _clear,
                tooltip: 'Clear',
              ),
          ],
        ),
        body: _buildBody(context, videos, albums, scanState, q, isMobile),
      ),
    );
  }

  Widget _buildBody(
    BuildContext context,
    List<MediaItem> allVideos,
    List<Album> albums,
    ScanState scanState,
    String q,
    bool isMobile,
  ) {
    if (scanState.isLoading && allVideos.isEmpty) {
      return const Center(child: CircularProgressIndicator());
    }

    if (q.isEmpty) return _buildEmptyQuery(context, allVideos, albums);

    // ── Filter by tab context ──────────────────────────

    final List<MediaItem> videos;
    if (widget.tabFilter == MediaType.image) {
      videos = [];
    } else {
      videos = allVideos
          .where(
            (v) =>
                _fuzzyMatch(q, v.name) ||
                _fuzzyMatch(q, v.extension) ||
                _fuzzyMatch(q, v.albumName),
          )
          .toList();
    }

    final List<MediaItem> images;
    final List<Album> matchedAlbums;
    if (widget.tabFilter == MediaType.video) {
      images = [];
      matchedAlbums = [];
    } else {
      images = _matchingImages(albums, q);
      matchedAlbums = _matchingAlbums(albums, q);
    }
    final total = videos.length + images.length + matchedAlbums.length;

    if (total == 0) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(
                Icons.search_off,
                size: 64,
                color: Theme.of(
                  context,
                ).colorScheme.primary.withValues(alpha: 0.4),
              ),
              const SizedBox(height: 16),
              Text(
                'No results for "$q"',
                style: Theme.of(context).textTheme.titleLarge,
              ),
              const SizedBox(height: 8),
              Text(
                'Try a different file name or extension (mp4, jpg, avif)',
                style: Theme.of(context).textTheme.bodyMedium,
              ),
              const SizedBox(height: 24),
              TextButton.icon(
                onPressed: _clear,
                icon: const Icon(Icons.close, size: 16),
                label: const Text('Clear search'),
              ),
            ],
          ),
        ),
      );
    }

    return ValueListenableBuilder<bool>(
      valueListenable: _isGrid,
      builder: (context, isGrid, _) {
        final width = MediaQuery.of(context).size.width;
        final videoCols = (width / 250).floor().clamp(2, 5);
        final imageCols = (width / 140).floor().clamp(2, 6);
        const gridPad = 24.0; // 12+12 horizontal
        const gap = 8.0;
        final videoCardW =
            (width - gridPad - gap * (videoCols - 1)) / videoCols;
        final videoAR = videoCardW / (videoCardW * 9 / 16 + 60);
        final imageAR = 1.0;

        return CustomScrollView(
          keyboardDismissBehavior: ScrollViewKeyboardDismissBehavior.onDrag,
          slivers: [
            // Header
            SliverToBoxAdapter(
              child: Padding(
                padding: const EdgeInsets.fromLTRB(16, 12, 4, 8),
                child: Row(
                  children: [
                    Text(
                      total == 1 ? '1 result' : '$total results',
                      style: Theme.of(context).textTheme.titleMedium?.copyWith(
                        color: Colors.white,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    const SizedBox(width: 8),
                    Text(
                      '"$_query"',
                      style: Theme.of(context).textTheme.titleMedium?.copyWith(
                        color: Theme.of(context).colorScheme.primary,
                      ),
                    ),
                    const Spacer(),
                    IconButton(
                      icon: Icon(
                        isGrid ? Icons.view_list : Icons.grid_view,
                        size: 20,
                      ),
                      tooltip: isGrid ? 'List view' : 'Grid view',
                      onPressed: () => _isGrid.value = !_isGrid.value,
                    ),
                  ],
                ),
              ),
            ),

            // ── Albums ────────────────────────────
            if (matchedAlbums.isNotEmpty) ...[
              SliverToBoxAdapter(
                child: Padding(
                  padding: const EdgeInsets.fromLTRB(16, 8, 16, 8),
                  child: _sectionHeader(
                    context,
                    'Albums (${matchedAlbums.length})',
                    Icons.folder,
                  ),
                ),
              ),
              SliverPadding(
                padding: const EdgeInsets.symmetric(horizontal: 12),
                sliver: SliverGrid(
                  gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
                    crossAxisCount: (width / 200).floor().clamp(2, 4),
                    childAspectRatio: 0.75,
                    crossAxisSpacing: 8,
                    mainAxisSpacing: 8,
                  ),
                  delegate: SliverChildBuilderDelegate(
                    (_, index) => AlbumCard(
                      album: matchedAlbums[index],
                      onTap: () => _openAlbum(matchedAlbums[index]),
                    ),
                    childCount: matchedAlbums.length,
                  ),
                ),
              ),
            ],

            // ── Videos ────────────────────────────
            if (videos.isNotEmpty) ...[
              SliverToBoxAdapter(
                child: Padding(
                  padding: const EdgeInsets.fromLTRB(16, 8, 16, 8),
                  child: _sectionHeader(
                    context,
                    'Videos (${videos.length})',
                    Icons.videocam,
                  ),
                ),
              ),
              if (isGrid)
                _buildVideoGrid(context, videos, videoCols, videoAR)
              else
                _buildVideoList(context, videos, isMobile),
            ],

            // ── Images ────────────────────────────
            if (images.isNotEmpty) ...[
              SliverToBoxAdapter(
                child: Padding(
                  padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
                  child: _sectionHeader(
                    context,
                    'Images (${images.length})',
                    Icons.image,
                  ),
                ),
              ),
              if (isGrid)
                _buildImageGrid(context, images, imageCols, imageAR)
              else
                _buildImageList(context, images),
            ],
            const SliverToBoxAdapter(child: SizedBox(height: 32)),
          ],
        );
      },
    );
  }

  // ── Grid ───────────────────────────────────────────────

  Widget _buildVideoGrid(
    BuildContext context,
    List<MediaItem> videos,
    int cols,
    double ar,
  ) {
    return SliverPadding(
      padding: const EdgeInsets.symmetric(horizontal: 12),
      sliver: SliverGrid(
        gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
          crossAxisCount: cols,
          childAspectRatio: ar,
          crossAxisSpacing: 8,
          mainAxisSpacing: 8,
        ),
        delegate: SliverChildBuilderDelegate(
          (ctx, index) => VideoCard(
            key: ValueKey(videos[index].url),
            item: videos[index],
            onTap: () => _openVideo(videos[index]),
          ),
          childCount: videos.length,
        ),
      ),
    );
  }

  Widget _buildImageGrid(
    BuildContext context,
    List<MediaItem> images,
    int cols,
    double ar,
  ) {
    return SliverPadding(
      padding: const EdgeInsets.symmetric(horizontal: 12),
      sliver: SliverGrid(
        gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
          crossAxisCount: cols,
          childAspectRatio: ar,
          crossAxisSpacing: 8,
          mainAxisSpacing: 8,
        ),
        delegate: SliverChildBuilderDelegate(
          (ctx, index) => ImageCard(
            key: ValueKey(images[index].url),
            item: images[index],
            onTap: () => _openImage(images, index),
          ),
          childCount: images.length,
        ),
      ),
    );
  }

  // ── List ───────────────────────────────────────────────

  Widget _buildVideoList(
    BuildContext context,
    List<MediaItem> videos,
    bool isMobile,
  ) {
    return SliverList(
      delegate: SliverChildBuilderDelegate((ctx, index) {
        final item = videos[index];
        return Padding(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
          child: SizedBox(
            height: 140,
            child: Row(
              children: [
                SizedBox(
                  width: 200,
                  child: VideoCard(
                    key: ValueKey(item.url),
                    item: item,
                    compact: true,
                    onTap: () => _openVideo(item),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: GestureDetector(
                    behavior: HitTestBehavior.opaque,
                    onTap: () => _openVideo(item),
                    child: _listInfo(context, item),
                  ),
                ),
              ],
            ),
          ),
        );
      }, childCount: videos.length),
    );
  }

  Widget _buildImageList(BuildContext context, List<MediaItem> images) {
    return SliverList(
      delegate: SliverChildBuilderDelegate((ctx, index) {
        final img = images[index];
        return Padding(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
          child: SizedBox(
            height: 90,
            child: Row(
              children: [
                SizedBox(
                  width: 80,
                  child: ClipRRect(
                    borderRadius: BorderRadius.circular(6),
                    child: ImageCard(
                      key: ValueKey(img.url),
                      item: img,
                      onTap: () => _openImage(images, index),
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: GestureDetector(
                    behavior: HitTestBehavior.opaque,
                    onTap: () => _openImage(images, index),
                    child: _listInfo(context, img),
                  ),
                ),
              ],
            ),
          ),
        );
      }, childCount: images.length),
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

  // ── Helpers ────────────────────────────────────────────

  /// Match albums whose name fuzzy-matches the query.
  List<Album> _matchingAlbums(List<Album> albums, String q) {
    return albums.where((a) => _fuzzyMatch(q, a.name)).toList();
  }

  List<MediaItem> _matchingImages(List<Album> albums, String q) {
    final images = <MediaItem>[];
    for (final album in albums) {
      for (final item in album.items) {
        if (_fuzzyMatch(q, item.name) ||
            _fuzzyMatch(q, item.extension) ||
            _fuzzyMatch(q, album.name)) {
          images.add(item);
        }
      }
    }
    return images;
  }

  /// Subsequence match: query characters must appear in order in [target].
  /// "brkn" matches "Breaking Bad", "mp4" matches "Movie.MP4".
  static bool _fuzzyMatch(String query, String target) {
    if (query.isEmpty) return true;
    var qi = 0;
    final qLen = query.length;
    final tLen = target.length;
    for (var i = 0; i < tLen && qi < qLen; i++) {
      if (target[i].toLowerCase() == query[qi]) qi++;
    }
    return qi == qLen;
  }

  Widget _buildEmptyQuery(
    BuildContext context,
    List<MediaItem> videos,
    List<Album> albums,
  ) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              Icons.search,
              size: 56,
              color: Theme.of(
                context,
              ).colorScheme.primary.withValues(alpha: 0.3),
            ),
            const SizedBox(height: 16),
            Text(
              'Search your library',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            Text(
              '${videos.length} videos, ${albums.length} albums',
              style: Theme.of(context).textTheme.bodySmall,
            ),
            const SizedBox(height: 20),
            Text(
              'Start typing a file name or extension\ne.g. mkv, avif, jpg',
              style: Theme.of(
                context,
              ).textTheme.bodySmall?.copyWith(height: 1.5),
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
    );
  }

  Widget _sectionHeader(BuildContext context, String title, IconData icon) {
    return Row(
      children: [
        Icon(icon, size: 18, color: Theme.of(context).colorScheme.primary),
        const SizedBox(width: 8),
        Text(
          title,
          style: Theme.of(context).textTheme.titleSmall?.copyWith(
            color: Theme.of(context).colorScheme.primary,
          ),
        ),
      ],
    );
  }
}
