// screens/home_screen.dart
// RCrm GUI — main shell with bottom navigation (Home / Videos / Images)
//
// Hosts three tab views: Home (recommendations + doctor), Videos (grid),
// and Images (albums). Each tab manages its own scanning and state.

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../models/media_item.dart';
import '../models/album.dart';
import '../providers/library_provider.dart';
import '../providers/server_provider.dart';
import '../widgets/doctor_panel.dart';
import '../widgets/album_preview.dart';
import '../widgets/video_card.dart';
import '../widgets/finger_preview_listener.dart';
import '../services/preview_player.dart';
import 'video_player_screen.dart';
import 'search_screen.dart';
import 'video_screen.dart';
import 'image_screen.dart';

class HomeScreen extends ConsumerStatefulWidget {
  const HomeScreen({super.key});

  @override
  ConsumerState<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends ConsumerState<HomeScreen> {
  int _currentIndex = 0;
  bool _isRefreshing = false;
  final _fp = FingerPreviewState();
  bool _fromHomeChip = false;

  final List<String> _titles = const ['RCrm', 'Videos', 'Images'];

  @override
  void initState() {
    super.initState();
    // warmUp creates a Player — defer to postFrame so the widget tree
    // renders even if media_kit native libs fail to load (Android .so arch
    // mismatch, missing codecs, etc.). Without this guard the exception
    // propagates from initState and Flutter shows a blank error page.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      try {
        PreviewPlayer.instance.warmUp();
      } catch (_) {
        // MediaKit unavailable on this device — preview features degrade
        // gracefully (cards show no hover preview, but everything else works).
      }
      _scanLibrary();
    });
  }

  Future<void> _scanLibrary() async {
    final lib = ref.read(mediaLibraryProvider);
    if (lib == null) return;
    if (mounted) setState(() => _isRefreshing = true);
    try {
      await ref.read(scanStateProvider.notifier).scan(lib);
    } catch (_) {}
    if (mounted) setState(() => _isRefreshing = false);
  }

  @override
  Widget build(BuildContext context) {
    final daySeed =
        DateTime.now().millisecondsSinceEpoch ~/ Duration.millisecondsPerDay;
    final scanState = ref.watch(scanStateProvider);
    final recommended = ref.watch(recommendedProvider(daySeed));
    final allRecent = ref.watch(recentVideosProvider);
    // Exclude already-shown recommended items to avoid visual overlap.
    final recentVideos = recommended.isNotEmpty
        ? allRecent.where((v) => !recommended.contains(v)).toList()
        : allRecent;
    final albums = ref.watch(albumsProvider);

    // When an album entered from a home chip is closed, return to home tab.
    ref.listen(imageAlbumOpenProvider, (prev, next) {
      if (prev == true && next == false && _fromHomeChip) {
        _fromHomeChip = false;
        if (_currentIndex == 2) setState(() => _currentIndex = 0);
      }
    });

    // Auto re-scan when server (re)starts while already mounted.
    ref.listen(serverProvider, (prev, next) {
      if (next.isRunning && !(prev?.isRunning ?? false)) _scanLibrary();
    });

    return PopScope(
      canPop: _currentIndex == 0,
      onPopInvokedWithResult: (didPop, _) {
        if (didPop) return;
        // When the image tab has an album open, let ImageScreen's own PopScope
        // close it (back → album list) instead of jumping to the Home tab.
        if (_currentIndex == 2 && ref.read(imageAlbumOpenProvider)) return;
        if (_currentIndex != 0) setState(() => _currentIndex = 0);
      },
      child: Scaffold(
        appBar: AppBar(
          title: Text(_titles[_currentIndex]),
          actions: [
            IconButton(
              icon: const Icon(Icons.search),
              onPressed: () => Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (_) => SearchScreen(
                    tabFilter: _currentIndex == 0
                        ? null
                        : _currentIndex == 1
                        ? MediaType.video
                        : MediaType.image,
                  ),
                ),
              ),
              tooltip: 'Search',
            ),
            IconButton(
              icon: _isRefreshing
                  ? const SizedBox(
                      width: 18,
                      height: 18,
                      child: CircularProgressIndicator(
                        strokeWidth: 2,
                        color: Colors.white54,
                      ),
                    )
                  : const Icon(Icons.refresh),
              onPressed: _isRefreshing ? null : _scanLibrary,
              tooltip: 'Refresh library',
            ),
            IconButton(
              icon: const Icon(Icons.settings),
              onPressed: () => Navigator.pushNamed(context, '/settings'),
            ),
          ],
        ),
        body: IndexedStack(
          index: _currentIndex,
          children: [
            // Tab 0: Home
            _buildHomeTab(scanState, recommended, recentVideos, albums),
            // Tab 1: Videos
            const VideoScreen(),
            // Tab 2: Images
            const ImageScreen(),
          ],
        ),
        bottomNavigationBar: BottomNavigationBar(
          currentIndex: _currentIndex,
          onTap: (index) => setState(() => _currentIndex = index),
          items: const [
            BottomNavigationBarItem(icon: Icon(Icons.home), label: 'Home'),
            BottomNavigationBarItem(
              icon: Icon(Icons.videocam),
              label: 'Videos',
            ),
            BottomNavigationBarItem(
              icon: Icon(Icons.photo_library),
              label: 'Images',
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildHomeTab(
    ScanState scanState,
    List<MediaItem> recommended,
    List<MediaItem> recentVideos,
    List<Album> albums,
  ) {
    if (scanState.isLoading && !scanState.hasCompletedOnce) {
      return const Center(child: CircularProgressIndicator());
    }
    if (scanState.error != null) {
      return _buildError(scanState.error!);
    }

    return FingerPreviewState.isMobile
        ? Listener(
            onPointerDown: (e) => _fp.onPointerDown(e, setState),
            child: _scrollContent(recommended, recentVideos, albums, scanState),
          )
        : _scrollContent(recommended, recentVideos, albums, scanState);
  }

  Widget _scrollContent(
    List<MediaItem> recommended,
    List<MediaItem> recentVideos,
    List<Album> albums,
    ScanState scanState,
  ) {
    // Mobile landscape has very limited vertical space (~400 px);
    // scale down horizontal row heights so all sections fit.
    final double rowScale =
        (FingerPreviewState.isMobile &&
            MediaQuery.of(context).orientation == Orientation.landscape)
        ? 0.68
        : 1.0;
    return RefreshIndicator(
      onRefresh: _scanLibrary,
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // ── Doctor panel ──────────────────────
          const DoctorPanel(),
          const SizedBox(height: 24),

          // ── Featured / Recommended section ────
          if (recommended.isNotEmpty) ...[
            _sectionHeader(context, 'Recommended', Icons.star),
            const SizedBox(height: 12),
            SizedBox(
              height: 220 * rowScale,
              child: ListView.builder(
                scrollDirection: Axis.horizontal,
                itemExtent: 332 * rowScale,
                itemCount: recommended.length,
                itemBuilder: (context, index) {
                  return Padding(
                    padding: const EdgeInsets.only(right: 12),
                    child: SizedBox(
                      width: 320 * rowScale,
                      child: VideoCard(
                        key: FingerPreviewState.isMobile
                            ? _fp.keyFor(recommended[index].path)
                            : ValueKey(recommended[index].url),
                        item: recommended[index],
                        preview: _fp.isActive(recommended[index].path),
                        onTap: () => _openVideo(recommended[index]),
                      ),
                    ),
                  );
                },
              ),
            ),
            SizedBox(height: 24 * rowScale),
          ],

          // ── Recent videos quick access ───────
          if (recentVideos.isNotEmpty) ...[
            _sectionHeader(
              context,
              'Recent Videos',
              Icons.videocam,
              onViewAll: () => setState(() => _currentIndex = 1),
            ),
            const SizedBox(height: 12),
            SizedBox(
              height: 180 * rowScale,
              child: ListView.builder(
                itemExtent: 292 * rowScale,
                scrollDirection: Axis.horizontal,
                itemCount: recentVideos.take(20).length,
                itemBuilder: (context, index) {
                  final item = recentVideos[index];
                  return Padding(
                    padding: const EdgeInsets.only(right: 12),
                    child: SizedBox(
                      width: 280 * rowScale,
                      child: VideoCard(
                        key: FingerPreviewState.isMobile
                            ? _fp.keyFor('recent:${item.path}')
                            : ValueKey(item.url),
                        item: item,
                        preview: _fp.isActive('recent:${item.path}'),
                        onTap: () => _openVideo(item),
                      ),
                    ),
                  );
                },
              ),
            ),
          ],

          // ── Albums quick access ──────────────
          if (albums.isNotEmpty) ...[
            SizedBox(height: 24 * rowScale),
            _sectionHeader(
              context,
              'Photo Albums',
              Icons.photo_library,
              onViewAll: () => setState(() => _currentIndex = 2),
            ),
            const SizedBox(height: 12),
            SizedBox(
              height: 165 * rowScale,
              child: ListView.builder(
                scrollDirection: Axis.horizontal,
                itemCount: albums.length,
                itemBuilder: (context, index) {
                  final album = albums[index];
                  return Padding(
                    padding: const EdgeInsets.only(right: 12),
                    child: _albumChip(context, album),
                  );
                },
              ),
            ),
          ],

          // ── Empty state ──────────────────────
          if (recentVideos.isEmpty &&
              albums.isEmpty &&
              (!scanState.isLoading || scanState.hasCompletedOnce))
            _buildEmptyState(context),

          const SizedBox(height: 32),
        ],
      ),
    );
  }

  Widget _sectionHeader(
    BuildContext context,
    String title,
    IconData icon, {
    VoidCallback? onViewAll,
  }) {
    return Row(
      children: [
        Icon(icon, size: 20, color: Theme.of(context).colorScheme.primary),
        const SizedBox(width: 8),
        Text(title, style: Theme.of(context).textTheme.titleLarge),
        const Spacer(),
        if (onViewAll != null)
          TextButton(onPressed: onViewAll, child: const Text('View all')),
      ],
    );
  }

  Widget _albumChip(BuildContext context, album) {
    return GestureDetector(
      onTap: () {
        _fromHomeChip = true;
        ref.read(selectedAlbumProvider.notifier).select(album);
        setState(() => _currentIndex = 2);
      },
      child: Container(
        width: 140,
        decoration: BoxDecoration(
          color: Theme.of(context).colorScheme.surface,
          borderRadius: BorderRadius.circular(12),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Expanded(
              // RepaintBoundary isolates the clipped album preview so
              // the parent column does not repaint on every scroll frame.
              child: RepaintBoundary(
                child: ClipRRect(
                  borderRadius: const BorderRadius.vertical(
                    top: Radius.circular(12),
                  ),
                  child: AlbumPreview(urls: album.coverPreviewUrls),
                ),
              ),
            ),
            Padding(
              padding: const EdgeInsets.all(8),
              child: Text(
                album.name,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: Theme.of(context).textTheme.bodyMedium,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildError(String error) {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const Icon(Icons.error_outline, size: 48, color: Colors.red),
          const SizedBox(height: 16),
          Text(error, textAlign: TextAlign.center),
        ],
      ),
    );
  }

  Widget _buildEmptyState(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              Icons.folder_open,
              size: 64,
              color: Theme.of(
                context,
              ).colorScheme.primary.withValues(alpha: 0.5),
            ),
            const SizedBox(height: 16),
            Text(
              'No media found',
              style: Theme.of(context).textTheme.titleLarge,
            ),
            const SizedBox(height: 8),
            Text(
              'Add folders with media files in Settings',
              style: Theme.of(context).textTheme.bodyMedium,
            ),
          ],
        ),
      ),
    );
  }

  void _openVideo(MediaItem item) {
    Future.microtask(() {
      if (mounted) {
        Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => VideoPlayerScreen(item: item)),
        );
      }
    });
  }

  // ── Thumbnail diagnostics (temporary) ────────────────────
}
