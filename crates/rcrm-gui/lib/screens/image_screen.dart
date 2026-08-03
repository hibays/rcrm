// screens/image_screen.dart
// RCrm GUI — image browsing: album list → simple grid
//
// Albums show a 2x2 preview. Tapping an album opens a simple grid
// with extension badges (no network requests). Tapping an image
// opens the full viewer which loads the image on demand.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../models/album.dart';
import '../models/media_item.dart';
import '../providers/library_provider.dart';
import '../providers/settings_provider.dart';
import '../utils/natural_sort.dart';
import '../widgets/album_card.dart';
import '../widgets/image_grid.dart';
import '../widgets/column_button.dart';
import 'image_viewer_screen.dart';

/// Shared notifier so home_screen can navigate directly into a specific album.
class SelectedAlbumNotifier extends Notifier<Album?> {
  @override
  Album? build() => null;
  void select(Album a) => state = a;
  void clear() => state = null;
}

final selectedAlbumProvider = NotifierProvider<SelectedAlbumNotifier, Album?>(
  SelectedAlbumNotifier.new,
);

/// True while the image tab has an album sub-view open. home_screen reads this
/// instead of switching to the Home tab.
class ImageAlbumOpenNotifier extends Notifier<bool> {
  @override
  bool build() => false;

  /// Guarded so a late call (e.g. ImageScreen.dispose while the provider
  /// container is already being torn down at app exit) is a no-op instead of
  /// throwing UnmountedRefException.
  void setOpen(bool v) {
    if (ref.mounted) state = v;
  }
}

final imageAlbumOpenProvider = NotifierProvider<ImageAlbumOpenNotifier, bool>(
  ImageAlbumOpenNotifier.new,
);

/// Keyboard shortcut: Esc on the album view returns to the album list.
class _CloseAlbumIntent extends Intent {
  const _CloseAlbumIntent();
}

class ImageScreen extends ConsumerStatefulWidget {
  const ImageScreen({super.key});

  @override
  ConsumerState<ImageScreen> createState() => _ImageScreenState();
}

class _ImageScreenState extends ConsumerState<ImageScreen> {
  Album? _selectedAlbum;

  /// Tracks the last external selection we processed, to avoid double-selecting.
  Album? _lastExternal;

  // Captured in initState so dispose() can use it without touching `ref`
  // (Riverpod forbids `ref` access during/after unmount).
  late final ImageAlbumOpenNotifier _albumOpen;

  @override
  void initState() {
    super.initState();
    _albumOpen = ref.read(imageAlbumOpenProvider.notifier);
  }

  void _selectAlbum(Album? a) {
    setState(() => _selectedAlbum = a);
    _albumOpen.setOpen(a != null);
  }

  @override
  void dispose() {
    // Direct call is safe now: setOpen no-ops when the provider container is
    // already gone. (The old `Future(...)` wrapper left a pending timer in
    // tests and could hit an unmounted ref at app exit.)
    _albumOpen.setOpen(false);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final albums = ref.watch(albumsProvider);
    final uiSettings = ref.watch(uiSettingsProvider);

    // Handle external album selection from home_screen.
    final external = ref.watch(selectedAlbumProvider);
    if (external == null) {
      // Selection was consumed (or never set) — allow the same album to be
      // re-selected later. Without this, _lastExternal stays pinned to the
      // previous album and a repeat tap is ignored (lands on the list).
      _lastExternal = null;
    } else if (external != _lastExternal) {
      _lastExternal = external;
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted) {
          _selectAlbum(external);
          ref.read(selectedAlbumProvider.notifier).clear();
        }
      });
    }

    return PopScope(
      canPop: _selectedAlbum == null,
      onPopInvokedWithResult: (didPop, _) {
        if (!didPop && _selectedAlbum != null) {
          _selectAlbum(null);
        }
      },
      child: _selectedAlbum != null
          ? _buildAlbumView(_selectedAlbum!, uiSettings.imageLayout)
          : _buildAlbumList(context, albums),
    );
  }

  Widget _buildAlbumList(BuildContext context, List<Album> albums) {
    if (albums.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              Icons.photo_library_outlined,
              size: 64,
              color: Theme.of(
                context,
              ).colorScheme.primary.withValues(alpha: 0.5),
            ),
            const SizedBox(height: 16),
            Text(
              'No albums found',
              style: Theme.of(context).textTheme.titleLarge,
            ),
            const SizedBox(height: 8),
            Text(
              'Add folders with image files in Settings',
              style: Theme.of(context).textTheme.bodyMedium,
            ),
          ],
        ),
      );
    }

    final width = MediaQuery.of(context).size.width;
    final cols = width < 500
        ? 2
        : width < 800
        ? 3
        : width < 1100
        ? 4
        : 5;

    return GridView.builder(
      key: const PageStorageKey<String>('imageAlbums'),
      padding: const EdgeInsets.all(12),
      gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: cols,
        childAspectRatio: 0.85,
        crossAxisSpacing: 12,
        mainAxisSpacing: 12,
      ),
      itemCount: albums.length,
      addAutomaticKeepAlives: false,
      itemBuilder: (context, index) {
        return AlbumCard(
          album: albums[index],
          onTap: () => _selectAlbum(albums[index]),
        );
      },
    );
  }

  Widget _buildAlbumView(Album album, String layout) {
    final items = _sortImages(album.items);
    final storedCols = ref.watch(uiSettingsProvider).imageColumns;
    // Cap columns to screen width: min 100 px per image.
    final width = MediaQuery.of(context).size.width;
    final maxColsByWidth = (width / 100).floor().clamp(2, 8);
    final cols = storedCols.clamp(2, maxColsByWidth);
    return Shortcuts(
      shortcuts: {
        const SingleActivator(LogicalKeyboardKey.escape):
            const _CloseAlbumIntent(),
      },
      child: Actions(
        actions: {
          _CloseAlbumIntent: CallbackAction<_CloseAlbumIntent>(
            onInvoke: (_) {
              _selectAlbum(null);
              return null;
            },
          ),
        },
        child: Focus(
          autofocus: true,
          skipTraversal: true,
          child: Column(
            children: [
              // Header bar
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                color: Theme.of(context).colorScheme.surface,
                child: Row(
                  children: [
                    IconButton(
                      icon: const Icon(Icons.arrow_back, size: 20),
                      onPressed: () => _selectAlbum(null),
                      visualDensity: VisualDensity.compact,
                    ),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            album.name,
                            style: Theme.of(context).textTheme.titleMedium,
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                          ),
                          Text(
                            '${album.itemCount} images',
                            style: Theme.of(context).textTheme.bodySmall,
                          ),
                        ],
                      ),
                    ),
                    ColumnButton(
                      current: cols,
                      min: 2,
                      max: maxColsByWidth,
                      onChanged: (n) => ref
                          .read(uiSettingsProvider.notifier)
                          .setImageColumns(n),
                    ),
                    IconButton(
                      icon: Icon(
                        layout == 'masonry'
                            ? Icons.grid_on
                            : Icons.dashboard_customize,
                        size: 20,
                      ),
                      onPressed: () {
                        ref
                            .read(uiSettingsProvider.notifier)
                            .setImageLayout(
                              layout == 'masonry' ? 'uniform' : 'masonry',
                            );
                      },
                      visualDensity: VisualDensity.compact,
                      tooltip: layout == 'masonry' ? 'Uniform' : 'Masonry',
                    ),
                  ],
                ),
              ),
              Expanded(
                child: ImageGrid(
                  items: items,
                  layout: layout,
                  crossAxisCount: cols,
                  onTap: (item) => _openViewer(items, items.indexOf(item)),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  // Memoization keyed by (sort field, ascending, item count, album url).
  // Uses url (unique per album) rather than name, which can collide.
  // Avoids identityHashCode: it can be reused across GC for different List
  // instances and stays identical when a list is re-scanned in place.
  String? _lastSortKey;
  List<MediaItem>? _lastSorted;

  List<MediaItem> _sortImages(List<MediaItem> items) {
    final uiSettings = ref.read(uiSettingsProvider);
    final key =
        '${uiSettings.imageSort}|${uiSettings.imageSortAsc}|${items.length}|${_selectedAlbum?.url ?? ''}';
    if (_lastSortKey == key && _lastSorted != null) return _lastSorted!;
    _lastSortKey = key;
    var sorted = List<MediaItem>.from(items);
    switch (uiSettings.imageSort) {
      case 'name':
        sorted.sort((a, b) => naturalCompare(a.name, b.name));
      case 'date':
        sorted.sort(
          (a, b) => (a.modified ?? DateTime(2000)).compareTo(
            b.modified ?? DateTime(2000),
          ),
        );
      case 'size':
        sorted.sort((a, b) => a.size.compareTo(b.size));
    }
    if (!uiSettings.imageSortAsc) sorted = sorted.reversed.toList();
    _lastSorted = sorted;
    return sorted;
  }

  void _openViewer(List<MediaItem> items, int initialIndex) {
    Navigator.push(
      context,
      PageRouteBuilder(
        opaque: false,
        transitionDuration: const Duration(milliseconds: 130),
        reverseTransitionDuration: const Duration(milliseconds: 180),
        pageBuilder: (_, _, _) =>
            ImageViewerScreen(items: items, initialIndex: initialIndex),
        transitionsBuilder: (_, a, _, child) =>
            FadeTransition(opacity: a, child: child),
      ),
    );
  }
}
