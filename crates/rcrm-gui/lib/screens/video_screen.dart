// screens/video_screen.dart
// Video browsing. Two arrangements of the same list:
//
//  * the FLAT grid/list of every video — the default, and what this screen has
//    always shown; and
//  * the FOLDER view, which mirrors the photo tab's albums: a grid of folders
//    with 2×2 poster previews, opened into that folder's videos.
//
// Which one is in effect is a persisted setting (`videoClassification`, default
// 'none' = flat) committed from the toolbar's organize menu. The folders are
// derived from the scanned list (`videoFoldersProvider`), not stored, so
// switching arrangements costs no re-scan.
//
// Mobile: finger-touch preview.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'dart:io' show Platform;
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../models/album.dart';
import '../models/media_item.dart';
import '../providers/library_provider.dart';
import '../providers/settings_provider.dart';
import '../widgets/media_toolbar.dart';
import '../widgets/video_card.dart';
import '../widgets/video_folder_card.dart';
import '../widgets/finger_preview_listener.dart';
import '../utils/poster_quiet_route.dart';
import 'video_player_screen.dart';

/// Keyboard shortcut: Esc on a folder view returns to the folder list. The photo
/// tab's album view answers Esc the same way.
class _CloseFolderIntent extends Intent {
  const _CloseFolderIntent();
}

/// True while the video tab has a folder sub-view open. home_screen reads this
/// instead of switching to the Home tab — the flag is what lets the system back
/// key close the folder first, exactly as it closes an open album on the photo
/// tab (`image_screen.dart`'s `ImageAlbumOpenNotifier` is the same thing over
/// there).
class VideoFolderOpenNotifier extends Notifier<bool> {
  @override
  bool build() => false;

  /// Guarded so a late call (e.g. dispose while the provider container is
  /// already being torn down at app exit) is a no-op instead of throwing.
  void setOpen(bool v) {
    if (ref.mounted) state = v;
  }
}

final videoFolderOpenProvider = NotifierProvider<VideoFolderOpenNotifier, bool>(
  VideoFolderOpenNotifier.new,
);

class VideoScreen extends ConsumerStatefulWidget {
  const VideoScreen({super.key});

  @override
  ConsumerState<VideoScreen> createState() => _VideoScreenState();
}

class _VideoScreenState extends ConsumerState<VideoScreen> {
  /// The folder the user opened, held by PATH rather than by `Album`.
  ///
  /// A re-scan rebuilds the albums, and an `Album` captured here would go on
  /// describing a folder the library no longer has; a path is re-resolved
  /// against the current list on every build, so a folder that disappears simply
  /// closes the view.
  String? _openPath;

  // Captured in initState so dispose() can use it without touching `ref`
  // (Riverpod forbids `ref` access during/after unmount).
  late final VideoFolderOpenNotifier _folderOpen;

  @override
  void initState() {
    super.initState();
    _folderOpen = ref.read(videoFolderOpenProvider.notifier);
  }

  @override
  void dispose() {
    // The screen is gone, so nothing is open any more: a flag left behind would
    // make home_screen defer the back key to a folder view that no longer exists.
    //
    // Deferred to the end of the frame because a provider cannot be written while
    // the tree is being finalised, and that is exactly where an unmount runs: a
    // direct `state = false` here throws "Tried to modify a provider while the
    // widget tree was building" (measured — the photo tab's own `dispose` did,
    // whenever the tab was left with its album open).
    WidgetsBinding.instance.addPostFrameCallback(
      (_) => _folderOpen.setOpen(false),
    );
    super.dispose();
  }

  /// The open folder, or null when the folder list (or the flat view) is shown.
  Album? _openFolder(List<Album> folders) {
    final path = _openPath;
    if (path == null) return null;
    for (final folder in folders) {
      if (folder.path == path) return folder;
    }
    return null;
  }

  /// ONE writer for the open folder: the state that draws the view and the flag
  /// home_screen reads describe the same fact, and two writers is how they drift.
  void _setOpenPath(String? path) {
    if (_openPath == path) return;
    setState(() => _openPath = path);
    _folderOpen.setOpen(path != null);
  }

  void _closeFolder() => _setOpenPath(null);

  /// The folder's videos, in the order the toolbar's sort produced: the sorted
  /// list stays the authority, so a folder never re-sorts behind the toolbar's
  /// back — and the filter the user chose still applies inside it.
  List<MediaItem> _videosIn(Album folder, List<MediaItem> sorted) {
    final paths = {for (final v in folder.items) v.path};
    return [
      for (final v in sorted)
        if (paths.contains(v.path)) v,
    ];
  }

  void _openVideo(MediaItem item) {
    Future.microtask(() {
      if (!mounted) return;
      Navigator.push(
        context,
        // Creates the screen's playback player inside the push and keeps the
        // poster pool suspended for as long as it is on screen — see
        // `utils/poster_quiet_route.dart`.
        PosterQuietRoute(
          build: (warm) => VideoPlayerScreen(item: item, warmPlayer: warm),
        ),
      );
    });
  }

  @override
  Widget build(BuildContext context) {
    final videos = ref.watch(sortedVideosProvider);
    final folders = ref.watch(videoFoldersProvider);
    final columns = ref.watch(videoGridColumnsProvider);
    final sort = ref.watch(videoSortProvider);
    final asc = ref.watch(videoSortAscProvider);
    final extensions = ref.watch(videoExtensionsProvider);
    final filter = ref.watch(videoFilterProvider);
    final uiSettings = ref.watch(uiSettingsProvider);
    final isGrid = uiSettings.videoLayout == 'grid';
    final grouping = uiSettings.videoClassification;
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
    final open = _openFolder(folders);

    // A re-scan can drop the folder the user is standing in (its files are gone,
    // or they moved). `_openFolder` re-resolves the path on every build, so the
    // view is already back at the list — but the two things that were told a
    // folder is open (this screen's `PopScope` and home_screen's back handler)
    // have to follow it, or the back key would be spent on a folder nobody can
    // see. Post-frame because clearing it rebuilds the screen.
    if (_openPath != null && open == null) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted && _openFolder(ref.read(videoFoldersProvider)) == null) {
          _closeFolder();
        }
      });
    }

    // The `Focus` sits INSIDE the `Shortcuts`, and that nesting is the whole of
    // it: a key event goes to the primary focus node and then bubbles UP through
    // its ancestors, so the focused node has to be a DESCENDANT of the
    // `Shortcuts` for the binding to be reachable at all. Wrapping the
    // `Shortcuts` in a `Focus(autofocus: true)` instead — which is what the photo
    // tab's album view does — puts the focus node above the handler and Esc
    // reaches nothing. The map itself stays empty while there is no folder to
    // close.
    final view = Shortcuts(
      shortcuts: {
        if (open != null)
          const SingleActivator(LogicalKeyboardKey.escape):
              const _CloseFolderIntent(),
      },
      child: Actions(
        actions: {
          _CloseFolderIntent: CallbackAction<_CloseFolderIntent>(
            onInvoke: (_) {
              _closeFolder();
              return null;
            },
          ),
        },
        child: Focus(
          autofocus: true,
          child: Column(
            children: [
              MediaToolbar(
                sortOptions: const ['name', 'date', 'size', 'duration'],
                currentSort: sort,
                isAscending: asc,
                onSortChanged: (s) =>
                    ref.read(videoSortProvider.notifier).set(s),
                // The arrow writes the direction provider — which
                // `sortedVideosProvider` already watches — and names the direction
                // it wants. It does not lean on the sort-field seam flipping when
                // the active field is re-picked (that rule is `_SortNotifier.set`).
                onSortDirectionChanged: () =>
                    ref.read(videoSortAscProvider.notifier).toggle(),
                extensions: extensions.toList(),
                currentFilter: filter,
                onFilterChanged: (f) =>
                    ref.read(videoFilterProvider.notifier).set(f),
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
                currentGrouping: grouping,
                onGroupingChanged: (g) {
                  // A different arrangement is a different view: never keep a
                  // folder open across the switch.
                  _closeFolder();
                  ref
                      .read(uiSettingsProvider.notifier)
                      .setVideoClassification(g);
                },
              ),
              Expanded(
                child: _body(
                  open,
                  videos,
                  folders,
                  grouping,
                  isGrid,
                  effectiveColumns,
                ),
              ),
            ],
          ),
        ),
      ),
    );

    // The folder view is a step INSIDE the tab, not a route, so the system back
    // key has to undo that step before it can mean anything else — the photo
    // tab's rule for an open album. `open`, not `_openPath`: what is on screen
    // decides what back does. HomeScreen owns the key (tab switching, and on
    // Android the double-back exit guard) and reads the flag above, so this
    // handler and the shell's rule are one decision, not two.
    return PopScope(
      canPop: open == null,
      onPopInvokedWithResult: (didPop, _) {
        if (!didPop && open != null) _closeFolder();
      },
      child: view,
    );
  }

  Widget _body(
    Album? open,
    List<MediaItem> videos,
    List<Album> folders,
    String grouping,
    bool isGrid,
    int columns,
  ) {
    if (open != null) {
      return Column(
        children: [
          _folderHeader(open),
          Expanded(
            child: _VideoGrid(
              videos: _videosIn(open, videos),
              columns: columns,
              isGrid: isGrid,
              onOpen: _openVideo,
            ),
          ),
        ],
      );
    }
    // Flat is the default and is stated explicitly, rather than inferred from
    // `folders.isEmpty`: it is also where an empty library lands, and
    // `_VideoGrid` owns the one and only "No videos found" state.
    if (grouping == 'none' || folders.isEmpty) {
      return _VideoGrid(
        videos: videos,
        columns: columns,
        isGrid: isGrid,
        onOpen: _openVideo,
      );
    }
    return _FolderGrid(
      folders: folders,
      columns: columns,
      onOpen: (folder) => _setOpenPath(folder.path),
    );
  }

  /// The open folder's name, how many videos are in it, and the way back — the
  /// same header the photo tab puts over an open album.
  Widget _folderHeader(Album folder) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(4, 4, 12, 0),
      child: Row(
        children: [
          IconButton(
            icon: const Icon(Icons.arrow_back),
            // Neutral on purpose: the same header sits over a folder (grouped by
            // folder) and over a format group.
            tooltip: 'Back to the list',
            onPressed: _closeFolder,
          ),
          Expanded(
            child: Text(
              folder.name,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: Theme.of(context).textTheme.titleMedium,
            ),
          ),
          Text(
            folder.itemCount == 1 ? '1 video' : '${folder.itemCount} videos',
            style: Theme.of(context).textTheme.bodySmall,
          ),
        ],
      ),
    );
  }
}

/// The folders themselves, as cards. Same grid rhythm as the video grid beside
/// it (the preview area keeps a 16:9 block, then two lines of text), so the two
/// arrangements read as the same screen.
class _FolderGrid extends StatelessWidget {
  final List<Album> folders;
  final int columns;
  final void Function(Album) onOpen;
  const _FolderGrid({
    required this.folders,
    required this.columns,
    required this.onOpen,
  });

  @override
  Widget build(BuildContext c) {
    return LayoutBuilder(
      builder: (_, constraints) {
        final cardWidth = (constraints.maxWidth - 16) / columns - 8;
        final cardHeight = cardWidth / 16 * 9 + 60;
        return GridView.builder(
          padding: const EdgeInsets.all(8),
          gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
            crossAxisCount: columns,
            childAspectRatio: cardWidth / cardHeight,
            crossAxisSpacing: 8,
            mainAxisSpacing: 8,
          ),
          itemCount: folders.length,
          addRepaintBoundaries: true,
          itemBuilder: (_, i) => VideoFolderCard(
            folder: folders[i],
            onTap: () => onOpen(folders[i]),
          ),
        );
      },
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

    final child = widget.isGrid ? _grid(c, videos) : _list(videos);
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

  Widget _list(List<MediaItem> videos) {
    return ListView.builder(
      padding: const EdgeInsets.all(8),
      itemCount: videos.length,
      addRepaintBoundaries: true,
      itemBuilder: (_, i) {
        final v = videos[i];
        return Padding(
          padding: const EdgeInsets.only(bottom: 8),
          child: VideoListTile(
            item: v,
            cardKey: _fp.keyFor(v.path),
            preview: _fp.isActive(v.path),
            onTap: () => widget.onOpen(v),
          ),
        );
      },
    );
  }
}
