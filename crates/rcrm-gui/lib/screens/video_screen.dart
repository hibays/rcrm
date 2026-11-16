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

import 'package:material_ui/material_ui.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../models/album.dart';
import '../models/media_item.dart';
import '../providers/library_provider.dart';
import '../providers/settings_provider.dart';
import '../services/item_cache_limit.dart';
import '../utils/library_columns.dart';
import '../widgets/media_toolbar.dart';
import '../widgets/media_item_menu.dart';
import '../widgets/two_finger_pinch.dart';
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
  /// The column count the current two-finger pinch started on, for the grid.
  /// A pinch reports a cumulative scale, so the count it maps FROM must stay the
  /// one the fingers started on (feeding the live count back in would make every
  /// frame a new step).
  int _pinchStartColumns = 4;

  /// A "Show in folder" request that arrived while the tab was grouped some
  /// other way. Switching the grouping is a provider write, so the folder list
  /// only exists on the NEXT build — the request waits here for that build
  /// instead of guessing at a folder list that is already stale.
  String? _revealPath;

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

  /// The folder (or format group) that contains [path], or null when the
  /// library no longer has one.
  Album? _folderContaining(String path, List<Album> folders) {
    for (final folder in folders) {
      for (final item in folder.items) {
        if (item.path == path) return folder;
      }
    }
    return null;
  }

  /// Two fingers start resizing: remember the count they started on, because the
  /// scale they report is cumulative and mapped FROM it.
  void _startPinch() {
    final width = MediaQuery.sizeOf(context).width;
    _pinchStartColumns = videoGridBounds(
      width: width,
      mobile: isMobile,
    ).resolve(ref.read(videoGridColumnsProvider));
  }

  /// Two fingers moved. A grid pinch sizes cells; a list pinch has two answers.
  void _pinchScale(double scale) {
    final width = MediaQuery.sizeOf(context).width;
    final settings = ref.read(uiSettingsProvider);
    if (settings.videoLayout == 'grid') {
      final bounds = videoGridBounds(width: width, mobile: isMobile);
      final target = pinchColumnCount(
        startColumns: _pinchStartColumns,
        scale: scale,
        min: bounds.min,
        max: bounds.max,
      );
      if (target != bounds.resolve(ref.read(videoGridColumnsProvider))) {
        ref.read(videoGridColumnsProvider.notifier).set(target);
      }
      return;
    }
    final target = pinchListColumns(scale: scale);
    if (target == null) return;
    final mode = target == 1 ? 'one' : 'two';
    // Only commit a mode that changes what is ON SCREEN. On a narrow window the
    // list is one column whatever the stored preference says (see
    // `kTwoColumnListMinWidth`), so a pinch-in there would store a preference
    // with no visible answer — a gesture that does nothing AND changes a setting.
    final current = videoListColumnCount(
      mode: settings.videoListColumns,
      width: width,
    );
    final next = videoListColumnCount(mode: mode, width: width);
    if (next == current) return;
    ref.read(uiSettingsProvider.notifier).setVideoListColumns(mode);
  }

  /// "Show in folder" — the one reveal this library can afford.
  ///
  /// The video tab's folders are DERIVED from the scanned list
  /// (`videoFoldersProvider`), so switching the arrangement costs no re-scan and
  /// no waiting. The photo tab's does: its albums are built inside the scanned
  /// `MediaLibrary`, which is why the image menu has no such row at all. A row
  /// that silently starts a full scan is a side effect, not a reveal.
  void _revealInFolder(MediaItem item) {
    if (ref.read(uiSettingsProvider).videoClassification != 'folder') {
      _revealPath = item.path;
      _closeFolder();
      ref.read(uiSettingsProvider.notifier).setVideoClassification('folder');
      return;
    }
    final folder = _folderContaining(item.path, ref.read(videoFoldersProvider));
    if (folder != null) _setOpenPath(folder.path);
  }

  /// Long press / right-click on a video: its menu at the pointer.
  Future<void> _showItemMenu(MediaItem item, Offset at) {
    return showMediaItemMenu(
      context: context,
      item: item,
      at: at,
      isVideo: true,
      onOpen: () => _openVideo(item),
      onReveal: () => _revealInFolder(item),
    );
  }

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
    final width = MediaQuery.sizeOf(context).width;
    // ONE owner for the range the grid may use (utils/library_columns.dart):
    // the toolbar, the pinch and this build must clamp to the same numbers, or
    // a pinch asks for a column the build silently refuses.
    final bounds = videoGridBounds(width: width, mobile: isMobile);
    final effectiveColumns = bounds.resolve(columns);
    // A wide window gets a two-column LIST, unless the user has pinned one.
    final listColumns = videoListColumnCount(
      mode: uiSettings.videoListColumns,
      width: width,
    );
    // The row height follows the cell width and the reader's text scale: a
    // two-column cell narrows the text column enough for the size line to wrap
    // (that is 14dp more than the established 100dp row holds, measured at the
    // 600dp floor), and the same row grows with the text it carries.
    final listRowHeight = videoListRowHeight(
      columns: listColumns,
      textScale: MediaQuery.textScalerOf(context).scale(1),
    );
    final open = _openFolder(folders);

    // A "Show in folder" asked for while the tab was grouped another way is
    // fulfilled on the build AFTER the grouping write — that write is what
    // creates the folder list this looks in.
    final reveal = _revealPath;
    if (reveal != null && grouping == 'folder') {
      _revealPath = null;
      final target = _folderContaining(reveal, folders);
      if (target != null) {
        WidgetsBinding.instance.addPostFrameCallback((_) {
          if (mounted) _setOpenPath(target.path);
        });
      }
    }

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
                minColumns: bounds.min,
                maxColumns: bounds.max,
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
                child: TwoFingerPinch(
                  onStart: _startPinch,
                  onScale: _pinchScale,
                  builder: (_, pinching) => _body(
                    open,
                    videos,
                    folders,
                    grouping,
                    isGrid,
                    effectiveColumns,
                    listColumns,
                    listRowHeight,
                    // The grid/list must not scroll under the fingers sizing it.
                    physics: pinching
                        ? const NeverScrollableScrollPhysics()
                        : null,
                  ),
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
    int listColumns,
    double listRowHeight, {
    ScrollPhysics? physics,
  }) {
    if (open != null) {
      return Column(
        children: [
          _folderHeader(open),
          Expanded(
            child: _VideoGrid(
              videos: _videosIn(open, videos),
              columns: columns,
              listColumns: listColumns,
              listRowHeight: listRowHeight,
              isGrid: isGrid,
              physics: physics,
              onOpen: _openVideo,
              onMenuRequested: _showItemMenu,
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
        listColumns: listColumns,
        listRowHeight: listRowHeight,
        isGrid: isGrid,
        physics: physics,
        onOpen: _openVideo,
        onMenuRequested: _showItemMenu,
      );
    }
    return _FolderGrid(
      folders: folders,
      columns: columns,
      physics: physics,
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
  final ScrollPhysics? physics;
  final void Function(Album) onOpen;
  const _FolderGrid({
    required this.folders,
    required this.columns,
    required this.onOpen,
    this.physics,
  });

  @override
  Widget build(BuildContext c) {
    return LayoutBuilder(
      builder: (_, constraints) {
        final cardWidth = (constraints.maxWidth - 16) / columns - 8;
        final cardHeight = cardWidth / 16 * 9 + 60;
        return GridView.builder(
          padding: const EdgeInsets.all(8),
          physics: physics,
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

  /// How many rows the LIST puts on one line — 1, or 2 on a wide window.
  final int listColumns;

  /// The height one list row needs at this text scale (and cell width).
  final double listRowHeight;
  final bool isGrid;
  final ScrollPhysics? physics;
  final void Function(MediaItem) onOpen;
  final void Function(MediaItem item, Offset globalPosition)? onMenuRequested;
  const _VideoGrid({
    required this.videos,
    required this.columns,
    required this.listColumns,
    required this.listRowHeight,
    required this.isGrid,
    required this.onOpen,
    this.physics,
    this.onMenuRequested,
  });
  @override
  State<_VideoGrid> createState() => _VideoGridState();
}

class _VideoGridState extends State<_VideoGrid> {
  final _fp = FingerPreviewState();

  /// This browser's own key namespace. The grid and the list are alternatives
  /// (never mounted together), so they share one surface — and no other
  /// surface may claim this name.
  late final FingerPreviewSurface _surface = _fp.surface('videoBrowser');

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
          physics: widget.physics,
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
              key: FingerPreviewState.isMobile ? _surface.keyFor(v.path) : null,
              item: v,
              preview: _surface.isActive(v.path),
              onTap: () => widget.onOpen(v),
              onMenuRequested: widget.onMenuRequested == null
                  ? null
                  : (at) => widget.onMenuRequested!(v, at),
            );
          },
        );
      },
    );
  }

  /// The list: one row per line, or two on a wide window.
  ///
  /// ONE `GridView` for both counts, not a `ListView` plus a `GridView`:
  /// swapping the scrollable's type is what threw the scroll position away when
  /// a pinch flipped 1 <-> 2 columns (measured: the list jumped from row 10
  /// back to row 0). A grid whose `crossAxisCount` changes keeps the same
  /// Scrollable, so the reader stays where they were.
  ///
  /// `mainAxisExtent` is the row's own height and nothing else: an aspect ratio
  /// would stretch the row with the WINDOW and turn the 16:9 poster into a
  /// band. `videoListRowHeight` adds the one thing that legitimately changes
  /// it — a narrower two-column cell (one more wrapped line) and the reader's
  /// text scale.
  Widget _list(List<MediaItem> videos) {
    final menu = widget.onMenuRequested;
    return GridView.builder(
      padding: const EdgeInsets.all(8),
      physics: widget.physics,
      gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: widget.listColumns,
        mainAxisExtent: widget.listRowHeight,
        crossAxisSpacing: 8,
        mainAxisSpacing: 8,
      ),
      itemCount: videos.length,
      addRepaintBoundaries: true,
      itemBuilder: (_, i) {
        final v = videos[i];
        return VideoListTile(
          item: v,
          cardKey: _surface.keyFor(v.path),
          preview: _surface.isActive(v.path),
          height: widget.listRowHeight,
          onTap: () => widget.onOpen(v),
          onMenuRequested: menu == null ? null : (at) => menu(v, at),
        );
      },
    );
  }
}
