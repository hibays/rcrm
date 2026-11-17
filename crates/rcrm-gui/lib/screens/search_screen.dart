// screens/search_screen.dart
// RCrm GUI — full-screen search as a regular route (not SearchDelegate),
// so nested navigation works: tap result → player → back returns to search.
//
// Video cards match the home screen's Recent Videos proportions (280×180).

import 'package:material_ui/material_ui.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../config/theme.dart';
import '../models/album.dart';
import '../models/media_item.dart';
import '../providers/keyword_provider.dart';
import '../providers/library_provider.dart';
import '../utils/keywords.dart';
import '../widgets/album_card.dart';
import '../widgets/image_card.dart';
import '../widgets/keyword_chip.dart';
import '../widgets/media_item_menu.dart';
import '../widgets/video_card.dart';
import '../utils/poster_quiet_route.dart';
import 'image_screen.dart'; // selectedAlbumProvider
import 'image_viewer_screen.dart';
import 'video_player_screen.dart';

class SearchScreen extends ConsumerStatefulWidget {
  final MediaType? tabFilter;

  /// A tag to OPEN the screen on: the field starts as `#label` and the results
  /// are exact tag matches until the viewer edits the query. The player's tag
  /// chips and the Home channels both land here — the same door as a search,
  /// which is what makes a tag click a real search rather than a second filter
  /// that only exists on one screen.
  final KeywordTag? initialTag;

  const SearchScreen({super.key, this.tabFilter, this.initialTag});

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
    final tag = widget.initialTag;
    if (tag != null) {
      final text = '#${tag.label}';
      _controller.value = TextEditingValue(
        text: text,
        selection: TextSelection.collapsed(offset: text.length),
      );
      _query = text;
    }
    _controller.addListener(_onQueryChanged);
    // A tag page opens on results, not on a keyboard: the viewer followed a
    // link, they did not ask to type. Plain search still focuses.
    if (tag == null) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted) _focusNode.requestFocus();
      });
    }
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

  static final RegExp _tagTokenRe = RegExp(r'#([^\s#]+)');

  /// The tag tokens in a query, in the order typed, unique by key.
  List<KeywordTag> _selectedTags(KeywordIndex index, String query) {
    final seen = <String>{};
    final tags = <KeywordTag>[];
    for (final match in _tagTokenRe.allMatches(query)) {
      final key = match.group(1)!.toLowerCase();
      if (seen.add(key)) tags.add(KeywordTag(key, index.labelFor(key)));
    }
    return tags;
  }

  /// Add a tag to the query. [append] is true when tags are already selected
  /// (a related-tag suggestion narrows the set); false replaces a plain search
  /// with this tag, which is what tapping a suggestion or Browse-by-tag means.
  void _addTag(KeywordTag tag, {required bool append}) {
    final text = _controller.text.trim();
    final already = _selectedTags(
      ref.read(keywordIndexProvider),
      text,
    ).any((t) => t.key == tag.key);
    if (already) return;
    final token = '#${tag.label}';
    final next = append && text.isNotEmpty ? '$text $token' : token;
    _controller.value = TextEditingValue(
      text: next,
      selection: TextSelection.collapsed(offset: next.length),
    );
    _focusNode.unfocus();
  }

  /// Remove one tag token from the query, keeping any free text and the other
  /// selected tags. The chips are the only visible list of selections, so a
  /// tap on one is the removal affordance.
  void _removeTag(KeywordTag tag) {
    final target = '#${tag.key}'.toLowerCase();
    final parts = _controller.text
        .split(RegExp(r'\s+'))
        .where((part) => part.isNotEmpty)
        .where((part) => part.toLowerCase() != target)
        .join(' ');
    _controller.value = TextEditingValue(
      text: parts,
      selection: TextSelection.collapsed(offset: parts.length),
    );
  }

  /// Images are not tagged, so a search that claims "tag" on the photo tab
  /// would promise a query it cannot answer.
  bool get _imageOnly => widget.tabFilter == MediaType.image;

  String get _searchHint => _imageOnly
      ? 'Search name or type (jpg, avif...)'
      : 'Search name, tag or type (mp4, jpg...)';

  // ── Navigation ─────────────────────────────────────────

  void _openVideo(MediaItem item) {
    Future.microtask(() {
      if (mounted) {
        Navigator.of(context).push(
          // Creates the screen's playback player inside the push and keeps the
          // poster pool suspended for as long as it is on screen — see
          // `utils/poster_quiet_route.dart`.
          PosterQuietRoute(
            build: (warm) => VideoPlayerScreen(item: item, warmPlayer: warm),
          ),
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

  /// A result's own menu: the actions that make sense where the item was FOUND.
  ///
  /// No "Show in folder" here: the folder view belongs to the video tab, which
  /// is a different screen — a search result's menu offers what can be done to
  /// the result itself (play/open, facts, copy), not a journey to another tab
  /// that would also have to change its grouping.
  Future<void> _showVideoMenu(MediaItem item, Offset at) {
    return showMediaItemMenu(
      context: context,
      item: item,
      at: at,
      isVideo: true,
      onOpen: () => _openVideo(item),
      keywords: ref.read(keywordIndexProvider).setFor(item.path).labels,
    );
  }

  Future<void> _showImageMenu(
    MediaItem item,
    Offset at,
    List<MediaItem> images,
  ) {
    final index = images.indexOf(item);
    final safe = index < 0 ? 0 : index;
    return showMediaItemMenu(
      context: context,
      item: item,
      at: at,
      isVideo: false,
      index: safe + 1,
      total: images.length,
      onOpen: () => _openImage(images, safe),
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
    final keywordIndex = ref.watch(keywordIndexProvider);
    final q = _query.toLowerCase().trim();

    return PopScope(
      canPop: true,
      child: Scaffold(
        appBar: AppBar(
          backgroundColor: RCrmColors.ash,
          foregroundColor: RCrmColors.textPrimary,
          elevation: 0,
          leading: IconButton(
            icon: const Icon(Icons.arrow_back),
            onPressed: () => Navigator.pop(context),
          ),
          title: TextField(
            controller: _controller,
            focusNode: _focusNode,
            style: TextStyle(color: RCrmColors.textPrimary),
            decoration: InputDecoration(
              hintText: _searchHint,
              hintStyle: TextStyle(color: RCrmColors.textSecondary),
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
        body: _buildBody(context, videos, albums, scanState, q, keywordIndex),
      ),
    );
  }

  Widget _buildBody(
    BuildContext context,
    List<MediaItem> allVideos,
    List<Album> albums,
    ScanState scanState,
    String q,
    KeywordIndex keywordIndex,
  ) {
    if (scanState.isLoading && allVideos.isEmpty) {
      return const Center(child: CircularProgressIndicator());
    }

    // A '#' token is a tag selection; the rest of the query is free text.
    // Several tokens are allowed and mean ALL of them, because adding a tag is
    // a narrowing action. The photo tab has no tags, so it never parses them.
    final selectedTags = _imageOnly
        ? const <KeywordTag>[]
        : _selectedTags(keywordIndex, q);
    final tagKeys = {for (final tag in selectedTags) tag.key};
    final tagOnly = tagKeys.isNotEmpty;
    final textQuery = q.replaceAll(_tagTokenRe, ' ').trim();

    if (q.isEmpty) {
      return _buildEmptyQuery(context, allVideos, albums, keywordIndex);
    }

    // ── Filter by tab context ──────────────────────────

    final List<MediaItem> videos;
    final List<MediaItem> images;
    final List<Album> matchedAlbums;
    if (tagOnly) {
      videos = allVideos.where((v) {
        final set = keywordIndex.setFor(v.path);
        if (!tagKeys.every(set.contains)) return false;
        if (textQuery.isEmpty) return true;
        return _fuzzyMatch(textQuery, v.name) ||
            _fuzzyMatch(textQuery, v.extension) ||
            _fuzzyMatch(textQuery, v.albumName) ||
            _matchesKeywords(keywordIndex, v, textQuery);
      }).toList();
      images = const [];
      matchedAlbums = const [];
    } else {
      if (widget.tabFilter == MediaType.image) {
        videos = [];
      } else {
        videos = allVideos
            .where(
              (v) =>
                  _fuzzyMatch(q, v.name) ||
                  _fuzzyMatch(q, v.extension) ||
                  _fuzzyMatch(q, v.albumName) ||
                  _matchesKeywords(keywordIndex, v, q),
            )
            .toList();
      }
      if (widget.tabFilter == MediaType.video) {
        images = [];
        matchedAlbums = [];
      } else {
        images = _matchingImages(albums, q);
        matchedAlbums = _matchingAlbums(albums, q);
      }
    }
    final total = videos.length + images.length + matchedAlbums.length;
    // With tags selected the suggestions are RELATED tags (the next likely
    // narrowing), not matches for the text: '#amateur' should offer #couple,
    // not just the tag already in the field.
    final suggestions = _imageOnly
        ? const <KeywordTag>[]
        : tagOnly
        ? keywordIndex.relatedTags(tagKeys, limit: 8)
        : _matchingTags(keywordIndex, q);
    // Tag mode already shows the query as selected chips; repeating it here
    // would be a third accent-coloured copy of the same words.
    final headerLabel = tagOnly ? null : '"$_query"';
    final countLabel = tagOnly
        ? (total == 1 ? '1 video' : '$total videos')
        : (total == 1 ? '1 result' : '$total results');

    final noResultsTitle = tagOnly
        ? 'No videos with "$_query"'
        : 'No results for "$_query"';
    final noResultsHint = tagOnly
        ? 'Remove a tag or try another keyword'
        : _imageOnly
        ? 'Try a different file name or extension (jpg, avif)'
        : 'Try a different file name, tag or extension (mp4, jpg, avif)';
    if (total == 0 && !tagOnly) {
      return _noResults(context, noResultsTitle, noResultsHint);
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
            // Tags: selected chips first (tap one to REMOVE it), then the
            // related tags the query points at (tap one to ADD it). Several
            // selected tags narrow with ALL, so '#amateur #couple' is the
            // files that carry both.
            if (selectedTags.isNotEmpty || suggestions.isNotEmpty) ...[
              SliverToBoxAdapter(
                child: Padding(
                  padding: const EdgeInsets.fromLTRB(16, 10, 16, 4),
                  child: _sectionHeader(context, 'Tags', Icons.tag),
                ),
              ),
              SliverToBoxAdapter(
                child: Padding(
                  padding: const EdgeInsets.fromLTRB(16, 0, 16, 4),
                  child: Wrap(
                    spacing: 6,
                    runSpacing: 2,
                    children: [
                      for (final tag in selectedTags)
                        SelectedKeywordChip(
                          tag: tag,
                          onRemove: () => _removeTag(tag),
                        ),
                      for (final tag in suggestions)
                        KeywordChip(
                          tag: tag,
                          additive: true,
                          onTap: () =>
                              _addTag(tag, append: selectedTags.isNotEmpty),
                        ),
                    ],
                  ),
                ),
              ),
            ],

            // Header
            SliverToBoxAdapter(
              child: Padding(
                padding: const EdgeInsets.fromLTRB(16, 12, 4, 8),
                child: Row(
                  children: [
                    Expanded(
                      child: Row(
                        children: [
                          Text(
                            countLabel,
                            style: Theme.of(context).textTheme.titleMedium
                                ?.copyWith(
                                  color: RCrmColors.textPrimary,
                                  fontWeight: FontWeight.w600,
                                ),
                          ),
                          if (headerLabel != null) ...[
                            const SizedBox(width: 8),
                            Flexible(
                              child: Text(
                                headerLabel,
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                                style: Theme.of(context).textTheme.titleMedium
                                    ?.copyWith(
                                      color: Theme.of(context)
                                          .colorScheme
                                          .primary,
                                    ),
                              ),
                            ),
                          ],
                        ],
                      ),
                    ),
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

            // A tag combination with no hits keeps the selected/related tag
            // row above; the message fills what is left instead of replacing
            // the whole page (which would take the chips away).
            if (total == 0)
              SliverFillRemaining(
                hasScrollBody: false,
                child: _noResults(context, noResultsTitle, noResultsHint),
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
                _buildVideoList(context, videos),
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
            onMenuRequested: (at) => _showVideoMenu(videos[index], at),
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
            onMenuRequested: (at) => _showImageMenu(images[index], at, images),
          ),
          childCount: images.length,
        ),
      ),
    );
  }

  // ── List ───────────────────────────────────────────────

  Widget _buildVideoList(BuildContext context, List<MediaItem> videos) {
    return SliverList(
      delegate: SliverChildBuilderDelegate((ctx, index) {
        final item = videos[index];
        return Padding(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
          child: VideoListTile(
            item: item,
            // Search results are rebuilt in place as the query changes, so the
            // card needs a per-item key to keep its poster state from being
            // reused for a different video.
            cardKey: ValueKey(item.url),
            onTap: () => _openVideo(item),
            onMenuRequested: (at) => _showVideoMenu(item, at),
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
                      onMenuRequested: (at) => _showImageMenu(img, at, images),
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: GestureDetector(
                    behavior: HitTestBehavior.opaque,
                    onTap: () => _openImage(images, index),
                    onLongPressStart: (d) => requestItemMenu(
                      (at) => _showImageMenu(img, at, images),
                      d.globalPosition,
                      haptic: true,
                    ),
                    onSecondaryTapDown: (d) => requestItemMenu(
                      (at) => _showImageMenu(img, at, images),
                      d.globalPosition,
                    ),
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

  /// Metadata column for the image list. The video list uses the shared
  /// [VideoListTile] instead, so this stays specific to images.
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

  /// A search hit on one of the item's automatic tags, so a tag the user saw
  /// as a chip is also a query they can type.
  static bool _matchesKeywords(
    KeywordIndex index,
    MediaItem item,
    String query,
  ) {
    for (final tag in index.setFor(item.path).tags) {
      if (_fuzzyMatch(query, tag.key) || _fuzzyMatch(query, tag.label)) {
        return true;
      }
    }
    return false;
  }

  /// The repeated tags a typed query points at, for the suggestion strip.
  /// A leading '#' is the tag syntax, not part of the word.
  List<KeywordTag> _matchingTags(KeywordIndex index, String query) {
    var q = query.trim().toLowerCase();
    if (q.startsWith('#')) q = q.substring(1);
    if (q.isEmpty) return const [];
    final out = <KeywordTag>[];
    for (final tag in index.topTags) {
      if (_fuzzyMatch(q, tag.key) || _fuzzyMatch(q, tag.label)) {
        out.add(tag);
        if (out.length >= 8) break;
      }
    }
    return out;
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
    KeywordIndex index,
  ) {
    // The photo tab has no tags, so it gets no tag discovery.
    final tags = _imageOnly
        ? const <KeywordTag>[]
        : index.topTags.take(10).toList();
    return Center(
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              Icons.search,
              size: 56,
              color: Theme.of(context).colorScheme.primary
                  .withValues(alpha: 0.3),
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
            if (tags.isNotEmpty) ...[
              const SizedBox(height: 24),
              Text(
                'Browse by tag',
                style: Theme.of(context).textTheme.titleSmall
                    ?.copyWith(color: RCrmColors.textSecondary),
              ),
              const SizedBox(height: 10),
              Wrap(
                alignment: WrapAlignment.center,
                spacing: 8,
                runSpacing: 2,
                children: [
                  for (final tag in tags)
                    KeywordChip(
                      tag: tag,
                      additive: true,
                      onTap: () => _addTag(tag, append: false),
                    ),
                ],
              ),
            ],
            const SizedBox(height: 20),
            Text(
              _imageOnly
                  ? 'Start typing a file name or extension\ne.g. avif, jpg'
                  : 'Start typing a file name, tag or extension\n'
                        'e.g. mkv, avif, jpg',
              style: Theme.of(context).textTheme.bodySmall
                  ?.copyWith(height: 1.5),
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
    );
  }

  Widget _noResults(BuildContext context, String title, String hint) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              Icons.search_off,
              size: 64,
              color: Theme.of(context).colorScheme.primary
                  .withValues(alpha: 0.4),
            ),
            const SizedBox(height: 16),
            Text(title, style: Theme.of(context).textTheme.titleLarge),
            const SizedBox(height: 8),
            Text(hint, style: Theme.of(context).textTheme.bodyMedium),
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

  Widget _sectionHeader(BuildContext context, String title, IconData icon) {
    return Row(
      children: [
        Icon(icon, size: 18, color: Theme.of(context).colorScheme.primary),
        const SizedBox(width: 8),
        Text(
          title,
          style: Theme.of(context).textTheme.titleSmall
              ?.copyWith(color: Theme.of(context).colorScheme.primary),
        ),
      ],
    );
  }
}
