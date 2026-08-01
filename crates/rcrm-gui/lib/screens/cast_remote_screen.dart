// screens/cast_remote_screen.dart
// Phone-side remote control screen after successful pairing: browses the
// server media library and sends play/pause/seek/volume commands to the TV.
//
// Responsive: portrait phones get a compact bottom control card; landscape /
// short windows tighten spacing and shrink the transport icons. The seek
// slider updates locally while dragging and sends ONE seek on release.

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../models/media_item.dart';
import '../providers/server_provider.dart';
import '../services/cast_protocol.dart';
import '../services/cast_remote.dart';
import '../services/cast_session_store.dart';
import '../widgets/pooled_image.dart';
import '../widgets/video_card.dart';
import 'cast_scan_screen.dart';

class CastRemoteScreen extends ConsumerStatefulWidget {
  final CastRemote remote;
  const CastRemoteScreen({super.key, required this.remote});

  @override
  ConsumerState<CastRemoteScreen> createState() => _State();
}

class _State extends ConsumerState<CastRemoteScreen> {
  Timer? _poll;

  /// Per-second transport state. Updated by the poll timer WITHOUT a
  /// full-page rebuild: only the status bar and control panel listen to it,
  /// so the media browser (thumbnails) is never rebuilt by polling.
  final _ui = _CastUiState();

  /// Connection health. Low-frequency (changes only on poll failure/recovery),
  /// so it keeps driving a full rebuild when it flips.
  bool _connected = true;
  String? _pollError;

  // ── media browser state ──────────────────────────────────
  List<String> _subdirs = [];
  List<MediaItem> _videos = [];
  List<MediaItem> _images = [];
  bool _showImages = false;
  String _currentDir = '/';
  bool _loadingDir = false;
  bool _dirError = false;
  bool _gridMode = false;

  @override
  void initState() {
    super.initState();
    _loadDir('/');
    _poll = Timer.periodic(const Duration(seconds: 1), (_) => _tick());
  }

  @override
  void dispose() {
    _poll?.cancel();
    _ui.dispose();
    // Keep the pairing alive: closing the screen must NOT end the session,
    // so the user can re-enter the remote screen without re-scanning. Only
    // the HTTP transport is dropped; the session token survives.
    widget.remote.suspend();
    super.dispose();
  }

  Future<void> _tick() async {
    final remote = widget.remote;
    try {
      final status = await remote.status();
      if (!mounted) return;
      _ui.mutate(() {
        _ui.status = status;
        _ui.localPlaying = null;
      });
      if (!_connected) {
        setState(() {
          _connected = true;
          _pollError = null;
        });
      }
    } catch (e) {
      if (!mounted) return;
      final unauthorized = e is CastException && e.message.contains('401');
      final wasConnected = _connected;
      _ui.mutate(() => _ui.localPlaying = null);
      setState(() {
        _connected = false;
        _pollError = unauthorized ? 'The TV ended the pairing - rescan' : '$e';
      });
      if (wasConnected && unauthorized) {
        // The TV ended the session (e.g. owner pressed 解除配对). Forget the
        // saved pairing so the next entry from home opens the scanner
        // directly instead of resuming a dead session.
        unawaited(CastSessionStore().clear());
      }
    }
  }

  Future<void> _loadDir(String path) async {
    setState(() {
      _loadingDir = true;
      _dirError = false;
      _currentDir = path;
    });
    final client = ref.read(serverProvider).client;
    List<String> subdirs = [];
    List<MediaItem> videos = [];
    List<MediaItem> images = [];
    if (client != null) {
      try {
        final result = await client.listAll(path);
        subdirs = result.subdirs.toList()..sort();
        final files = result.files.toList();
        // Single source of truth: MediaItem.type (same classification as
        // the main library).
        videos = files.where((f) => f.type == MediaType.video).toList()
          ..sort(
            (a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()),
          );
        images = files.where((f) => f.type == MediaType.image).toList()
          ..sort(
            (a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()),
          );
      } catch (_) {
        if (!mounted) return;
        setState(() {
          _loadingDir = false;
          _dirError = true;
        });
        return;
      }
    }
    if (!mounted) return;
    setState(() {
      _subdirs = subdirs;
      _videos = videos;
      _images = images;
      _loadingDir = false;
    });
  }

  bool _playInFlight = false;

  Future<void> _play(MediaItem item) async {
    if (_playInFlight) return;
    _playInFlight = true;
    try {
      _ui.mutate(() => _ui.localPlaying = true);
      await widget.remote.play(
        item.path,
        type: item.type == MediaType.image ? 'image' : 'video',
      );
    } catch (e) {
      if (!mounted) return;
      _ui.mutate(() => _ui.localPlaying = null);
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text('Play failed: $e')));
    } finally {
      _playInFlight = false;
    }
  }

  void _goUp() {
    final parts = _currentDir.split('/').where((p) => p.isNotEmpty).toList();
    parts.removeLast();
    _loadDir('/${parts.join('/')}');
  }

  String _nameOf(String path) {
    final parts = path.split('/').where((p) => p.isNotEmpty).toList();
    return parts.isEmpty ? path : parts.last;
  }

  void _togglePlay() {
    if (_ui.showPlaying) {
      _ui.mutate(() => _ui.localPlaying = false);
      widget.remote.pause().catchError((_) {});
    } else {
      _ui.mutate(() => _ui.localPlaying = true);
      widget.remote.resume().catchError((_) {});
    }
  }

  Future<void> _stop() async {
    try {
      await widget.remote.stop();
      if (!mounted) return;
      _ui.mutate(() => _ui.localPlaying = false);
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text('Stop failed: $e')));
    }
  }

  Future<void> _stepVolume(int delta) async {
    try {
      final v = (_ui.status.volume + delta).clamp(0, 100);
      await widget.remote.setVolume(v);
      if (!mounted) return;
      final s = _ui.status;
      _ui.mutate(() {
        _ui.status = CastStatus(
          paired: s.paired,
          playing: s.playing,
          posMs: s.posMs,
          durMs: s.durMs,
          path: s.path,
          serverOk: s.serverOk,
          rate: s.rate,
          volume: v,
        );
      });
    } catch (_) {}
  }

  /// "Stop casting" flow: confirm, stop playback on the TV and end the
  /// session so the receiver goes back to a fresh QR.
  Future<void> _stopCasting() async {
    final stop = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Exit cast?'),
        content: const Text(
          'Stops playback, unpairs, and the TV returns to its QR page.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Exit cast'),
          ),
        ],
      ),
    );
    if (stop != true || !mounted) return;
    var unpaired = true;
    try {
      await widget.remote.unpair();
    } catch (_) {
      unpaired = false;
    }
    if (!mounted) return;
    if (unpaired) {
      // Forget the persisted pairing so the next cast entry shows the
      // scanner. Stop the phone-side HTTPS relay; the TV no longer needs it.
      await CastSessionStore().clear();
      await ref.read(castHttpsRelayProvider).stop();
    } else {
      // The TV never got the unpair (unreachable): its session is still
      // alive and it still shows "已配对" with no QR. Keep the saved pairing
      // + relay so the user can resume later; wiping them would strand the
      // TV with no way to re-pair.
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('TV unreachable - not unpaired, connection kept'),
        ),
      );
    }
    if (!mounted) return;
    if (unpaired) {
      // Go straight to the scanner (camera) so the user can pair again
      // immediately, replacing this screen in the stack.
      Navigator.of(context).pushReplacement(
        MaterialPageRoute<void>(builder: (_) => const CastScanScreen()),
      );
    } else {
      Navigator.of(context).pop();
    }
  }

  /// Plain disconnect: keep the TV playing, just leave this screen. The
  /// pairing is kept so re-entering resumes without scanning.
  void _disconnectOnly() {
    widget.remote.suspend();
    Navigator.of(context).pop();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Remote'),
        actions: [
          PopupMenuButton<String>(
            tooltip: 'More',
            icon: const Icon(Icons.more_vert),
            onSelected: (v) {
              if (v == 'disconnect') _disconnectOnly();
              if (v == 'stop') _stopCasting();
            },
            itemBuilder: (context) => [
              const PopupMenuItem(
                value: 'disconnect',
                child: ListTile(
                  dense: true,
                  leading: Icon(Icons.link_off),
                  title: Text('Disconnect remote'),
                  subtitle: Text('TV keeps playing'),
                ),
              ),
              const PopupMenuItem(
                value: 'stop',
                child: ListTile(
                  dense: true,
                  leading: Icon(Icons.cast_connected),
                  title: Text('Exit cast'),
                  subtitle: Text('Stops playback and unpairs'),
                ),
              ),
            ],
          ),
        ],
      ),
      body: LayoutBuilder(
        builder: (context, constraints) {
          // Wide screens (desktop, landscape): browser on the left, a
          // floating control panel on the right. Portrait phones keep the
          // compact stacked layout.
          if (constraints.maxWidth > 760 &&
              constraints.maxWidth > constraints.maxHeight * 1.02) {
            return Row(
              children: [
                Expanded(
                  child: Column(
                    children: [
                      _buildStatusBar(),
                      const Divider(height: 1),
                      Expanded(child: _buildBrowser()),
                    ],
                  ),
                ),
                const VerticalDivider(width: 1),
                SizedBox(
                  width: 360,
                  child: Column(
                    children: [
                      Expanded(child: _buildControlPanel(asBottomBar: false)),
                    ],
                  ),
                ),
              ],
            );
          }
          return Column(
            children: [
              _buildStatusBar(),
              const Divider(height: 1),
              Expanded(child: _buildBrowser()),
              const Divider(height: 1),
              _buildControls(),
            ],
          );
        },
      ),
    );
  }

  Widget _buildStatusBar() {
    final connected = _connected;
    final theme = Theme.of(context);
    return ListenableBuilder(
      listenable: _ui,
      builder: (context, _) {
        final playing = _ui.showPlaying;
        return Container(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
          color: connected
              ? playing
                    ? theme.colorScheme.primary.withValues(alpha: 0.12)
                    : null
              : theme.colorScheme.error.withValues(alpha: 0.14),
          child: Row(
            children: [
              Icon(
                connected
                    ? (playing ? Icons.cast_connected : Icons.cast)
                    : Icons.cast,
                size: 20,
                color: connected
                    ? (playing
                          ? theme.colorScheme.primary
                          : const Color(0xFF4CAF50))
                    : theme.colorScheme.error,
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Text(
                  connected
                      ? playing
                            ? 'Now playing - ${_nameOf(_ui.status.path ?? '')}'
                            : 'Connected - pick a video to play'
                      : (_pollError ?? 'Connection lost - rescan'),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: const TextStyle(fontSize: 14),
                ),
              ),
              if (!connected)
                IconButton(
                  tooltip: 'Rescan',
                  icon: const Icon(Icons.qr_code_scanner),
                  visualDensity: VisualDensity.compact,
                  onPressed: () async {
                    // The stored session is stale (TV restarted / session lost):
                    // drop it so the scan flow starts from a clean pairing.
                    widget.remote.suspend();
                    await CastSessionStore().clear();
                    if (!context.mounted) return;
                    Navigator.of(context).pushReplacement(
                      MaterialPageRoute<void>(
                        builder: (_) => const CastScanScreen(),
                      ),
                    );
                  },
                )
              else if (connected && !_ui.dragging)
                Text(
                  '${_fmtMs(_ui.status.posMs)} / ${_fmtMs(_ui.status.durMs)}',
                  style: const TextStyle(fontSize: 12, color: Colors.white54),
                ),
            ],
          ),
        );
      },
    );
  }

  Widget _buildBrowser() {
    if (_loadingDir && _subdirs.isEmpty && _videos.isEmpty) {
      return const Center(child: CircularProgressIndicator());
    }
    if (_dirError && _subdirs.isEmpty && _videos.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.folder_off, size: 48, color: Colors.white38),
            const SizedBox(height: 12),
            const Text(
              'Failed to load folder',
              style: TextStyle(color: Colors.white70),
            ),
            const SizedBox(height: 8),
            TextButton(
              onPressed: () => _loadDir(_currentDir),
              child: const Text('Retry'),
            ),
          ],
        ),
      );
    }
    return Column(
      children: [
        _buildBrowserToolbar(),
        Expanded(child: _gridMode ? _buildGrid() : _buildList()),
      ],
    );
  }

  Widget _buildBrowserToolbar() {
    return Padding(
      padding: const EdgeInsets.fromLTRB(12, 4, 4, 4),
      child: Row(
        children: [
          if (_currentDir != '/')
            IconButton(
              tooltip: 'Up',
              icon: const Icon(Icons.arrow_upward, size: 20),
              visualDensity: VisualDensity.compact,
              onPressed: _goUp,
            )
          else
            const Icon(Icons.folder, size: 20, color: Color(0xFFFFB74D)),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              _currentDir == '/' ? 'Root' : _nameOf(_currentDir),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: const TextStyle(fontWeight: FontWeight.w600),
            ),
          ),
          // Video / image tab switch. Kept compact (icons only) to fit the
          // remote's narrow control column.
          IconButton(
            tooltip: _showImages ? 'Show videos' : 'Show images',
            icon: Icon(
              _showImages ? Icons.movie_outlined : Icons.photo_outlined,
            ),
            visualDensity: VisualDensity.compact,
            onPressed: () => setState(() => _showImages = !_showImages),
          ),
          IconButton(
            tooltip: _gridMode ? 'List view' : 'Grid view',
            icon: Icon(_gridMode ? Icons.view_list : Icons.grid_view),
            visualDensity: VisualDensity.compact,
            onPressed: () => setState(() => _gridMode = !_gridMode),
          ),
        ],
      ),
    );
  }

  Widget _buildList() {
    final rows = <Widget>[];
    for (final d in _subdirs) {
      rows.add(
        ListTile(
          leading: const CircleAvatar(
            radius: 20,
            backgroundColor: Color(0xFF2A2A3E),
            child: Icon(Icons.folder, size: 20, color: Color(0xFFFFB74D)),
          ),
          title: Text(_nameOf(d), maxLines: 1, overflow: TextOverflow.ellipsis),
          trailing: const Icon(
            Icons.chevron_right,
            size: 20,
            color: Colors.white38,
          ),
          onTap: () => _loadDir(d),
        ),
      );
    }
    for (final v in _showImages ? _images : _videos) {
      rows.add(_mediaRow(v));
    }
    if (rows.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              _showImages ? Icons.photo_outlined : Icons.video_library_outlined,
              size: 48,
              color: Colors.white38,
            ),
            const SizedBox(height: 12),
            Text(
              _showImages ? 'No images here' : 'No videos here',
              style: const TextStyle(color: Colors.white70),
            ),
          ],
        ),
      );
    }
    return ListView.separated(
      itemCount: rows.length,
      separatorBuilder: (_, _) => const Divider(height: 1, indent: 72),
      itemBuilder: (_, i) => rows[i],
    );
  }

  /// List row with a poster thumbnail on the left. Videos use the same
  /// ThumbnailService pipeline as the main app; images use PooledImage
  /// (same disk-cache + resize path as the main image grid).
  Widget _mediaRow(MediaItem v) {
    final theme = Theme.of(context);
    final isImage = v.type == MediaType.image;
    return InkWell(
      onTap: () => _play(v),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
        child: Row(
          children: [
            SizedBox(
              width: 108,
              height: 60,
              child: ClipRRect(
                borderRadius: BorderRadius.circular(6),
                child: isImage
                    ? PooledImage(
                        url: v.url,
                        fit: BoxFit.cover,
                        // Same size as the main image grid (PooledImage
                        // default) so the disk/RAM cache is shared.
                        decodeWidth: 400,
                        errorWidget: Container(
                          color: const Color(0xFF2A2A3E),
                          child: const Icon(
                            Icons.broken_image_outlined,
                            color: Colors.white38,
                          ),
                        ),
                      )
                    : VideoCard(
                        key: ValueKey('cast-thumb-${v.path}'),
                        item: v,
                        compact: true,
                        onTap: () => _play(v),
                      ),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Text(
                    v.name,
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(
                      fontSize: 14,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    [
                      if (!isImage && v.durationSeconds != null)
                        v.formattedDuration,
                      if (v.size > 0) v.formattedSize,
                    ].join(' • '),
                    style: TextStyle(
                      fontSize: 12,
                      color: Colors.white.withValues(alpha: 0.5),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(width: 8),
            Icon(
              isImage ? Icons.image_outlined : Icons.play_circle_outline,
              color: theme.colorScheme.primary,
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildGrid() {
    return LayoutBuilder(
      builder: (context, constraints) {
        final minCard = 150.0;
        final cols = (constraints.maxWidth / minCard).floor().clamp(2, 6);
        return GridView.builder(
          padding: const EdgeInsets.all(8),
          gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
            crossAxisCount: cols,
            childAspectRatio: 16 / 11,
            crossAxisSpacing: 8,
            mainAxisSpacing: 8,
          ),
          itemCount:
              _subdirs.length + (_showImages ? _images.length : _videos.length),
          itemBuilder: (context, i) {
            if (i < _subdirs.length) {
              final d = _subdirs[i];
              return _FolderGridCell(
                name: _nameOf(d),
                onTap: () => _loadDir(d),
              );
            }
            if (_showImages) {
              final img = _images[i - _subdirs.length];
              return _ImageGridCell(
                key: ValueKey('cast-grid-img-${img.path}'),
                item: img,
                onTap: () => _play(img),
              );
            }
            final v = _videos[i - _subdirs.length];
            return VideoCard(
              key: ValueKey('cast-grid-${v.path}'),
              item: v,
              onTap: () => _play(v),
            );
          },
        );
      },
    );
  }

  /// Shared transport controls. [asBottomBar] renders it as the compact
  /// bottom bar (portrait phone); otherwise it renders as a centered panel
  /// (landscape right rail).
  Widget _buildControlPanel({required bool asBottomBar}) {
    final connected = _connected;
    final compact = asBottomBar && MediaQuery.sizeOf(context).height < 520;
    final buttonSize = compact ? 40.0 : 48.0;
    final theme = Theme.of(context);

    final controls = ListenableBuilder(
      listenable: _ui,
      builder: (context, _) {
        final playing = _ui.showPlaying;
        final dur = _ui.status.durMs;
        final pos = _ui.status.posMs.clamp(0, dur > 0 ? dur : 0);
        final shownPos =
            (_ui.dragging ? (_ui.dragMs ?? pos.toDouble()) : pos.toDouble())
                .toDouble();
        return Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Row(
              children: [
                _TransportButton(
                  icon: playing ? Icons.pause : Icons.play_arrow,
                  // Resume/pause only makes sense once a video was selected:
                  // resume on an empty player silently does nothing, which
                  // reads as "no reaction" and invites double taps.
                  tooltip: playing
                      ? 'Pause'
                      : (_ui.status.path != null
                            ? 'Resume'
                            : 'Pick a video first'),
                  size: buttonSize,
                  filled: true,
                  onPressed: connected && (playing || _ui.status.path != null)
                      ? _togglePlay
                      : null,
                ),
                const SizedBox(width: 8),
                _TransportButton(
                  icon: Icons.stop,
                  tooltip: 'Stop',
                  size: buttonSize,
                  onPressed: connected ? _stop : null,
                ),
                const Spacer(),
                _VolumeButton(
                  icon: Icons.volume_down,
                  tooltip: 'Volume down',
                  size: buttonSize,
                  onPressed: connected ? () => _stepVolume(-10) : null,
                ),
                Container(
                  constraints: const BoxConstraints(minWidth: 44),
                  child: Text(
                    '${_ui.status.volume}',
                    textAlign: TextAlign.center,
                    style: const TextStyle(
                      fontSize: 14,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ),
                _VolumeButton(
                  icon: Icons.volume_up,
                  tooltip: 'Volume up',
                  size: buttonSize,
                  onPressed: connected ? () => _stepVolume(10) : null,
                ),
              ],
            ),
            SizedBox(height: compact ? 2 : 6),
            Row(
              children: [
                Text(
                  _fmtMs(shownPos.round()),
                  style: const TextStyle(fontSize: 11, color: Colors.white54),
                ),
                Expanded(
                  child: SliderTheme(
                    data: SliderTheme.of(context).copyWith(
                      trackHeight: 3,
                      thumbShape: const RoundSliderThumbShape(
                        enabledThumbRadius: 7,
                      ),
                      overlayShape: const RoundSliderOverlayShape(
                        overlayRadius: 14,
                      ),
                    ),
                    child: Slider(
                      value: (dur > 0 ? shownPos : 0.0).clamp(
                        0.0,
                        dur > 0 ? dur.toDouble() : 1.0,
                      ),
                      max: dur > 0 ? dur.toDouble() : 1.0,
                      onChangeStart: connected && dur > 0
                          ? (_) => _ui.mutate(() {
                              _ui.dragging = true;
                              _ui.dragMs = pos.toDouble();
                            })
                          : null,
                      onChanged: connected && dur > 0
                          ? (v) => _ui.mutate(() => _ui.dragMs = v)
                          : null,
                      onChangeEnd: connected && dur > 0
                          ? (v) {
                              final target = v.round();
                              final s = _ui.status;
                              _ui.mutate(() {
                                _ui.dragging = false;
                                _ui.dragMs = null;
                                _ui.status = CastStatus(
                                  paired: s.paired,
                                  playing: s.playing,
                                  posMs: target,
                                  durMs: s.durMs,
                                  path: s.path,
                                  serverOk: s.serverOk,
                                  rate: s.rate,
                                  volume: s.volume,
                                );
                              });
                              widget.remote.seek(target).catchError((_) {});
                            }
                          : null,
                    ),
                  ),
                ),
                Text(
                  _fmtMs(dur),
                  style: const TextStyle(fontSize: 11, color: Colors.white54),
                ),
              ],
            ),
          ],
        );
      },
    );

    if (asBottomBar) {
      return SafeArea(
        child: Container(
          decoration: BoxDecoration(
            color: theme.colorScheme.surface.withValues(alpha: 0.6),
            border: Border(
              top: BorderSide(
                color: theme.colorScheme.outline.withValues(alpha: 0.2),
              ),
            ),
          ),
          padding: EdgeInsets.fromLTRB(
            16,
            compact ? 6 : 10,
            16,
            compact ? 6 : 10,
          ),
          child: controls,
        ),
      );
    }
    // Landscape right rail: card with a header, centered vertically.
    return Center(
      child: Container(
        width: 320,
        margin: const EdgeInsets.all(20),
        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 24),
        decoration: BoxDecoration(
          color: theme.colorScheme.surface.withValues(alpha: 0.7),
          borderRadius: BorderRadius.circular(20),
          border: Border.all(
            color: theme.colorScheme.outline.withValues(alpha: 0.2),
          ),
        ),
        child: controls,
      ),
    );
  }

  Widget _buildControls() => _buildControlPanel(asBottomBar: true);

  static String _fmtMs(int ms) {
    final s = (ms / 1000).round();
    final h = s ~/ 3600;
    final m = (s % 3600) ~/ 60;
    final sec = s % 60;
    final mm = m.toString().padLeft(2, '0');
    final ss = sec.toString().padLeft(2, '0');
    return h > 0 ? '$h:$mm:$ss' : '$mm:$ss';
  }
}

/// Grid cell for a subdirectory (folder icon + name).
class _FolderGridCell extends StatelessWidget {
  final String name;
  final VoidCallback onTap;
  const _FolderGridCell({required this.name, required this.onTap});

  @override
  Widget build(BuildContext context) {
    return Card(
      clipBehavior: Clip.antiAlias,
      color: const Color(0xFF1E1E30),
      child: InkWell(
        onTap: onTap,
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.folder, size: 44, color: Color(0xFFFFB74D)),
            const SizedBox(height: 8),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 8),
              child: Text(
                name,
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
                textAlign: TextAlign.center,
                style: const TextStyle(fontSize: 12),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

/// Grid cell for an image file (PooledImage thumbnail).
class _ImageGridCell extends StatelessWidget {
  final MediaItem item;
  final VoidCallback onTap;
  const _ImageGridCell({super.key, required this.item, required this.onTap});

  @override
  Widget build(BuildContext context) {
    return Card(
      clipBehavior: Clip.antiAlias,
      color: const Color(0xFF1E1E30),
      child: InkWell(
        onTap: onTap,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Expanded(
              child: PooledImage(
                url: item.url,
                fit: BoxFit.cover,
                // Same size as the main image grid so caches are shared.
                decodeWidth: 400,
                errorWidget: Container(
                  color: const Color(0xFF2A2A3E),
                  child: const Icon(
                    Icons.broken_image_outlined,
                    color: Colors.white38,
                    size: 40,
                  ),
                ),
              ),
            ),
            Padding(
              padding: const EdgeInsets.all(6),
              child: Text(
                item.name,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: const TextStyle(fontSize: 12),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _TransportButton extends StatelessWidget {
  final IconData icon;
  final String tooltip;
  final double size;
  final bool filled;
  final VoidCallback? onPressed;
  const _TransportButton({
    required this.icon,
    required this.tooltip,
    required this.size,
    this.filled = false,
    this.onPressed,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final Widget child = Icon(icon, size: size * 0.55);
    if (!filled) {
      return IconButton(
        tooltip: tooltip,
        icon: child,
        iconSize: size * 0.55,
        onPressed: onPressed,
      );
    }
    return IconButton.filled(
      tooltip: tooltip,
      iconSize: size * 0.55,
      style: IconButton.styleFrom(
        backgroundColor: theme.colorScheme.primary,
        foregroundColor: theme.colorScheme.onPrimary,
        minimumSize: Size(size, size),
      ),
      onPressed: onPressed,
      icon: child,
    );
  }
}

class _VolumeButton extends StatelessWidget {
  final IconData icon;
  final String tooltip;
  final double size;
  final VoidCallback? onPressed;
  const _VolumeButton({
    required this.icon,
    required this.tooltip,
    required this.size,
    this.onPressed,
  });

  @override
  Widget build(BuildContext context) {
    return IconButton(
      tooltip: tooltip,
      icon: Icon(icon),
      iconSize: size * 0.5,
      onPressed: onPressed,
    );
  }
}

/// Transport state that changes every second (poll-driven) or on transport
/// taps. Held in a [ChangeNotifier] so the 1s poll notifies ONLY the small
/// status bar + control panel listeners; the media browser — including every
/// thumbnail — is never rebuilt by polling.
class _CastUiState extends ChangeNotifier {
  CastStatus status = const CastStatus(
    paired: true,
    playing: false,
    posMs: 0,
    durMs: 0,
    serverOk: false,
    rate: 1.0,
  );

  /// Optimistic transport state: set immediately on tap, cleared when the
  /// next status poll confirms (or contradicts) the server.
  bool? localPlaying;

  /// Seek slider drag state: while dragging, the slider shows local value
  /// and only /v1/seek is fired once on release.
  bool dragging = false;
  double? dragMs;

  bool get showPlaying => localPlaying ?? status.playing;

  /// Apply [fn] and notify listeners once (the only way to mutate state).
  void mutate(void Function() fn) {
    fn();
    notifyListeners();
  }
}
