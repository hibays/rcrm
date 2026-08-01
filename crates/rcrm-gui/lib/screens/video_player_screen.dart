// screens/video_player_screen.dart — media_kit video player
//
// Desktop: hover shows/hides controls, mouse move resets idle timer.
// Mobile: tap toggles controls, left-zone swipe = seek/brightness,
//         right-zone swipe = volume. Long-press = 2x speed.

import 'dart:async';
import 'dart:io' show Platform;
import 'dart:math';
import 'package:flutter/material.dart';
import 'package:flutter/gestures.dart';
import 'package:window_manager/window_manager.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:media_kit/media_kit.dart';
import 'package:media_kit_video/media_kit_video.dart';
import 'package:screen_brightness/screen_brightness.dart';
import '../models/media_item.dart';
import '../services/net.dart';
import '../providers/library_provider.dart';
import '../providers/settings_provider.dart';
import '../providers/window_chrome_provider.dart';
import '../widgets/video_card.dart';
import '../widgets/media_player_keys.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../widgets/player_controls.dart';
import '../widgets/finger_preview_listener.dart';
import '../widgets/player_settings_panel.dart';

class VideoPlayerScreen extends ConsumerStatefulWidget {
  final MediaItem item;
  final bool startFullscreen;
  const VideoPlayerScreen({
    super.key,
    required this.item,
    this.startFullscreen = false,
  });
  @override
  ConsumerState<VideoPlayerScreen> createState() => _State();
}

enum _OverlayType { brightness, volume }

class _State extends ConsumerState<VideoPlayerScreen> {
  Player? p;
  VideoController? vc;

  StreamSubscription? _posSub;
  StreamSubscription? _durSub;
  StreamSubscription? _bufSub;
  StreamSubscription? _playingSub;
  StreamSubscription? _completedSub;
  bool show2x = false;
  bool fullscreen = false;
  Duration _fadeMs = const Duration(milliseconds: 200);
  bool _showControls = true;
  Timer? _hideTimer;
  Timer? _exitTimer;
  static const _idleSecs = 2;
  final List<MediaItem> hist = [];
  final _videoKey = GlobalKey();

  /// Persistent focus node for keyboard shortcuts. `Focus(autofocus: true)`
  /// only grabs focus on first mount; clicking a slider/button moves focus
  /// away and arrows/space/ESC stop reaching the CallbackShortcuts. We
  /// re-request focus on any tap so the shortcuts stay alive.
  final _shortcutFocus = FocusNode();
  final _barKey = GlobalKey();

  static SharedPreferences? _volPrefs;
  Timer? _gOverlayTimer;
  double _volume = 100;
  Timer? _videoTapTimer;
  bool _navigating = false;
  // The route being popped if its animation is reversing or the route is gone.
  bool get _isRoutePopping {
    final route = ModalRoute.of(context);
    return route == null || route.animation?.status == AnimationStatus.reverse;
  }

  bool _showSettings = false;
  bool _disposed = false;
  bool _globalImmersive = false;
  double _savedRate = 1.0;
  List<MediaItem>? _relCache;
  int _relCacheGen = -1;
  String? _relCacheUrl;

  // Mini progress bar (shown when controls hidden) — throttled-lightweight.
  final ValueNotifier<Duration> _miniPos = ValueNotifier(Duration.zero);
  final ValueNotifier<Duration> _miniDur = ValueNotifier(Duration.zero);
  final ValueNotifier<Duration> _miniBuf = ValueNotifier(Duration.zero);
  int _miniLastMs = 0;
  ScrollController? _scrollCtrl;
  bool _pip = false;
  bool _pipDismissed = false;
  double _pipX = 0;
  double _pipY = 0;
  double _pipW = 300;
  double _pipH = 169;
  final _fp = FingerPreviewState(); // mobile preview for related-videos list

  bool get _isMobile => Platform.isAndroid || Platform.isIOS;

  // ── Mobile gesture state ─────────────────────────────────
  // mode: 0 none, 1 seek (horizontal), 2 brightness (left vertical), 3 volume (right vertical)
  int _gMode = 0;
  Offset _gStart = Offset.zero;
  double _seekPreviewMs = 0; // previewed position during a horizontal drag
  bool _seeking = false; // show minimal bottom progress bar
  double _pipSeekMs = 0; // seek preview during PiP horizontal drag

  bool _pipSeeking = false;
  _OverlayType? _gOverlayType;
  int _gOverlayValue = 0;
  double _brightness = 1.0;

  static Future<void> _initVolPrefs() async {
    _volPrefs ??= await SharedPreferences.getInstance();
    // volume loaded below after init in initState
  }

  void _prefsSetVol() {
    _volPrefs?.setDouble('player_volume', _volume);
  }

  @override
  void initState() {
    super.initState();
    _initVolPrefs().then((_) {
      if (_volPrefs != null && mounted) {
        final v = _volPrefs!.getDouble('player_volume') ?? 100;
        _volume = v;
        p?.setVolume(v);
      }
    });
    _scrollCtrl = ScrollController();
    _scrollCtrl!.addListener(_onScroll);
    _resetIdle();
    fullscreen = widget.startFullscreen;
    if (_isMobile) {
      ScreenBrightness().application
          .then((b) {
            _brightness = b;
          })
          .catchError((_) {});
      if (fullscreen) {
        SystemChrome.setEnabledSystemUIMode(SystemUiMode.immersiveSticky);
      }
    } else if (fullscreen) {
      windowManager.setFullScreen(true);
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted) {
          ref.read(windowChromeVisibleProvider.notifier).setVisible(false);
        }
      });
    }
    WidgetsBinding.instance.addPostFrameCallback((_) {
      // Guard against a mid-first-frame navigation (_go disposes p and
      // sets _navigating): don't spawn a stray Player on the widget
      // being replaced.
      if (!mounted || _disposed || _navigating) return;
      p = Player();
      vc = VideoController(p!);
      p!.open(Media(widget.item.url, httpHeaders: sharedAuthHeader));
      p!.play();
      p!.setVolume(_volume);
      if (_disposed && p != null) {
        // Disposed before the player finished initializing — tear down now.
        p!.dispose();
        p = null;
        vc = null;
        return;
      }
      if (mounted) setState(() {});
      _posSub = p!.stream.position.listen((pos) {
        final ms = pos.inMilliseconds;
        if ((ms - _miniLastMs).abs() < 100) return;
        _miniLastMs = ms;
        if (mounted) _miniPos.value = pos;
      });
      _durSub = p!.stream.duration.listen((d) {
        if (mounted) _miniDur.value = d;
      });
      _bufSub = p!.stream.buffer.listen((b) {
        if (mounted) _miniBuf.value = b;
      });
      bool hasBeenPlaying = p!.state.playing;
      _playingSub = p!.stream.playing.listen((isPlaying) {
        if (isPlaying) hasBeenPlaying = true;
      });
      bool handlingCompletion = false;
      _completedSub = p!.stream.completed.listen((_) {
        if (!mounted || _disposed || handlingCompletion || _navigating) return;
        if (!hasBeenPlaying) return;
        handlingCompletion = true;
        if (!mounted) return;
        final mode = ref.read(uiSettingsProvider).playbackMode;
        switch (mode) {
          case 'loopAll':
            onNext();
            break;
          case 'loopOne':
            p!.seek(Duration.zero);
            p!.play();
            break;
          case 'pauseAfter':
            break;
        }
        handlingCompletion = false;
      });
      if (_isMobile && fullscreen) {
        Future.delayed(const Duration(milliseconds: 700), () {
          if (mounted) _applyOrientation();
        });
      }
    });
  }

  @override
  void dispose() {
    _disposed = true;
    _posSub?.cancel();
    _durSub?.cancel();
    _bufSub?.cancel();
    _playingSub?.cancel();
    _completedSub?.cancel();
    _videoTapTimer?.cancel();
    _gOverlayTimer?.cancel();
    _scrollCtrl?.dispose();
    _miniPos.dispose();
    _miniDur.dispose();
    _miniBuf.dispose();
    _hideTimer?.cancel();
    _exitTimer?.cancel();
    p?.stop();
    _shortcutFocus.dispose();
    p?.dispose();
    p = null;
    vc = null;
    if (_isMobile) {
      // When navigating to another player (_go), the new screen manages its
      // own UI mode/orientation. Resetting here would override its immersive
      // fullscreen with edge-to-edge (system bars reappear mid-transition).
      if (!_navigating) {
        SystemChrome.setEnabledSystemUIMode(SystemUiMode.edgeToEdge);
        SystemChrome.setPreferredOrientations(DeviceOrientation.values);
      }
    } else if (fullscreen && !_navigating) {
      if (!_globalImmersive) {
        windowManager.setFullScreen(false);
      }
      Future(
        () => ref.read(windowChromeVisibleProvider.notifier).setVisible(true),
      );
    }
    super.dispose();
  }

  // and lock orientation to the video aspect.
  void _setFullscreen(bool on) {
    setState(() => fullscreen = on);
    _globalImmersive = ref.read(immersiveModeProvider);
    if (_isMobile) {
      SystemChrome.setEnabledSystemUIMode(
        on ? SystemUiMode.immersiveSticky : SystemUiMode.edgeToEdge,
      );
      _applyOrientation();
    } else {
      if (on || !_globalImmersive) {
        windowManager.setFullScreen(on);
      }
    }
    ref.read(windowChromeVisibleProvider.notifier).setVisible(!on);
  }

  // Mobile fullscreen: lock orientation to the video's aspect (landscape for
  // wide videos, portrait for tall); free rotation again when not fullscreen
  // or when auto-rotate is enabled.
  void _applyOrientation() {
    if (!_isMobile) return;
    if (!fullscreen) {
      SystemChrome.setPreferredOrientations(DeviceOrientation.values);
      return;
    }
    final autoRotate = ref.read(uiSettingsProvider).autoRotate;
    if (autoRotate) {
      SystemChrome.setPreferredOrientations(DeviceOrientation.values);
      return;
    }
    final w = p?.state.width ?? 0;
    final h = p?.state.height ?? 0;
    final landscape = w == 0 || w >= h; // default landscape if unknown
    SystemChrome.setPreferredOrientations(
      landscape
          ? const [
              DeviceOrientation.landscapeLeft,
              DeviceOrientation.landscapeRight,
            ]
          : const [
              DeviceOrientation.portraitUp,
              DeviceOrientation.portraitDown,
            ],
    );
  }

  void _togglePlayPause() {
    if (p == null) return;
    p!.state.playing ? p!.pause() : p!.play();
  }

  // ── Show/hide ─────────────────────────────────────────────
  void _show() {
    _exitTimer?.cancel();
    _hideTimer?.cancel();
    _fadeMs = const Duration(milliseconds: 80);
    if (!_showControls && mounted) setState(() => _showControls = true);
  }

  void _poke() {
    _show();
    _resetIdle();
  }

  void _resetIdle() {
    _hideTimer?.cancel();
    _fadeMs = const Duration(milliseconds: 200);
    _hideTimer = Timer(const Duration(seconds: _idleSecs), () {
      if (mounted) setState(() => _showControls = false);
    });
  }

  void _onVideoExit(_) {
    _exitTimer?.cancel();
    _hideTimer?.cancel();
    _fadeMs = const Duration(milliseconds: 200);
    _exitTimer = Timer(const Duration(milliseconds: 100), () {
      if (mounted) setState(() => _showControls = false);
    });
  }

  void _onBarEnter(_) {
    _exitTimer?.cancel();
    _hideTimer?.cancel();
    _show();
  }

  void _onBarExit(_) {
    if (!_showControls) return;
    _resetIdle();
  }

  void _onTap() {
    if (!_isMobile) return;
    _shortcutFocus.requestFocus();
    setState(() {
      if (_showControls) {
        _showControls = false;
        _hideTimer?.cancel();
      } else {
        _showControls = true;
        _resetIdle();
      }
    });
  }

  // ── Mobile gesture handlers (direction-locked) ──────────
  void _onPanStart(DragStartDetails d) {
    if (!_isMobile) return;
    _gMode = 0;
    _gStart = d.localPosition;
  }

  void _onPanUpdate(DragUpdateDetails d, Size size) {
    if (!_isMobile || p == null) return;
    final dx = d.localPosition.dx - _gStart.dx;
    final dy = d.localPosition.dy - _gStart.dy;
    // Lock direction once movement is significant.
    if (_gMode == 0) {
      if (dx.abs() < 12 && dy.abs() < 12) return;
      if (dx.abs() > dy.abs()) {
        _gMode = 1; // seek
        _seekPreviewMs = p!.state.position.inMilliseconds.toDouble();
        _hideTimer?.cancel();
        // While seeking, show ONLY the minimal seek bar — hide full controls.
        setState(() {
          _seeking = true;
          _showControls = false;
        });
      } else {
        _gMode = (_gStart.dx < size.width / 2)
            ? 2
            : 3; // left=brightness, right=volume
      }
    }
    if (_gMode == 1) {
      final dur = p!.state.duration.inMilliseconds.toDouble();
      if (dur > 0) {
        // full-width drag ≈ whole duration
        _seekPreviewMs = (_seekPreviewMs + (d.delta.dx / size.width) * dur)
            .clamp(0, dur);
        setState(() {});
      }
    } else if (_gMode == 2) {
      _brightness = (_brightness - d.delta.dy / size.height).clamp(0.0, 1.0);
      try {
        ScreenBrightness().setApplicationScreenBrightness(_brightness);
      } catch (_) {}
      setState(() {
        _gOverlayType = _OverlayType.brightness;
        _gOverlayValue = (_brightness * 100).round();
      });
    } else if (_gMode == 3) {
      final v = (p!.state.volume - (d.delta.dy / size.height) * 100).clamp(
        0.0,
        100.0,
      );
      p!.setVolume(v);
      setState(() {
        _gOverlayType = _OverlayType.volume;
        _gOverlayValue = v.round();
      });
    }
  }

  void _onPanEnd(_) {
    if (!_isMobile) return;
    if (_gMode == 1 && p != null) {
      p!.seek(Duration(milliseconds: _seekPreviewMs.round()));
    }
    _gMode = 0;
    setState(() {
      _seeking = false;
      _gOverlayType = null;
    });
    _resetIdle();
  }

  void _onScroll() {
    if (!_scrollCtrl!.hasClients || fullscreen) return;
    if (!ref.read(uiSettingsProvider).pipEnabled) return;
    final pipSize = ref.read(uiSettingsProvider).pipSize;
    final vh = (context.size?.width ?? 400) / 16 * 9;
    final playing = p?.state.playing == true;
    final show = _scrollCtrl!.offset > vh * 0.7 && playing;
    if (!show) _pipDismissed = false;
    if (_pipDismissed) return;
    if (show != _pip && mounted) {
      if (show) {
        if (pipSize == 'small') {
          _pipW = 200;
          _pipH = 113;
          final sw = MediaQuery.of(context).size.width;
          _pipX = sw - _pipW;
        } else {
          _pipW = context.size?.width ?? MediaQuery.of(context).size.width;
          _pipH = _pipW * 9 / 16;
          _pipX = 0;
        }
      }
      setState(() => _pip = show);
    }
  }

  // ── Navigation ─────────────────────────────────────────
  int _urlSeed(String url) =>
      url.codeUnits.fold(0, (h, c) => ((h << 5) + h) ^ c);

  List<MediaItem> _relFor(MediaItem vid, List<MediaItem> allVideos) {
    final dir = vid.name.contains('/')
        ? vid.name.substring(0, vid.name.lastIndexOf('/') + 1)
        : '';
    final seed = _urlSeed(vid.url);
    final rng = Random(seed);

    var all = allVideos.where((v) => v.path != vid.path).toList();

    // Fisher-Yates shuffle with seeded RNG
    for (var i = all.length - 1; i > 0; i--) {
      final j = rng.nextInt(i + 1);
      final tmp = all[i];
      all[i] = all[j];
      all[j] = tmp;
    }

    // Stable priority: same-directory first, then same-extension, then rest
    final sameDir = <MediaItem>[];
    final sameExt = <MediaItem>[];
    final rest = <MediaItem>[];
    for (final v in all) {
      final vDir = v.name.contains('/')
          ? v.name.substring(0, v.name.lastIndexOf('/') + 1)
          : '';
      if (vDir == dir && dir.isNotEmpty) {
        sameDir.add(v);
      } else if (v.extension == vid.extension) {
        sameExt.add(v);
      } else {
        rest.add(v);
      }
    }
    return [...sameDir, ...sameExt, ...rest].take(24).toList();
  }

  void onNext() {
    if (_navigating || _isRoutePopping) return;
    final r = _relFor(widget.item, ref.read(videosListProvider));
    if (r.isEmpty) return;
    hist.add(widget.item);
    _go(r.first);
  }

  void onPrev() {
    if (_navigating || _isRoutePopping) return;
    if (hist.isEmpty) return;
    _go(hist.removeLast());
  }

  void _go(MediaItem item) {
    if (_navigating || _isRoutePopping) return;
    _navigating = true;
    // Tear down our Player/Video synchronously so the outgoing route doesn't
    // keep rendering a disposed texture during the transition (black screen).
    _posSub?.cancel();
    _durSub?.cancel();
    _bufSub?.cancel();
    _playingSub?.cancel();
    _completedSub?.cancel();
    _scrollCtrl?.removeListener(_onScroll);
    p?.stop();
    p?.dispose();
    p = null;
    vc = null;
    if (mounted) setState(() {});
    Navigator.pushReplacement(
      context,
      MaterialPageRoute(
        builder: (_) =>
            VideoPlayerScreen(item: item, startFullscreen: fullscreen),
      ),
    );
  }

  // Keyboard shortcuts (space/arrows/F/ESC) — the verified global-key
  // approach (MediaPlayerKeys wraps HardwareKeyboard, so it works even
  // when no Flutter widget holds focus). Wraps BOTH the fullscreen and
  // normal layouts.
  Widget _withShortcuts(Widget child) {
    return Focus(
      focusNode: _shortcutFocus,
      autofocus: true,
      child: MediaPlayerKeys(
        actions: MediaPlayerKeyActions(
          onTogglePlay: () {
            if (p != null) {
              if (p!.state.playing) {
                p!.pause();
              } else {
                p!.play();
              }
            }
          },
          onSeek: (delta) {
            if (p == null) return;
            final pos = p!.state.position + delta;
            p!.seek(Duration(seconds: pos.inSeconds.clamp(0, 999999)));
          },
          onVolume: (delta) {
            _volume = (_volume + delta * 100).clamp(0, 100);
            p?.setVolume(_volume);
          },
          onEscape: fullscreen ? () => _setFullscreen(false) : null,
          onToggleFullscreen: _isMobile
              ? null
              : () => _setFullscreen(!fullscreen),
        ),
        child: child,
      ),
    );
  }

  @override
  Widget build(BuildContext c) {
    final allVideos = ref.watch(videosListProvider);
    final scanGen = ref.watch(scanStateProvider).scanGen;
    final List<MediaItem> related;
    if (_relCache != null &&
        _relCacheGen == scanGen &&
        _relCacheUrl == widget.item.url) {
      related = _relCache!;
    } else {
      related = _relFor(widget.item, allVideos);
      _relCache = related;
      _relCacheGen = scanGen;
      _relCacheUrl = widget.item.url;
    }
    final size = MediaQuery.of(c).size;
    final isLandscape = size.width > size.height;
    final wide = _isMobile
        ? (isLandscape && size.width > 600)
        : size.width > 900;
    final video = _video();
    if (fullscreen) {
      return _withShortcuts(
        PopScope(
          canPop: false,
          onPopInvokedWithResult: (didPop, _) {
            if (!didPop) _setFullscreen(false);
          },
          child: Scaffold(
            backgroundColor: Colors.black,
            body: MouseRegion(
              onHover: (_) => _poke(),
              onEnter: (_) => _show(),
              child: Listener(
                onPointerDown: (_) => _shortcutFocus.requestFocus(),
                onPointerSignal: (event) {
                  if (event is PointerScrollEvent) {
                    final dy = event.scrollDelta.dy;
                    if (dy.abs() > 0) {
                      final step = dy > 0 ? -5 : 5;
                      final nv = (_volume + step).clamp(0.0, 100.0);
                      if (nv != _volume) {
                        _volume = nv;
                        p?.setVolume(_volume);
                        _prefsSetVol();
                        _resetIdle();
                      }
                      _gOverlayTimer?.cancel();
                      if (mounted) {
                        setState(() {
                          _gOverlayType = _OverlayType.volume;
                          _gOverlayValue = _volume.round();
                        });
                      }
                      _gOverlayTimer = Timer(const Duration(seconds: 1), () {
                        if (mounted) setState(() => _gOverlayType = null);
                      });
                    }
                  }
                },
                child: Stack(
                  children: [
                    _wrapPointer(
                      Center(
                        child: vc != null
                            ? Video(
                                key: ValueKey('video_fs_$fullscreen'),
                                controller: vc!,
                                fit: BoxFit.contain,
                                controls: NoVideoControls,
                              )
                            : const SizedBox(),
                      ),
                    ),
                    if (_isMobile)
                      Positioned(
                        top: 0,
                        left: 0,
                        right: 0,
                        child: IgnorePointer(
                          ignoring: !_showControls,
                          child: AnimatedOpacity(
                            opacity: _showControls ? 1.0 : 0.0,
                            duration: _fadeMs,
                            child: _topTitleBar(),
                          ),
                        ),
                      ),
                    Positioned(
                      bottom: 0,
                      left: 0,
                      right: 0,
                      child: IgnorePointer(
                        ignoring: !_showControls,
                        child: AnimatedOpacity(
                          opacity: _showControls ? 1.0 : 0.0,
                          duration: _fadeMs,
                          child: _bar(),
                        ),
                      ),
                    ),
                    if (_seeking) _seekBar(),
                    if (show2x) _speedBadge(),
                    if (_gOverlayType != null) _centerOverlay(),
                    if (_showSettings) _settingsOverlay(),
                  ],
                ),
              ),
            ),
          ),
        ),
      );
    }

    final narrow = CustomScrollView(
      controller: _scrollCtrl,
      slivers: [
        SliverToBoxAdapter(
          child: _pip ? SizedBox(width: _pipW, height: _pipH) : video,
        ),
        SliverToBoxAdapter(child: _meta()),
        if (related.isNotEmpty) ...[
          SliverToBoxAdapter(
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Row(
                children: [
                  Container(
                    width: 4,
                    height: 4,
                    decoration: const BoxDecoration(
                      color: Color(0xFFFF6B00),
                      shape: BoxShape.circle,
                    ),
                  ),
                  const SizedBox(width: 8),
                  const Text(
                    'Related',
                    style: TextStyle(
                      color: Colors.white70,
                      fontSize: 16,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ],
              ),
            ),
          ),
          SliverList(
            delegate: SliverChildBuilderDelegate(
              (_, i) => _relItem(related[i]),
              childCount: related.length,
            ),
          ),
        ],
      ],
    );
    final body = wide
        ? Row(
            children: [
              Expanded(
                flex: 3,
                child: SingleChildScrollView(
                  child: Column(
                    children: [
                      _pip ? SizedBox(width: _pipW, height: _pipH) : video,
                      _meta(),
                    ],
                  ),
                ),
              ),
              if (related.isNotEmpty)
                SizedBox(width: 380, child: _related(related)),
            ],
          )
        : (FingerPreviewState.isMobile
              ? Listener(
                  onPointerDown: (e) => _fp.onPointerDown(e, setState),
                  child: narrow,
                )
              : narrow);
    return _withShortcuts(
      Scaffold(
        backgroundColor: Colors.black,
        body: SafeArea(
          child: Stack(
            children: [
              body,
              if (_pip &&
                  !fullscreen &&
                  ref.watch(uiSettingsProvider).pipEnabled)
                _pipWidget(),
              if (_showSettings) _settingsOverlay(),
            ],
          ),
        ),
      ),
    );
  }

  Widget _wrapPointer(Widget child) {
    if (_isMobile) {
      return LayoutBuilder(
        builder: (_, c) {
          final sz = Size(c.maxWidth, c.maxHeight);
          return GestureDetector(
            onTap: _onTap,
            onDoubleTap: _togglePlayPause,
            onPanStart: _onPanStart,
            onPanUpdate: (d) => _onPanUpdate(d, sz),
            onPanEnd: _onPanEnd,
            onLongPressStart: (_) {
              _savedRate = p?.state.rate ?? 1.0;
              p?.setRate(2.0);
              setState(() => show2x = true);
            },
            onLongPressEnd: (_) {
              p?.setRate(_savedRate);
              setState(() => show2x = false);
            },
            child: child,
          );
        },
      );
    }
    return GestureDetector(
      onTapDown: (_) {},
      onTap: () {
        _shortcutFocus.requestFocus();
        if (_videoTapTimer == null) {
          _videoTapTimer = Timer(const Duration(milliseconds: 300), () {
            _videoTapTimer = null;
            _togglePlayPause();
          });
        } else {
          _videoTapTimer!.cancel();
          _videoTapTimer = null;
          _setFullscreen(!fullscreen);
        }
      },
      onLongPressStart: (_) {
        _savedRate = p?.state.rate ?? 1.0;
        p?.setRate(2.0);
        setState(() => show2x = true);
      },
      onLongPressEnd: (_) {
        p?.setRate(_savedRate);
        setState(() => show2x = false);
      },
      child: child,
    );
  }

  Widget _video() => MouseRegion(
    key: _videoKey,
    onHover: (_) => _poke(),
    onEnter: (_) => _show(),
    onExit: _onVideoExit,
    child: Stack(
      children: [
        _wrapPointer(
          AspectRatio(
            aspectRatio: 16 / 9,
            child: Stack(
              children: [
                vc != null
                    ? Video(
                        key: ValueKey('video_norm'),
                        controller: vc!,
                        fit: BoxFit.contain,
                        controls: NoVideoControls,
                      )
                    : const Center(child: CircularProgressIndicator()),
                if (!_showControls && p != null && !_seeking)
                  Positioned(bottom: 0, left: 0, right: 0, child: _miniBar()),
              ],
            ),
          ),
        ),
        Positioned(
          top: 0,
          left: 0,
          child: IgnorePointer(
            ignoring: !_showControls,
            child: AnimatedOpacity(
              opacity: _showControls ? 1.0 : 0.0,
              duration: _fadeMs,
              child: SafeArea(
                bottom: false,
                child: IconButton(
                  icon: const Icon(Icons.arrow_back, color: Colors.white70),
                  onPressed: () => Navigator.pop(context),
                ),
              ),
            ),
          ),
        ),
        Positioned(
          bottom: 0,
          left: 0,
          right: 0,
          child: IgnorePointer(
            ignoring: !_showControls,
            child: AnimatedOpacity(
              opacity: _showControls ? 1.0 : 0.0,
              duration: _fadeMs,
              child: _bar(),
            ),
          ),
        ),
        if (show2x) _speedBadge(),
        if (_seeking) _seekBar(),
        if (_gOverlayType != null) _centerOverlay(),
      ],
    ),
  );

  // Fullscreen top title bar (mobile): fades with the controls.
  Widget _topTitleBar() => Container(
    padding: const EdgeInsets.fromLTRB(16, 12, 16, 12),
    decoration: const BoxDecoration(
      gradient: LinearGradient(
        begin: Alignment.topCenter,
        end: Alignment.bottomCenter,
        colors: [Color(0xB3000000), Color(0x00000000)],
      ),
    ),
    child: Text(
      widget.item.name,
      style: const TextStyle(
        color: Colors.white,
        fontSize: 15,
        fontWeight: FontWeight.w500,
      ),
      maxLines: 1,
      overflow: TextOverflow.ellipsis,
    ),
  );

  Widget _bar() => p == null
      ? const SizedBox.shrink()
      : MouseRegion(
          key: _barKey,
          onEnter: _onBarEnter,
          onExit: _onBarExit,
          child: PlayerControls(
            player: p!,
            onPrev: null,
            onNext: onNext,
            onSettingsTap: () => setState(() => _showSettings = !_showSettings),
            showFullscreen: fullscreen,
            onFullscreen: () => _setFullscreen(!fullscreen),
            scale: fullscreen ? 1.3 : 1.0,
          ),
        );

  // Minimal bottom progress bar shown while horizontal-seeking (no full controls).
  Widget _seekBar() {
    final dur = (p?.state.duration.inMilliseconds ?? 0).toDouble();
    final pct = dur > 0 ? (_seekPreviewMs / dur).clamp(0.0, 1.0) : 0.0;
    return Positioned(
      bottom: 0,
      left: 0,
      right: 0,
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(12, 8, 12, 0),
            child: Text(
              '${_fmt(_seekPreviewMs)} / ${_fmt(dur)}',
              style: const TextStyle(color: Colors.white, fontSize: 13),
            ),
          ),
          const SizedBox(height: 6),
          LinearProgressIndicator(
            value: pct,
            minHeight: 4,
            backgroundColor: const Color(0x33FFFFFF),
            valueColor: const AlwaysStoppedAnimation(Color(0xFFFF6B00)),
          ),
          const SizedBox(height: 10),
        ],
      ),
    );
  }

  Widget _miniBar() => ListenableBuilder(
    listenable: Listenable.merge([_miniPos, _miniDur, _miniBuf]),
    builder: (_, _) {
      final d = _miniDur.value.inMilliseconds.toDouble();
      if (d <= 0) return const SizedBox.shrink();
      final pct = (_miniPos.value.inMilliseconds / d).clamp(0.0, 1.0);
      final buf = (_miniBuf.value.inMilliseconds / d).clamp(0.0, 1.0);
      // RepaintBoundary prevents the parent from repainting when the
      // progress bar updates continuously during playback.
      return RepaintBoundary(
        child: Opacity(
          opacity: 0.5,
          child: Stack(
            children: [
              LinearProgressIndicator(
                value: buf,
                minHeight: 1,
                backgroundColor: Colors.transparent,
                valueColor: const AlwaysStoppedAnimation(Color(0x33FFFFFF)),
              ),
              LinearProgressIndicator(
                value: pct,
                minHeight: 1,
                backgroundColor: Colors.transparent,
                valueColor: const AlwaysStoppedAnimation(Color(0xFFFF6B00)),
              ),
            ],
          ),
        ),
      );
    },
  );

  // Compact seek preview overlay for PiP horizontal drag.
  Widget _pipSeekOverlay() {
    final dur = (p?.state.duration.inMilliseconds ?? 0).toDouble();
    final pct = dur > 0 ? (_pipSeekMs / dur).clamp(0.0, 1.0) : 0.0;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(
            '${_fmt(_pipSeekMs)} / ${_fmt(dur)}',
            style: const TextStyle(color: Colors.white, fontSize: 11),
          ),
          const SizedBox(height: 2),
          ClipRRect(
            borderRadius: BorderRadius.circular(2),
            child: LinearProgressIndicator(
              value: pct,
              minHeight: 3,
              backgroundColor: const Color(0x33FFFFFF),
              valueColor: const AlwaysStoppedAnimation(Color(0xFFFF6B00)),
            ),
          ),
        ],
      ),
    );
  }

  void _closePip() {
    p?.pause();
    setState(() {
      _pip = false;
      _pipDismissed = true;
    });
  }

  void _onPipSeekStart(DragStartDetails d) {
    _pipSeekMs = p?.state.position.inMilliseconds.toDouble() ?? 0;
    setState(() => _pipSeeking = true);
  }

  void _onPipSeekUpdate(DragUpdateDetails d) {
    final dur = (p?.state.duration.inMilliseconds ?? 0).toDouble();
    if (dur > 0) {
      _pipSeekMs = (_pipSeekMs + (d.delta.dx / _pipW) * dur).clamp(0, dur);
      setState(() {});
    }
  }

  void _onPipSeekEnd(DragEndDetails d) {
    if (p != null) {
      p!.seek(Duration(milliseconds: _pipSeekMs.round()));
    }
    setState(() => _pipSeeking = false);
  }

  void _onPipDragStart(DragStartDetails d) {
    // no-op: _onPipPanUpdate accumulates from current position
  }

  void _onPipPanUpdate(DragUpdateDetails d) {
    final sw = MediaQuery.of(context).size.width;
    final maxX = (sw - _pipW).clamp(0.0, double.infinity);
    final maxY = (MediaQuery.of(context).size.height - _pipH - 80).clamp(
      0.0,
      double.infinity,
    );
    setState(() {
      _pipX = (_pipX + d.delta.dx).clamp(0.0, maxX);
      _pipY = (_pipY + d.delta.dy).clamp(0.0, maxY);
    });
  }

  void _onPipDragEnd(DragEndDetails d) {
    // clamping already handled per-frame in _onPipPanUpdate
  }
  Widget _pipWidget() {
    final isSmall = ref.watch(uiSettingsProvider).pipSize == 'small';
    return Positioned(
      left: _pipX,
      top: _pipY,
      child: GestureDetector(
        onHorizontalDragStart: isSmall ? null : _onPipSeekStart,
        onHorizontalDragUpdate: isSmall ? null : _onPipSeekUpdate,
        onHorizontalDragEnd: isSmall ? null : _onPipSeekEnd,
        onPanStart: _onPipDragStart,
        onPanUpdate: _onPipPanUpdate,
        onPanEnd: _onPipDragEnd,
        child: Container(
          width: _pipW,
          height: _pipH,
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(6),
            color: Colors.black,
            boxShadow: [
              BoxShadow(
                color: Colors.black.withValues(alpha: 0.5),
                blurRadius: 16,
                offset: const Offset(0, 4),
              ),
            ],
          ),
          clipBehavior: Clip.antiAlias,
          child: Stack(
            children: [
              if (vc != null)
                Video(
                  controller: vc!,
                  fit: BoxFit.contain,
                  controls: NoVideoControls,
                ),
              // Close button
              Positioned(
                top: 4,
                right: 4,
                child: GestureDetector(
                  onTap: _closePip,
                  child: Container(
                    decoration: const BoxDecoration(
                      color: Colors.black54,
                      shape: BoxShape.circle,
                    ),
                    padding: const EdgeInsets.all(6),
                    child: const Icon(
                      Icons.close,
                      size: 18,
                      color: Colors.white,
                    ),
                  ),
                ),
              ),
              // Fullscreen button
              Positioned(
                top: 4,
                right: 40,
                child: GestureDetector(
                  onTap: () {
                    setState(() => _pip = false);
                    _setFullscreen(true);
                  },
                  child: Container(
                    decoration: const BoxDecoration(
                      color: Colors.black54,
                      shape: BoxShape.circle,
                    ),
                    padding: const EdgeInsets.all(6),
                    child: const Icon(
                      Icons.fullscreen,
                      size: 18,
                      color: Colors.white,
                    ),
                  ),
                ),
              ),
              // Seek preview overlay
              if (_pipSeeking)
                Positioned(
                  bottom: 0,
                  left: 0,
                  right: 0,
                  child: _pipSeekOverlay(),
                )
              else
                // Mini progress bar (hidden during seek)
                Positioned(bottom: 0, left: 0, right: 0, child: _miniBar()),
            ],
          ),
        ),
      ),
    );
  }

  // Center chip for brightness/volume gesture feedback.
  Widget _centerOverlay() {
    final isBrightness = _gOverlayType == _OverlayType.brightness;
    final icon = isBrightness ? Icons.brightness_6 : Icons.volume_up;
    final pct = _gOverlayValue / 100;
    return Positioned.fill(
      child: IgnorePointer(
        child: Center(
          child: Container(
            width: 160,
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
            decoration: BoxDecoration(
              color: Colors.black.withValues(alpha: 0.6),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(icon, color: Colors.white, size: 28),
                const SizedBox(height: 8),
                ClipRRect(
                  borderRadius: BorderRadius.circular(2),
                  child: LinearProgressIndicator(
                    value: pct,
                    minHeight: 4,
                    backgroundColor: const Color(0x33FFFFFF),
                    valueColor: AlwaysStoppedAnimation(
                      isBrightness
                          ? const Color(0xFFFFD600)
                          : const Color(0xFFFF6B00),
                    ),
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  '$_gOverlayValue%',
                  style: const TextStyle(color: Colors.white, fontSize: 13),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _speedBadge() {
    return Positioned(
      top: 8,
      left: 0,
      right: 0,
      child: IgnorePointer(
        child: Center(child: _SpeedBadgeWidget(visible: show2x)),
      ),
    );
  }

  Widget _settingsOverlay() {
    final settings = ref.watch(uiSettingsProvider);
    return Positioned.fill(
      child: PlayerSettingsPanel(
        mode: PlaybackMode.fromString(settings.playbackMode),
        onModeChanged: (m) {
          ref.read(uiSettingsProvider.notifier).setPlaybackMode(m.key);
        },
        autoRotate: settings.autoRotate,
        onAutoRotateChanged: (v) {
          ref.read(uiSettingsProvider.notifier).setAutoRotate(v);
          // Re-apply orientation immediately when toggled.
          _applyOrientation();
        },
        onDismiss: () => setState(() => _showSettings = false),
      ),
    );
  }

  String _fmt(double ms) {
    final t = ms.round();
    final m = (t ~/ 60000);
    final s = (t % 60000) ~/ 1000;
    return '${m.toString().padLeft(2, '0')}:${s.toString().padLeft(2, '0')}';
  }

  Widget _meta() => Container(
    padding: const EdgeInsets.all(16),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          widget.item.name,
          style: const TextStyle(
            color: Colors.white,
            fontSize: 20,
            fontWeight: FontWeight.w600,
          ),
        ),
        const SizedBox(height: 8),
        Row(
          children: [
            if (widget.item.durationSeconds != null) ...[
              Text(
                widget.item.formattedDuration,
                style: const TextStyle(color: Colors.white54, fontSize: 13),
              ),
              const SizedBox(width: 8),
              const Text('•', style: TextStyle(color: Colors.white54)),
            ],
            const SizedBox(width: 8),
            Text(
              widget.item.formattedSize,
              style: const TextStyle(color: Colors.white54, fontSize: 13),
            ),
            const SizedBox(width: 8),
            const Text('•', style: TextStyle(color: Colors.white54)),
            const SizedBox(width: 8),
            Text(
              widget.item.extension.toUpperCase(),
              style: const TextStyle(color: Colors.white54, fontSize: 13),
            ),
          ],
        ),
        const SizedBox(height: 12),
        const Divider(color: Colors.white12),
      ],
    ),
  );

  Widget _related(List items) {
    final col = Column(
      children: [
        Padding(
          padding: const EdgeInsets.all(12),
          child: Row(
            children: [
              Container(
                width: 4,
                height: 4,
                decoration: const BoxDecoration(
                  color: Color(0xFFFF6B00),
                  shape: BoxShape.circle,
                ),
              ),
              const SizedBox(width: 8),
              const Text(
                'Related',
                style: TextStyle(
                  color: Colors.white70,
                  fontSize: 16,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
        ),
        Expanded(
          child: ListView.builder(
            padding: const EdgeInsets.symmetric(horizontal: 8),
            itemCount: items.length,
            itemBuilder: (_, i) => _relItem(items[i]),
          ),
        ),
      ],
    );
    if (!FingerPreviewState.isMobile) return col;
    return Listener(
      onPointerDown: (e) => _fp.onPointerDown(e, setState),
      child: col,
    );
  }

  Widget _relItem(MediaItem item) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 4),
    child: SizedBox(
      height: 90,
      child: Row(
        children: [
          Expanded(
            flex: 2,
            child: VideoCard(
              key: _fp.keyFor(item.path),
              item: item,
              preview: _fp.isActive(item.path),
              compact: true,
              onTap: () => _go(item),
            ),
          ),
          const SizedBox(width: 8),
          Expanded(
            flex: 3,
            child: GestureDetector(
              behavior: HitTestBehavior.opaque,
              onTap: () => _go(item),
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    item.name,
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(color: Colors.white, fontSize: 13),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    '${item.formattedSize} • ${item.extension.toUpperCase()}',
                    style: const TextStyle(color: Colors.white54, fontSize: 11),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    ),
  );
}

// ── Animated 2x speed badge ─────────────────────────────────────────

class _SpeedBadgeWidget extends StatefulWidget {
  final bool visible;
  const _SpeedBadgeWidget({required this.visible});

  @override
  State<_SpeedBadgeWidget> createState() => _SpeedBadgeWidgetState();
}

class _SpeedBadgeWidgetState extends State<_SpeedBadgeWidget>
    with SingleTickerProviderStateMixin {
  late final AnimationController _ctrl;

  @override
  void initState() {
    super.initState();
    _ctrl = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 900),
    );
    if (widget.visible) _ctrl.repeat();
  }

  @override
  void didUpdateWidget(covariant _SpeedBadgeWidget old) {
    super.didUpdateWidget(old);
    if (widget.visible && !old.visible) {
      _ctrl.forward(from: 0);
      _ctrl.repeat();
    } else if (!widget.visible && old.visible) {
      _ctrl.stop();
      _ctrl.reset();
    }
  }

  @override
  void dispose() {
    _ctrl.dispose();
    super.dispose();
  }

  static const _accent = Color(0xFFFF6B00);

  // Single play-arrow triangle, opacity driven by animation value.
  Widget _triangle(double phase) {
    final t = (_ctrl.value - phase) % 1.0;
    final opacity = 0.75 + 0.25 * cos(pi * 2 * t);
    return Icon(
      Icons.play_arrow,
      color: _accent.withValues(alpha: opacity),
      size: 18,
    );
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedScale(
      scale: widget.visible ? 1.0 : 0.5,
      duration: const Duration(milliseconds: 200),
      curve: Curves.easeOutBack,
      child: AnimatedOpacity(
        opacity: widget.visible ? 1.0 : 0.0,
        duration: const Duration(milliseconds: 150),
        child: AnimatedBuilder(
          animation: _ctrl,
          builder: (_, child) => Container(
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
            decoration: BoxDecoration(
              color: _accent.withValues(alpha: 0.2),
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: _accent.withValues(alpha: 0.5)),
            ),
            child: child!,
          ),
          // Static subtree extracted so AnimatedBuilder only rebuilds
          // the Container wrapper; the Row content stays cached.
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              SizedBox(
                width: 34,
                child: Stack(
                  children: [
                    _triangle(0.0),
                    Positioned(left: 10, child: _triangle(1 / 3)),
                    Positioned(left: 20, child: _triangle(2 / 3)),
                  ],
                ),
              ),
              const SizedBox(width: 6),
              const Text(
                '2x',
                style: TextStyle(
                  color: _accent,
                  fontSize: 16,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
