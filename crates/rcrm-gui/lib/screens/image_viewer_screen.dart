// screens/image_viewer_screen.dart
// RCrm GUI — full image viewer with per-page pinch zoom, double-tap zoom-to-
// point, long-press to play animated images (gif/apng/webp/avif), and swipe nav.

import 'dart:async';
import 'dart:ui' as ui;
import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/gestures.dart';
import 'package:flutter/services.dart';
import 'dart:io' show Platform;
import '../models/media_item.dart';
import '../widgets/image_wall_strip.dart';

import 'package:media_kit/media_kit.dart';
import 'package:media_kit_video/media_kit_video.dart';
import '../services/item_cache_limit.dart';
import '../services/net.dart';
import '../services/mobile_image_decoder.dart';
import '../services/animated_detector.dart';
import '../services/live_photo.dart';
import '../services/player_factory.dart';
import '../widgets/pooled_image.dart';

enum _ViewerMode { still, animation, live }

/// Keyboard shortcuts: ←/→ page between images, Esc closes the viewer.
class _PrevIntent extends Intent {
  const _PrevIntent();
}

class _NextIntent extends Intent {
  const _NextIntent();
}

class _CloseIntent extends Intent {
  const _CloseIntent();
}

/// In-process sound toggle — defaults to enabled, resets on app restart.
bool _soundEnabled = true;

class ImageViewerScreen extends StatefulWidget {
  final List<MediaItem> items;
  final int initialIndex;

  const ImageViewerScreen({
    super.key,
    required this.items,
    this.initialIndex = 0,
  });

  @override
  State<ImageViewerScreen> createState() => _ImageViewerScreenState();
}

class _ImageViewerScreenState extends State<ImageViewerScreen> {
  late PageController _pageController;
  late int _currentIndex;
  final ValueNotifier<bool> _showUI = ValueNotifier(true);
  final ValueNotifier<bool> _showArrows = ValueNotifier(false);
  static final _isDesktop = !Platform.isAndroid && !Platform.isIOS;
  bool _popped = false;
  bool _navAnimating = false;

  final Map<int, TransformationController> _controllers = {};
  TransformationController _ctrlFor(int i) =>
      _controllers.putIfAbsent(i, () => TransformationController());

  @override
  void initState() {
    super.initState();
    _currentIndex = widget.initialIndex;
    _pageController = PageController(initialPage: _currentIndex);
    // zoom state tracked per-page in _ViewerPageState
  }

  @override
  void dispose() {
    _pageController.dispose();
    for (final c in _controllers.values) {
      c.dispose();
    }
    _showArrows.dispose();
    _showUI.dispose();
    super.dispose();
  }

  void _showInfo() {
    final item = widget.items[_currentIndex];
    showDialog(
      context: context,
      builder: (_) => AlertDialog(
        title: Text(item.name),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text("Type: ${item.extension.toUpperCase()}"),
            const SizedBox(height: 4),
            Text("Size: ${item.formattedSize}"),
            if (item.durationSeconds != null)
              Text("Duration: ${item.formattedDuration}"),
            if (item.resolution != null) Text("Resolution: ${item.resolution}"),
            if (item.modified != null)
              Text("Modified: ${item.modified.toString().substring(0, 19)}"),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text("OK"),
          ),
        ],
      ),
    );
  }

  void _close() {
    if (_popped) return;
    _popped = true;
    Navigator.of(context).pop();
  }

  void _zoom(double factor) {
    final c = _ctrlFor(_currentIndex);
    final s = (c.value.getMaxScaleOnAxis() * factor).clamp(1.0, 6.0);
    c.value = Matrix4.identity()..scaleByDouble(s, s, s, 1.0);
  }

  /// Page ±1 with the same animated navigation the arrow buttons use.
  void _goTo(int delta) {
    if (_navAnimating) return;
    final target = _currentIndex + delta;
    if (target < 0 || target >= widget.items.length) return;
    _navAnimating = true;
    _pageController
        .animateToPage(
          target,
          duration: const Duration(milliseconds: 300),
          curve: Curves.easeInOut,
        )
        .whenComplete(() {
          if (mounted) setState(() => _navAnimating = false);
        });
  }

  Widget _chrome(Widget child) => ValueListenableBuilder<bool>(
    valueListenable: _showUI,
    builder: (_, show, c) => IgnorePointer(
      ignoring: !show,
      child: AnimatedOpacity(
        opacity: show ? 1 : 0,
        duration: const Duration(milliseconds: 100),
        child: c,
      ),
    ),
    child: child,
  );

  /// Desktop: arrows auto-hide, show on hover with 120ms fade.
  /// Mobile: arrows follow _showUI (unchanged).
  Widget _arrowChrome(Widget arrow) {
    if (_isDesktop) {
      return ValueListenableBuilder<bool>(
        valueListenable: _showArrows,
        builder: (_, show, child) => IgnorePointer(
          ignoring: !show,
          child: AnimatedOpacity(
            opacity: show ? 1 : 0,
            duration: const Duration(milliseconds: 120),
            child: child,
          ),
        ),
        child: arrow,
      );
    }
    return _chrome(arrow);
  }

  Widget _buildPrevArrow() => _ArrowButton(
    icon: Icons.chevron_left,
    onTap: () => _goTo(-1),
    isDesktop: _isDesktop,
  );

  Widget _buildNextArrow() => _ArrowButton(
    icon: Icons.chevron_right,
    onTap: () => _goTo(1),
    isDesktop: _isDesktop,
  );

  @override
  Widget build(BuildContext context) {
    return Shortcuts(
      shortcuts: {
        const SingleActivator(LogicalKeyboardKey.arrowLeft):
            const _PrevIntent(),
        const SingleActivator(LogicalKeyboardKey.arrowRight):
            const _NextIntent(),
        const SingleActivator(LogicalKeyboardKey.escape): const _CloseIntent(),
      },
      child: Actions(
        actions: {
          _PrevIntent: CallbackAction<_PrevIntent>(
            onInvoke: (_) {
              _goTo(-1);
              return null;
            },
          ),
          _NextIntent: CallbackAction<_NextIntent>(
            onInvoke: (_) {
              _goTo(1);
              return null;
            },
          ),
          _CloseIntent: CallbackAction<_CloseIntent>(
            onInvoke: (_) {
              _close();
              return null;
            },
          ),
        },
        child: Focus(
          autofocus: true,
          skipTraversal: true,
          child: PopScope(
            canPop: true,
            child: Scaffold(
              backgroundColor: Colors.transparent,
              body: Stack(
                children: [
                  ScrollConfiguration(
                    behavior: ScrollConfiguration.of(context).copyWith(
                      dragDevices: {
                        PointerDeviceKind.touch,
                        PointerDeviceKind.mouse,
                        PointerDeviceKind.trackpad,
                      },
                    ),
                    child: PageView.builder(
                      controller: _pageController,
                      physics: const NeverScrollableScrollPhysics(),
                      // CRITICAL: the page offset is driven manually via jumpTo.
                      // With the default pageSnapping, PageView wraps the physics in
                      // PageScrollPhysics and every jumpTo starts a snap-back spring
                      // toward the nearest page. While the finger holds still at a
                      // partial swipe, that spring fights the finger — the page
                      // visibly slides back (position race / flicker). Disabling it
                      // makes jumpTo end idle; release snapping is handled by
                      // _onInteractionEnd.
                      pageSnapping: false,
                      itemCount: widget.items.length,
                      onPageChanged: (index) {
                        setState(() {
                          _currentIndex = index.clamp(
                            0,
                            widget.items.length - 1,
                          );
                        });
                      },
                      itemBuilder: (context, index) => _ViewerPage(
                        item: widget.items[index],
                        controller: _ctrlFor(index),
                        pageController: _pageController,
                        showUINotifier: _showUI,
                        isDesktop: _isDesktop,
                        onZoomChanged: (_) {
                          if (mounted) setState(() {});
                        },
                        onToggleUi: () => _showUI.value = !_showUI.value,
                        onHideUi: () => _showUI.value = false,
                      ),
                    ),
                  ),
                  Positioned(
                    top: 0,
                    left: 0,
                    right: 0,
                    child: _chrome(
                      SafeArea(
                        child: Container(
                          padding: const EdgeInsets.symmetric(
                            horizontal: 8,
                            vertical: 4,
                          ),
                          color: Colors.black.withValues(alpha: 0.6),
                          child: Row(
                            children: [
                              IconButton(
                                icon: const Icon(
                                  Icons.arrow_back,
                                  color: Colors.white,
                                ),
                                onPressed: _close,
                              ),
                              const SizedBox(width: 8),
                              Expanded(
                                child: Text(
                                  widget.items[_currentIndex].name,
                                  style: const TextStyle(color: Colors.white),
                                  maxLines: 1,
                                  overflow: TextOverflow.ellipsis,
                                ),
                              ),
                              Text(
                                '${_currentIndex + 1} / ${widget.items.length}',
                                style: const TextStyle(color: Colors.white70),
                              ),
                              IconButton(
                                icon: const Icon(
                                  Icons.zoom_in,
                                  color: Colors.white,
                                ),
                                onPressed: () => _zoom(1.5),
                              ),
                              IconButton(
                                icon: const Icon(
                                  Icons.zoom_out,
                                  color: Colors.white,
                                ),
                                onPressed: () => _zoom(1 / 1.5),
                              ),
                              IconButton(
                                icon: const Icon(
                                  Icons.info,
                                  color: Colors.white70,
                                ),
                                onPressed: _showInfo,
                              ),
                            ],
                          ),
                        ),
                      ),
                    ),
                  ),

                  // ── Bottom strip ──
                  if (widget.items.length > 1)
                    Positioned(
                      bottom: 0,
                      left: 0,
                      right: 0,
                      child: _chrome(
                        ImageWallStrip(
                          items: widget.items,
                          currentIndex: _currentIndex,
                          onTap: (index) => _pageController.jumpToPage(index),
                        ),
                      ),
                    ),

                  // ── Prev arrow ──
                  if (_currentIndex > 0)
                    Positioned(
                      left: 0,
                      top: 70,
                      bottom: 120,
                      width: 60,
                      child: _isDesktop
                          ? MouseRegion(
                              onEnter: (_) => _showArrows.value = true,
                              onExit: (_) => _showArrows.value = false,
                              child: _arrowChrome(_buildPrevArrow()),
                            )
                          : _chrome(_buildPrevArrow()),
                    ),

                  // ── Next arrow ──
                  if (_currentIndex < widget.items.length - 1)
                    Positioned(
                      right: 0,
                      top: 70,
                      bottom: 90,
                      width: 60,
                      child: _isDesktop
                          ? MouseRegion(
                              onEnter: (_) => _showArrows.value = true,
                              onExit: (_) => _showArrows.value = false,
                              child: _arrowChrome(_buildNextArrow()),
                            )
                          : _chrome(_buildNextArrow()),
                    ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _ViewerPage extends StatefulWidget {
  final MediaItem item;
  final TransformationController controller;
  final PageController pageController;
  final ValueNotifier<bool> showUINotifier;
  final VoidCallback onToggleUi;
  final VoidCallback onHideUi;
  final ValueChanged<bool> onZoomChanged;
  final bool isDesktop;
  const _ViewerPage({
    required this.item,
    required this.controller,
    required this.pageController,
    required this.showUINotifier,
    required this.onToggleUi,
    required this.onHideUi,
    required this.onZoomChanged,
    required this.isDesktop,
  });

  @override
  State<_ViewerPage> createState() => _ViewerPageState();
}

class _ViewerPageState extends State<_ViewerPage>
    with SingleTickerProviderStateMixin {
  TapDownDetails? _tap;
  _ViewerMode _mode = _ViewerMode.still;
  bool _dragging = false;
  bool _dragEngaged = false;
  bool _confirmedAnimated = false;
  Timer? _tapTimer;
  Offset _dismissOffset = Offset.zero;
  Offset _dragStart = Offset.zero;
  late final AnimationController _dismissCtrl;
  VoidCallback? _dismissListener;
  Player? _livePlayer;
  VideoController? _liveVC;
  bool _showFullRes = false;
  bool _isZoomed = false;
  // Page-drag tracking in global coordinates: [_dragStartGlobal] anchors the
  // finger position at gesture start; [_dragStartOffset] is the page offset at
  // that moment. Null means the current gesture is not a page drag (zoomed,
  // multi-touch, or ended).
  Offset? _dragStartGlobal;
  double _dragStartOffset = 0;

  @override
  void initState() {
    super.initState();
    _dismissCtrl = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 300),
    );
    _detectAnimation();
    _isZoomed = widget.controller.value.getMaxScaleOnAxis() > 1.01;
    widget.controller.addListener(_onZoomChange);
    // Arm the full-res decode only after the push transition AND any page
    // scroll animation have finished. The full-res texture upload on first
    // paint is this screen's largest single-frame cost; landing inside a
    // transition/scroll window is what drops frames on open & swipe.
    WidgetsBinding.instance.addPostFrameCallback((_) => _armFullRes());
  }

  Animation<double>? _routeAnim;
  ScrollPosition? _scrollPos;

  void _armFullRes() {
    if (!mounted || _showFullRes) return;
    final route = ModalRoute.of(context);
    final pos = widget.pageController.hasClients
        ? widget.pageController.position
        : null;
    final routeDone =
        route?.animation == null ||
        route!.animation!.status == AnimationStatus.completed;
    final idle = pos == null || !pos.isScrollingNotifier.value;
    if (routeDone && idle) {
      setState(() => _showFullRes = true);
      return;
    }
    if (!routeDone) {
      final anim = route.animation;
      _routeAnim = anim;
      anim?.addStatusListener(_onRouteStatus);
    }
    if (!idle) {
      _scrollPos = pos;
      pos.isScrollingNotifier.addListener(_onScrollIdle);
    }
  }

  void _onRouteStatus(AnimationStatus status) {
    if (status != AnimationStatus.completed) return;
    _routeAnim?.removeStatusListener(_onRouteStatus);
    _routeAnim = null;
    _armFullRes();
  }

  void _onScrollIdle() {
    final pos = _scrollPos;
    if (pos == null || !pos.isScrollingNotifier.value) {
      pos?.isScrollingNotifier.removeListener(_onScrollIdle);
      _scrollPos = null;
      _armFullRes();
    }
  }

  void _onZoomChange() {
    final z = widget.controller.value.getMaxScaleOnAxis() > 1.01;
    if (z != _isZoomed && mounted) {
      setState(() => _isZoomed = z);
      widget.onZoomChanged(z);
    }
  }

  void _onInteractionStart(ScaleStartDetails d) {
    // Zoomed or multi-touch: the gesture belongs to zoom/pan, never the page.
    if (_isZoomed || d.pointerCount > 1) {
      _dragStartGlobal = null;
      return;
    }
    // Anchor the drag in GLOBAL screen coordinates. The page's own movement
    // (from jumpTo) can never contaminate the measured finger delta, which
    // avoids the position race when the finger holds still at a partial page.
    _dragStartGlobal = d.focalPoint;
    _dragStartOffset = widget.pageController.offset;
  }

  void _onInteractionUpdate(ScaleUpdateDetails d) {
    if (_isZoomed) {
      _dragStartGlobal = null;
      return;
    }
    if (d.pointerCount != 1) {
      // Pinch: hand control to zoom. Re-anchor if it returns to one finger
      // (the focal point jumps when a finger lands or lifts).
      _dragStartGlobal = null;
      return;
    }
    final start = _dragStartGlobal;
    if (start == null) {
      _dragStartGlobal = d.focalPoint;
      _dragStartOffset = widget.pageController.offset;
      return;
    }
    final target = (_dragStartOffset - (d.focalPoint.dx - start.dx)).clamp(
      0.0,
      widget.pageController.position.maxScrollExtent,
    );
    if ((target - widget.pageController.offset).abs() > 0.01) {
      widget.pageController.jumpTo(target);
    }
  }

  void _onInteractionEnd(ScaleEndDetails d) {
    // The route may have been popped mid-gesture (e.g. Esc while a swipe is
    // in flight): the controller is then detached, and any position access
    // would throw "PageController not attached".
    if (!mounted || !widget.pageController.hasClients) return;
    final wasPageDrag = _dragStartGlobal != null;
    _dragStartGlobal = null;
    // When zoomed, never trigger page change — just spring back.
    if (!wasPageDrag || _isZoomed) {
      return;
    }
    final pageWidth = widget.pageController.position.viewportDimension;
    if (pageWidth <= 0) {
      return;
    }
    // Baseline page comes from where the drag STARTED, not the live
    // `pageController.page`. Mid-drag the offset can sit at e.g. 60% of a
    // page, where `page.round()` rounds UP to the next page and flips the
    // direction of `delta` — a large swipe would snap back instead of
    // turning the page.
    final startPage = (_dragStartOffset / pageWidth).round();
    final maxPage = (widget.pageController.position.maxScrollExtent / pageWidth)
        .round();
    final offset = widget.pageController.offset;
    final delta = offset - startPage * pageWidth;

    final velocity = d.velocity.pixelsPerSecond.dx;
    final vxAbs = velocity.abs();
    if (delta.abs() > pageWidth * 0.25 || vxAbs > 800) {
      // Decide direction: prefer delta, but use velocity when delta is
      // near 0 (PageView clamps offset at edges, zeroing delta even
      // though the user's swipe had clear direction).
      final bool goNext;
      if (delta.abs() > 1.0) {
        goNext = delta > 0;
      } else {
        goNext = velocity < 0; // finger moving left → next page
      }
      final target = goNext ? startPage + 1 : startPage - 1;
      final clamped = target.clamp(0, maxPage);
      if (clamped == startPage) {
        // At edge — user tried to swipe past bounds; spring back in place.
        widget.pageController.animateToPage(
          startPage,
          duration: const Duration(milliseconds: 250),
          curve: Curves.easeOut,
        );
      } else {
        widget.pageController.animateToPage(
          clamped,
          duration: const Duration(milliseconds: 250),
          curve: Curves.easeOut,
        );
      }
    } else {
      // Spring back to the page we started on.
      widget.pageController.animateToPage(
        startPage,
        duration: const Duration(milliseconds: 250),
        curve: Curves.easeOut,
      );
    }
  }

  Future<void> _detectAnimation() async {
    final e = widget.item.extension;
    if (e != 'png' &&
        e != 'webp' &&
        e != 'avif' &&
        e != 'heic' &&
        e != 'heif') {
      return;
    }
    final animated = await isAnimatedUrl(
      widget.item.url,
      headers: sharedAuthHeader,
    );
    if (mounted && animated) {
      setState(() => _confirmedAnimated = true);
    }
  }

  @override
  void dispose() {
    widget.controller.removeListener(_onZoomChange);
    _routeAnim?.removeStatusListener(_onRouteStatus);
    _scrollPos?.isScrollingNotifier.removeListener(_onScrollIdle);
    _liveDoneTimer?.cancel();
    _tapTimer?.cancel();
    _livePlayer?.dispose();
    _livePlayer = null;
    _liveVC = null;
    _liveReadySub?.cancel();
    _liveDurSub?.cancel();
    _dismissCtrl.removeStatusListener(_dismissStatusListener);
    if (_dismissListener != null) {
      _dismissCtrl.removeListener(_dismissListener!);
      _dismissListener = null;
    }
    _dismissCtrl.dispose();
    if (_isLargeImage(widget.item)) {
      _FullResImageProvider.evictImage(widget.item.url);
    }
    super.dispose();
  }

  // ── VRAM eviction threshold ───────────────────────────

  /// Compressed file size thresholds for evicting full-res textures on dispose.
  /// Below the threshold, keep in cache for instant back-swipe; at or above,
  /// evict VRAM immediately to prevent OOM from double-allocated textures.
  /// Thresholds vary by format because compression ratios differ by >10x.
  static const _evictThresholdKB = <String, int>{
    'avif': 2048,
    'heic': 2048,
    'heif': 2048,
    'jxl': 2048,
    'jpg': 4096,
    'jpeg': 4096,
    'webp': 5120,
    'png': 10240,
    'gif': 10240,
    'tiff': 12288,
    'tif': 12288,
    'bmp': 16384,
  };

  bool _isLargeImage(MediaItem item) {
    final limitKB = _evictThresholdKB[item.extension.toLowerCase()] ?? 6144;
    return item.size >= limitKB * 1024;
  }

  bool get _isAlwaysAnimated {
    final e = widget.item.extension;
    return e == 'gif' || e == 'apng';
  }

  bool get _animatable {
    final e = widget.item.extension;
    return _isAlwaysAnimated ||
        e == 'webp' ||
        e == 'avif' ||
        e == 'heic' ||
        e == 'heif';
  }

  bool get _couldBeLive {
    final e = widget.item.extension;
    return e == 'jpg' || e == 'jpeg' || e == 'heic' || e == 'heif';
  }

  double get _dist => _dismissOffset.distance;
  double get _t => (_dist / _threshold).clamp(0.0, 1.0);
  double get _threshold => MediaQuery.of(context).size.height * 0.17;

  Timer? _liveDoneTimer;
  bool _liveReady = false;
  StreamSubscription<dynamic>? _liveReadySub;
  StreamSubscription<dynamic>? _liveDurSub;

  Future<void> _playLive() async {
    if (!mounted) return;
    final media = await createLiveMedia(
      widget.item.url,
      headers: sharedAuthHeader,
    );
    if (!mounted || media == null) return;
    final p = PlayerFactory.playback();
    _livePlayer = p;
    _liveVC = VideoController(p);
    p.open(media);
    if (!_soundEnabled) p.setVolume(0);
    p.play();
    _liveReady = false;
    setState(() => _mode = _ViewerMode.live);
    _liveReadySub = p.stream.width.listen((w) {
      if (w is int && w > 0 && mounted && _mode == _ViewerMode.live) {
        setState(() => _liveReady = true);
        _liveReadySub?.cancel();
        _liveReadySub = null;
      }
    });
    _waitForDuration(p);
  }

  void _waitForDuration(Player p) {
    if (!mounted || _livePlayer != p) return;
    final known = p.state.duration.inMilliseconds;
    if (known > 0) {
      _scheduleLiveStop(p, known);
      return;
    }
    // Duration not reported yet — wait for the stream event instead of
    // re-checking every 150ms.
    _liveDurSub?.cancel();
    _liveDurSub = p.stream.duration.listen((d) {
      if (!mounted || _livePlayer != p) return;
      if (d.inMilliseconds > 0) {
        _liveDurSub?.cancel();
        _liveDurSub = null;
        _scheduleLiveStop(p, d.inMilliseconds);
      }
    });
  }

  void _scheduleLiveStop(Player p, int durMs) {
    _liveDoneTimer?.cancel();
    _liveDoneTimer = Timer(Duration(milliseconds: durMs + 200), () {
      if (mounted && _livePlayer == p) _stopLive();
    });
  }

  void _stopLive() {
    _liveDoneTimer?.cancel();
    _liveDoneTimer = null;
    _liveReadySub?.cancel();
    _liveReadySub = null;
    _liveDurSub?.cancel();
    _liveDurSub = null;
    _liveReady = false;
    _livePlayer?.dispose();
    _livePlayer = null;
    _liveVC = null;
    if (mounted) setState(() => _mode = _ViewerMode.still);
  }

  void _toggleSound() {
    setState(() => _soundEnabled = !_soundEnabled);
    _livePlayer?.setVolume(_soundEnabled ? 100 : 0);
  }

  void _onPtrDown(PointerDownEvent e) {
    _dragging = false;
    _dragEngaged = false;
    _dragStart = e.localPosition;
  }

  void _onPtrMove(PointerMoveEvent e) {
    if (widget.controller.value.getMaxScaleOnAxis() > 1.01) return;
    if (!_dragEngaged) {
      final dx = (e.localPosition.dx - _dragStart.dx).abs();
      final dy = e.localPosition.dy - _dragStart.dy;
      if (dy < 10 || dx > dy * 2) return;
      _dragEngaged = true;
      widget.onToggleUi();
    }
    if (!_dragging) _dragging = true;
    setState(() => _dismissOffset += e.localDelta);
  }

  void _onPtrUp(PointerUpEvent e) {
    _dragging = false;
    _dragEngaged = false;
    if (_dismissOffset == Offset.zero) return;

    if (_dist > _threshold) {
      final dir = _dismissOffset / _dist;
      final target = dir * MediaQuery.of(context).size.longestSide;
      final from = _dismissOffset;
      // Pop only once the forward animation completes; guard with mounted
      // so we never navigate after dispose or on a stale listener.
      _animateDismiss((t) => Offset.lerp(from, target, t)!, popOnEnd: true);
    } else {
      final from = _dismissOffset;
      _animateDismiss(
        (t) => Offset.lerp(from, Offset.zero, Curves.easeOut.transform(t))!,
      );
    }
  }

  /// Run one dismiss spring with the given position lerp. Resets the
  /// controller first so a previous gesture (successful dismiss, interrupted
  /// spring-back) can't leak stale state into this one; [popOnEnd] attaches
  /// the status listener that pops the route once the animation completes.
  void _animateDismiss(
    Offset Function(double t) lerp, {
    bool popOnEnd = false,
  }) {
    _dismissCtrl.stop();
    _dismissCtrl.removeStatusListener(_dismissStatusListener);
    if (_dismissListener != null) {
      _dismissCtrl.removeListener(_dismissListener!);
      _dismissListener = null;
    }
    _dismissListener = () {
      if (!mounted) return;
      setState(() => _dismissOffset = lerp(_dismissCtrl.value));
    };
    _dismissCtrl.addListener(_dismissListener!);
    if (popOnEnd) _dismissCtrl.addStatusListener(_dismissStatusListener);
    _dismissCtrl.forward(from: 0);
  }

  // Set once the dismiss animation has popped the route: guards against a
  // second pop arriving from _close()/system back during the same moment
  // (a double-pop would exit the screen below the viewer too).
  bool _dismissed = false;

  void _dismissStatusListener(AnimationStatus status) {
    if (status == AnimationStatus.completed) {
      _dismissCtrl.removeStatusListener(_dismissStatusListener);
      if (!_dismissed && mounted) {
        _dismissed = true;
        Navigator.pop(context);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final isMobile = Platform.isAndroid || Platform.isIOS;
    final showBadge = widget.item.isAnimated || _confirmedAnimated;
    final bgOp = (1.0 - _t).clamp(0.0, 1.0);
    final scale = (1.0 - _t * 0.4).clamp(0.6, 1.0);

    final imageContent = InteractiveViewer(
      transformationController: widget.controller,
      scaleEnabled: true,
      minScale: 1.0,
      maxScale: 6.0,
      // Desktop: only enable InteractiveViewer pan when zoomed — at scale 1
      // the drag passes through to PageView's native PageScrollPhysics
      // (eliminates jumpTo-vs-physics jitter).
      panEnabled: !widget.isDesktop || _isZoomed,
      onInteractionStart: _onInteractionStart,
      onInteractionUpdate: _onInteractionUpdate,
      onInteractionEnd: _onInteractionEnd,
      child: GestureDetector(
        behavior: HitTestBehavior.translucent,
        onTapDown: (d) => _tap = d,
        onTap: () {
          if (_tapTimer == null) {
            _tapTimer = Timer(const Duration(milliseconds: 300), () {
              _tapTimer = null;
              widget.onToggleUi();
            });
          } else {
            _tapTimer!.cancel();
            _tapTimer = null;
            final c = widget.controller;
            final zoomed = c.value.getMaxScaleOnAxis() > 1.01;
            if (zoomed) {
              c.value = Matrix4.identity();
            } else {
              const scale = 2.5;
              final p = _tap?.localPosition ?? Offset.zero;
              c.value = Matrix4.identity()
                ..translateByDouble(
                  -p.dx * (scale - 1),
                  -p.dy * (scale - 1),
                  0,
                  1.0,
                )
                ..scaleByDouble(scale, scale, scale, 1.0);
            }
            widget.onHideUi();
          }
        },
        onLongPressStart: isMobile && (_animatable || _couldBeLive)
            ? (_) async {
                if (_couldBeLive && _mode != _ViewerMode.live) {
                  final isLive = await isLivePhotoUrl(
                    widget.item.url,
                    headers: sharedAuthHeader,
                  );
                  if (isLive) {
                    _playLive();
                    return;
                  }
                }
                if (_isAlwaysAnimated || _confirmedAnimated) {
                  setState(() => _mode = _ViewerMode.animation);
                }
              }
            : null,
        onLongPressEnd: isMobile && (_animatable || _couldBeLive)
            ? (_) {
                if (_mode != _ViewerMode.live) {
                  setState(() => _mode = _ViewerMode.still);
                }
              }
            : null,
        child: _buildImage(),
      ),
    );

    return Container(
      color: Colors.black.withValues(alpha: bgOp),
      child: Listener(
        onPointerDown: _onPtrDown,
        onPointerMove: _onPtrMove,
        onPointerUp: _onPtrUp,
        child: Transform.translate(
          offset: _dismissOffset,
          child: Transform.scale(
            scale: scale,
            child: Stack(
              children: [
                imageContent,
                if (showBadge)
                  ValueListenableBuilder<bool>(
                    valueListenable: widget.showUINotifier,
                    builder: (_, showUI, child) => AnimatedPositioned(
                      duration: const Duration(milliseconds: 100),
                      curve: Curves.easeInOut,
                      right: 12,
                      bottom: showUI ? 92 : 12,
                      child: child!,
                    ),
                    child: GestureDetector(
                      onTap: isMobile
                          ? null
                          : () => setState(
                              () => _mode = _mode == _ViewerMode.animation
                                  ? _ViewerMode.still
                                  : _ViewerMode.animation,
                            ),
                      child: Container(
                        padding: const EdgeInsets.all(6),
                        decoration: const BoxDecoration(
                          color: Colors.black54,
                          shape: BoxShape.circle,
                        ),
                        child: Icon(
                          _mode == _ViewerMode.animation
                              ? Icons.stop
                              : Icons.motion_photos_on,
                          size: 20,
                          color: Colors.white70,
                        ),
                      ),
                    ),
                  ),
                if (_couldBeLive)
                  ValueListenableBuilder<bool>(
                    valueListenable: widget.showUINotifier,
                    builder: (_, showUI, child) => AnimatedPositioned(
                      duration: const Duration(milliseconds: 100),
                      curve: Curves.easeInOut,
                      left: 44,
                      bottom: showUI ? 92 : 12,
                      child: child!,
                    ),
                    child: FutureBuilder<bool>(
                      future: isLivePhotoUrl(
                        widget.item.url,
                        headers: sharedAuthHeader,
                      ),
                      builder: (_, snap) {
                        if (snap.data != true) return const SizedBox.shrink();
                        return GestureDetector(
                          onTap: _toggleSound,
                          child: Container(
                            padding: const EdgeInsets.all(6),
                            decoration: const BoxDecoration(
                              color: Colors.black54,
                              shape: BoxShape.circle,
                            ),
                            child: Icon(
                              _soundEnabled
                                  ? Icons.volume_up
                                  : Icons.volume_off,
                              size: 20,
                              color: _soundEnabled
                                  ? Colors.white
                                  : Colors.white54,
                            ),
                          ),
                        );
                      },
                    ),
                  ),
                if (_couldBeLive)
                  ValueListenableBuilder<bool>(
                    valueListenable: widget.showUINotifier,
                    builder: (_, showUI, child) => AnimatedPositioned(
                      duration: const Duration(milliseconds: 100),
                      curve: Curves.easeInOut,
                      left: 12,
                      bottom: showUI ? 92 : 12,
                      child: child!,
                    ),
                    child: FutureBuilder<bool>(
                      future: isLivePhotoUrl(
                        widget.item.url,
                        headers: sharedAuthHeader,
                      ),
                      builder: (_, snap) {
                        if (snap.data != true) return const SizedBox.shrink();
                        return GestureDetector(
                          onTap: () async {
                            if (_mode == _ViewerMode.live) {
                              _stopLive();
                              return;
                            }
                            final isLive = await isLivePhotoUrl(
                              widget.item.url,
                              headers: sharedAuthHeader,
                            );
                            if (!mounted || !isLive) return;
                            _playLive();
                          },
                          child: Container(
                            padding: const EdgeInsets.all(6),
                            decoration: const BoxDecoration(
                              color: Colors.black54,
                              shape: BoxShape.circle,
                            ),
                            child: Icon(
                              _mode == _ViewerMode.live
                                  ? Icons.motion_photos_on
                                  : Icons.motion_photos_off,
                              size: 20,
                              color: _mode == _ViewerMode.live
                                  ? Colors.white
                                  : Colors.white54,
                            ),
                          ),
                        );
                      },
                    ),
                  ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildImage() {
    return Stack(
      fit: StackFit.expand,
      children: [
        // Bottom: fast 400px thumbnail (grid LRU cache). Same memory/disk
        // path as the wall (PooledImage): static after the first frame —
        // animation is played by the full-res layer above it.
        PooledImage(
          url: widget.item.url,
          fit: BoxFit.contain,
          decodeWidth: 400,
          placeholder: const SizedBox.shrink(),
          errorWidget: const SizedBox.shrink(),
        ),
        // Middle: full-resolution image (multi-frame codecs animate).
        _fullResLayer(),
        // Top: live photo video overlay (only when first frame is ready).
        if (_mode == _ViewerMode.live && _liveReady)
          Video(
            controller: _liveVC!,
            fit: BoxFit.contain,
            controls: NoVideoControls,
          ),
      ],
    );
  }

  Widget _fullResLayer() {
    if (!_showFullRes) return const SizedBox.shrink();
    // Same provider in both still and animation mode: switching providers
    // on mode change would re-fetch + re-decode the same URL.
    return Image(
      image: _FullResImageProvider(widget.item.url),
      fit: BoxFit.contain,
      gaplessPlayback: true,
      frameBuilder: _fullResFrameBuilder,
      errorBuilder: (_, _, _) => _errorPlaceholder(),
    );
  }

  static Widget _fullResFrameBuilder(
    BuildContext context,
    Widget child,
    int? frame,
    bool wasSynchronouslyLoaded,
  ) {
    if (wasSynchronouslyLoaded) return child;
    if (frame == null) return const SizedBox.shrink();
    return TweenAnimationBuilder<double>(
      tween: Tween(begin: 0.0, end: 1.0),
      duration: const Duration(milliseconds: 250),
      builder: (_, value, _) => Opacity(opacity: value, child: child),
    );
  }

  Widget _errorPlaceholder() => const Center(
    child: Icon(Icons.broken_image, color: Colors.white24, size: 40),
  );
}

// ── Full-res ImageProvider with private ImageCache ──────────────

class _FullResImageProvider extends ImageProvider<_FullResImageProvider> {
  static final _cache = ImageCache()..maximumSizeBytes = _maxBytes;

  static int get _maxBytes => ItemCacheLimit.fullResImageCacheMaxBytes;

  final String url;
  const _FullResImageProvider(this.url);

  @override
  Future<_FullResImageProvider> obtainKey(ImageConfiguration configuration) =>
      SynchronousFuture<_FullResImageProvider>(this);

  @override
  void resolveStreamForKey(
    ImageConfiguration configuration,
    ImageStream stream,
    _FullResImageProvider key,
    ImageErrorListener handleError,
  ) {
    // Drop the cache entry on decode failure so a broken result is never
    // served again: the next resolve re-decodes from scratch (large images
    // that fail once must not keep showing the placeholder).
    //
    // ImageCache.putIfAbsent's onError only fires on a *synchronous* loader()
    // throw, not on the async decode error that surfaces through the
    // completer's reportError. A failed completer left in _pendingImages
    // would otherwise be re-served on every subsequent resolve. So the async
    // eviction is wired directly to the completer's listener.onError below.
    void onErr(Object e, StackTrace? st) {
      _cache.evict(key);
      handleError(e, st); // needed so the sync-throw path reaches errorBuilder
    }

    // Attach a self-removing error listener to [c] so that:
    //  - On decode success: the listener removes itself after the first frame,
    //    allowing ImageCache._liveImages to clean up when the Image widget
    //    removes its own listener. Without this, permanent listeners prevent
    //    _liveImages eviction, causing unbounded GPU memory growth.
    //  - On decode failure: evicts the cache entry so the next resolve
    //    re-fetches, and removes itself.
    void attachErrorListener(ImageStreamCompleter c) {
      ImageStreamListener? el;
      var cleanedUp = false;
      el = ImageStreamListener(
        (_, _) {
          if (!cleanedUp) {
            cleanedUp = true;
            c.removeListener(el!);
          }
        },
        onError: (Object e, StackTrace? st) {
          if (!cleanedUp) {
            cleanedUp = true;
            c.removeListener(el!);
          }
          _cache.evict(key);
        },
      );
      c.addListener(el);
    }

    if (stream.completer != null) {
      attachErrorListener(stream.completer!);
      final completer = _cache.putIfAbsent(
        key,
        () => stream.completer!,
        onError: onErr,
      );
      assert(identical(completer, stream.completer));
      return;
    }
    final completer = _cache.putIfAbsent(
      key,
      () => loadImage(
        key,
        PaintingBinding.instance.instantiateImageCodecWithSize,
      ),
      onError: onErr,
    );
    if (completer != null) {
      // Async decode failures bypass putIfAbsent's onError; attach our own
      // self-removing error listener so the failed entry is evicted.
      attachErrorListener(completer);
      stream.setCompleter(completer);
    }
  }

  @override
  ImageStreamCompleter loadImage(
    _FullResImageProvider key,
    ImageDecoderCallback decode,
  ) {
    final chunkEvents = StreamController<ImageChunkEvent>();
    return MultiFrameImageStreamCompleter(
      codec: _loadAsync(key.url, decode),
      chunkEvents: chunkEvents.stream,
      scale: 1.0,
      debugLabel: key.url,
    );
  }

  static Future<ui.Codec> _loadAsync(
    String url,
    ImageDecoderCallback decode,
  ) async {
    final uri = Uri.parse(Uri.encodeFull(url));
    final req = await sharedHttpClient.getUrl(uri);
    final auth = sharedAuthHeader;
    if (auth != null) {
      req.headers.set('Authorization', auth['Authorization']!);
    }
    final resp = await req.close();
    if (resp.statusCode != 200) throw Exception('HTTP ${resp.statusCode}');
    final bytes = await consolidateHttpClientResponseBytes(resp);

    // On mobile, route AVIF/JXL through the Rust software decoder.
    final swCodec = await MobileImageDecoder.tryDecode(bytes, url);
    if (swCodec != null) return swCodec;

    final buffer = await ui.ImmutableBuffer.fromUint8List(bytes);
    return decode(buffer);
  }

  @override
  bool operator ==(Object other) =>
      other is _FullResImageProvider && other.url == url;

  @override
  int get hashCode => url.hashCode;

  /// Evict the cached full-res texture for [url], freeing GPU memory immediately.
  /// Call when a page scrolls off-screen to avoid VRAM peaks from large images.
  static void evictImage(String url) {
    _cache.evict(_FullResImageProvider(url), includeLive: true);
  }
}

// ── Polished arrow button: dark circular bg, white icon, hover/press states ──

class _ArrowButton extends StatefulWidget {
  final IconData icon;
  final VoidCallback onTap;
  final bool isDesktop;
  const _ArrowButton({
    required this.icon,
    required this.onTap,
    required this.isDesktop,
  });
  @override
  State<_ArrowButton> createState() => _ArrowButtonState();
}

class _ArrowButtonState extends State<_ArrowButton> {
  bool _hovered = false;
  bool _pressed = false;

  Color get _bgColor {
    if (_pressed) return Colors.black.withValues(alpha: 0.55);
    if (_hovered && widget.isDesktop) {
      return Colors.black.withValues(alpha: 0.40);
    }
    return Colors.black.withValues(alpha: 0.45);
  }

  double get _scale {
    if (_pressed) return 0.92;
    if (_hovered && widget.isDesktop) return 1.08;
    return 1.0;
  }

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      behavior: HitTestBehavior.opaque,
      onTap: widget.onTap,
      onTapDown: (_) => setState(() => _pressed = true),
      onTapUp: (_) => setState(() => _pressed = false),
      onTapCancel: () => setState(() => _pressed = false),
      child: widget.isDesktop
          ? MouseRegion(
              onEnter: (_) => setState(() => _hovered = true),
              onExit: (_) => setState(() => _hovered = false),
              child: _buildButton(),
            )
          : _buildButton(),
    );
  }

  Widget _buildButton() => Container(
    alignment: Alignment.center,
    child: AnimatedScale(
      scale: _scale,
      duration: const Duration(milliseconds: 120),
      curve: Curves.easeOutCubic,
      child: Container(
        width: 44,
        height: 44,
        decoration: BoxDecoration(color: _bgColor, shape: BoxShape.circle),
        child: Icon(widget.icon, color: Colors.white, size: 28),
      ),
    ),
  );
}
