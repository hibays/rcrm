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
import '../config/theme.dart';
import '../models/media_item.dart';
import '../widgets/image_wall_strip.dart';

import 'package:media_kit/media_kit.dart';
import 'package:media_kit_video/media_kit_video.dart';
import '../services/item_cache_limit.dart';
import '../services/bounded_fetch.dart';
import '../services/net.dart';
import '../services/mobile_image_decoder.dart';
import '../services/animated_detector.dart';
import '../services/live_photo.dart';
import '../services/live_media_server.dart';
import '../services/player_factory.dart';
import '../services/media_metadata.dart';
import '../widgets/pooled_image.dart';
import '../widgets/viewer_zoom.dart';
import '../widgets/image_info_sheet.dart';

enum _ViewerMode { still, animation, live }

/// Which way a pointer gesture is committed to travel, decided once and never
/// revisited (see [_ViewerPageState._decideGestureAxis]): a finger that curves
/// mid-swipe keeps the axis it committed to, so the pull-to-dismiss and the
/// pager can never both act on one gesture.
enum _GestureAxis { undecided, page, pull }

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

  /// One viewport key per page: zoom commands (chrome buttons, the info
  /// sheet's 1:1 chip) are geometry-aware, so they run inside the page.
  final Map<int, GlobalKey<ZoomableViewportState>> _viewports = {};
  GlobalKey<ZoomableViewportState> _viewportFor(int i) =>
      _viewports.putIfAbsent(i, () => GlobalKey<ZoomableViewportState>());

  /// Decoded pixel size per page, for the info sheet and the 1:1 chip.
  final Map<int, Size> _pixelSizes = {};

  /// Pages whose container header confirmed real animation frames (webp/avif
  /// and friends, which the extension alone cannot tell apart). The info sheet
  /// reports the same fact the badge and long-press use.
  final Set<int> _animatedPages = {};

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

  /// The info sheet: what the file is, in the gallery-panel shape people
  /// already read — one big date, the name, the camera block, labelled rows.
  /// EXIF comes from the Rust parser (fetched once per URL, then cached).
  void _showInfo() {
    final index = _currentIndex;
    final item = widget.items[index];
    final viewport = _viewportFor(index).currentState;
    final metadata = MediaMetadataService.forUrl(
      item.url,
      kind: MetadataKind.image,
    );
    showModalBottomSheet<void>(
      context: context,
      backgroundColor: Colors.transparent,
      // The panel is the point of this sheet — let it size to its content
      // instead of the default half-screen cap (its own scroll view handles a
      // short screen or a large text scale).
      isScrollControlled: true,
      // Light scrim: the photo stays the subject, the sheet is a layer over it.
      barrierColor: Colors.black.withValues(alpha: 0.35),
      builder: (sheetContext) => ImageInfoSheet(
        item: item,
        index: index + 1,
        total: widget.items.length,
        pixelSize: _pixelSizes[index],
        metadata: metadata,
        // Same verdict the badge and long-press use: the extension test, plus
        // a container header that really confirmed animation frames.
        animated: item.isAnimated || _animatedPages.contains(index),
        onActualSize: viewport != null && viewport.canShowActualSize
            ? () {
                Navigator.of(sheetContext).pop();
                viewport.zoomToActualSize();
              }
            : null,
      ),
    );
  }

  void _close() {
    if (_popped) return;
    _popped = true;
    Navigator.of(context).pop();
  }

  /// Zoom the current page; the page owns the geometry (viewport + image size)
  /// so the transform can never push the picture off screen.
  void _zoom(double factor) => _viewportFor(_currentIndex).currentState?.zoomBy(
    factor,
  );

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

  Widget _buildPrevArrow() => _RoundButton(
    icon: Icons.chevron_left,
    onTap: () => _goTo(-1),
    isDesktop: _isDesktop,
  );

  Widget _buildNextArrow() => _RoundButton(
    icon: Icons.chevron_right,
    onTap: () => _goTo(1),
    isDesktop: _isDesktop,
  );

  /// Top chrome, floating over the photo: a scrim instead of a bar, round
  /// buttons instead of a toolbar, the file name plus its position as the one
  /// line of text. Zoom buttons belong to the pointer platforms — touch has
  /// pinch and double-tap, and stock mobile viewers carry no zoom chrome.
  Widget _topChrome() => Container(
    decoration: const BoxDecoration(
      gradient: LinearGradient(
        begin: Alignment.topCenter,
        end: Alignment.bottomCenter,
        colors: [Color(0xB3000000), Color(0x00000000)],
      ),
    ),
    child: SafeArea(
      bottom: false,
      child: Padding(
        padding: const EdgeInsets.fromLTRB(8, 4, 8, 22),
        child: Row(
          children: [
            _RoundButton(
              icon: Icons.arrow_back,
              tooltip: 'Close',
              onTap: _close,
              isDesktop: _isDesktop,
              size: 40,
              iconSize: 22,
            ),
            const SizedBox(width: 6),
            Expanded(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    widget.items[_currentIndex].name,
                    style: const TextStyle(
                      color: RCrmColors.white,
                      fontSize: 14,
                      fontWeight: FontWeight.w500,
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                  const SizedBox(height: 2),
                  Text(
                    '${_currentIndex + 1} / ${widget.items.length}',
                    style: const TextStyle(
                      color: RCrmColors.silver,
                      fontSize: 12,
                    ),
                  ),
                ],
              ),
            ),
            if (_isDesktop) ...[
              _RoundButton(
                icon: Icons.zoom_out,
                tooltip: 'Zoom out',
                onTap: () => _zoom(1 / 1.5),
                isDesktop: true,
                size: 40,
                iconSize: 20,
              ),
              _RoundButton(
                icon: Icons.zoom_in,
                tooltip: 'Zoom in',
                onTap: () => _zoom(1.5),
                isDesktop: true,
                size: 40,
                iconSize: 20,
              ),
            ],
            _RoundButton(
              icon: Icons.info_outline,
              tooltip: 'Info',
              onTap: _showInfo,
              isDesktop: _isDesktop,
              size: 40,
              iconSize: 20,
            ),
          ],
        ),
      ),
    ),
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
            // The system back button pops this route without going through
            // `_close()`, so `_popped` has to be set here too: while the exit
            // transition runs the page is still mounted and its ticker still
            // fires, and a dismissal that lands then would call `_close()` →
            // `Navigator.pop()` — which pops the screen *underneath* the viewer,
            // because a route that is already popping is not "present" any more.
            onPopInvokedWithResult: (didPop, _) {
              if (didPop) _popped = true;
            },
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
                        viewportKey: _viewportFor(index),
                        item: widget.items[index],
                        controller: _ctrlFor(index),
                        pageController: _pageController,
                        showUINotifier: _showUI,
                        isDesktop: _isDesktop,
                        onZoomChanged: (_) {
                          if (mounted) setState(() {});
                        },
                        onImageSize: (size) {
                          if (!mounted || _pixelSizes[index] == size) return;
                          setState(() => _pixelSizes[index] = size);
                        },
                        onAnimated: () {
                          if (!mounted || _animatedPages.contains(index)) {
                            return;
                          }
                          setState(() => _animatedPages.add(index));
                        },
                        onToggleUi: () => _showUI.value = !_showUI.value,
                        onHideUi: () => _showUI.value = false,
                        onDismiss: _close,
                      ),
                    ),
                  ),
                  Positioned(
                    top: 0,
                    left: 0,
                    right: 0,
                    child: _chrome(_topChrome()),
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

  /// Reports the decoded pixel size once (info sheet + the 1:1 affordance).
  final ValueChanged<Size> onImageSize;

  /// Reports that the container header confirmed real animation frames, so the
  /// info sheet can state the same fact as the badge.
  final VoidCallback onAnimated;

  /// Key of the zoom viewport, so the viewer chrome can zoom this page.
  final GlobalKey<ZoomableViewportState> viewportKey;

  final bool isDesktop;

  /// Closes the whole viewer. The page never pops the route itself: the screen
  /// owns the once-only guard, so a dismiss that finishes while the back button
  /// (or Esc, or a system back) is also closing the viewer cannot pop twice and
  /// take the library screen down with it.
  final VoidCallback onDismiss;

  const _ViewerPage({
    required this.item,
    required this.controller,
    required this.pageController,
    required this.showUINotifier,
    required this.onToggleUi,
    required this.onHideUi,
    required this.onZoomChanged,
    required this.onImageSize,
    required this.onAnimated,
    required this.onDismiss,
    required this.viewportKey,
    required this.isDesktop,
  });

  @override
  State<_ViewerPage> createState() => _ViewerPageState();
}

class _ViewerPageState extends State<_ViewerPage>
    with SingleTickerProviderStateMixin {
  _ViewerMode _mode = _ViewerMode.still;
  bool _dragEngaged = false;
  bool _confirmedAnimated = false;
  Timer? _tapTimer;
  Offset _dismissOffset = Offset.zero;

  /// Where the finger went down, in GLOBAL screen coordinates. The direction
  /// lock measures its travel from here, and never through this page's own
  /// transform: the pager slides the page sideways under the finger, so a
  /// position read in the page's own space carries the page's movement as well
  /// as the finger's — and the only thing this lock may be decided from is the
  /// finger.
  Offset _pointerStart = Offset.zero;
  late final AnimationController _dismissCtrl;
  VoidCallback? _dismissListener;
  Player? _livePlayer;
  VideoController? _liveVC;

  /// Decoded pixel size of this photo, once the full-res decode lands.
  Size? _imageSize;

  /// Velocity of the current pull, so a quick flick closes the viewer even
  /// when it travelled less than the distance threshold.
  VelocityTracker _pullVelocity = VelocityTracker.withKind(
    PointerDeviceKind.touch,
  );

  /// Set while a pull-to-dismiss owns the gesture: the image must not pan at
  /// the same time, or the photo moves twice as fast as the finger.
  bool _pulling = false;

  /// Which axis owns the current gesture. Reset on pointer down, then set the
  /// first time the finger has travelled [_axisLockSlop] — and never changed
  /// again for that gesture (see [_decideGestureAxis]).
  _GestureAxis _axis = _GestureAxis.undecided;

  /// Full-res stream subscription, for the decoded size.
  ImageStream? _sizeStream;
  ImageStreamListener? _sizeListener;

  /// Loopback URL of the currently-registered live-photo payload, released
  /// when the player is torn down so the bytes do not linger in RAM.
  String? _liveMediaUri;
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
      _watchDecodedSize();
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

  void _onZoomChanged(bool zoomed) {
    if (!mounted || zoomed == _isZoomed) return;
    setState(() => _isZoomed = zoomed);
    widget.onZoomChanged(zoomed);
  }

  /// Single tap toggles the chrome; a second tap within 300ms zooms to the
  /// point (or back out). Kept out of the gesture arena's double-tap
  /// recognizer so a single tap still acts immediately.
  void _onTapAt(Offset point) {
    if (_tapTimer == null) {
      _tapTimer = Timer(const Duration(milliseconds: 300), () {
        _tapTimer = null;
        widget.onToggleUi();
      });
      return;
    }
    _tapTimer!.cancel();
    _tapTimer = null;
    final viewport = widget.viewportKey.currentState;
    if (viewport == null) return;
    if (_isZoomed) {
      viewport.reset();
    } else {
      viewport.zoomAt(point, 2.5);
    }
    widget.onHideUi();
  }

  /// Picks up the decoded pixel size off the full-res stream (the same
  /// provider the layer paints from, so the cache is shared — no extra
  /// decode). Feeds the info sheet and the "1:1" affordance.
  void _watchDecodedSize() {
    if (_sizeListener != null) return;
    final stream = _FullResImageProvider(
      widget.item.url,
    ).resolve(ImageConfiguration.empty);
    _sizeStream = stream;
    _sizeListener = ImageStreamListener(
      (info, _) {
        final size = Size(
          info.image.width.toDouble(),
          info.image.height.toDouble(),
        );
        if (!mounted || size == _imageSize) return;
        setState(() => _imageSize = size);
        widget.onImageSize(size);
      },
      onError: (_, _) {},
    );
    stream.addListener(_sizeListener!);
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
    // A pull-to-dismiss owns the whole gesture once it engages — including
    // any sideways drift the finger picks up afterwards. Dragging down and
    // drifting left must never also slide the pager to the next picture.
    if (_pulling) {
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

  /// Set while a pull-to-dismiss owns the current gesture: the page drag and
  /// the picture's own panning both stand down for the rest of it.
  bool _pullGesture = false;

  /// Snap the pager onto the nearest page without changing which one it is.
  void _settlePager() {
    if (!widget.pageController.hasClients) return;
    final pageWidth = widget.pageController.position.viewportDimension;
    if (pageWidth <= 0) return;
    final offset = widget.pageController.offset;
    final nearest = (offset / pageWidth).round();
    if ((offset - nearest * pageWidth).abs() <= 0.5) return;
    widget.pageController.animateToPage(
      nearest,
      duration: const Duration(milliseconds: 200),
      curve: Curves.easeOut,
    );
  }

  void _onInteractionEnd(ScaleEndDetails d) {
    // The route may have been popped mid-gesture (e.g. Esc while a swipe is
    // in flight): the controller is then detached, and any position access
    // would throw "PageController not attached".
    if (!mounted || !widget.pageController.hasClients) return;
    final wasPull = _pullGesture;
    final wasPageDrag = _dragStartGlobal != null;
    _dragStartGlobal = null;
    _pullGesture = false;
    // A pull never decides a page: put the pager back on the page it belongs
    // to (a sideways move can land before the pull is recognised, and the
    // pager must not be left parked between two pictures).
    if (wasPull) {
      _settlePager();
      return;
    }
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
      widget.onAnimated();
    }
  }

  @override
  void dispose() {
    _routeAnim?.removeStatusListener(_onRouteStatus);
    _scrollPos?.isScrollingNotifier.removeListener(_onScrollIdle);
    if (_sizeListener != null) {
      _sizeStream?.removeListener(_sizeListener!);
      _sizeListener = null;
      _sizeStream = null;
    }
    _liveDoneTimer?.cancel();
    _tapTimer?.cancel();
    _livePlayer?.dispose();
    _livePlayer = null;
    _liveVC = null;
    LiveMediaServer.instance.release(_liveMediaUri);
    _liveMediaUri = null;
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

  double get _viewportHeight => MediaQuery.sizeOf(context).height;

  /// Vertical travel of the pull. The dismissal is a vertical gesture, so
  /// sideways drift must never count toward the threshold.
  double get _dist => _dismissOffset.dy > 0 ? _dismissOffset.dy : 0;

  double get _t => dismissProgress(_dist, _viewportHeight);

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
    if (!mounted) {
      // Screen went away while the payload was being registered — drop it
      // instead of leaving it in the proxy until LRU evicts it.
      LiveMediaServer.instance.release(media?.uri);
      return;
    }
    if (media == null) return;
    LiveMediaServer.instance.release(_liveMediaUri);
    _liveMediaUri = media.uri;
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
    LiveMediaServer.instance.release(_liveMediaUri);
    _liveMediaUri = null;
    if (mounted) setState(() => _mode = _ViewerMode.still);
  }

  void _toggleSound() {
    setState(() => _soundEnabled = !_soundEnabled);
    _livePlayer?.setVolume(_soundEnabled ? 100 : 0);
  }

  void _onPtrDown(PointerDownEvent e) {
    _dragEngaged = false;
    _pulling = false;
    _pullGesture = false;
    _axis = _GestureAxis.undecided;
    _pointerStart = e.position;
    _pullVelocity = VelocityTracker.withKind(e.kind)
      ..addPosition(e.timeStamp, e.position);
  }

  /// A pull may only begin at rest — fit size, 1×. A zoomed picture owns the
  /// drag: it pans, and the way out of a zoom is zooming out (pinch or
  /// double-tap), never yanking the photo off the screen. The edge check that
  /// used to live here allowed exactly that at the top edge, which is the drag
  /// people make when they mean "pan to the top of the picture".
  bool _pullAllowed() => !_isZoomed;

  /// Travel before the direction lock commits to an axis. Small enough that a
  /// real swipe decides almost immediately, large enough to ignore the first
  /// few pixels of finger tremor.
  static const double _axisLockSlop = 8;

  /// How far the leading axis must beat the other one to own the gesture.
  static const double _axisDominance = 1.5;

  /// The direction lock: which axis a finger's total [travel] since it went
  /// down commits this gesture to. Decided once — a finger that curves later
  /// keeps the axis it started on, because a gesture whose ownership can be
  /// re-decided mid-flight is one where both gestures can fire.
  ///
  /// The case this exists for is a sideways page swipe whose finger sinks as it
  /// goes: the pull used to be re-tested on every event against the finger's
  /// total travel, so once the dip passed two thirds of the sideways travel it
  /// took the gesture over mid-swipe — the photo slid down (and a long enough
  /// dip dismissed the whole viewer) while the pager was switching pages. The
  /// mirror case, a downward pull that drifts sideways, is why nothing here may
  /// hand a vertical-leading gesture to the pager: it stays a pull, exactly as
  /// it always was.
  _GestureAxis _decideGestureAxis(Offset travel) {
    final dx = travel.dx.abs();
    // Sideways clearly dominates: the pager owns the gesture, so the pull must
    // contribute nothing at all for the rest of it.
    if (dx > _axisLockSlop && dx > travel.dy.abs() * _axisDominance) {
      return _GestureAxis.page;
    }
    // Downward travel that dominates: the pull, on the rule it always used to
    // engage (8px down, and not more than 1.5× sideways).
    if (travel.dy >= _axisLockSlop && dx <= travel.dy * _axisDominance) {
      return _GestureAxis.pull;
    }
    return _GestureAxis.undecided;
  }

  void _onPtrMove(PointerMoveEvent e) {
    _pullVelocity.addPosition(e.timeStamp, e.position);
    if (!_dragEngaged) {
      if (!_pullAllowed()) return;
      if (_axis == _GestureAxis.undecided) {
        _axis = _decideGestureAxis(e.position - _pointerStart);
      }
      // The pager owns this gesture: no offset, no scale/fade, and no dismissal
      // on release — `_dragEngaged` stays false, so `_onPtrUp` bails out
      // however far down the finger then travels.
      if (_axis == _GestureAxis.page) return;
      if (_axis != _GestureAxis.pull) return;
      _dragEngaged = true;
      _pulling = true;
      _pullGesture = true;
      // Drop any page drag that slipped in before the pull was recognised.
      _dragStartGlobal = null;
      widget.onHideUi();
    }
    // Sideways tremor is damped so the photo tracks the pull, and upward
    // travel is resisted so a change of mind is smooth rather than a wall.
    final pulled = pullOffsetDelta(e.localDelta);
    setState(() => _dismissOffset += pulled);
  }

  void _onPtrUp(PointerUpEvent e) {
    final wasPulling = _dragEngaged;
    _dragEngaged = false;
    _pulling = false;
    if (!wasPulling) return;
    if (_dismissOffset == Offset.zero) return;

    // Velocity as well as distance: a flick closes the viewer even when it
    // travelled less than the threshold.
    final velocity = _pullVelocity.getVelocity().pixelsPerSecond.dy;
    if (shouldDismissPull(
      distance: _dist,
      velocity: velocity,
      viewportHeight: _viewportHeight,
    )) {
      final from = _dismissOffset;
      final dir = from.distance == 0 ? const Offset(0, 1) : from / from.distance;
      final target = dir * _viewportHeight * 1.1;
      // Commit at the speed the finger was already moving.
      _dismissCtrl.duration = Duration(
        milliseconds: (110 + 190 * (1 - _t)).round(),
      );
      _animateDismiss(
        (t) => Offset.lerp(from, target, Curves.easeOut.transform(t))!,
        popOnEnd: true,
      );
    } else {
      final from = _dismissOffset;
      _dismissCtrl.duration = const Duration(milliseconds: 200);
      _animateDismiss(
        (t) => Offset.lerp(from, Offset.zero, Curves.easeOutCubic.transform(t))!,
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

  // Deliberately NOT a second guard: the close itself goes through
  // `widget.onDismiss` → the screen's `_close()`, which owns the once-only flag.
  // Keeping a page-local copy only reintroduced the race it was meant to stop.

  void _dismissStatusListener(AnimationStatus status) {
    if (status == AnimationStatus.completed) {
      _dismissCtrl.removeStatusListener(_dismissStatusListener);
      // Hand the close to the screen instead of popping here: it holds the
      // one-shot guard, so this finish and a back/Esc press racing it during
      // the route's exit animation collapse into a single pop. (The route stays
      // mounted for ~300ms after the first pop, which is exactly the window a
      // second, page-owned pop used to slip through — dismissing the library
      // screen underneath as well.)
      if (mounted) widget.onDismiss();
    }
  }

  @override
  Widget build(BuildContext context) {
    final isMobile = Platform.isAndroid || Platform.isIOS;
    final showBadge = widget.item.isAnimated || _confirmedAnimated;
    // The photo lifts off the wall as it is pulled away: it shrinks and the
    // backdrop opens up behind it, but never all the way to nothing.
    final bgOp = (1.0 - _t * 0.92).clamp(0.0, 1.0);
    final scale = (1.0 - _t * 0.4).clamp(0.6, 1.0);

    final imageContent = ZoomableViewport(
      key: widget.viewportKey,
      controller: widget.controller,
      contentSize: _imageSize,
      fallbackAspect: _imageSize == null
          ? PooledImage.knownAspectRatio(widget.item.url)
          : null,
      panEnabled: !_pulling,
      onZoomChanged: _onZoomChanged,
      onTapAt: _onTapAt,
      onScaleStart: _onInteractionStart,
      onScaleUpdate: _onInteractionUpdate,
      onScaleEnd: _onInteractionEnd,
      child: GestureDetector(
        behavior: HitTestBehavior.opaque,
        // Long-press belongs to the photo itself (play animation / live photo).
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
    // No `chunkEvents`: this provider used to open a
    // `StreamController<ImageChunkEvent>` per load that was never fed and never
    // closed, and nothing subscribes to chunk events for it (the `Image` below
    // uses frameBuilder/errorBuilder, not a chunk listener) — so the controller
    // was a per-load allocation that outlived the entry in `_cache`. Download
    // progress is not surfaced here; the thumbnail layer underneath is.
    return MultiFrameImageStreamCompleter(
      codec: _loadAsync(key.url, decode),
      scale: 1.0,
      debugLabel: key.url,
    );
  }

  static Future<ui.Codec> _loadAsync(
    String url,
    ImageDecoderCallback decode,
  ) async {
    // Software-decoded formats first, copy-free: the compressed bytes land in
    // native memory and go straight to Rust. (The decoded RGBA still has to be
    // copied once into Dart — dart:ui can only build a ui.Image from a Dart
    // buffer — but the input no longer is.)
    //
    // A failed native decode falls through to the fetch below ON PURPOSE: the
    // fallback is the ENGINE, a different decoder that can succeed where Rust
    // refused (a HEIF the `heic` crate cannot read, a container that is really
    // JPEG/PNG, or a file past Rust's shared 64 MP ceiling). The disk-thumbnail
    // cache applies the same rule — its fallback is the engine too. The native
    // attempt took ownership of its bytes, so they cannot be handed over; the cost
    // is one extra download on this path only.
    final soft = await MobileImageDecoder.fetchForDecode(url);
    if (soft != null) {
      final swCodec = await MobileImageDecoder.tryDecodeNative(soft, url);
      if (swCodec != null) return swCodec;
    }

    // Bounded end to end (see [fetchBoundedBytes]): a stall must surface as an
    // error here, not as a pending future — the error is what `onErr` (in
    // `resolveStreamForKey`) uses to evict this cache entry so the next resolve
    // retries, and a pending one would leave the viewer on its placeholder with
    // the decode slot still held.
    final bytes = await fetchBoundedBytes(url);

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

// ── Round chrome button: dark circular bg, white icon, hover/press states ──

class _RoundButton extends StatefulWidget {
  final IconData icon;
  final VoidCallback onTap;
  final bool isDesktop;
  final String? tooltip;
  final double size;
  final double iconSize;

  const _RoundButton({
    required this.icon,
    required this.onTap,
    required this.isDesktop,
    this.tooltip,
    this.size = 44,
    this.iconSize = 28,
  });

  @override
  State<_RoundButton> createState() => _RoundButtonState();
}

class _RoundButtonState extends State<_RoundButton> {
  bool _hovered = false;
  bool _pressed = false;

  Color get _bgColor {
    if (_pressed) return Colors.black.withValues(alpha: 0.55);
    if (_hovered && widget.isDesktop) {
      return Colors.black.withValues(alpha: 0.40);
    }
    return Colors.black.withValues(alpha: 0.32);
  }

  double get _scale {
    if (_pressed) return 0.92;
    if (_hovered && widget.isDesktop) return 1.08;
    return 1.0;
  }

  @override
  Widget build(BuildContext context) {
    Widget button = GestureDetector(
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
    if (widget.tooltip != null) {
      button = Tooltip(message: widget.tooltip!, child: button);
    }
    return button;
  }

  Widget _buildButton() => Container(
    alignment: Alignment.center,
    child: AnimatedScale(
      scale: _scale,
      duration: const Duration(milliseconds: 120),
      curve: Curves.easeOutCubic,
      child: Container(
        width: widget.size,
        height: widget.size,
        decoration: BoxDecoration(color: _bgColor, shape: BoxShape.circle),
        child: Icon(widget.icon, color: Colors.white, size: widget.iconSize),
      ),
    ),
  );
}
