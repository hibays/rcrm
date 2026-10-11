// screens/video_player_screen.dart — media_kit video player
//
// Desktop: hover shows/hides controls, mouse move resets idle timer.
// Mobile: tap toggles controls, left-zone swipe = seek/brightness,
//         right-zone swipe = volume. Long-press = 2x speed.

import 'dart:async';
import 'dart:io' show Platform;
import 'package:flutter/material.dart';
import 'package:window_manager/window_manager.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:media_kit/media_kit.dart';
import 'package:media_kit_video/media_kit_video.dart';
import 'package:screen_brightness/screen_brightness.dart';
import '../models/media_item.dart';
import '../services/net.dart';
import '../services/player_factory.dart';
import '../providers/library_provider.dart';
import '../providers/settings_provider.dart';
import '../providers/video_jump_stack.dart';
import '../providers/window_chrome_provider.dart';
import '../widgets/video_card.dart';
import '../widgets/media_player_keys.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../widgets/player_controls.dart';
import '../widgets/finger_preview_listener.dart';
import '../widgets/player_settings_panel.dart';
import '../widgets/episode_picker_panel.dart';
import '../utils/format.dart';
import '../utils/pan_lock.dart';
import '../utils/player_exit.dart';
import '../utils/player_panels.dart';
import '../utils/poster_quiet_route.dart';
import '../utils/related_videos.dart';
import '../utils/seek_preview.dart';
import '../utils/wheel_guard.dart';

class VideoPlayerScreen extends ConsumerStatefulWidget {
  final MediaItem item;
  final bool startFullscreen;

  /// A playback `Player` created for this screen before it mounted, by the
  /// route that pushed it (`PosterQuietRoute`), so `mpv_create`/`mpv_initialize`
  /// and the configuration writes do not run on the UI isolate during the route
  /// transition. This screen adopts it in `initState` and owns it from then on;
  /// null (no warm player, or creating one failed) means the screen creates its
  /// own exactly as it always did.
  final Player? warmPlayer;

  const VideoPlayerScreen({
    super.key,
    required this.item,
    this.startFullscreen = false,
    this.warmPlayer,
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
  StreamSubscription? _volumeSub;
  StreamSubscription? _rateSub;
  bool show2x = false;
  bool fullscreen = false;
  Duration _fadeMs = const Duration(milliseconds: 200);
  bool _showControls = true;
  Timer? _hideTimer;
  Timer? _exitTimer;
  static const _idleSecs = 2;
  final _videoKey = GlobalKey();

  /// The session's jump history, captured once so `dispose` can drop it without
  /// touching `ref` after the element is deactivated (see the dispose body).
  /// The stack itself lives in `providers/video_jump_stack.dart` — a field here
  /// would be born empty in the screen a jump creates, and the Related list
  /// could not read it.
  VideoJumpStackNotifier? _jumpStack;

  /// The video this screen is playing. It is STATE rather than `widget.item`
  /// because the transport bar's prev/next change it INSIDE this screen
  /// (`_playInPlace`): the title, the Related list, the poster key and the info
  /// sheet all derive from the current video, so they have to follow an
  /// assignment instead of a new route.
  late MediaItem _item;

  /// Persistent focus node for keyboard shortcuts. `Focus(autofocus: true)`
  /// only grabs focus on first mount; clicking a slider/button moves focus
  /// away and arrows/space/ESC stop reaching the CallbackShortcuts. We
  /// re-request focus on any tap so the shortcuts stay alive.
  final _shortcutFocus = FocusNode();
  final _barKey = GlobalKey();

  static SharedPreferences? _volPrefs;
  Timer? _gOverlayTimer;
  Timer? _videoTapTimer;
  bool _navigating = false;

  /// True while `_playInPlace` is swapping the media in the player this screen
  /// already owns. A separate flag from `_navigating` because that one also
  /// means "this screen is on its way out" — `dispose()` reads it to decide
  /// whether to drop the jump history — and a switch never leaves.
  bool _switching = false;
  // The route being popped if its animation is reversing or the route is gone.
  bool get _isRoutePopping {
    final route = ModalRoute.of(context);
    return route == null || route.animation?.status == AnimationStatus.reverse;
  }

  bool _showSettings = false;
  bool _showEpisodes = false;
  bool _disposed = false;
  bool _globalImmersive = false;
  double _savedRate = 1.0;

  /// The Related list and the key it was computed for. The list is a pure
  /// function of (item, scan generation, jump stack's excluded paths) — see
  /// `utils/related_videos.dart` — so the key is those three inputs, and a
  /// rebuild that changes none of them (a play/pause repaint) reuses the list
  /// instead of shuffling again.
  List<MediaItem>? _relCache;
  String? _relCacheKey;

  // Mini progress bar (shown when controls hidden) — throttled-lightweight.
  final ValueNotifier<Duration> _miniPos = ValueNotifier(Duration.zero);
  final ValueNotifier<Duration> _miniDur = ValueNotifier(Duration.zero);
  final ValueNotifier<Duration> _miniBuf = ValueNotifier(Duration.zero);

  // Playback state the chrome renders from. One owner (this screen), one
  // value per fact: the control bar is a pure widget fed by these, so volume
  // can no longer diverge between the bar, the keyboard and the swipe gesture.
  final ValueNotifier<bool> _playing = ValueNotifier(false);
  final ValueNotifier<double> _volume = ValueNotifier(100);
  final ValueNotifier<double> _rate = ValueNotifier(1.0);
  late final Listenable _chromeState = Listenable.merge([
    _miniPos,
    _miniDur,
    _miniBuf,
    _playing,
    _volume,
    _rate,
  ]);

  /// Last non-zero volume, so unmute never lands on silence.
  double _prevVolume = 100;
  Timer? _volSaveTimer;

  /// True while the speed menu is open — it is a panel, so the chrome must not
  /// fade out from under it.
  bool _speedMenuOpen = false;
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
  }

  // ── Volume ────────────────────────────────────────────────
  // One entry point for every volume path (slider, wheel, arrow keys, swipe),
  // so the bar, the player and the persisted value can never disagree.

  void _setVolume(double v, {bool persist = true}) {
    final nv = v.clamp(0.0, 100.0);
    if (nv > 0) _prevVolume = nv;
    _volume.value = nv;
    p?.setVolume(nv);
    if (persist) _queueVolSave();
  }

  /// Debounced: a slider drag must not fire a platform write per frame, and
  /// the value still lands well before the route is popped.
  void _queueVolSave() {
    _volSaveTimer?.cancel();
    _volSaveTimer = Timer(const Duration(milliseconds: 300), _flushVolSave);
  }

  void _flushVolSave() {
    _volSaveTimer?.cancel();
    _volSaveTimer = null;
    _volPrefs?.setDouble('player_volume', _volume.value);
  }

  void _toggleMute() {
    if (_volume.value > 0) {
      _setVolume(0);
    } else {
      _setVolume(_prevVolume > 0 ? _prevVolume : 100);
    }
  }

  @override
  void initState() {
    super.initState();
    _item = widget.item;
    _jumpStack = ref.read(videoJumpStackProvider.notifier);
    _initVolPrefs().then((_) {
      if (_volPrefs != null && mounted) {
        _setVolume(
          _volPrefs!.getDouble('player_volume') ?? 100,
          persist: false,
        );
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
      // Guard against a mid-first-frame navigation (_go hands this route's place
      // to another screen and sets _navigating): don't spawn a stray Player on
      // the widget being replaced.
      if (!mounted || _disposed || _navigating) return;
      // The route already created one (see `PosterQuietRoute`), so the
      // expensive native init is behind us; otherwise create it here as
      // before. Either way exactly one player, owned by this screen.
      p = widget.warmPlayer ?? PlayerFactory.playback();
      vc = VideoController(p!);
      p!.open(Media(_item.url, httpHeaders: sharedAuthHeader));
      p!.play();
      p!.setVolume(_volume.value);
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
      _playing.value = p!.state.playing;
      _playingSub = p!.stream.playing.listen((isPlaying) {
        if (isPlaying) hasBeenPlaying = true;
        if (mounted) _playing.value = isPlaying;
      });
      _volumeSub = p!.stream.volume.listen((v) {
        if (mounted && v != _volume.value) _volume.value = v;
      });
      _rate.value = p!.state.rate;
      _rateSub = p!.stream.rate.listen((r) {
        if (mounted) _rate.value = r;
      });
      bool handlingCompletion = false;
      _completedSub = p!.stream.completed.listen((_) {
        if (!mounted ||
            _disposed ||
            handlingCompletion ||
            _navigating ||
            _switching) {
          return;
        }
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
    _volumeSub?.cancel();
    _rateSub?.cancel();
    _videoTapTimer?.cancel();
    _gOverlayTimer?.cancel();
    _scrollCtrl?.dispose();
    // Persist the live volume before the notifiers go away.
    _flushVolSave();
    _miniPos.dispose();
    _miniDur.dispose();
    _miniBuf.dispose();
    _playing.dispose();
    _volume.dispose();
    _rate.dispose();
    _hideTimer?.cancel();
    _exitTimer?.cancel();
    p?.stop();
    _shortcutFocus.dispose();
    p?.dispose();
    p = null;
    vc = null;
    // Leaving the player for good drops the session's jump history. A jump
    // (`_navigating`) must not: the screen replacing this one is the stack's
    // reader, and its own `Back` needs what is left in it.
    if (!_navigating) _jumpStack?.clear();
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
    // The episode sheet only exists in fullscreen — drop it on the way out so
    // re-entering fullscreen does not resurrect a stale sheet.
    if (!on) _showEpisodes = false;
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

  /// The panels this screen can have open, in the shape the shared rule in
  /// `utils/player_panels.dart` wants.
  PlayerPanels get _panels => PlayerPanels(
    settings: _showSettings,
    episodes: _showEpisodes,
    speedMenu: _speedMenuOpen,
  );

  void _resetIdle() {
    _hideTimer?.cancel();
    // An open sheet — or the speed menu, which is a panel too — owns the
    // screen: fading the bar (and the gear that closes the panel) out from
    // under the user is never what they asked for. Same rule as the wheel's.
    if (_panels.anyOpen) return;
    _fadeMs = const Duration(milliseconds: 200);
    _hideTimer = Timer(const Duration(seconds: _idleSecs), () {
      if (mounted) setState(() => _showControls = false);
    });
  }

  /// A drag on the bar's seek or volume slider is an interaction in progress,
  /// exactly like an open panel: while it lasts the bar must not fade out (the
  /// slider would leave with it), and when it ends the ordinary idle countdown
  /// resumes.
  void _onScrubActive(bool active) {
    if (active) {
      _hideTimer?.cancel();
      return;
    }
    // The drag can also end while a panel owns the screen: `_resetIdle` is the
    // one place that decides whether the countdown may be re-armed.
    _resetIdle();
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
    // Lock direction once movement is significant. The rule lives in
    // `utils/pan_lock.dart`, where it is unit-tested: a 12px slop on
    // `max(|dx|, |dy|)` alone committed a 30px/29px diagonal to a seek, which
    // hides the whole control bar (deliberate for a real scrub, wrong for a
    // diagonal) — the dominance ratio is what the near-diagonal band needed.
    if (_gMode == 0) {
      final mode = decidePanMode(Offset(dx, dy));
      if (mode == 0) return;
      if (mode == 1) {
        _gMode = 1; // seek
        _seekPreviewMs = p!.state.position.inMilliseconds.toDouble();
        _hideTimer?.cancel();
        // While seeking, show ONLY the minimal seek bar — hide full controls.
        setState(() {
          _seeking = true;
          _showControls = false;
        });
      } else {
        // Brightness or volume — the one part of the decision the function
        // cannot make, because it does not know where the drag started.
        _gMode = (_gStart.dx < size.width / 2)
            ? 2
            : 3; // left=brightness, right=volume
      }
    }
    if (_gMode == 1) {
      // The arithmetic lives in `utils/seek_preview.dart`, where it is unit-tested:
      // a zero-width gesture area (before the first layout) used to make the drag
      // factor NaN, which `clamp` cannot catch and which threw in `Duration.round()`
      // when the finger lifted.
      final next = advanceScrubPreview(
        current: _seekPreviewMs,
        delta: d.delta.dx,
        width: size.width,
        duration: p!.state.duration,
      );
      if (next != _seekPreviewMs) {
        _seekPreviewMs = next;
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
      // The swipe feeds the shared volume setter, so the bar's slider and the
      // persisted value follow the gesture; only the write is deferred.
      _setVolume(
        _volume.value - (d.delta.dy / size.height) * 100,
        persist: false,
      );
      setState(() {
        _gOverlayType = _OverlayType.volume;
        _gOverlayValue = _volume.value.round();
      });
    }
  }

  void _onPanEnd(_) {
    if (!_isMobile) return;
    final mode = _gMode;
    if (mode == 1 && p != null) {
      // Clamped against the duration as it is NOW and refused when the preview
      // stopped being a number — see `utils/seek_preview.dart` and its tests.
      final target = scrubSeekTarget(
        previewMs: _seekPreviewMs,
        duration: p!.state.duration,
      );
      if (target != null) p!.seek(target);
    }
    _gMode = 0;
    if (mode == 3) _queueVolSave();
    setState(() {
      _seeking = false;
      _gOverlayType = null;
    });
    _resetIdle();
  }

  /// A cancelled drag never reaches [_onPanEnd], and without this the UI stayed in
  /// the gesture's state: `_seeking` true means the full controls stay hidden and
  /// the minimal seek bar stays on screen, forever, because nothing else resets it.
  /// A system gesture or losing the arena is enough to cancel a drag, so this is
  /// reachable in normal use.
  ///
  /// A second finger is NOT one of them: `MultitouchDragStrategy.latestPointer`
  /// hands the drag over to the newcomer rather than cancelling it, so this
  /// callback never runs for it — and because `_gStart` still holds the FIRST
  /// finger's origin, the mode gets picked from dx/dy that mix the two pointers'
  /// positions. That is left as it is on purpose: a second finger can then choose
  /// a different mode, but it cannot leave the UI stuck (this callback and
  /// [_onPanEnd] both clear the state), and re-anchoring the drag mid-gesture
  /// would let a gesture switch modes under the user.
  ///
  /// Nothing is committed here — the user did not finish the gesture — but the
  /// bookkeeping is the same as the end of a drag, minus the seek and the deferred
  /// volume write.
  void _onPanCancel() {
    if (!_isMobile) return;
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

  /// The Related list for this screen, cached by its three inputs: the item,
  /// the scan generation and the jump stack's excluded paths. The shuffle
  /// itself is `relatedFor` (`utils/related_videos.dart`) — a pure function,
  /// because the player cannot be mounted in a test.
  List<MediaItem> _relatedFor(
    List<MediaItem> allVideos,
    Set<String> excluded,
    int scanGen,
  ) {
    final key = '$scanGen\u0000${_item.url}\u0000${excluded.join('\u0000')}';
    if (_relCache != null && _relCacheKey == key) return _relCache!;
    final list = relatedFor(_item, allVideos, excludePaths: excluded);
    _relCache = list;
    _relCacheKey = key;
    return list;
  }

  void onNext() {
    if (_navigating || _switching || _isRoutePopping) return;
    // The same list the user is looking at, exclusions included: "next" must
    // not play a video the Related list refuses to show.
    final r = _relatedFor(
      ref.read(videosListProvider),
      ref.read(jumpExcludedPathsProvider),
      ref.read(scanStateProvider).scanGen,
    );
    if (r.isEmpty) return;
    _playInPlace(r.first, back: false);
  }

  void onPrev() {
    if (_navigating || _switching || _isRoutePopping) return;
    // Back through the jump history: the newest entry is where this screen was
    // jumped from, and popping it is what makes the step one-way.
    final from = ref.read(videoJumpStackProvider.notifier).pop();
    if (from == null) return;
    _playInPlace(from, back: true);
  }

  /// Switches to [item] inside this screen — what the transport bar's prev/next
  /// do.
  ///
  /// Not `_go`, and that difference is the whole point of the pair. `_go`
  /// REPLACES the route, so the incoming screen is built from its constructor:
  /// everything the outgoing one held is gone unless it is handed over again.
  /// Fullscreen survives only because it is passed explicitly; the speed,
  /// picture-in-picture (with the geometry it was dragged to AND the scroll
  /// position that put it there), the chrome's visibility and the screen
  /// brightness are silently reset. Opening the media in the player that is
  /// already playing keeps every one of them BY CONSTRUCTION — nothing is
  /// re-created, so there is nothing to carry and nothing to forget — and
  /// nothing on screen moves: no route transition, no re-mount, no second player
  /// starting while the first one is torn down.
  ///
  /// [back] is the direction the history is walked in, exactly as in `_go`: a
  /// forward step records the video being left, a back step has already popped
  /// the entry it plays. The transition is what the two paths no longer share.
  /// `Back` still walks the history as a ROUTE step, with the platform's
  /// back-direction animation, which is what keeps it a different gesture from
  /// this control ("like back, but not the same").
  Future<void> _playInPlace(MediaItem item, {required bool back}) async {
    final player = p;
    if (player == null) {
      // The player is created in the first post-frame callback, so a switch
      // cannot normally arrive before it exists; a route step is the honest
      // fallback if one ever does.
      _go(item, back: back);
      return;
    }
    _switching = true;
    try {
      if (!back) ref.read(videoJumpStackProvider.notifier).push(_item);
      setState(() {
        _item = item;
        // The episodes panel lists the SIBLINGS of the video it was opened on,
        // and auto-advance can fire while it is open.
        _showEpisodes = false;
      });
      await player.open(Media(item.url, httpHeaders: sharedAuthHeader));
      if (_disposed || !mounted) return;
      // A fresh load resets what the user set on the player, so the two facts
      // mpv does not carry across are re-applied from this screen's own state —
      // which is the state they were watching in.
      player.setVolume(_volume.value);
      player.setRate(_rate.value);
      player.play();
    } finally {
      _switching = false;
    }
  }

  /// Replaces this route with [item]'s player.
  ///
  /// [back] is the direction the history is being walked in, and it is one flag
  /// because it decides two things that must never disagree:
  ///
  ///  * the jump stack's push. Every FORWARD jump records the video it leaves —
  ///    that entry is exactly what `Back` returns to. The back paths (`onPrev`,
  ///    the back button) have already popped the entry they are navigating to,
  ///    and re-recording it would make `Back` bounce between the same two
  ///    videos.
  ///  * the route's transition (`PosterQuietRoute.backStep`): a step back
  ///    through the history enters from the left, so it no longer looks like
  ///    opening a video.
  void _go(MediaItem item, {bool back = false}) {
    if (_navigating || _switching || _isRoutePopping) return;
    _navigating = true;
    if (!back) ref.read(videoJumpStackProvider.notifier).push(_item);
    // Stop feeding the outgoing screen, but leave its player ALIVE. This route
    // stays in the tree until the replacement has finished animating (measured
    // on a 300ms zoom: its subtree is present at 0/100/200ms and gone once
    // settled), so disposing the player here — as this used to — blanks the
    // video area for exactly the length of the transition: the black was the
    // disposed texture's, not the route's absence. Muting is enough to keep the
    // two soundtracks from overlapping, and it happens after the volume
    // subscription is cancelled so the bar cannot flicker to 0 on the way out.
    // The player is stopped and disposed by this screen's own `dispose()`, when
    // the route really goes.
    _posSub?.cancel();
    _durSub?.cancel();
    _bufSub?.cancel();
    _playingSub?.cancel();
    _completedSub?.cancel();
    _volumeSub?.cancel();
    _rateSub?.cancel();
    _scrollCtrl?.removeListener(_onScroll);
    p?.setVolume(0);
    if (mounted) setState(() {});
    Navigator.pushReplacement(
      context,
      // Same route class as the other three push sites: it suspends the poster
      // pool synchronously at push time and creates the incoming screen's
      // playback player there, instead of in that screen's own post-frame
      // callback. Its install/dispose depth is what keeps this replacement from
      // lifting the suspension between the two screens.
      PosterQuietRoute(
        backStep: back,
        build: (warm) => VideoPlayerScreen(
          item: item,
          startFullscreen: fullscreen,
          warmPlayer: warm,
        ),
      ),
    );
  }

  /// Leaves the whole player chain and lands on the library — the "home" action
  /// in the player chrome.
  ///
  /// Not one more jump step, and deliberately not a `_go`: a jump replaces this
  /// route with another player and keeps the history, while this ends the
  /// session. So it takes the ordinary "leaving the player for good" path,
  /// which is the one the screen already has:
  ///
  ///  * `p?.stop()` first — the documented rule before any navigation away from
  ///    the player (the route's `dispose()` disposes the player, and a player
  ///    must not be mid-playback when it is dropped);
  ///  * `popUntil` on the landing rule in `utils/player_exit.dart`, which
  ///    unwinds the player AND the search screen a player may have been opened
  ///    from, and stops at the library;
  ///  * `_navigating` stays false, so `dispose()` runs its "leaving for good"
  ///    branch: the jump stack is CLEARED (every entry in it is a video on the
  ///    chain being left, and a stale stack would both offer `Back` a jump into
  ///    a session that is over and hide those videos from the next player's
  ///    Related list), the system UI/orientation and window chrome are restored
  ///    as on any other exit.
  void _goHome() {
    if (_navigating || _switching || _isRoutePopping) return;
    p?.stop();
    Navigator.popUntil(context, isLibraryLandingRoute);
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
            _setVolume(_volume.value + delta * 100);
          },
          onEscape: () {
            // The speed menu owns ESC while it is open: it is a popup ROUTE, so
            // the same key press reaches its `DismissIntent` through the focus
            // tree and the menu dismisses itself. Without this early return one
            // press did both things at once — close the menu AND (fullscreen)
            // leave fullscreen — because this global handler
            // (`widgets/media_player_keys.dart`) sees every press regardless.
            if (_speedMenuOpen) return;
            // The episode sheet and the settings panel are plain widgets in this
            // screen's tree, so neither has an ESC handler of its own: this chain
            // closes the first one that is open, and only a press that closes
            // nothing at all — a bare ESC — reaches fullscreen.
            if (_showEpisodes) {
              _toggleEpisodes();
            } else if (_showSettings) {
              _toggleSettings();
            } else if (fullscreen) {
              _setFullscreen(false);
            }
          },
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
    // The jump stack is an input to the Related list — its entries are excluded
    // — so it is watched here, and `_relatedFor` caches on it. It is also what
    // decides whether the chrome offers Previous and Home at all: with an empty
    // history `Back` leaves the player by itself, so both would repeat it.
    final excluded = ref.watch(jumpExcludedPathsProvider);
    final hasHistory = ref.watch(videoJumpStackProvider).isNotEmpty;
    final related = _relatedFor(allVideos, excluded, scanGen);
    final size = MediaQuery.of(c).size;
    final isLandscape = size.width > size.height;
    final wide = _isMobile
        ? (isLandscape && size.width > 600)
        : size.width > 900;
    final video = _video();
    if (fullscreen) {
      // Notch / camera cutout insets. viewPadding (not padding): immersive
      // mode hides the system bars, and padding collapses to zero with them —
      // exactly when the back arrow would slide under the cutout.
      final view = MediaQuery.viewPaddingOf(c);
      final safe = EdgeInsets.only(
        left: view.left,
        top: view.top,
        right: view.right,
      );
      return _withShortcuts(
        PopScope(
          canPop: false,
          onPopInvokedWithResult: (didPop, _) {
            if (didPop) return;
            _handleBack();
          },
          child: Scaffold(
            backgroundColor: Colors.black,
            body: MouseRegion(
              onHover: (_) => _poke(),
              onEnter: (_) => _show(),
              child: Listener(
                onPointerDown: (_) => _shortcutFocus.requestFocus(),
                child: PlayerWheelLayer(
                  // Wheel over the video: desktop's fastest volume path. It
                  // goes through `WheelGuard` (see `utils/wheel_guard.dart`)
                  // instead of acting here, so Flutter's `PointerSignalResolver`
                  // decides the one handler for a notch — whoever is hit first
                  // wins. Acting directly made this listen THROUGH the playlist:
                  // a wheel over the open episode sheet scrolled the list AND
                  // stepped the volume in the same notch.
                  volume: () => _volume.value,
                  nextVolume: (current, delta) =>
                      (current + (delta > 0 ? -5.0 : 5.0)).clamp(0.0, 100.0),
                  setVolume: (v) {
                    _setVolume(v);
                    _resetIdle();
                    _gOverlayTimer?.cancel();
                    if (mounted) {
                      setState(() {
                        _gOverlayType = _OverlayType.volume;
                        _gOverlayValue = _volume.value.round();
                      });
                    }
                    _gOverlayTimer = Timer(const Duration(seconds: 1), () {
                      if (mounted) setState(() => _gOverlayType = null);
                    });
                  },
                  gate: () => _panels.anyOpen,
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
                      // Top chrome on every platform: back on the left, title,
                      // settings on the right. It used to exist on mobile only —
                      // which is why desktop fullscreen had no way back.
                      Positioned(
                        top: 0,
                        left: 0,
                        right: 0,
                        child: IgnorePointer(
                          ignoring: !_showControls,
                          child: AnimatedOpacity(
                            opacity: _showControls ? 1.0 : 0.0,
                            duration: _fadeMs,
                            child: PlayerTopBar(
                              title: _item.name,
                              onBack: _handleBack,
                              // Only while the history makes it a DIFFERENT
                              // action from Back; see `PlayerTopBar.onHome`.
                              onHome: hasHistory ? _goHome : null,
                              onSettings: _toggleSettings,
                              safe: safe,
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
                            child: _bar(
                              safe: EdgeInsets.only(bottom: view.bottom),
                            ),
                          ),
                        ),
                      ),
                      if (_seeking) _seekBar(),
                      _speedBadge(top: safe.top + 52),
                      _gestureChip(),
                      if (_showSettings) _settingsOverlay(),
                      if (_showEpisodes)
                        EpisodePickerPanel(
                          items: related,
                          fingerPreview: _fp,
                          onPick: (item) {
                            setState(() => _showEpisodes = false);
                            _go(item);
                          },
                          onDismiss: () {
                            setState(() => _showEpisodes = false);
                            _poke();
                          },
                        ),
                    ],
                  ),
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
      // The platform back gesture takes the same path as the on-screen back
      // button here too, so it retraces the jump history (and closes overlays)
      // instead of popping the route behind the screen's back. Mirrors the
      // fullscreen branch above, `canPop: false` included: an empty stack pops
      // the route from `_handleBack`.
      PopScope(
        canPop: false,
        onPopInvokedWithResult: (didPop, _) {
          if (didPop) return;
          _handleBack();
        },
        child: Scaffold(
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
            onPanCancel: _onPanCancel,
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
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    IconButton(
                      icon: const Icon(Icons.arrow_back, color: Colors.white70),
                      tooltip: 'Back',
                      onPressed: _handleBack,
                    ),
                    // Beside Back because it is the other way OUT of the player:
                    // back retraces one jump of the history, home leaves the
                    // whole chain for the library (`_goHome`). Only while there
                    // IS a history to retrace — with an empty stack Back leaves
                    // the player too, and two buttons for one action is one too
                    // many.
                    if (ref.watch(videoJumpStackProvider).isNotEmpty)
                      IconButton(
                        icon: const Icon(Icons.home, color: Colors.white70),
                        tooltip: 'Home',
                        onPressed: _goHome,
                      ),
                  ],
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
        if (_seeking) _seekBar(),
        _speedBadge(top: 8),
        _gestureChip(),
      ],
    ),
  );

  /// Windowed back: leaves the player. Fullscreen back (top bar) exits
  /// fullscreen first — overlays close before either. Before leaving, back
  /// retraces one jump: the newest entry of the shared stack is popped and
  /// played, and only an empty stack lets the player route itself be popped.
  void _handleBack() {
    if (_showEpisodes) {
      setState(() => _showEpisodes = false);
      _poke();
      return;
    }
    if (_showSettings) {
      setState(() => _showSettings = false);
      _poke();
      return;
    }
    if (fullscreen) {
      _setFullscreen(false);
      return;
    }
    // The same guards the jump paths use: a navigation already owns this route
    // (a jump in flight, a media swap, or this route already reversing), so back
    // must not pop the route out from under it — nor consume a stack entry that
    // nothing would then navigate to.
    if (_navigating || _switching || _isRoutePopping) return;
    final from = ref.read(videoJumpStackProvider.notifier).pop();
    if (from != null) {
      // Deliberately the ROUTE step and not the transport bar's in-place switch:
      // back is "leave this video", so it plays the platform's back-direction
      // transition. The transport's prev reaches the same video with nothing on
      // screen moving at all — the same navigation, presented differently.
      _go(from, back: true);
      return;
    }
    Navigator.pop(context);
  }

  Widget _bar({EdgeInsets safe = EdgeInsets.zero}) => p == null
      ? const SizedBox.shrink()
      : MouseRegion(
          key: _barKey,
          onEnter: _onBarEnter,
          onExit: _onBarExit,
          child: ListenableBuilder(
            listenable: _chromeState,
            builder: (_, _) => PlayerControlBar(
              playing: _playing.value,
              position: _miniPos.value,
              duration: _miniDur.value,
              buffer: _miniBuf.value,
              volume: _volume.value,
              speed: _rate.value,
              fullscreen: fullscreen,
              hasPrev: ref.watch(videoJumpStackProvider).isNotEmpty,
              hasNext: _relCache?.isNotEmpty ?? false,
              // The episode sheet only exists in fullscreen.
              hasEpisodes: fullscreen && (_relCache?.isNotEmpty ?? false),
              safe: safe,
              onPlayPause: _togglePlayPause,
              onSeek: (d) => p?.seek(d),
              onScrubActive: _onScrubActive,
              onVolumeChanged: (v) => _setVolume(v, persist: false),
              onVolumeChangeEnd: _queueVolSave,
              onToggleMute: _toggleMute,
              onSpeedChanged: (s) => p?.setRate(s),
              onPrev: onPrev,
              onNext: onNext,
              onEpisodes: _toggleEpisodes,
              onFullscreen: () => _setFullscreen(!fullscreen),
              onMenuVisibilityChanged: (open) {
                _speedMenuOpen = open;
                // Closing the menu hands the idle timer back (the pointer has
                // usually left the bar by then, so nothing else would).
                if (!open) _poke();
              },
            ),
          ),
        );

  void _toggleSettings() {
    setState(() {
      _showEpisodes = false;
      _showSettings = !_showSettings;
      if (_showSettings) _showControls = true;
    });
    if (_showSettings) {
      // Pin the chrome: the gear is the way back out of the panel.
      _hideTimer?.cancel();
    } else {
      _poke();
    }
  }

  void _toggleEpisodes() {
    setState(() {
      _showSettings = false;
      _showEpisodes = !_showEpisodes;
      if (_showEpisodes) _showControls = true;
    });
    if (_showEpisodes) {
      // Keep the bar underneath the sheet from fading while browsing.
      _hideTimer?.cancel();
    } else {
      _poke();
    }
  }

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
              '${formatMs(_seekPreviewMs.round())} / ${formatMs(dur.round())}',
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
            '${formatMs(_pipSeekMs.round())} / ${formatMs(dur.round())}',
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
    // Same tested arithmetic as the full-screen gesture: a PiP width of zero (or a
    // duration that is not known yet) must not turn the preview into a NaN, which
    // `Duration.round()` would throw on when the finger lifts.
    final next = advanceScrubPreview(
      current: _pipSeekMs,
      delta: d.delta.dx,
      width: _pipW,
      duration: p?.state.duration ?? Duration.zero,
    );
    if (next != _pipSeekMs) setState(() => _pipSeekMs = next);
  }

  void _onPipSeekEnd(DragEndDetails d) {
    final target = scrubSeekTarget(
      previewMs: _pipSeekMs,
      duration: p?.state.duration ?? Duration.zero,
    );
    if (target != null) p?.seek(target);
    setState(() => _pipSeeking = false);
  }

  /// A cancelled drag never reaches [_onPipSeekEnd], so the seek overlay would stay
  /// on the PiP forever (a second finger or a system gesture is enough). Abort
  /// without seeking, exactly like the full-screen gesture's [_onPanCancel].
  void _onPipSeekCancel() {
    if (!_pipSeeking) return;
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
        onHorizontalDragCancel: isSmall ? null : _onPipSeekCancel,
        // The pan drag only ever moves the overlay (clamped per frame in
        // `_onPipPanUpdate`) and its end handler is a documented no-op, so a
        // cancelled pan has nothing to unwind.
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
              // Home (leave the player chain for the library). The PiP is what
              // the windowed chrome collapses to once the page is scrolled, and
              // the video's own Back/Home cluster is not in the tree then — so
              // the way out has to live here too.
              Positioned(
                top: 4,
                right: 76,
                child: GestureDetector(
                  onTap: _goHome,
                  child: Container(
                    decoration: const BoxDecoration(
                      color: Colors.black54,
                      shape: BoxShape.circle,
                    ),
                    padding: const EdgeInsets.all(6),
                    child: const Icon(
                      Icons.home,
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

  // Centre chip for brightness/volume gesture feedback. Always mounted so the
  // fade-out can finish; null value means "hidden".
  Widget _gestureChip() => Positioned.fill(
    child: PlayerGestureChip(
      brightness: _gOverlayType == _OverlayType.brightness,
      value: _gOverlayType == null ? null : _gOverlayValue,
    ),
  );

  Widget _speedBadge({required double top}) {
    return Positioned(
      top: top,
      left: 0,
      right: 0,
      child: Center(child: PlayerSpeedBadge(visible: show2x)),
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
        onDismiss: () {
          setState(() => _showSettings = false);
          // Re-arm the idle timer: the panel's own dismiss affordance is a way
          // out too, and nothing else would restart it.
          _poke();
        },
      ),
    );
  }

  Widget _meta() => Container(
    padding: const EdgeInsets.all(16),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          _item.name,
          style: const TextStyle(
            color: Colors.white,
            fontSize: 20,
            fontWeight: FontWeight.w600,
          ),
        ),
        const SizedBox(height: 8),
        Row(
          children: [
            if (_item.durationSeconds != null) ...[
              Text(
                _item.formattedDuration,
                style: const TextStyle(color: Colors.white54, fontSize: 13),
              ),
              const SizedBox(width: 8),
              const Text('•', style: TextStyle(color: Colors.white54)),
            ],
            const SizedBox(width: 8),
            Text(
              _item.formattedSize,
              style: const TextStyle(color: Colors.white54, fontSize: 13),
            ),
            const SizedBox(width: 8),
            const Text('•', style: TextStyle(color: Colors.white54)),
            const SizedBox(width: 8),
            Text(
              _item.extension.toUpperCase(),
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
