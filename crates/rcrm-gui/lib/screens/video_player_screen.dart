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
import '../config/theme.dart';
import '../services/net.dart';
import '../services/player_factory.dart';
import '../services/screen_orientation.dart';
import '../services/system_volume.dart';
import '../providers/library_provider.dart';
import '../providers/settings_provider.dart';
import '../providers/video_jump_stack.dart';
import '../providers/window_chrome_provider.dart';
import '../widgets/video_card.dart';
import '../widgets/media_player_keys.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../widgets/player_controls.dart';
import '../widgets/player_overlays.dart';
import '../widgets/finger_preview_listener.dart';
import '../widgets/player_settings_panel.dart';
import '../widgets/episode_picker_panel.dart';
import '../utils/format.dart';
import '../utils/pan_lock.dart';
import '../utils/player_eof.dart';
import '../utils/player_exit.dart';
import '../utils/player_orientation.dart';
import '../utils/player_panels.dart';
import '../utils/player_volume.dart';
import '../utils/poster_quiet_route.dart';
import '../utils/related_videos.dart';
import '../utils/seek_preview.dart';
import '../utils/swipe_value.dart';
import '../utils/wheel_guard.dart';

class VideoPlayerScreen extends ConsumerStatefulWidget {
  final MediaItem item;
  final bool startFullscreen;

  /// The shape the orientation mask is locked to as this screen takes over --
  /// handed over by the screen this one REPLACES, exactly like [startFullscreen]
  /// and for the same reason: the outgoing screen does not release the mask on
  /// its way out (the replacement is still the player, and releasing would drop
  /// the library's own chrome mid-transition), so the platform is still holding
  /// it when this screen mounts. That makes it this screen's first
  /// `OrientationRequest.fittedShape`, and holding it is what keeps a route step
  /// to another video from rotating off the fitted axis while the new file
  /// loads. Null when nothing was locked, which is the whole of a player opened
  /// from the library.
  final bool? startLockedShape;

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
    this.startLockedShape,
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
  /// The video shape the orientation mask in force is locked to, or null while
  /// nothing is locked to one (outside fullscreen, a strategy that does not read
  /// the shape, or no shape reported yet).
  ///
  /// It is the last request's `fittedShape`, and `_applyOrientation` is its only
  /// writer (initState seeds it from `startLockedShape`), so the record cannot
  /// drift from the mask the platform is actually holding. It has two jobs. It
  /// stops the parameters stream's repeated reports (mpv sends them per property
  /// change) from re-applying a mask that is already right — including after a
  /// release, which is why `_releaseOrientation` leaves it alone — and it is what
  /// `fill` HOLDS while the next file loads: a skip reports no size for a moment,
  /// and releasing the lock for that moment is what cost a video change two
  /// rotations. See `orientationRequestFor`.
  bool? _lockedShape;

  StreamSubscription? _bufferingSub;
  StreamSubscription? _shapeSub;
  bool show2x = false;
  bool fullscreen = false;
  Duration _fadeMs = const Duration(milliseconds: 200);
  bool _showControls = true;
  Timer? _hideTimer;
  Timer? _exitTimer;
  static const _idleSecs = 2;

  /// How long a stall has to last before it is worth showing a spinner for.
  ///
  /// media_kit reports `buffering` for the handful of frames a seek spends
  /// refilling, so without this the spinner would flash on every scrub — an
  /// animation that means "wait" fired at something that was never a wait.
  /// 300ms is the same grace video.js gives its own loading spinner
  /// (`vjs-spinner-show 0s linear 0.3s forwards`); only a stall longer than
  /// this is a stall the user is sitting through.
  static const _bufferGrace = Duration(milliseconds: 300);
  Timer? _bufferStall;

  /// How long the up-next card waits before playing what it is offering.
  ///
  /// Long enough to read a title and decide, short enough that a viewer who
  /// wants the next episode is not waiting on a formality. The card draws the
  /// same countdown, so this number is never a claim about the ring — it IS the
  /// ring.
  static const _upNextSeconds = Duration(seconds: 8);

  /// True once a stall has outlived [_bufferGrace]. Never a `setState`: the
  /// spinner only repaints itself.
  final ValueNotifier<bool> _buffering = ValueNotifier(false);
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

  /// Which reading the bar's time display shows. Persisted with the volume, for
  /// the same reason: it is a preference about how the user watches, not a
  /// property of one video.
  PlayerTimeMode _timeMode = PlayerTimeMode.elapsed;

  /// The video waiting for a yes, while `loopAll` counts down to it. Null the
  /// rest of the time — including while the countdown is running out of the
  /// user's sight behind an open panel, where it is still the autoplay they
  /// asked for.
  MediaItem? _upNext;

  /// Where this file has got to at its end — the app's own memory of the
  /// ending, because media_kit cannot report it (see `utils/player_eof.dart`).
  /// Every event that can change it goes through the value's own methods, so
  /// there is exactly one rule for what a finished file is and one for what
  /// taking it back means.
  PlayerEof _eof = PlayerEof.idle;

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

  /// The level a volume swipe is asking for, 0..100 — the gesture's own
  /// accumulator, exactly like [_brightness] for the other half of the screen.
  ///
  /// It is re-seeded from the bar when a swipe commits and belongs to the finger
  /// until it lifts; the value the DEVICE landed on is adopted at the end of the
  /// gesture (`_onPanEnd`). Reading the bar back every frame instead — which is
  /// what this used to do — hands the finger the quantised step it just came
  /// from, so travel is thrown away (see `utils/swipe_value.dart`).
  double _gVolume = 100;

  static Future<void> _initVolPrefs() async {
    _volPrefs ??= await SharedPreferences.getInstance();
  }

  // ── Volume ────────────────────────────────────────────────
  // One entry point for every volume path (slider, wheel, arrow keys, swipe,
  // mute) and ONE owner of the state behind it: `_vol`
  // (`utils/player_volume.dart`), which decides whether that control drives the
  // DEVICE's media stream or libmpv's own gain. On mobile the device is the
  // default (`use_system_volume`, Settings → Display); the player's own gain is
  // what every platform falls back to.
  //
  // The screen itself decides nothing here -- it adopts a value and does what
  // that value says. It cannot be mounted in a test (its first frame builds a
  // real media_kit `Player`), so the transitions that have bitten live in the
  // util instead.

  /// The session's volume. `_volume` (the notifier the chrome listens to) is a
  /// mirror of `level`, written only by [_adoptVolume].
  PlayerVolume _vol = PlayerVolume.initial;

  /// True while [SystemVolume.state] is being followed. A notifier would take the
  /// same listener twice, and the seeding path can run twice (a reading already
  /// held first, the fresh one after it).
  bool _followingSystem = false;

  /// The gain handed to the player itself — unity while the device owns the
  /// level, the level itself otherwise (`PlayerVolume.playerGain`).
  double get _playerGain => _vol.playerGain;

  /// THE place the session's volume changes: the bar and the player's own gain
  /// follow [next], and the device subscription is attached, kept or dropped to
  /// match — which is how a binding decided from a stale reading can still be
  /// dropped when the fresh one reports a fixed output.
  ///
  /// [applyGain] is false for a level that came FROM the player's own gain
  /// stream: telling the player what it has just said is an echo, not an update.
  void _adoptVolume(
    PlayerVolume next, {
    bool persist = true,
    bool applyGain = true,
  }) {
    final PlayerVolume before = _vol;
    _vol = next;
    if (next.bound && !_followingSystem) {
      _followingSystem = true;
      SystemVolume.state.addListener(_onSystemVolume);
    } else if (!next.bound && _followingSystem) {
      _followingSystem = false;
      SystemVolume.state.removeListener(_onSystemVolume);
    }
    if (next.level != _volume.value) _volume.value = next.level;
    // The player hears about it when the app's own volume IS the level, and when
    // the level just changed owner; while bound its gain stays at unity.
    if (applyGain && (!next.bound || next.bound != before.bound)) {
      p?.setVolume(next.playerGain);
    }
    if (persist) _queueVolSave();
  }

  /// Picks the volume this screen starts at, and where it comes from.
  ///
  /// Unbound: the level this app remembers (`player_volume`), as it always has.
  /// Bound: the DEVICE's media volume — the setting means "the phone's volume
  /// IS the volume", so opening a video must not move it, and what the bar shows
  /// is what the phone is at now rather than what this app last played at.
  ///
  /// The read is a platform round trip and can fail; when it does, or when the
  /// output cannot be set at all (a fixed-volume sink), the binding is dropped
  /// and the player's own volume is used rather than a bar starting from a
  /// number nobody read.
  Future<void> _seedVolume() async {
    final want =
        SystemVolume.supported && ref.read(uiSettingsProvider).useSystemVolume;
    final stored = _volPrefs?.getDouble('player_volume') ?? 100;
    SystemVolumeReading? reading;
    if (want) {
      SystemVolume.watch();
      // A reading is already here more often than not (the app takes one at
      // startup), and it is applied BEFORE the round trip below: the bar opens
      // on the level the phone is at, not on 100 for a frame while the platform
      // answers.
      reading = SystemVolume.state.value;
      if (reading != null) _seedFrom(reading, want, stored);
      reading = await SystemVolume.read() ?? reading;
      if (!mounted) return;
      // The second pass CONFIRMS the decision; it does not re-adopt the level.
      // Its reading was already in flight when anything that happened in between
      // did, and a volume-key press in the first moments of a video is exactly
      // that -- it arrives as a push and must not be undone by a stale answer.
      _adoptVolume(
        _vol.reconfirmed(
          supported: SystemVolume.supported,
          setting: want,
          reading: reading,
          fallbackLevel: stored,
        ),
        persist: false,
      );
      return;
    }
    _seedFrom(reading, want, stored);
  }

  void _seedFrom(SystemVolumeReading? reading, bool want, double stored) {
    _adoptVolume(
      _vol.seeded(
        supported: SystemVolume.supported,
        setting: want,
        reading: reading,
        fallbackLevel: stored,
      ),
      persist: false,
    );
  }

  /// A volume change made anywhere but here — the hardware keys, another app,
  /// the system's own panel. The bar follows it, because the phone's volume is
  /// the number the bar is showing.
  void _onSystemVolume() => _adoptDevice(SystemVolume.state.value);

  /// What the DEVICE says the level is: the push after somebody moved it, and
  /// the answer to this app's own write.
  ///
  /// The second one is applied HERE and not only through `state`, because a
  /// quantised request can come back equal to the reading the notifier already
  /// holds — and an unchanged `ValueNotifier` notifies nobody, which would leave
  /// the bar showing the 41% the finger asked for while the phone sits at 40%.
  void _adoptDevice(SystemVolumeReading? reading) {
    if (_disposed) return;
    // Mid-swipe the FINGER owns the level, and an answer that arrives while it
    // is down would move the bar under it — on a coarse stream, backwards. What
    // the device said is still in `SystemVolume.state`, and the end of the
    // gesture adopts it (`_onPanEnd`).
    if (_gMode == 3) return;
    _adoptVolume(_vol.reported(reading), persist: false);
  }

  /// The player's own gain stream: the truth for the app's volume when the app
  /// owns it (a fresh `open` resets it). Never while bound — that stream then
  /// carries only the unity gain this screen set, and mirroring it would stomp
  /// the level the user is looking at.
  void _onPlayerGain(double v) {
    if (_vol.bound) return;
    _adoptVolume(_vol.withLevel(v), persist: false, applyGain: false);
  }

  void _setVolume(double v, {bool persist = true}) {
    // A level that is not a number is refused by `withLevel`, at the one place
    // every volume path goes through: a gesture area with no height yet produces
    // one, and `clamp` is transparent to NaN (on a bound session its `round()`
    // would throw from inside an unawaited write).
    if (!v.isFinite) return;
    _adoptVolume(_vol.withLevel(v), persist: persist);
    if (!_vol.bound) return;
    // The device is asked for what the user asked for, and answers with the step
    // it really landed on.
    unawaited(SystemVolume.setPercent(_vol.level).then(_adoptDevice));
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
    // Bound to the device, the number belongs to the phone and not to this app:
    // remembering it would override the system volume at the next launch and
    // feed a stale level to an unbound player.
    if (!_vol.remembersAppVolume) return;
    _volPrefs?.setDouble('player_volume', _vol.level);
  }

  void _toggleMute() {
    if (_vol.level > 0) {
      _setVolume(0);
      return;
    }
    // Bound to the device, the level to come back to may not be one this app
    // ever saw — a session can start with the phone already silent, and then
    // nothing has been seen at all — so the device's own last audible level
    // answers (`PlayerVolume.unmuteTo`, which is why `lastAudible` starts at 0).
    _setVolume(
      _vol.bound
          ? _vol.unmuteTo(SystemVolume.state.value)
          : (_vol.lastAudible > 0 ? _vol.lastAudible : 100),
    );
  }

  // ── Time reading ──────────────────────────────────────────

  /// Swaps elapsed/total for elapsed/remaining — the same two readings a
  /// video.js skin offers as separate time controls, in the one line this bar
  /// has room for. Persisted: someone who watches with a countdown wants it
  /// next time too.
  void _toggleTimeMode() {
    setState(() {
      _timeMode = _timeMode == PlayerTimeMode.remaining
          ? PlayerTimeMode.elapsed
          : PlayerTimeMode.remaining;
    });
    _volPrefs?.setString(
      'player_time_mode',
      _timeMode == PlayerTimeMode.remaining ? 'remaining' : 'elapsed',
    );
    // The user just touched the bar; the idle countdown starts over rather than
    // expiring under the finger.
    _resetIdle();
  }

  // ── Up next ───────────────────────────────────────────────

  /// Offers the next video rather than taking it.
  ///
  /// `loopAll` used to call `onNext()` the instant a file ended — the one place
  /// playback decided something on the user's behalf with no chance to
  /// disagree, and it did it at the exact moment they were looking at the last
  /// frame. The same list, the same next video; what changed is that it now
  /// asks. The list is the one `onNext` reads, exclusions included, so the card
  /// cannot promise a video the Related list refuses to show.
  void _offerNext() {
    final r = _relatedFor(
      ref.read(videosListProvider),
      ref.read(jumpExcludedPathsProvider),
      ref.read(scanStateProvider).scanGen,
    );
    if (r.isEmpty) return;
    if (!mounted) return;
    setState(() => _upNext = r.first);
  }

  /// The card's "yes", from the button and from the ring running out alike.
  void _playUpNext() {
    final item = _upNext;
    if (mounted) setState(() => _upNext = null);
    if (item != null) _playInPlace(item, back: false);
  }

  /// The card's "not this one": the video stays where it ended, paused, and
  /// nothing plays until the user asks for something.
  void _dismissUpNext() {
    setState(() => _upNext = null);
    _poke();
  }

  /// Drops a pending offer without answering it — for every path that navigates
  /// somewhere else while one is up, where keeping it would play a video the
  /// user has already left.
  void _clearUpNext() {
    if (_upNext != null && mounted) setState(() => _upNext = null);
  }

  @override
  void initState() {
    super.initState();
    _item = widget.item;
    _jumpStack = ref.read(videoJumpStackProvider.notifier);
    _initVolPrefs().then((_) {
      if (_volPrefs != null && mounted) {
        setState(() {
          _timeMode = _volPrefs!.getString('player_time_mode') == 'remaining'
              ? PlayerTimeMode.remaining
              : PlayerTimeMode.elapsed;
        });
        // Which volume the bar means, and the level it starts at
        // (`_seedVolume`): the device's stream, or this app's own.
        _seedVolume();
      }
    });
    _scrollCtrl = ScrollController();
    _scrollCtrl!.addListener(_onScroll);
    _resetIdle();
    fullscreen = widget.startFullscreen;
    // The mask is still whatever the screen this one replaces left it at (see
    // `startLockedShape`), so that is what this screen starts out believing it
    // holds.
    _lockedShape = widget.startLockedShape;
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
      p!.setVolume(_playerGain);
      if (_disposed && p != null) {
        // Disposed before the player finished initializing — tear down now.
        p!.dispose();
        p = null;
        vc = null;
        return;
      }
      if (mounted) setState(() {});
      _posSub = p!.stream.position.listen(_onPosition);
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
      _volumeSub = p!.stream.volume.listen(_onPlayerGain);
      _bufferingSub = p!.stream.buffering.listen((buffering) {
        if (!mounted) return;
        _bufferStall?.cancel();
        if (!buffering) {
          // Recovery is immediate: a spinner that lingers after the picture is
          // moving again is a lie about the state of the player.
          if (_buffering.value) _buffering.value = false;
          return;
        }
        // Nothing is loading on a finished file: the picture is the last frame
        // and the viewer is being offered what plays next. A stall reported here
        // is not a wait this app is in, and a spinner drawn over the frame they
        // are deliberately sitting on claims "working on it" about nothing.
        if (_eof.finished) return;
        _bufferStall = Timer(_bufferGrace, () {
          if (mounted && !_disposed) _buffering.value = true;
        });
      });
      _rate.value = p!.state.rate;
      _rateSub = p!.stream.rate.listen((r) {
        if (mounted) _rate.value = r;
      });
      _shapeSub = p!.stream.videoParams.listen(_onVideoParams);
      _completedSub = p!.stream.completed.listen((completed) {
        // The VALUE, not just the event: media_kit publishes `completed: false`
        // every time a file STARTS (`stop()`, which `open()` calls), and running
        // the end-of-video logic for that offers the next video over one that has
        // only just begun. Only the race between this screen's un-awaited `open()`
        // and `play()` kept it quiet -- `play()` publishes `playing: true`
        // optimistically, so `hasBeenPlaying` can already be true by the time
        // `open()`'s own `stop()` lands.
        if (!completed) return;
        if (!mounted || _disposed || _navigating || _switching) return;
        if (!hasBeenPlaying) return;
        // ONE decision per ending: mpv reports the end again after every
        // take-back, and `loopOne` re-enters this same file immediately, so a
        // second pass would seek a video the viewer had just dragged back to 0.
        if (_eof.finished) return;
        _eof = _eof.endedAt(p!.state.position.inMilliseconds);
        final mode = ref.read(uiSettingsProvider).playbackMode;
        switch (mode) {
          case 'loopAll':
            _offerNext();
            break;
          case 'loopOne':
            // Rolling again before this returns, so the latch is dropped here --
            // kept, it would sit over the whole loop and swallow the next ending.
            _eof = PlayerEof.idle;
            p!.seek(Duration.zero);
            p!.play();
            break;
          case 'pauseAfter':
            break;
        }
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
    _bufferingSub?.cancel();
    _shapeSub?.cancel();
    _bufferStall?.cancel();
    _videoTapTimer?.cancel();
    _gOverlayTimer?.cancel();
    _scrollCtrl?.dispose();
    // Persist the live volume before the notifiers go away.
    _flushVolSave();
    // The device's stream outlives this screen; stop following it.
    SystemVolume.state.removeListener(_onSystemVolume);
    _miniPos.dispose();
    _miniDur.dispose();
    _miniBuf.dispose();
    _playing.dispose();
    _volume.dispose();
    _rate.dispose();
    _buffering.dispose();
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
    // The exits that come through `_handleBack`/`_goHome` have already done this
    // — at the start of the exit, so it does not land after the transition as a
    // second motion. This is the fallback for every other way a player route can
    // go (a `popUntil` from elsewhere, teardown), and it is idempotent.
    if (!_navigating) _restoreExitChrome();
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

  // Mobile fullscreen: apply the viewer's orientation strategy
  // (`utils/player_orientation.dart`), outside fullscreen hand the app back to
  // the system's own preference.
  //
  // Called on every event that can change the answer: entering or leaving
  // fullscreen, the strategy changing in the panel, the video's own aspect
  // arriving (see `_onVideoParams`), and leaving the player.
  void _applyOrientation() {
    if (!_isMobile) return;
    final request = orientationRequestFor(
      mode: ref.read(uiSettingsProvider).playerOrientation,
      fullscreen: fullscreen,
      landscapeVideo: _landscapeVideo(),
      // What the platform is holding right now, so a request made while the
      // player has no shape to give repeats the mask in force instead of
      // releasing it (see `orientationRequestFor`).
      lockedShape: _lockedShape,
    );
    // Written HERE, before the call and unconditionally: whatever mask this
    // request carries is what the screen is held at from now on, and a request
    // that locks to no shape (out of fullscreen, the app's own direction) has to
    // clear the record or the next unknown-shape request would hold a lock that
    // was never asked for.
    _lockedShape = request.fittedShape;
    // The ORDER lives in `applyOrientationRequest` with a test: the mask first,
    // the sensor request second (see that function).
    unawaited(
      applyOrientationRequest(
        request,
        writeMask: SystemChrome.setPreferredOrientations,
        writeFollow: ScreenOrientation.followDevice,
      ),
    );
  }

  /// The video's own aspect: true for a wide picture, false for a tall one, and
  /// null while the player has not reported one (which `fill` refuses to guess
  /// at).
  ///
  /// `state.width`/`height` and not the coded size: media_kit builds them from
  /// mpv's `dw`/`dh` and SWAPS them for a 90/270 rotation tag, so a portrait
  /// video recorded as a landscape frame is portrait here -- which is the whole
  /// question this asks.
  bool? _landscapeVideo() {
    final w = p?.state.width ?? 0;
    final h = p?.state.height ?? 0;
    if (w <= 0 || h <= 0) return null;
    return w >= h;
  }

  /// Hands the app back to the system's own preference, whatever the strategy
  /// says -- the direction the library lives in.
  ///
  /// Deliberately not `_applyOrientation()`: the exit restores the chrome BEFORE
  /// the route pops, so `fullscreen` is still true at that moment and the
  /// strategy would be applied to a screen that is already leaving.
  void _releaseOrientation() {
    if (!_isMobile) return;
    // `_lockedShape` is deliberately NOT cleared here, and that is load-bearing
    // rather than an oversight. This runs at the START of an exit -- `_goHome`
    // and `_handleBack` reach it while `fullscreen` is still true and the player
    // is still playing -- and `_shapeSub` stays subscribed for the whole pop
    // (only `_go` cancels it). So a `video-params` report inside that window
    // finds `fullscreen` still true and would re-apply the fitted axis ON TOP of
    // the release just written, and the library would arrive rotated: exactly
    // the second motion on the way out that `_restoreExitChrome` exists to
    // prevent. Keeping the record is what lets `_onVideoParams` recognise that
    // report as the shape it already knows and do nothing.
    //
    // Nothing outlives it either: every caller of `_restoreExitChrome` pops the
    // route, so a screen never re-enters fullscreen after a release, and
    // `_applyOrientation` rewrites the record on the first real event anyway.
    //
    // The way out has its own order (`releaseOrientationRequest`): the sensor
    // stops first, then the mask goes back to the app's default.
    unawaited(
      releaseOrientationRequest(
        writeMask: SystemChrome.setPreferredOrientations,
        writeFollow: ScreenOrientation.followDevice,
        mask: orientationRequestFor(
          mode: ref.read(uiSettingsProvider).playerOrientation,
          fullscreen: false,
          landscapeVideo: null,
        ).orientations,
      ),
    );
  }

  /// The player has (re)reported the video's parameters.
  ///
  /// This is the event the old code was missing: it decided the orientation when
  /// fullscreen was toggled, when the size was often not known yet, and then
  /// never asked again -- so a portrait video locked landscape (the unknown-size
  /// default) stayed that way, and swapping to a different-shaped video in place
  /// kept the previous one's lock. Only a change of SHAPE costs anything here.
  void _onVideoParams(_) {
    if (!_isMobile) return;
    final landscape = _landscapeVideo();
    // No size is not news: mpv reports none while the file it is loading has no
    // track open yet, which is every video skip and every seek over a gap. Acting
    // on it released the fitted lock the screen was already held at and took it
    // back when the real size landed -- two rotations per video change, and for
    // two same-shaped videos two that cancelled out. The lock is held across the
    // gap instead (`orientationRequestFor`), so there is nothing to decide here.
    if (landscape == null) return;
    // The shape in force is the one the mask already says: mpv repeats this
    // report per property change, and re-writing the same mask is a call for no
    // reason.
    if (landscape == _lockedShape) return;
    _applyOrientation();
  }

  /// A position report, and the one thing it decides.
  ///
  /// While the file is finished this is where "the viewer took it back" is
  /// detected, because it is the only signal that reports it: media_kit publishes
  /// `playing: false` at the end and never undoes it ([_eof]), and nothing else
  /// in the player reports that the file has become live again. Without this the
  /// transport sits on ▶ over a picture that is not moving, and the up-next
  /// countdown keeps running over a video the viewer is watching again -- which
  /// is also how it used to advance a video they had just decided not to leave.
  void _onPosition(Duration pos) {
    final ms = pos.inMilliseconds;
    // The value answers whether anything happened, so the screen needs no second
    // copy of the truth to compare against.
    final next = _eof.onPosition(ms);
    if (next != _eof) {
      _eof = next;
      _clearUpNext();
      _resumeAfterTakeBack();
    }
    if ((ms - _miniLastMs).abs() < 100) return;
    _miniLastMs = ms;
    if (mounted) _miniPos.value = pos;
  }

  /// Starts a finished file running again from the frame the viewer dragged back
  /// to.
  ///
  /// An UNPAUSE, and not `p.play()`. Two facts, both measured rather than
  /// assumed: media_kit runs mpv with `--keep-open=yes`, which leaves a finished
  /// file **paused on its last frame** — dragging the bar back moves `time-pos`
  /// and nothing else, so the picture froze on the frame it was dragged to, and
  /// `p.play()` is the obvious cure. But media_kit clears `state.completed` only
  /// in `stop()` and `START_FILE`, never on a seek, so at this moment it is still
  /// true and `play()` takes its "the playlist ended, play it again" branch
  /// (`real.dart:373`) — it seeks to 0 first, which throws the viewer from
  /// wherever they just dragged back to the first frame. Un-pausing and restarting
  /// are two different things and only one of them is wanted here.
  ///
  /// So the property is written straight to mpv, which is also what makes the
  /// state honest: media_kit observes `pause` (`real.dart:1507`) and publishes
  /// `playing` from it, so the icon, this screen's `_playing` and the PiP gate
  /// follow the player instead of this method guessing. `_playing` is still
  /// written first, because the icon should not sit on ▶ for the few ms until
  /// the echo arrives — and it is now a record of what was ASKED for, not an
  /// inference from a position that may have moved without anything playing.
  ///
  /// The platform check is `PlayerFactory`'s, for the same reason as there: a
  /// host without the native half simply does not get the un-pause, and the
  /// viewer can still drag or press play.
  void _resumeAfterTakeBack() {
    _playing.value = true;
    final platform = p?.platform;
    if (platform is NativePlayer) {
      unawaited(platform.setProperty('pause', 'no').catchError((_) {}));
    }
  }

  void _togglePlayPause() {
    if (p == null) return;
    // The app's own belief, NOT `p.state.playing`: media_kit writes
    // `playing: false` at the end of a file and never undoes it, so the flag and
    // the picture can disagree — and this control has to do what its own icon
    // says. One decision, shared by the button, the tap and Space/K.
    if (_playing.value) {
      p!.pause();
      return;
    }
    // Pressing play on a finished file: media_kit reads that as "the playlist
    // ended, play it again" and restarts it from 0 (`real.dart:373`), which is a
    // coherent reading of the gesture — and the offer of the next video is
    // withdrawn, because the viewer has just asked for THIS one.
    _eof = PlayerEof.idle;
    _clearUpNext();
    p!.play();
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
        final onLeft = _gStart.dx < size.width / 2;
        _gMode = onLeft ? 2 : 3; // left=brightness, right=volume
        if (!onLeft) {
          // The volume swipe takes over from the level that is on screen right
          // now, and owns it until the finger lifts (`_gVolume`).
          _gVolume = _volume.value;
        }
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
      // The arithmetic lives in `utils/swipe_value.dart`, where it is
      // unit-tested, and it is the SAME arithmetic the volume half below uses:
      // one private number the finger owns, pushed out to whoever applies it.
      _brightness = advanceVerticalValue(
        current: _brightness,
        deltaDy: d.delta.dy,
        height: size.height,
        max: 1,
      );
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
      //
      // It starts from `_gVolume` and NOT from `_volume.value`, which is the
      // difference between this and a value the finger can actually aim: while
      // bound, `_volume` holds the STEP the device landed on, so re-reading it
      // every frame throws the finger's travel away (a 15-step phone answers in
      // 6.7% jumps, i.e. one step per ~40px of a 600px screen) -- a slow swipe
      // would move nothing at all, and a wobble across a step boundary would
      // walk it backwards. The device is asked for the accumulator's value and
      // answers at the end of the gesture (`_onPanEnd`).
      _gVolume = advanceVerticalValue(
        current: _gVolume,
        deltaDy: d.delta.dy,
        height: size.height,
      );
      _setVolume(_gVolume, persist: false);
      setState(() {
        _gOverlayType = _OverlayType.volume;
        _gOverlayValue = _gVolume.round();
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
    if (mode == 3) {
      _queueVolSave();
      // The finger is up, so the device's answer is the level again: what it
      // landed on is coarser than the accumulator asked for, and the bar goes
      // back to showing the truth (which the swipe was deliberately allowed to
      // outrun while it lasted).
      _adoptDevice(SystemVolume.state.value);
    }
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
    final mode = _gMode;
    _gMode = 0;
    // A cancelled volume swipe wrote real levels on the way (each frame applies
    // one), so the device's answer is adopted here too — the bookkeeping is the
    // same as the end of a drag, minus the seek and the deferred save.
    if (mode == 3) _adoptDevice(SystemVolume.state.value);
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
    // The app's belief, not `p.state.playing`: a video the viewer took back from
    // its last frame is rolling while that flag still says paused, and a PiP that
    // only appears for a player the app thinks is stopped is a PiP that never
    // appears.
    final playing = _playing.value;
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

  /// What the player knows about the file that is playing, for the settings
  /// panel.
  ///
  /// Every row is something the player actually reported: a fact it has nothing
  /// to say about is left out rather than printed as "unknown", because an
  /// invented absence reads like a defect in the file. An empty list is a
  /// normal answer — it means the first frame has not been decoded yet.
  List<PlayerMediaFact> _playbackInfo() {
    final st = p?.state;
    if (st == null) return const [];
    final out = <PlayerMediaFact>[];
    final vp = st.videoParams;
    final ap = st.audioParams;

    // The DISPLAY size, not the coded one: an anamorphic file stores 720x576
    // and shows 1024x576, and the number the viewer can check against their
    // screen is the one they are looking at.
    final w = vp.dw ?? vp.w ?? st.width;
    final h = vp.dh ?? vp.h ?? st.height;
    if (w != null && h != null && w > 0 && h > 0) {
      out.add(PlayerMediaFact('Resolution', resolutionLabel(w, h)));
    }
    if (vp.pixelformat != null && vp.pixelformat!.isNotEmpty) {
      out.add(PlayerMediaFact('Pixel format', vp.pixelformat!));
    }
    // Only when the decoder really left the CPU: an empty `hwPixelformat` on a
    // software decode is the honest silence, not "none".
    if (vp.hwPixelformat != null && vp.hwPixelformat!.isNotEmpty) {
      out.add(PlayerMediaFact('Hardware decode', vp.hwPixelformat!));
    }
    if (vp.rotate != null && vp.rotate != 0) {
      out.add(PlayerMediaFact('Rotation', '${vp.rotate}°'));
    }
    final audio = _audioLine(ap.sampleRate, ap.channels, ap.channelCount);
    if (audio != null) out.add(PlayerMediaFact('Audio', audio));
    if (st.audioBitrate != null && st.audioBitrate! > 0) {
      out.add(
        PlayerMediaFact(
          'Audio bitrate',
          '${(st.audioBitrate! / 1000).round()} kbps',
        ),
      );
    }
    out.add(
      PlayerMediaFact(
        'File',
        '${_item.extension.toUpperCase()} · ${_item.formattedSize}',
      ),
    );
    return out;
  }

  /// `48 kHz · stereo`, from whatever of the three facts the decoder gave.
  static String? _audioLine(int? sampleRate, String? channels, int? count) {
    final parts = <String>[];
    if (sampleRate != null && sampleRate > 0) {
      parts.add('${(sampleRate / 1000).toStringAsFixed(1)} kHz');
    }
    if (count != null && count > 0) {
      parts.add(switch (count) {
        1 => 'mono',
        2 => 'stereo',
        _ => '$count ch',
      });
    } else if (channels != null && channels.isNotEmpty) {
      parts.add(channels);
    }
    return parts.isEmpty ? null : parts.join(' · ');
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
    _clearUpNext();
    // A new file has not finished, whatever the last one did — and this is the
    // one place the latch is dropped for a switch, since the card's own advance
    // comes through here too.
    _eof = PlayerEof.idle;
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
      player.setVolume(_playerGain);
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
  ///    through the history enters from the left, and the page it replaces
  ///    LEAVES to the right — that half is the framework's own announcement to
  ///    the outgoing route, so there is nothing to pass here. Both halves
  ///    matter: on their own, an entrance from the left over an exit to the
  ///    left is the same two-page movement a forward push makes, so a step back
  ///    still read as opening a video.
  void _go(MediaItem item, {bool back = false}) {
    if (_navigating || _switching || _isRoutePopping) return;
    _navigating = true;
    _clearUpNext();
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
    // Including the shape: the outgoing screen's player stays alive for the whole
    // transition, and a `video-params` report from it would re-apply ITS
    // orientation strategy on top of the incoming screen's.
    _shapeSub?.cancel();
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
          startLockedShape: _lockedShape,
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
  ///  * `popUntil` on the landing rule in `utils/player_exit.dart`, which
  ///    unwinds the player AND the search screen a player may have been opened
  ///    from, and stops at the library;
  ///  * `_navigating` stays false, so `dispose()` runs its "leaving for good"
  ///    branch: the jump stack is CLEARED (every entry in it is a video on the
  ///    chain being left, and a stale stack would both offer `Back` a jump into
  ///    a session that is over and hide those videos from the next player's
  ///    Related list), the system UI/orientation and window chrome are restored
  ///    as on any other exit.
  ///
  /// Deliberately NOT `p?.stop()` before the pop, which is what this used to do.
  /// The route's own `dispose()` stops the player before disposing it — that is
  /// the documented order, and it is what makes `Back` work — so stopping here
  /// only moved the teardown to the far side of the transition, and the teardown
  /// is visible: a stopped `Player` paints no frame, so the exit played as the
  /// same step with the picture missing while `Back` played it with the video
  /// still there. Two ways out of the player, two different animations, one of
  /// them blank — and no safety was bought by it: the player is still never
  /// dropped mid-playback, because `dispose()` stops it first.
  void _goHome() {
    if (_navigating || _switching || _isRoutePopping) return;
    _clearUpNext();
    _restoreExitChrome();
    final mine = ModalRoute.of(context);
    // ONE animated step, the one `Back` plays: `leavePlayerForLibrary` takes the
    // screen the video was opened from (the search results) out of the chain
    // without animating it, then pops the player. `popUntil` on its own animated
    // every route it popped, so this exit — and only this one — played as two
    // pages sliding away at once.
    leavePlayerForLibrary(
      Navigator.of(context),
      below: mine is PosterQuietRoute ? mine.previousRoute : null,
    );
  }

  /// Puts the app back the way the library expects to find it — and does it at
  /// the START of the exit rather than after it.
  ///
  /// This is what `dispose()` does when the player is left for good, and it used
  /// to happen only there, once the pop had finished. That made leaving the
  /// player two motions in sequence: the exit played on an app still in
  /// immersive fullscreen landscape, and THEN the system bars came back and the
  /// device rotated, re-laying the library out into the window it was going to
  /// live in anyway. One gesture, a second animation nobody asked for — and only
  /// on this exit, because a jump keeps the player's own chrome by design.
  /// Started here, it is over by the time the library has arrived.
  ///
  /// `dispose()` still does it too, for the exits that never come through this
  /// method (a `popUntil` from elsewhere, the app closing); the calls are
  /// idempotent.
  void _restoreExitChrome() {
    if (_isMobile) {
      SystemChrome.setEnabledSystemUIMode(SystemUiMode.edgeToEdge);
      _releaseOrientation();
    } else if (fullscreen) {
      if (!_globalImmersive) {
        windowManager.setFullScreen(false);
      }
      Future(
        () => ref.read(windowChromeVisibleProvider.notifier).setVisible(true),
      );
    }
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
          onTogglePlay: _togglePlayPause,
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
          onToggleMute: _toggleMute,
          // Steps the rate the chip shows, so the bar reports what the key did.
          // The clamp is wider than the speed menu's list on purpose: a menu is
          // a shortlist of the usual rates, not the player's range.
          onSpeed: (delta) {
            final next = (_rate.value + delta).clamp(0.25, 4.0);
            if (next != _rate.value) p?.setRate(next);
          },
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
                      // Above the picture, below the chrome: the spinner is
                      // about the video, and the bars stay usable while it
                      // shows.
                      _bufferingLayer(),
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
                      // Under the panels on purpose: the countdown is the
                      // autoplay the user asked for, so an open sheet covers
                      // the card without cancelling what it stands for.
                      _upNextCard(bottom: _barClearance(safe.bottom)),
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
                _bufferingLayer(),
                _upNextCard(bottom: _barClearance(0)),
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
                    // The gear belongs to the player, not to fullscreen: the
                    // windowed screen has been able to SHOW this panel all
                    // along (`_settingsOverlay` is in this Stack too) and had
                    // no way to ask for it. The fullscreen top bar and this row
                    // are the same chrome at two sizes.
                    IconButton(
                      icon: const Icon(Icons.settings, color: Colors.white70),
                      tooltip: 'Playback settings',
                      onPressed: _toggleSettings,
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
    _clearUpNext();
    final from = ref.read(videoJumpStackProvider.notifier).pop();
    if (from != null) {
      // Deliberately the ROUTE step and not the transport bar's in-place switch:
      // back is "leave this video", so it plays the platform's back-direction
      // transition. The transport's prev reaches the same video with nothing on
      // screen moving at all — the same navigation, presented differently.
      _go(from, back: true);
      return;
    }
    // The history is empty: this Back leaves the player for the library. The
    // chrome goes back to the library's own now, at the START of the exit, so
    // the bars/orientation/window are already the library's by the time it
    // arrives instead of following it as a second motion — `Back` and `Home`
    // leave the same way, so they restore it at the same moment.
    _restoreExitChrome();
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
              timeMode: _timeMode,
              onTimeModeChanged: _toggleTimeMode,
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
      //
      // 2px, and no blanket opacity over it: the played line is the accent at
      // full strength and the buffered one carries its own 25%, which is what
      // keeps a line this thin legible over a bright frame. Fading the whole
      // thing to half of that made a readout nobody could see (measured: the
      // old 0.5 x 0x33 buffered layer painted at 10% white).
      return RepaintBoundary(
        child: Stack(
          children: [
            LinearProgressIndicator(
              value: buf,
              minHeight: 2,
              backgroundColor: Colors.transparent,
              valueColor: const AlwaysStoppedAnimation(Color(0x40FFFFFF)),
            ),
            LinearProgressIndicator(
              value: pct,
              minHeight: 2,
              backgroundColor: Colors.transparent,
              valueColor: const AlwaysStoppedAnimation(RCrmColors.primary),
            ),
          ],
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

  /// The buffering spinner, in the layer the picture is in.
  ///
  /// Driven by its own notifier rather than a `setState`: a stall happens while
  /// the user is watching, and rebuilding the whole screen — the Related list
  /// included — to show a spinner would cost more than the spinner is worth.
  Widget _bufferingLayer() => Positioned.fill(
    child: ValueListenableBuilder<bool>(
      valueListenable: _buffering,
      builder: (_, buffering, _) =>
          PlayerBufferingIndicator(visible: buffering),
    ),
  );

  /// The up-next card, clear of the transport bar.
  ///
  /// The bar is not necessarily on screen when a video ends — it has usually
  /// faded — but it is where the controls would be, and a card that jumped when
  /// the user moved the mouse would be worse than one that sits a little high.
  Widget _upNextCard({required double bottom}) {
    final next = _upNext;
    if (next == null) return const SizedBox.shrink();
    return Positioned(
      // A KEY, and the card needs one: it is the last child of a Stack whose
      // siblings come and go with things that have nothing to do with it — the
      // mini bar when the windowed chrome fades, the seek bar on a mobile swipe.
      // Flutter reconciles a Stack's children by INDEX, and every one of these
      // is a `Positioned`, so an unkeyed card shifted down one slot was judged
      // "same type, update in place": the element above was rewritten as the
      // card and the card's element was destroyed. A fresh State re-runs
      // `initState`, so the entrance and the whole 8s countdown started again
      // every time the controls faded. Keyed, it is matched by key wherever it
      // sits and its State survives.
      key: const ValueKey('up_next'),
      left: 0,
      right: 0,
      bottom: bottom,
      child: PlayerUpNextCard(
        title: next.name,
        subtitle: '${next.formattedSize} · ${next.extension.toUpperCase()}',
        countdown: _upNextSeconds,
        onAdvance: _playUpNext,
        onDismiss: _dismissUpNext,
      ),
    );
  }

  /// Height the transport bar occupies, plus the bottom safe inset.
  double _barClearance(double safeBottom) {
    final m = PlayerChromeMetrics.of(
      MediaQuery.sizeOf(context),
      fullscreen: fullscreen,
    );
    return m.seekHeight + m.gap + m.tap + m.pad / 2 + safeBottom;
  }

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
        facts: _playbackInfo(),
        // Both rows are about what THIS platform can do: orientation is mobile
        // only (both mobile platforms, each with its own way of following the
        // phone — see `services/screen_orientation.dart`), the key map is desktop
        // only, and a control that cannot act is not shown at all.
        showOrientation: _isMobile,
        showShortcuts: !_isMobile,
        mode: PlaybackMode.fromString(settings.playbackMode),
        onModeChanged: (m) {
          // Leaving `loopAll` withdraws the offer: the card is that mode's
          // countdown, and it would otherwise still advance a video the user
          // has just told the player not to advance to.
          if (m != PlaybackMode.loopAll) _clearUpNext();
          ref.read(uiSettingsProvider.notifier).setPlaybackMode(m.key);
        },
        orientation: settings.playerOrientation,
        onOrientationChanged: (o) {
          ref.read(uiSettingsProvider.notifier).setPlayerOrientation(o);
          // The strategy is a property of the screen the viewer is looking at,
          // so it applies now rather than at the next fullscreen.
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
