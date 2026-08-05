// screens/cast_receiver_screen.dart
// TV-side receiver screen: shows the pairing QR code, hosts the TLS control
// service (see services/cast_receiver.dart), and plays media with media_kit
// when the phone commands it.
//
// Responsive: the QR card scales with the window (TV 4K down to a small
// desktop window), tall/narrow layouts scroll instead of overflowing, and the
// same screen works on Android TV (no back button), desktop and phone
// (showBack → AppBar with back).

import 'dart:async';
import 'dart:io';
import 'dart:ui' as ui;

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:media_kit/media_kit.dart';
import 'package:media_kit_video/media_kit_video.dart';
import 'package:path_provider/path_provider.dart';

import '../providers/server_provider.dart';
import '../services/cast_protocol.dart';
import '../services/cast_receiver.dart';
import '../services/mobile_image_decoder.dart';
import '../widgets/cast_receiver_qr_view.dart';
import '../widgets/media_player_keys.dart';

class CastReceiverScreen extends ConsumerStatefulWidget {
  /// Show an AppBar with a back button (desktop/manual entry). Android TV
  /// auto-launches this screen full-screen without back affordances.
  final bool showBack;
  const CastReceiverScreen({super.key, this.showBack = false});

  @override
  ConsumerState<CastReceiverScreen> createState() => _State();
}

class _State extends ConsumerState<CastReceiverScreen> {
  CastReceiver? _receiver;
  Player? _player;
  VideoController? _vc;
  StreamSubscription? _posSub;
  StreamSubscription? _durSub;
  StreamSubscription? _playingSub;
  StreamSubscription? _buffSub;

  bool _starting = true;
  String? _error;
  CastQrPayload? _qr;
  Timer? _qrTimer;
  bool _playing = false;
  bool _buffering = false;
  String? _currentPath;

  /// Top overlay (progress + filename + stop) visibility. Shown on start /
  /// seek / tap, auto-hides after a few seconds so playback is clean.
  bool _overlayVisible = true;
  Timer? _overlayTimer;

  /// The last known QR payload stays on screen after the token expires or is
  /// consumed, but gets dimmed + struck through via [CastQrPayload] badge.
  bool _qrExpired = false;

  // Snapshot flags so the 2s QR refresh only rebuilds on actual changes.
  bool _lastPaired = false;
  bool _lastServerOk = false;
  int _lastRemainSec = -1;

  // Playback progress (throttled via ValueNotifier, no per-frame setState).
  final ValueNotifier<double> _progress = ValueNotifier(0);
  final ValueNotifier<Duration> _pos = ValueNotifier(Duration.zero);
  final ValueNotifier<Duration> _dur = ValueNotifier(Duration.zero);

  /// Non-null while displaying a cast image (instead of video). The image
  /// is decoded at the screen width to keep low-end TV memory bounded.
  String? _imageUrl;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _start());
  }

  @override
  void dispose() {
    _qrTimer?.cancel();
    _overlayTimer?.cancel();
    _posSub?.cancel();
    _durSub?.cancel();
    _playingSub?.cancel();
    _receiver?.stop();
    _receiver = null;
    _player?.dispose();
    _player = null;
    _vc = null;
    _progress.dispose();
    _pos.dispose();
    _dur.dispose();
    super.dispose();
  }

  Future<void> _start() async {
    try {
      final bridge = ref.read(rustBridgeProvider);
      if (!bridge.isLoaded) bridge.load();
      final dir = await getApplicationSupportDirectory();
      final receiver = CastReceiver(
        playerHost: _PlayerHost(this),
        rustBridge: bridge,
      );
      await receiver.start(dir.path);
      _receiver = receiver;
      if (!mounted) return;
      _lastPaired = receiver.isPaired;
      _lastServerOk = receiver.serverOk;
      setState(() {
        _starting = false;
        _qr = receiver.currentQr();
      });
      // Tick once per second: update the countdown, and mark the QR expired
      // when the one-time token expires (receiver stops offering it). The
      // stale QR stays on screen dimmed + struck through; new pairing codes
      // are minted manually only.
      _qrTimer = Timer.periodic(const Duration(seconds: 1), (_) {
        final r = _receiver;
        if (r == null || !mounted) return;
        final qr = r.currentQr();
        final tokenRenewed = qr != null && qr.token != _qr?.token;
        final pairedChanged = r.isPaired != _lastPaired;
        final serverChanged = r.serverOk != _lastServerOk;
        // Token expired or consumed: the payload vanished. Dim the shown QR
        // (unless a fresh token replaced it).
        final expiredNow =
            qr == null && _qr != null && !r.isPaired && !_qrExpired;
        // Countdown: recompute seconds left from wall clock; rebuild only
        // when the displayed value actually changes.
        final exp = r.pairExpiresAt;
        final remainSec = !r.isPaired && exp != null
            ? (exp.difference(DateTime.now()).inMilliseconds / 1000).ceil()
            : -1;
        final remainChanged = remainSec >= 0 && remainSec != _lastRemainSec;
        _lastPaired = r.isPaired;
        _lastServerOk = r.serverOk;
        _lastRemainSec = remainSec;
        if (tokenRenewed ||
            expiredNow ||
            pairedChanged ||
            serverChanged ||
            remainChanged) {
          setState(() {
            if (tokenRenewed) {
              _qr = qr;
              _qrExpired = false;
            }
            if (expiredNow) _qrExpired = true;
          });
        }
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _starting = false;
        _error = '$e';
      });
    }
  }

  // ── player host callbacks ─────────────────────────────────

  /// Show the top overlay and auto-hide it after 4s of inactivity.
  void _showOverlay() {
    _overlayTimer?.cancel();
    if (!_overlayVisible && mounted) {
      setState(() => _overlayVisible = true);
    } else {
      _overlayVisible = true;
    }
    _overlayTimer = Timer(const Duration(seconds: 4), () {
      if (!mounted) return;
      setState(() => _overlayVisible = false);
    });
  }

  Future<void> _play(String streamUrl, {bool isImage = false}) async {
    final receiver = _receiver;
    if (receiver == null) return;
    // Immediate feedback: the open below can take seconds for network
    // streams, so show the overlay (filename/status) right away instead of
    // a black screen with no indication.
    _showOverlay();

    if (isImage) {
      // Image cast: release the video player (decoder/GL textures) so a
      // low-end TV doesn't hold both the video pipeline and the image.
      await _disposePlayer();
      if (!mounted) return;
      setState(() {
        _playing = true;
        _currentPath = receiver.currentPath;
        _imageUrl = streamUrl;
        _pos.value = Duration.zero;
        _progress.value = 0;
      });
      _showOverlay();
      return;
    }

    // Video cast.
    // Reset the buffering flag: media_kit's `stream.buffering` only emits on
    // state transitions, so a stale `true` from a previous session would
    // otherwise show the spinner until the new player happens to transition.
    _buffering = false;
    var player = _player;
    if (player == null) {
      player = Player();
      _player = player;
      _vc = VideoController(player);
      _posSub = player.stream.position.listen((pos) {
        _pos.value = pos;
        final d = _dur.value;
        _progress.value = d.inMilliseconds > 0
            ? (pos.inMilliseconds / d.inMilliseconds).clamp(0.0, 1.0)
            : 0;
        receiver.updatePlayback(
          playing: _playing,
          posMs: pos.inMilliseconds,
          durMs: _dur.value.inMilliseconds,
        );
      });
      _durSub = player.stream.duration.listen((d) {
        _dur.value = d;
        receiver.updatePlayback(
          playing: _playing,
          posMs: _pos.value.inMilliseconds,
          durMs: d.inMilliseconds,
        );
      });
      _playingSub = player.stream.playing.listen((playing) {
        if (!mounted) return;
        _playing = playing;
        receiver.updatePlayback(
          playing: playing,
          posMs: _pos.value.inMilliseconds,
          durMs: _dur.value.inMilliseconds,
        );
      });
      _buffSub = player.stream.buffering.listen((buffering) {
        if (!mounted) return;
        setState(() => _buffering = buffering);
      });
    }
    await player.open(Media(streamUrl));
    await player.play();
    if (!mounted) return;
    setState(() {
      _playing = true;
      _currentPath = receiver.currentPath;
      _imageUrl = null;
      _pos.value = Duration.zero;
      _progress.value = 0;
    });
    _showOverlay();
  }

  Future<void> _pause() async => _player?.pause();

  Future<void> _resume() async => _player?.play();

  Future<void> _seek(Duration position) async {
    await _player?.seek(position);
    _showOverlay();
  }

  Future<void> _stopPlayback() async {
    _overlayTimer?.cancel();
    _overlayVisible = true;
    // Image cast: release the decoded image (memory + cache) immediately.
    if (_imageUrl != null) {
      PaintingBinding.instance.imageCache.clear();
    }
    await _disposePlayer();
    if (!mounted) return;
    setState(() {
      _playing = false;
      _currentPath = null;
      _imageUrl = null;
    });
    _pos.value = Duration.zero;
    _dur.value = Duration.zero;
    _progress.value = 0;
  }

  Future<void> _setVolume(int level) async =>
      _player?.setVolume(level.toDouble());

  Future<void> _setRate(double rate) async => _player?.setRate(rate);

  /// Stop and release the video player. Cancels the progress/duration/
  /// playing/buffering subscriptions FIRST so a disposed Player never
  /// delivers stale events, then disposes the Player + controller.
  Future<void> _disposePlayer() async {
    _posSub?.cancel();
    _posSub = null;
    _durSub?.cancel();
    _durSub = null;
    _playingSub?.cancel();
    _playingSub = null;
    _buffSub?.cancel();
    _buffSub = null;
    final player = _player;
    if (player != null) {
      try {
        await player.stop();
      } catch (_) {}
      player.dispose();
    }
    _player = null;
    _vc = null;
  }

  /// Leave the receiver screen: stop playback first, ask for confirmation
  /// when something is playing (so the TV owner does not lose it silently).
  Future<void> _exitReceiver() async {
    if (_playing) {
      final ok = await showDialog<bool>(
        context: context,
        builder: (context) => AlertDialog(
          title: const Text('Exit receiver?'),
          content: const Text('Playback stops and the cast connection closes.'),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(context).pop(false),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: () => Navigator.of(context).pop(true),
              child: const Text('Exit'),
            ),
          ],
        ),
      );
      if (ok != true || !mounted) return;
    }
    await _stopPlayback();
    if (!mounted) return;
    Navigator.of(context).pop();
  }

  /// End the current pairing (TV owner side): stop playback, drop the
  /// session + server credentials, and show a fresh QR.
  Future<void> _unpair() async {
    final r = _receiver;
    if (r == null) return;
    await _stopPlayback();
    r.unpair();
    if (!mounted) return;
    setState(() {
      _qr = r.currentQr();
      _qrExpired = false;
      _lastPaired = false;
      _lastServerOk = false;
      _lastRemainSec = -1;
    });
  }

  void _regenerateQr() {
    final r = _receiver;
    if (r == null) return;
    r.regeneratePairToken();
    setState(() {
      _qr = r.currentQr();
      _qrExpired = false;
      _error = null;
    });
  }

  @override
  Widget build(BuildContext context) {
    if (_starting) {
      return Scaffold(
        appBar: widget.showBack
            ? AppBar(title: const Text('RCrm Cast Receiver'))
            : null,
        body: const Center(child: CircularProgressIndicator()),
      );
    }
    if (_error != null) {
      return Scaffold(
        appBar: widget.showBack
            ? AppBar(title: const Text('RCrm Cast Receiver'))
            : null,
        body: Center(
          child: Padding(
            padding: const EdgeInsets.all(32),
            child: Text(
              'Receiver failed to start\n$_error',
              textAlign: TextAlign.center,
            ),
          ),
        ),
      );
    }
    final qr = _qr;
    if (qr == null) {
      return Scaffold(
        appBar: widget.showBack
            ? AppBar(title: const Text('RCrm Cast Receiver'))
            : null,
        body: const Center(child: Text('No pairing QR')),
      );
    }
    if (_playing) {
      return _buildPlaying();
    }
    final paired = _receiver?.isPaired ?? false;
    return _buildQrPage(qr, usable: !paired && !_qrExpired);
  }

  // ── QR pairing page ───────────────────────────────────────

  Widget _buildQrPage(CastQrPayload qr, {required bool usable}) {
    final receiver = _receiver!;
    final paired = receiver.isPaired;
    // Keep the badge text short: it sits inside the QR card, and a long
    // phrase ('Expired - generate a new code') wraps inside small cards and
    // the strike-through X crosses the multi-line pill. The page text below
    // the QR already spells out what to do.
    final badge = usable ? null : (paired ? 'Paired' : 'Expired');
    return CastReceiverQrView(
      qr: qr,
      paired: paired,
      usable: usable,
      badge: badge,
      showBack: widget.showBack,
      localIpv4s: receiver.localIpv4s,
      pairExpiresAt: receiver.pairExpiresAt,
      serverOk: receiver.serverOk,
      tick: _qrTimer != null,
      callbacks: CastReceiverQrViewCallbacks(
        onUnpair: _unpair,
        onRegenerate: _regenerateQr,
        onSelectIpv4: (ip) {
          receiver.selectLocalIpv4(ip);
          setState(() => _qr = receiver.currentQr());
        },
      ),
    );
  }

  // ── playing page ──────────────────────────────────────────

  Widget _buildPlaying() {
    // Same global-key approach as the video player (MediaPlayerKeys wraps
    // HardwareKeyboard): arrows/space/ESC work on the cast target even when
    // no widget holds Flutter focus.
    return MediaPlayerKeys(
      actions: MediaPlayerKeyActions(
        onTogglePlay: () {
          final p = _player;
          if (p == null) return;
          if (p.state.playing) {
            p.pause();
          } else {
            p.play();
          }
        },
        onSeek: (delta) {
          final p = _player;
          if (p == null) return;
          final pos = p.state.position + delta;
          p.seek(Duration(seconds: pos.inSeconds.clamp(0, 999999)));
        },
        onVolume: (delta) {
          final p = _player;
          if (p == null) return;
          final v = (p.state.volume + delta).clamp(0.0, 1.0);
          p.setVolume(v);
        },
        onEscape: _stopPlayback,
      ),
      child: PopScope(
        // While playing, the back key stops PLAYBACK but keeps the receiver
        // and the cast connection alive (same as the Stop button). Only a
        // plain back (nothing playing) pops the screen; use the Exit button
        // to leave the receiver entirely.
        canPop: !_playing,
        onPopInvokedWithResult: (didPop, _) async {
          if (didPop || !_playing) return;
          await _stopPlayback();
        },
        child: Scaffold(
          // No AppBar: full-screen video. The overlay (shown briefly on
          // start/seek, or on tap) carries the filename, progress and controls.
          body: GestureDetector(
            behavior: HitTestBehavior.opaque,
            onTap: _showOverlay,
            child: Stack(
              children: [
                Positioned.fill(
                  child: _imageUrl != null
                      ? _CastImage(
                          key: ValueKey(_imageUrl),
                          url: _imageUrl!,
                          filePath: _currentPath ?? '',
                          errorWidget: const ColoredBox(
                            color: Colors.black,
                            child: Center(
                              child: Text(
                                'Image failed to load',
                                style: TextStyle(color: Colors.white70),
                              ),
                            ),
                          ),
                        )
                      : _vc != null
                      ? Video(controller: _vc!, fit: BoxFit.contain)
                      : const ColoredBox(color: Colors.black),
                ),
                // Buffering spinner over the video while it loads/seeks.
                if (_vc != null && _buffering)
                  const Center(
                    child: CircularProgressIndicator(color: Colors.white70),
                  ),
                // Top overlay: status + thin progress bar. Auto-hides.
                if (_overlayVisible)
                  Positioned(
                    left: 0,
                    right: 0,
                    top: 0,
                    child: Container(
                      decoration: BoxDecoration(
                        gradient: LinearGradient(
                          begin: Alignment.topCenter,
                          end: Alignment.bottomCenter,
                          colors: [
                            Colors.black.withValues(alpha: 0.7),
                            Colors.transparent,
                          ],
                        ),
                      ),
                      child: SafeArea(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.stretch,
                          children: [
                            Padding(
                              padding: const EdgeInsets.fromLTRB(
                                20,
                                12,
                                20,
                                14,
                              ),
                              child: Row(
                                children: [
                                  const Icon(
                                    Icons.cast_connected,
                                    color: Color(0xFF6C8CFF),
                                  ),
                                  const SizedBox(width: 12),
                                  Expanded(
                                    child: Column(
                                      crossAxisAlignment:
                                          CrossAxisAlignment.start,
                                      children: [
                                        Text(
                                          'Casting',
                                          style: TextStyle(
                                            fontSize: 13,
                                            color: Colors.white.withValues(
                                              alpha: 0.7,
                                            ),
                                          ),
                                        ),
                                        Text(
                                          _currentPath?.split('/').last ??
                                              'Loading...',
                                          maxLines: 1,
                                          overflow: TextOverflow.ellipsis,
                                          style: const TextStyle(
                                            fontSize: 17,
                                            fontWeight: FontWeight.w600,
                                          ),
                                        ),
                                      ],
                                    ),
                                  ),
                                  ValueListenableBuilder<Duration>(
                                    valueListenable: _pos,
                                    builder: (context, pos, _) {
                                      // No progress display for images.
                                      if (_imageUrl != null) {
                                        return const SizedBox.shrink();
                                      }
                                      return Text(
                                        _fmtMs(pos.inMilliseconds),
                                        style: TextStyle(
                                          fontSize: 13,
                                          color: Colors.white.withValues(
                                            alpha: 0.7,
                                          ),
                                        ),
                                      );
                                    },
                                  ),
                                  const SizedBox(width: 12),
                                  Focus(
                                    child: OutlinedButton.icon(
                                      onPressed: _stopPlayback,
                                      style: OutlinedButton.styleFrom(
                                        foregroundColor: Colors.white,
                                        side: BorderSide(
                                          color: Colors.white.withValues(
                                            alpha: 0.4,
                                          ),
                                        ),
                                        visualDensity: VisualDensity.compact,
                                      ),
                                      icon: const Icon(Icons.stop, size: 18),
                                      label: const Text('Stop'),
                                    ),
                                  ),
                                  const SizedBox(width: 8),
                                  Focus(
                                    child: OutlinedButton.icon(
                                      onPressed: _exitReceiver,
                                      style: OutlinedButton.styleFrom(
                                        foregroundColor: const Color(
                                          0xFFFF8A80,
                                        ),
                                        side: BorderSide(
                                          color: Colors.white.withValues(
                                            alpha: 0.4,
                                          ),
                                        ),
                                        visualDensity: VisualDensity.compact,
                                      ),
                                      icon: const Icon(Icons.logout, size: 18),
                                      label: const Text('Exit'),
                                    ),
                                  ),
                                ],
                              ),
                            ),
                            // No progress bar for images.
                            if (_imageUrl == null)
                              ValueListenableBuilder<double>(
                                valueListenable: _progress,
                                builder: (context, value, _) =>
                                    LinearProgressIndicator(
                                      value: value,
                                      minHeight: 3,
                                      backgroundColor: Colors.white.withValues(
                                        alpha: 0.15,
                                      ),
                                      color: const Color(0xFF6C8CFF),
                                    ),
                              ),
                          ],
                        ),
                      ),
                    ),
                  ),
              ],
            ),
          ),
        ),
      ),
    );
  }

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

/// Wires [CastReceiver] commands to the screen's player.
class _PlayerHost implements CastPlayerHost {
  final _State state;
  _PlayerHost(this.state);

  @override
  Future<void> play(String streamUrl, {bool isImage = false}) =>
      state._play(streamUrl, isImage: isImage);

  @override
  Future<void> pause() => state._pause();

  @override
  Future<void> resume() => state._resume();

  @override
  Future<void> seek(Duration position) => state._seek(position);

  @override
  Future<void> stopPlayback() => state._stopPlayback();

  @override
  Future<void> setVolume(int level) => state._setVolume(level);

  @override
  Future<void> setRate(double rate) => state._setRate(rate);
}

/// Full-screen cast image with AVIF/JXL support and correct physical-pixel
/// decoding.
///
/// The receiver previously used `Image.network`, which has two problems on a
/// TV: Flutter's built-in codec cannot decode AVIF/JXL (the phone routes
/// those through the Rust software decoder — this widget does the same), and
/// `cacheWidth` used the LOGICAL screen width, so on a 4K TV a 4K photo was
/// decoded at half resolution and upscaled — the "small blurry image" look.
///
/// Decoding is capped at the PHYSICAL screen size (fit, aspect preserved):
/// large photos are downscaled (bounded memory on low-end TVs), small images
/// decode at their native size (no pointless upscale), matching the phone
/// viewer's small/large distinction. [filePath] is the original server path
/// (not the proxy URL) so AVIF/JXL are routed to the Rust decoder.
class _CastImage extends StatefulWidget {
  /// Localhost proxy URL of the full image file.
  final String url;

  /// Original server-side path (used for format detection — the proxy URL's
  /// extension lives in a query parameter, not the URL path).
  final String filePath;

  /// Shown when the image cannot be fetched or decoded.
  final Widget errorWidget;

  const _CastImage({
    super.key,
    required this.url,
    required this.filePath,
    required this.errorWidget,
  });

  @override
  State<_CastImage> createState() => _CastImageState();
}

class _CastImageState extends State<_CastImage> {
  ui.Image? _image;
  bool _failed = false;

  /// Lowercased file extension (e.g. "avif", "jxl") from a path, or null.
  static String? _extOf(String path) {
    final p = Uri.tryParse(path)?.path ?? path;
    final dot = p.lastIndexOf('.');
    if (dot == -1 || dot == p.length - 1) return null;
    final ext = p.substring(dot + 1).toLowerCase();
    return ext.isEmpty ? null : ext;
  }

  /// Bumped on every URL change so a stale in-flight load (the fetch/decode
  /// is async) can never clobber the image or error state of the current
  /// URL. Without this, rapid image casts could flash the wrong picture.
  int _gen = 0;

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void didUpdateWidget(_CastImage oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.url != widget.url || oldWidget.filePath != widget.filePath) {
      _gen++; // invalidate any in-flight load
      _image?.dispose();
      _image = null;
      _failed = false;
      _load();
    }
  }

  @override
  void dispose() {
    _gen++; // invalidate any in-flight load
    _image?.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    final gen = _gen;
    // The proxy URL is plain http://127.0.0.1:<port> — a bare HttpClient is
    // fine (no TLS, no certificate decision to make).
    final client = HttpClient();
    try {
      final req = await client.getUrl(Uri.parse(widget.url));
      final res = await req.close();
      if (res.statusCode != 200) throw Exception('HTTP ${res.statusCode}');
      final bytes = await consolidateHttpClientResponseBytes(res);
      if (!mounted || gen != _gen) return;

      // Physical-pixel decode cap: on a 4K TV this is 3840, so large photos
      // stay sharp; on a phone-as-receiver it is the screen's own pixels.
      final dpr = MediaQuery.devicePixelRatioOf(context);
      final physicalWidth = (MediaQuery.sizeOf(context).width * dpr).round();
      final physicalHeight = (MediaQuery.sizeOf(context).height * dpr).round();

      // AVIF/JXL → Rust software decoder (available on the Android TV build
      // via the mobile-decode feature; no-op elsewhere). format is derived
      // from the REAL path — the proxy URL's query param holds it.
      final format = _extOf(widget.filePath);
      var codec = await MobileImageDecoder.tryDecode(
        bytes,
        widget.url,
        targetWidth: physicalWidth,
        format: format,
      );
      if (codec == null) {
        final buffer = await ui.ImmutableBuffer.fromUint8List(bytes);
        // Scale DOWN to fit the physical screen, preserving aspect ratio —
        // never set width and height independently (that distorts, e.g. a
        // 4000×3000 photo would decode square). Small images keep native
        // resolution (no pointless upscale).
        codec = await ui.instantiateImageCodecWithSize(
          buffer,
          getTargetSize: (int w, int h) {
            if (w <= physicalWidth && h <= physicalHeight) {
              return const ui.TargetImageSize();
            }
            final scale = (physicalWidth / w) < (physicalHeight / h)
                ? physicalWidth / w
                : physicalHeight / h;
            return ui.TargetImageSize(
              width: (w * scale).round(),
              height: (h * scale).round(),
            );
          },
        );
      }
      final frame = await codec.getNextFrame();
      if (!mounted || gen != _gen) return;
      setState(() {
        _image?.dispose();
        _image = frame.image;
      });
    } catch (_) {
      if (mounted && gen == _gen) setState(() => _failed = true);
    } finally {
      client.close(force: true);
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_failed) return widget.errorWidget;
    final image = _image;
    if (image == null) {
      // Loading: black backdrop + spinner (the fetch and decode are async).
      return const ColoredBox(
        color: Colors.black,
        child: Center(child: CircularProgressIndicator(color: Colors.white70)),
      );
    }
    return RawImage(
      image: image,
      fit: BoxFit.contain,
      // gaplessPlayback analog: keep the previous frame while a new URL
      // loads so the screen never flashes black between cast images.
      isAntiAlias: true,
    );
  }
}
