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

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:media_kit/media_kit.dart';
import 'package:media_kit_video/media_kit_video.dart';
import 'package:path_provider/path_provider.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../providers/server_provider.dart';
import '../services/cast_protocol.dart';
import '../services/cast_receiver.dart';
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

  bool _starting = true;
  String? _error;
  CastQrPayload? _qr;
  Timer? _qrTimer;
  bool _playing = false;
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
  /// playing subscriptions FIRST so a disposed Player never delivers stale
  /// events, then disposes the Player + controller.
  Future<void> _disposePlayer() async {
    _posSub?.cancel();
    _posSub = null;
    _durSub?.cancel();
    _durSub = null;
    _playingSub?.cancel();
    _playingSub = null;
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

  /// Advertised address row. When several NICs exist (VPN/Hyper-V/Docker
  /// virtual adapters alongside the real LAN one), shows a picker so the
  /// user can select the address that is actually reachable by the phone.
  Widget _buildAddressRow(
    CastQrPayload qr,
    CastReceiver receiver, {
    required bool landscape,
  }) {
    final candidates = receiver.localIpv4s;
    final style = TextStyle(
      fontSize: landscape ? 15 : 14,
      color: Colors.white.withValues(alpha: 0.55),
    );
    final label = 'Address ${qr.host}:${qr.port}';
    if (candidates.length <= 1) {
      return Align(
        alignment: landscape ? Alignment.centerLeft : Alignment.center,
        child: Text(label, style: style),
      );
    }
    return Row(
      mainAxisSize: MainAxisSize.min,
      mainAxisAlignment: landscape
          ? MainAxisAlignment.start
          : MainAxisAlignment.center,
      children: [
        Text(label, style: style),
        const SizedBox(width: 4),
        PopupMenuButton<String>(
          tooltip: 'Change LAN address',
          icon: Icon(
            Icons.swap_horiz,
            size: 16,
            color: Colors.white.withValues(alpha: 0.55),
          ),
          onSelected: (ip) {
            receiver.selectLocalIpv4(ip);
            setState(() => _qr = receiver.currentQr());
          },
          itemBuilder: (context) => [
            for (final ip in candidates)
              PopupMenuItem<String>(
                value: ip,
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    if (ip == qr.host)
                      const Icon(Icons.check, size: 16)
                    else
                      const SizedBox(width: 16),
                    const SizedBox(width: 8),
                    Text(ip),
                  ],
                ),
              ),
          ],
        ),
      ],
    );
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
    final badge = usable
        ? null
        : (paired ? 'Paired' : 'Expired - generate a new code');
    return Scaffold(
      appBar: widget.showBack
          ? AppBar(title: const Text('RCrm Cast Receiver'))
          : null,
      body: Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
            colors: [Color(0xFF101428), Color(0xFF1A1030), Color(0xFF0B0B14)],
          ),
        ),
        child: SafeArea(
          child: LayoutBuilder(
            builder: (context, constraints) {
              // Landscape (TV, desktop windows, landscape phones): side-by-side
              // info + QR. Portrait: stacked, scrollable column.
              final landscape =
                  constraints.maxWidth > 700 &&
                  constraints.maxWidth > constraints.maxHeight * 1.02;
              if (landscape) {
                return _buildLandscape(qr, paired, usable, badge, constraints);
              }
              return _buildPortrait(qr, paired, usable, badge, constraints);
            },
          ),
        ),
      ),
    );
  }

  Widget _buildLandscape(
    CastQrPayload qr,
    bool paired,
    bool usable,
    String? badge,
    BoxConstraints constraints,
  ) {
    final receiver = _receiver!;
    final qrSize = (constraints.maxHeight * 0.52).clamp(220.0, 520.0);
    return Center(
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 1280),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 40, vertical: 24),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              // Left: brand + status + actions.
              Expanded(
                flex: 5,
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const _BrandHeader(),
                    const SizedBox(height: 20),
                    Text(
                      paired
                          ? 'Phone connected, waiting to play...'
                          : usable
                          ? 'Scan the QR with the RCrm phone app'
                          : 'Code expired - tap below for a new one',
                      style: TextStyle(
                        fontSize: 18,
                        color: Colors.white.withValues(alpha: 0.75),
                      ),
                    ),
                    const SizedBox(height: 28),
                    Wrap(
                      spacing: 12,
                      runSpacing: 10,
                      children: [
                        _StatusChip(
                          label: paired ? 'Paired' : 'Waiting to scan',
                          ok: paired,
                          icon: paired
                              ? Icons.check_circle
                              : Icons.radio_button_checked,
                        ),
                        _StatusChip(
                          label: receiver.serverOk
                              ? 'Server reachable'
                              : 'Server not connected',
                          ok: receiver.serverOk,
                          icon: receiver.serverOk
                              ? Icons.cloud_done
                              : Icons.cloud_off,
                        ),
                      ],
                    ),
                    const SizedBox(height: 20),
                    _buildAddressRow(qr, receiver, landscape: true),
                    const SizedBox(height: 26),
                    _PairCountdown(
                      expiresAt: receiver.pairExpiresAt,
                      paired: paired,
                      tick: _qrTimer != null,
                    ),
                    const SizedBox(height: 16),
                    Focus(
                      child: OutlinedButton.icon(
                        onPressed: paired ? _unpair : _regenerateQr,
                        style: OutlinedButton.styleFrom(
                          foregroundColor: Colors.white,
                          side: BorderSide(
                            color: Colors.white.withValues(alpha: 0.35),
                          ),
                          padding: const EdgeInsets.symmetric(
                            horizontal: 20,
                            vertical: 12,
                          ),
                        ),
                        icon: Icon(paired ? Icons.link_off : Icons.qr_code_2),
                        label: Text(paired ? 'Unpair' : 'New code'),
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 48),
              // Right: the QR card.
              Expanded(
                flex: 4,
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    _QrCard(qr: qr, size: qrSize, badge: badge),
                    const SizedBox(height: 14),
                    Text(
                      'One-time code, auto-destroys on expiry',
                      style: TextStyle(
                        fontSize: 13,
                        color: Colors.white.withValues(alpha: 0.4),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildPortrait(
    CastQrPayload qr,
    bool paired,
    bool usable,
    String? badge,
    BoxConstraints constraints,
  ) {
    final receiver = _receiver!;
    final shortSide = constraints.maxWidth < constraints.maxHeight
        ? constraints.maxWidth
        : constraints.maxHeight;
    final qrSize = (shortSide * 0.42).clamp(180.0, 430.0);
    return SingleChildScrollView(
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 20),
      child: ConstrainedBox(
        constraints: BoxConstraints(minHeight: constraints.maxHeight - 40),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const _BrandHeader(),
            const SizedBox(height: 12),
            Text(
              paired
                  ? 'Phone connected, waiting to play...'
                  : usable
                  ? 'Scan the QR with the RCrm phone app'
                  : 'Code expired - tap below for a new one',
              textAlign: TextAlign.center,
              style: TextStyle(
                fontSize: 17,
                color: Colors.white.withValues(alpha: 0.75),
              ),
            ),
            const SizedBox(height: 28),
            // QR card — the pairing surface.
            _QrCard(qr: qr, size: qrSize, badge: badge),
            const SizedBox(height: 20),
            _PairCountdown(
              expiresAt: receiver.pairExpiresAt,
              paired: paired,
              tick: _qrTimer != null,
            ),
            const SizedBox(height: 20),
            Wrap(
              spacing: 12,
              runSpacing: 10,
              alignment: WrapAlignment.center,
              children: [
                _StatusChip(
                  label: paired ? 'Paired' : 'Waiting to scan',
                  ok: paired,
                  icon: paired
                      ? Icons.check_circle
                      : Icons.radio_button_checked,
                ),
                _StatusChip(
                  label: receiver.serverOk
                      ? 'Server reachable'
                      : 'Server not connected',
                  ok: receiver.serverOk,
                  icon: receiver.serverOk ? Icons.cloud_done : Icons.cloud_off,
                ),
              ],
            ),
            const SizedBox(height: 18),
            _buildAddressRow(qr, receiver, landscape: false),
            const SizedBox(height: 22),
            Focus(
              child: OutlinedButton.icon(
                onPressed: paired ? _unpair : _regenerateQr,
                style: OutlinedButton.styleFrom(
                  foregroundColor: Colors.white,
                  side: BorderSide(color: Colors.white.withValues(alpha: 0.35)),
                  padding: const EdgeInsets.symmetric(
                    horizontal: 20,
                    vertical: 12,
                  ),
                ),
                icon: Icon(paired ? Icons.link_off : Icons.qr_code_2),
                label: Text(paired ? 'Unpair' : 'New code'),
              ),
            ),
            const SizedBox(height: 10),
            Text(
              'One-time code, auto-destroys on expiry',
              style: TextStyle(
                fontSize: 13,
                color: Colors.white.withValues(alpha: 0.4),
              ),
            ),
          ],
        ),
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
        // While playing, intercept the system back button so the TV
        // owner does not lose playback silently; confirm first.
        canPop: !_playing,
        onPopInvokedWithResult: (didPop, _) async {
          if (didPop || !_playing) return;
          await _exitReceiver();
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
                      ? Image.network(
                          _imageUrl!,
                          fit: BoxFit.contain,
                          // Decode at the screen width so a low-end TV
                          // never holds a full-resolution RGBA buffer.
                          cacheWidth: MediaQuery.of(context).size.width.round(),
                          gaplessPlayback: true,
                          errorBuilder: (_, _, _) => const ColoredBox(
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

/// The white QR card. When [badge] is non-null the QR is dimmed and struck
/// through with a badge (expired / already paired) while the layout stays
/// unchanged.
class _QrCard extends StatelessWidget {
  final CastQrPayload qr;
  final double size;
  final String? badge;
  const _QrCard({required this.qr, required this.size, this.badge});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: EdgeInsets.all(size * 0.05),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(size * 0.07),
        boxShadow: [
          BoxShadow(
            color: const Color(0xFF4C6FFF).withValues(alpha: 0.35),
            blurRadius: 40,
            spreadRadius: 2,
          ),
        ],
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(size * 0.03),
        child: Stack(
          children: [
            QrImageView(
              data: qr.encode(),
              size: size,
              backgroundColor: Colors.white,
              eyeStyle: const QrEyeStyle(
                eyeShape: QrEyeShape.square,
                color: Color(0xFF101428),
              ),
              dataModuleStyle: const QrDataModuleStyle(
                dataModuleShape: QrDataModuleShape.square,
                color: Color(0xFF101428),
              ),
            ),
            if (badge != null)
              Positioned.fill(
                child: ColoredBox(
                  color: Colors.black.withValues(alpha: 0.45),
                  child: CustomPaint(
                    painter: const _StrikeThroughPainter(),
                    child: Center(
                      child: Container(
                        padding: const EdgeInsets.symmetric(
                          horizontal: 14,
                          vertical: 8,
                        ),
                        decoration: BoxDecoration(
                          color: const Color(
                            0xFF101428,
                          ).withValues(alpha: 0.85),
                          borderRadius: BorderRadius.circular(20),
                          border: Border.all(
                            color: Colors.white.withValues(alpha: 0.5),
                          ),
                        ),
                        child: Text(
                          badge!,
                          textAlign: TextAlign.center,
                          style: const TextStyle(
                            fontSize: 15,
                            fontWeight: FontWeight.w700,
                            color: Colors.white,
                          ),
                        ),
                      ),
                    ),
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }
}

/// Paints an X across the QR to mark it invalid.
class _StrikeThroughPainter extends CustomPainter {
  const _StrikeThroughPainter();

  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = Colors.white.withValues(alpha: 0.75)
      ..strokeWidth = size.shortestSide * 0.02
      ..strokeCap = StrokeCap.round;
    canvas.drawLine(
      Offset(size.width * 0.08, size.height * 0.08),
      Offset(size.width * 0.92, size.height * 0.92),
      paint,
    );
    canvas.drawLine(
      Offset(size.width * 0.92, size.height * 0.08),
      Offset(size.width * 0.08, size.height * 0.92),
      paint,
    );
  }

  @override
  bool shouldRepaint(_StrikeThroughPainter oldDelegate) => false;
}

class _BrandHeader extends StatelessWidget {
  const _BrandHeader();

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Container(
          width: 52,
          height: 52,
          decoration: BoxDecoration(
            gradient: const LinearGradient(
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
              colors: [Color(0xFF6C8CFF), Color(0xFF9A6CFF)],
            ),
            borderRadius: BorderRadius.circular(14),
            boxShadow: [
              BoxShadow(
                color: const Color(0xFF6C8CFF).withValues(alpha: 0.4),
                blurRadius: 18,
              ),
            ],
          ),
          child: const Icon(Icons.cast, color: Colors.white, size: 30),
        ),
        const SizedBox(width: 14),
        const Text(
          'Cast Receiver',
          style: TextStyle(
            fontSize: 30,
            fontWeight: FontWeight.w700,
            letterSpacing: 0.5,
          ),
        ),
      ],
    );
  }
}

/// Shows the seconds left until the one-time pair token expires. On expiry
/// the token is destroyed (receiver stops offering the QR) and the parent
/// switches to the expired state; this widget itself stays stateless.
class _PairCountdown extends StatelessWidget {
  final DateTime? expiresAt;
  final bool paired;
  final bool tick;
  const _PairCountdown({
    required this.expiresAt,
    required this.paired,
    required this.tick,
  });

  @override
  Widget build(BuildContext context) {
    if (paired) {
      return Text(
        'Paired - QR no longer needed',
        style: TextStyle(
          fontSize: 13,
          color: Colors.white.withValues(alpha: 0.45),
        ),
      );
    }
    final exp = expiresAt;
    if (exp == null) return const SizedBox.shrink();
    final left = exp.difference(DateTime.now());
    if (left.isNegative) {
      return Text(
        'Code expired and destroyed',
        style: const TextStyle(
          fontSize: 13,
          color: Color(0xFFFFB74D),
          fontWeight: FontWeight.w600,
        ),
      );
    }
    final secs = (left.inMilliseconds / 1000).ceil();
    final urgent = secs <= 15;
    return Text(
      'Code expires in ${secs}s',
      style: TextStyle(
        fontSize: 13,
        color: urgent
            ? const Color(0xFFFFB74D)
            : Colors.white.withValues(alpha: 0.45),
        fontWeight: urgent ? FontWeight.w600 : FontWeight.normal,
      ),
    );
  }
}

class _StatusChip extends StatelessWidget {
  final String label;
  final bool ok;
  final IconData icon;
  const _StatusChip({
    required this.label,
    required this.ok,
    required this.icon,
  });

  @override
  Widget build(BuildContext context) {
    final bg = ok
        ? const Color(0xFF1B5E20).withValues(alpha: 0.85)
        : const Color(0xFF4A148C).withValues(alpha: 0.85);
    final fg = ok ? const Color(0xFFA5D6A7) : const Color(0xFFCE93D8);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
      decoration: BoxDecoration(
        color: bg,
        borderRadius: BorderRadius.circular(22),
        border: Border.all(color: fg.withValues(alpha: 0.35)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 16, color: fg),
          const SizedBox(width: 7),
          Text(
            label,
            style: TextStyle(
              fontSize: 14,
              color: fg,
              fontWeight: FontWeight.w500,
            ),
          ),
        ],
      ),
    );
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
