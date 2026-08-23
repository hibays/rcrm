// widgets/player_controls.dart
// Controls bar: back, seek, play/pause, prev/next, speed popup, volume (always visible), fullscreen

import 'dart:async';
import 'package:flutter/material.dart';

import 'package:flutter/gestures.dart';
import 'package:media_kit/media_kit.dart';
import 'package:shared_preferences/shared_preferences.dart';

class PlayerControls extends StatefulWidget {
  final Player player;
  final VoidCallback? onPrev;
  final VoidCallback? onNext;
  final bool showFullscreen;
  final VoidCallback onFullscreen;
  final VoidCallback? onSettingsTap;

  /// Opens the episode picker (fullscreen only; null hides the button).
  final VoidCallback? onEpisodesTap;

  final double scale; // 1.0 normal, >1.0 fullscreen
  const PlayerControls({
    super.key,
    required this.player,
    this.onPrev,
    this.onNext,
    this.onSettingsTap,
    this.onEpisodesTap,
    required this.showFullscreen,
    required this.onFullscreen,
    this.scale = 1.0,
  });

  @override
  State<PlayerControls> createState() => _PlayerControlsState();
}

class _PlayerControlsState extends State<PlayerControls> {
  bool _playing = false;
  final ValueNotifier<Duration> _pos = ValueNotifier(Duration.zero);
  final ValueNotifier<Duration> _dur = ValueNotifier(Duration.zero);
  final ValueNotifier<Duration> _buffer = ValueNotifier(Duration.zero);
  bool _seeking = false;
  double _speed = 1.0;
  static SharedPreferences? _prefs;
  static double _savedVolume = 100;
  final ValueNotifier<double> _volume = ValueNotifier(_savedVolume);

  StreamSubscription? _playingSub;
  StreamSubscription? _positionSub;
  StreamSubscription? _durationSub;
  StreamSubscription? _bufferSub;
  StreamSubscription? _volumeSub;
  double _prevVol = 100;
  static const _speeds = [0.5, 0.75, 1.0, 1.25, 1.5, 2.0];
  int _lastPosMs = 0; // throttle position notifier to ~every 100ms

  static Future<void> _initPrefs() async {
    if (_prefs != null) return;
    _prefs = await SharedPreferences.getInstance();
    _savedVolume = _prefs!.getDouble('player_volume') ?? 100;
  }

  static void _saveVol(double v) {
    _savedVolume = v;
    _prefs?.setDouble('player_volume', v);
  }

  @override
  void initState() {
    super.initState();
    _playing = widget.player.state.playing;
    _pos.value = widget.player.state.position;
    _dur.value = widget.player.state.duration;
    _buffer.value = widget.player.state.buffer;
    _initPrefs().then((_) {
      if (mounted) {
        _volume.value = _savedVolume;
        widget.player.setVolume(_savedVolume);
      }
    });
    _playingSub = widget.player.stream.playing.listen((p) {
      if (mounted && _playing != p) setState(() => _playing = p);
    });
    _positionSub = widget.player.stream.position.listen((p) {
      if (!_seeking && mounted) {
        final ms = p.inMilliseconds;
        if ((ms - _lastPosMs).abs() < 100) return;
        _lastPosMs = ms;
        _pos.value = p;
      }
    });
    _durationSub = widget.player.stream.duration.listen((d) {
      if (mounted) _dur.value = d;
    });
    _bufferSub = widget.player.stream.buffer.listen((b) {
      if (mounted) _buffer.value = b;
    });
    _volumeSub = widget.player.stream.volume.listen((v) {
      if (mounted) _volume.value = v;
    });
  }

  @override
  void dispose() {
    _playingSub?.cancel();
    _positionSub?.cancel();
    _durationSub?.cancel();
    _bufferSub?.cancel();
    _volumeSub?.cancel();
    _pos.dispose();
    _dur.dispose();
    _buffer.dispose();
    _volume.dispose();
    super.dispose();
  }

  bool get _muted => _volume.value == 0;

  void _togglePlay() {
    setState(() => _playing = !_playing);
    _playing ? widget.player.play() : widget.player.pause();
  }

  void _setSpeed(double s) {
    _speed = s;
    widget.player.setRate(s);
    setState(() {});
  }

  void _toggleMute() {
    if (_muted) {
      _volume.value = _prevVol;
      widget.player.setVolume(_prevVol);
      _saveVol(_prevVol);
    } else {
      _prevVol = _volume.value;
      _volume.value = 0;
      widget.player.setVolume(0);
      _saveVol(0);
    }
  }

  void _setVolume(double v) {
    _volume.value = v;
    _saveVol(v);
    widget.player.setVolume(v);
  }

  void _wheelVolume(PointerSignalEvent e) {
    if (e is! PointerScrollEvent) return;
    final cur = _muted ? 0.0 : _volume.value;
    final v = (cur + (e.scrollDelta.dy < 0 ? 5.0 : -5.0)).clamp(0.0, 100.0);
    _setVolume(v);
  }

  @override
  Widget build(BuildContext c) {
    final durListen = Listenable.merge([_pos, _dur, _buffer]);
    return LayoutBuilder(
      builder: (ctx, constraints) {
        final narrow = constraints.maxWidth < 400;
        return Stack(
          children: [
            Container(
              decoration: const BoxDecoration(
                gradient: LinearGradient(
                  begin: Alignment.bottomCenter,
                  end: Alignment.topCenter,
                  colors: [Color(0x80000000), Color(0x00000000)],
                ),
              ),
              padding: EdgeInsets.only(
                bottom: 4 * widget.scale,
                left: 12 * widget.scale,
                right: 12 * widget.scale,
              ),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  ListenableBuilder(
                    listenable: durListen,
                    builder: (_, _) {
                      final d = _dur.value.inMilliseconds.toDouble();
                      final p = _pos.value.inMilliseconds.toDouble();
                      final pct = d > 0 ? (p / d).clamp(0.0, 1.0) : 0.0;
                      final buf = d > 0
                          ? (_buffer.value.inMilliseconds / d).clamp(0.0, 1.0)
                          : 0.0;
                      return SizedBox(
                        height: 20 * widget.scale,
                        child: SliderTheme(
                          data: SliderThemeData(
                            trackHeight: 3 * widget.scale,
                            thumbShape: RoundSliderThumbShape(
                              enabledThumbRadius: 5 * widget.scale,
                            ),
                            activeTrackColor: const Color(0xFFFF6B00),
                            inactiveTrackColor: const Color(0x33FFFFFF),
                            thumbColor: const Color(0xFFFF6B00),
                            secondaryActiveTrackColor: const Color(0x66FFFFFF),
                          ),
                          child: Slider(
                            value: pct,
                            secondaryTrackValue: buf,
                            onChanged: (v) {
                              if (!_seeking) setState(() => _seeking = true);
                              _pos.value = Duration(
                                milliseconds: (v * d).toInt(),
                              );
                            },
                            onChangeEnd: (v) {
                              _seeking = false;
                              widget.player.seek(
                                Duration(milliseconds: (v * d).toInt()),
                              );
                            },
                          ),
                        ),
                      );
                    },
                  ),
                  SizedBox(height: 4 * widget.scale),
                  Row(
                    children: [
                      IconButton(
                        icon: Icon(
                          _playing ? Icons.pause : Icons.play_arrow,
                          color: Colors.white70,
                          size: 22 * widget.scale,
                        ),
                        onPressed: _togglePlay,
                        visualDensity: VisualDensity.compact,
                        padding: EdgeInsets.zero,
                      ),
                      SizedBox(width: 4 * widget.scale),
                      ValueListenableBuilder<double>(
                        valueListenable: _volume,
                        builder: (_, v, _) {
                          final muted = v == 0;
                          return Listener(
                            onPointerSignal: _wheelVolume,
                            child: Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                IconButton(
                                  icon: Icon(
                                    muted ? Icons.volume_off : Icons.volume_up,
                                    color: Colors.white54,
                                    size: 18 * widget.scale,
                                  ),
                                  onPressed: _toggleMute,
                                  visualDensity: VisualDensity.compact,
                                  padding: EdgeInsets.zero,
                                ),
                                if (!narrow)
                                  SizedBox(
                                    height: 36 * widget.scale,
                                    width: 100 * widget.scale,
                                    child: SliderTheme(
                                      data: SliderThemeData(
                                        trackHeight: 3 * widget.scale,
                                        thumbShape: RoundSliderThumbShape(
                                          enabledThumbRadius: 5 * widget.scale,
                                        ),
                                        activeTrackColor: Colors.white54,
                                        inactiveTrackColor: const Color(
                                          0x33FFFFFF,
                                        ),
                                        thumbColor: Colors.white,
                                      ),
                                      child: Slider(
                                        value: muted ? 0 : v,
                                        onChanged: _setVolume,
                                        min: 0,
                                        max: 100,
                                      ),
                                    ),
                                  ),
                              ],
                            ),
                          );
                        },
                      ),
                      SizedBox(width: 6 * widget.scale),
                      ValueListenableBuilder(
                        valueListenable: _pos,
                        builder: (_, p, _) => Text(
                          _fmt(p),
                          style: TextStyle(
                            color: Colors.white54,
                            fontSize: 11 * widget.scale,
                          ),
                        ),
                      ),
                      ValueListenableBuilder(
                        valueListenable: _dur,
                        builder: (_, d, _) => Text(
                          ' / ${_fmt(d)}',
                          style: TextStyle(
                            color: Colors.white30,
                            fontSize: 11 * widget.scale,
                          ),
                        ),
                      ),
                      const Spacer(),
                      if (!narrow && widget.onPrev != null)
                        IconButton(
                          icon: const Icon(
                            Icons.skip_previous,
                            color: Colors.white54,
                            size: 20,
                          ),
                          onPressed: widget.onPrev,
                          visualDensity: VisualDensity.compact,
                          padding: EdgeInsets.zero,
                        ),
                      SizedBox(width: 4 * widget.scale),
                      if (!narrow && widget.onNext != null)
                        IconButton(
                          icon: const Icon(
                            Icons.skip_next,
                            color: Colors.white54,
                            size: 20,
                          ),
                          onPressed: widget.onNext,
                          visualDensity: VisualDensity.compact,
                          padding: EdgeInsets.zero,
                        ),
                      SizedBox(width: 4 * widget.scale),
                      PopupMenuButton<double>(
                        initialValue: _speed,
                        onSelected: _setSpeed,
                        offset: Offset(0, -200 * widget.scale),
                        child: Container(
                          padding: EdgeInsets.symmetric(
                            horizontal: 6 * widget.scale,
                            vertical: 2 * widget.scale,
                          ),
                          decoration: BoxDecoration(
                            color: Colors.white.withValues(alpha: 0.08),
                            borderRadius: BorderRadius.circular(4),
                          ),
                          child: Text(
                            '${_speed}x',
                            style: TextStyle(
                              color: Colors.white54,
                              fontSize: 11 * widget.scale,
                            ),
                          ),
                        ),
                        itemBuilder: (_) => _speeds
                            .map(
                              (s) => PopupMenuItem(
                                value: s,
                                child: Text(
                                  '${s}x',
                                  style: TextStyle(
                                    color: _speed == s
                                        ? Colors.orange
                                        : Colors.white70,
                                    fontSize: 13 * widget.scale,
                                  ),
                                ),
                              ),
                            )
                            .toList(),
                      ),
                      SizedBox(width: 4 * widget.scale),
                      IconButton(
                        icon: Icon(
                          widget.showFullscreen
                              ? Icons.fullscreen_exit
                              : Icons.fullscreen,
                          color: Colors.white54,
                          size: 20 * widget.scale,
                        ),
                        onPressed: widget.onFullscreen,
                        visualDensity: VisualDensity.compact,
                        padding: EdgeInsets.zero,
                      ),
                      if (widget.scale > 1.0 &&
                          widget.onEpisodesTap != null) ...[
                        SizedBox(width: 4 * widget.scale),
                        IconButton(
                          tooltip: 'Episodes',
                          icon: Icon(
                            Icons.playlist_play,
                            color: Colors.white54,
                            size: 22 * widget.scale,
                          ),
                          onPressed: widget.onEpisodesTap,
                          visualDensity: VisualDensity.compact,
                          padding: EdgeInsets.zero,
                        ),
                      ],
                      if (widget.scale > 1.0 &&
                          widget.onSettingsTap != null) ...[
                        SizedBox(width: 4 * widget.scale),
                        IconButton(
                          icon: Icon(
                            Icons.settings,
                            color: Colors.white54,
                            size: 20 * widget.scale,
                          ),
                          onPressed: widget.onSettingsTap,
                          visualDensity: VisualDensity.compact,
                          padding: EdgeInsets.zero,
                        ),
                      ],
                    ],
                  ),
                ],
              ),
            ),
          ],
        );
      },
    );
  }

  String _fmt(Duration d) {
    final m = d.inMinutes.remainder(60).toString().padLeft(2, '0');
    final s = d.inSeconds.remainder(60).toString().padLeft(2, '0');
    return '$m:$s';
  }
}
