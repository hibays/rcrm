// screens/cast_scan_screen.dart
// Phone-side pairing screen: scans the TV's QR code, pins the TV certificate
// (fingerprint from the QR payload), exchanges the one-time pair token for a
// session, and hands the server credentials + server certificate fingerprint
// to the TV. On success it navigates to the remote control screen.
//
// Scanning is self-built: on Android/iOS the `camera` package's live frame
// stream (yuv420 — the Y plane is luma, fed straight to rxing, zero
// conversion) provides continuous decoding like mobile_scanner did. Windows
// has no frame stream in camera_windows, so it polls takePicture JPEG stills
// at 100 ms at maximum resolution. All decoding runs in the Rust bridge
// (zune-jpeg / rxing — pure Rust, no native barcode API).

import 'dart:async';
import 'dart:io';

import 'package:camera/camera.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../ffi/rust_bridge.dart';
import '../providers/server_provider.dart';
import '../services/cast_protocol.dart';
import '../services/cast_remote.dart';
import '../services/cast_session_store.dart';
import '../services/net.dart';
import 'cast_remote_screen.dart';

class CastScanScreen extends ConsumerStatefulWidget {
  const CastScanScreen({super.key});

  @override
  ConsumerState<CastScanScreen> createState() => _State();
}

class _State extends ConsumerState<CastScanScreen> with WidgetsBindingObserver {
  CameraController? _camera;
  bool _cameraReady = false;

  /// True while `_initCamera` is awaiting `availableCameras()`/`initialize()`
  /// so the resumed callback (the permission dialog drops the app to
  /// `inactive`) cannot start a second initialization in flight.
  bool _initializing = false;

  /// True while the app is truly backgrounded (paused/hidden). A camera
  /// initialized after that point is disposed immediately instead of
  /// replacing the released one.
  bool _backgrounded = false;

  /// Camera error codes: `CameraAccessDenied` / `CameraAccessDeniedWithoutPrompt`
  /// (Android) and `CameraAccessDenied` (iOS) all mean permission was refused.
  bool _permissionDenied = false;
  String? _cameraError;

  /// Set while a capture+decode round is in flight, so overlapping polls
  /// (slow takePicture on Windows) never pile up, and so frame-stream
  /// callbacks arriving faster than a decode finishes are dropped.
  bool _capturing = false;
  bool _busy = false;
  String? _error;
  String? _notice;
  Timer? _noticeTimer;
  Timer? _scanTimer;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    // Bumped to re-attach the camera so it re-requests permission after a
    // denial.
    _initCamera();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _noticeTimer?.cancel();
    _scanTimer?.cancel();
    _camera?.dispose();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      _backgrounded = false;
      if (!_cameraReady) _initCamera();
    } else if (state == AppLifecycleState.paused ||
        state == AppLifecycleState.hidden) {
      // Release the camera only when truly backgrounded. `inactive` fires
      // on Windows focus loss, the Android notification shade, and iOS
      // in-app permission dialogs — the capture session must survive those.
      _backgrounded = true;
      _scanTimer?.cancel();
      _scanTimer = null;
      final cam = _camera;
      _camera = null;
      _cameraReady = false;
      cam?.dispose();
    }
  }

  Future<void> _initCamera() async {
    // Guard against duplicate in-flight initializations (initState + resume):
    // `_camera != null` only covers COMPLETED inits — the permission dialog
    // drops the app to `inactive`, and the resumed callback can fire while
    // the first initialize() is still waiting on it.
    if (_camera != null || _initializing) return;
    _initializing = true;
    setState(() {
      _permissionDenied = false;
      _cameraError = null;
    });
    try {
      final cameras = await availableCameras();
      if (!mounted || cameras.isEmpty) {
        if (mounted) {
          setState(() => _cameraError = 'No camera found on this device');
        }
        return;
      }
      // Prefer the back camera (what the user expects for scanning); fall
      // back to any camera (webcams have no lens direction).
      var description = cameras.firstWhere(
        (c) => c.lensDirection == CameraLensDirection.back,
        orElse: () => cameras.first,
      );
      // Windows webcams report an unknown/front direction — accept any.
      if (description.lensDirection == CameraLensDirection.external) {
        description = cameras.first;
      }
      final isDesktop =
          Platform.isWindows || Platform.isLinux || Platform.isMacOS;
      // Mobile: max frame rate via the yuv420 frame stream (the Y plane is
      // luma — fed straight to rxing, zero conversion, no JPEG round-trip).
      // Desktop: camera_windows has no frame stream — poll takePicture at a
      // high rate with the camera's maximum resolution (a low preset is why
      // a QR had to be shoved right against the lens to decode).
      final controller = CameraController(
        description,
        isDesktop ? ResolutionPreset.max : ResolutionPreset.high,
        enableAudio: false,
        imageFormatGroup: isDesktop
            ? ImageFormatGroup.jpeg
            : ImageFormatGroup.yuv420,
      );
      await controller.initialize();
      // The app may have gone to the background while we were waiting (e.g.
      // the permission dialog was dismissed into the task switcher): don't
      // keep a live camera stream nobody is looking at.
      if (!mounted || _backgrounded) {
        await controller.dispose();
        return;
      }
      setState(() {
        _camera = controller;
        _cameraReady = true;
        _cameraError = null;
      });
      if (isDesktop) {
        _startScanLoop();
      } else {
        try {
          await controller.startImageStream(_onStreamFrame);
        } catch (e) {
          if (!mounted) return;
          setState(() {
            _cameraError = 'Frame stream unavailable: $e';
          });
        }
      }
    } on CameraException catch (e) {
      if (!mounted) return;
      final denied =
          e.code == 'CameraAccessDenied' ||
          e.code == 'CameraAccessDeniedWithoutPrompt';
      setState(() {
        _permissionDenied = denied;
        _cameraError = denied
            ? 'Camera permission denied'
            : 'Camera unavailable: ${e.description ?? e.code}';
      });
    } catch (e) {
      if (!mounted) return;
      setState(() => _cameraError = 'Camera unavailable: $e');
    } finally {
      _initializing = false;
    }
  }

  /// Poll the camera at 100 ms on desktop (camera_windows has no frame
  /// stream). Each tick takes a JPEG still and decodes it in Rust.
  void _startScanLoop() {
    _scanTimer?.cancel();
    _scanTimer = Timer.periodic(const Duration(milliseconds: 100), (_) {
      if (!mounted || _busy || _capturing || !_cameraReady) return;
      _captureAndDecode();
    });
  }

  /// Frame-stream callback (Android/iOS): decode every frame that arrives
  /// while the previous decode has already finished. yuv420's Y plane is
  /// luma already, so no format conversion happens at all.
  Future<void> _onStreamFrame(CameraImage image) async {
    if (!mounted || _busy || _capturing) return;
    _capturing = true;
    try {
      String? raw;
      final plane = image.planes.first;
      if (image.format.group == ImageFormatGroup.yuv420 ||
          image.format.group == ImageFormatGroup.nv21) {
        // Y plane: greyscale, one byte per pixel, possibly padded rows.
        raw = RustBridge().decodeQrFromLuma(
          plane.bytes,
          image.width,
          image.height,
          plane.bytesPerRow,
        );
      } else if (image.format.group == ImageFormatGroup.bgra8888) {
        raw = RustBridge().decodeQrFromBgra(
          plane.bytes,
          image.width,
          image.height,
          plane.bytesPerRow,
        );
      } else if (image.format.group == ImageFormatGroup.jpeg) {
        raw = RustBridge().decodeQrFromJpeg(plane.bytes);
      }
      if (raw == null) return;
      await _onRawQr(raw);
    } catch (e) {
      // Transient frame errors (format mismatch, buffer reuse) are expected
      // in a live stream; skip the frame.
    } finally {
      _capturing = false;
    }
  }

  Future<void> _captureAndDecode() async {
    final cam = _camera;
    if (cam == null || !cam.value.isInitialized) return;
    _capturing = true;
    try {
      final file = await cam.takePicture();
      final bytes = await file.readAsBytes();
      // camera_windows writes stills into the user's Pictures folder —
      // delete each one after decoding so scanning does not litter it.
      try {
        final f = File(file.path);
        if (await f.exists()) await f.delete();
      } catch (_) {
        // Non-fatal: deletion failures must not break the scan loop.
      }
      final raw = RustBridge().decodeQrFromJpeg(bytes);
      if (raw == null) return;
      await _onRawQr(raw);
    } catch (e) {
      // Transient capture errors (camera busy, resolution change) are
      // expected in a poll loop; skip this frame silently.
    } finally {
      _capturing = false;
    }
  }

  Future<void> _onRawQr(String raw) async {
    if (_busy) return;
    final qr = CastQrPayload.tryDecode(raw);
    if (qr == null) {
      _flashNotice('No RCrm code detected - point at the TV');
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final serverState = ref.read(serverProvider);
      if (!serverState.isRunning) {
        throw const CastException('Connect to a server first');
      }
      var url = serverState.url;
      if (url == null) {
        throw const CastException('Server address unavailable');
      }
      // Loopback-only local server: the TV cannot reach it, so the phone
      // starts a TLS relay on 0.0.0.0 and hands the TV its address + cert
      // fingerprint instead. The relay forwards to the loopback server with
      // its Basic credentials.
      final firstHost = Uri.tryParse(url)?.host ?? '';
      final loopbackOnly =
          firstHost == '127.0.0.1' ||
          firstHost == 'localhost' ||
          firstHost == '::1';
      var sha1 = '';
      if (loopbackOnly) {
        final relay = ref.read(castHttpsRelayProvider);
        final client = serverState.client;
        if (client == null) {
          throw const CastException('Server client unavailable');
        }
        final relayUrl = await _routableServerUrl(url);
        if (relayUrl == url) {
          // No LAN IPv4 found: the TV would not be able to reach the phone.
          throw const CastException('No phone LAN address found - cannot cast');
        }
        await relay.start(
          targetBase: url,
          username: client.username ?? '',
          password: client.password ?? '',
        );
        // The TV dials the relay: https://<phone LAN IP>:<relay TLS port>.
        url = 'https://${Uri.parse(relayUrl).host}:${relay.port}';
        sha1 = relay.certSha1;
      }
      final parsed = Uri.tryParse(url);
      if (parsed == null ||
          (parsed.scheme != 'http' && parsed.scheme != 'https')) {
        throw const CastException('Server address must be http:// or https://');
      }
      final isHttps = parsed.scheme == 'https';
      if (isHttps && sha1.isEmpty) {
        final s = CertTrust.lastAcceptedSha1;
        if (s == null) {
          throw const CastException(
            'No server cert fingerprint - reconnect the server, then rescan',
          );
        }
        sha1 = s;
      }
      // Local servers often advertise 0.0.0.0/127.0.0.1 (bound for the phone
      // itself). The TV cannot reach those; rewrite to a routable LAN address.
      final serverUrl = await _routableServerUrl(url);
      final client = ref.read(serverProvider).client;
      if (client == null) {
        throw const CastException('Server client unavailable');
      }
      final remote = CastRemote(qr: qr);
      await remote.pair();
      await remote.claim(
        serverUrl: serverUrl,
        username: client.username ?? '',
        password: client.password ?? '',
        serverSha1: sha1,
      );
      final session = remote.sessionToken;
      if (session != null) {
        await CastSessionStore().save(qr: qr, session: session);
      }
      if (!mounted) return;
      Navigator.of(context).pushReplacement(
        MaterialPageRoute<void>(
          builder: (_) => CastRemoteScreen(remote: remote),
        ),
      );
    } on CastException catch (e) {
      // A relay may have been started for a loopback server before pair
      // failed; stop it so it does not leak an open TLS port.
      await ref.read(castHttpsRelayProvider).stop();
      if (!mounted) return;
      setState(() {
        _busy = false;
        _error = e.message;
      });
    } catch (e) {
      await ref.read(castHttpsRelayProvider).stop();
      if (!mounted) return;
      setState(() {
        _busy = false;
        _error = 'Pairing failed: $e';
      });
    }
  }

  /// Transient info banner (e.g. "not an RCrm QR"), auto-clears.
  void _flashNotice(String msg) {
    _noticeTimer?.cancel();
    setState(() => _notice = msg);
    _noticeTimer = Timer(const Duration(seconds: 2), () {
      if (mounted) setState(() => _notice = null);
    });
  }

  /// Rewrite loopback/unspecified hosts in [url] to the phone's first
  /// routable LAN IPv4, so the TV proxy can reach a self-hosted server.
  /// Non-loopback hosts (cloud, LAN IP) pass through untouched.
  Future<String> _routableServerUrl(String url) async {
    final uri = Uri.tryParse(url);
    if (uri == null) return url;
    final host = uri.host;
    final isLoopback =
        host == '127.0.0.1' ||
        host == 'localhost' ||
        host == '::1' ||
        host == '0.0.0.0' ||
        host == '::';
    if (!isLoopback) return url;
    final lan = await _firstLanIpv4();
    if (lan == null) return url;
    return uri.replace(host: lan).toString();
  }

  /// Best-first LAN IPv4 (192.168.x → 10.x → 172.16-31 → other), or null.
  static Future<String?> _firstLanIpv4() async {
    final found = <String>{};
    try {
      final ifaces = await NetworkInterface.list(
        type: InternetAddressType.IPv4,
        includeLoopback: false,
      );
      for (final iface in ifaces) {
        for (final addr in iface.addresses) {
          if (!addr.isLoopback && !addr.isLinkLocal) {
            found.add(addr.address);
          }
        }
      }
    } catch (_) {}
    if (found.isEmpty) return null;
    int priority(String ip) {
      final parts = ip.split('.');
      if (parts.length != 4) return 4;
      final a = int.tryParse(parts[0]) ?? -1;
      final b = int.tryParse(parts[1]) ?? -1;
      if (a == 192 && b == 168) return 0;
      if (a == 10) return 1;
      if (a == 172 && b >= 16 && b <= 31) return 2;
      return 3;
    }

    final list = found.toList()
      ..sort((a, b) => priority(a).compareTo(priority(b)));
    return list.first;
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      appBar: AppBar(title: const Text('Scan the QR on the TV')),
      body: Stack(
        children: [
          Column(
            children: [
              Expanded(
                child: Stack(
                  children: [
                    _buildCameraArea(theme),
                    // Top banners: pairing error (persistent, dismissible)
                    // and transient scan notices.
                    Positioned(
                      top: 0,
                      left: 0,
                      right: 0,
                      child: _buildBanner(theme),
                    ),
                  ],
                ),
              ),
              Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  children: [
                    Text(
                      _busy ? 'Pairing...' : 'Point at the QR on the TV',
                      style: const TextStyle(fontSize: 16),
                    ),
                  ],
                ),
              ),
            ],
          ),
          // Blocking overlay while pairing: covers the whole screen so the
          // user knows the operation is in flight and cannot re-trigger.
          if (_busy)
            Positioned.fill(
              child: AbsorbPointer(
                child: ColoredBox(
                  color: Colors.black.withValues(alpha: 0.65),
                  child: Center(
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        const CircularProgressIndicator(),
                        const SizedBox(height: 20),
                        Text(
                          'Pairing with TV...',
                          style: theme.textTheme.titleMedium?.copyWith(
                            color: Colors.white,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                        const SizedBox(height: 6),
                        Text(
                          'Verifying certificate and handing over server credentials...',
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: Colors.white.withValues(alpha: 0.7),
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ),
            ),
        ],
      ),
    );
  }

  /// Live camera preview, or a clear explainer when the camera is missing or
  /// permission was denied (with a retry button that re-requests it).
  Widget _buildCameraArea(ThemeData theme) {
    if (_cameraError != null) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(
                _permissionDenied ? Icons.no_photography : Icons.videocam_off,
                size: 56,
                color: theme.colorScheme.error,
              ),
              const SizedBox(height: 16),
              Text(
                _permissionDenied
                    ? 'Camera permission needed to scan'
                    : 'Camera unavailable',
                style: theme.textTheme.titleMedium,
              ),
              const SizedBox(height: 8),
              Text(
                _permissionDenied
                    ? 'Allow camera access in the prompt. If denied before,'
                          'enable it in system settings and retry.'
                    : _cameraError!,
                textAlign: TextAlign.center,
                style: theme.textTheme.bodyMedium?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
              const SizedBox(height: 16),
              FilledButton.icon(
                onPressed: () {
                  // Re-attach a fresh camera so the permission prompt is
                  // requested again.
                  setState(() {
                    _camera?.dispose();
                    _camera = null;
                    _cameraReady = false;
                  });
                  _initCamera();
                },
                icon: const Icon(Icons.refresh),
                label: const Text('Request permission'),
              ),
            ],
          ),
        ),
      );
    }
    if (!_cameraReady) {
      return const Center(child: CircularProgressIndicator());
    }
    return CameraPreview(_camera!);
  }

  /// Red error banner (persistent until dismissed) or transient yellow
  /// notice for non-RCrm scans.
  Widget _buildBanner(ThemeData theme) {
    final Widget content;
    if (_error != null) {
      content = Container(
        margin: const EdgeInsets.fromLTRB(12, 12, 12, 0),
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        decoration: BoxDecoration(
          color: theme.colorScheme.errorContainer,
          borderRadius: BorderRadius.circular(12),
        ),
        child: Row(
          children: [
            Icon(
              Icons.error_outline,
              size: 20,
              color: theme.colorScheme.onErrorContainer,
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                _error!,
                style: TextStyle(
                  color: theme.colorScheme.onErrorContainer,
                  fontWeight: FontWeight.w500,
                ),
              ),
            ),
            IconButton(
              tooltip: 'Close',
              icon: Icon(
                Icons.close,
                size: 18,
                color: theme.colorScheme.onErrorContainer,
              ),
              visualDensity: VisualDensity.compact,
              onPressed: () => setState(() => _error = null),
            ),
          ],
        ),
      );
    } else if (_notice != null) {
      content = Container(
        margin: const EdgeInsets.fromLTRB(12, 12, 12, 0),
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        decoration: BoxDecoration(
          color: const Color(0xFFFFF3CD),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: const Color(0xFFE6C463)),
        ),
        child: Row(
          children: [
            const Icon(Icons.info_outline, size: 20, color: Color(0xFF8A6D1A)),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                _notice!,
                style: const TextStyle(
                  color: Color(0xFF8A6D1A),
                  fontWeight: FontWeight.w500,
                ),
              ),
            ),
          ],
        ),
      );
    } else {
      return const SizedBox.shrink();
    }
    return SafeArea(
      bottom: false,
      child: Align(alignment: Alignment.topCenter, child: content),
    );
  }
}
