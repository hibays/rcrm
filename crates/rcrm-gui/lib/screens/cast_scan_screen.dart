// screens/cast_scan_screen.dart
// Phone-side pairing screen: scans the TV's QR code, pins the TV certificate
// (fingerprint from the QR payload), exchanges the one-time pair token for a
// session, and hands the server credentials + server certificate fingerprint
// to the TV. On success it navigates to the remote control screen.

import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

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

class _State extends ConsumerState<CastScanScreen> {
  bool _busy = false;
  String? _error;
  String? _notice;
  Timer? _noticeTimer;

  /// Bumped to re-attach [MobileScanner] so it re-requests camera
  /// permission after a denial.
  Key _scannerKey = const ValueKey('scanner-v1');

  @override
  void dispose() {
    _noticeTimer?.cancel();
    super.dispose();
  }

  /// Transient info banner (e.g. "not an RCrm QR"), auto-clears.
  void _flashNotice(String msg) {
    _noticeTimer?.cancel();
    setState(() => _notice = msg);
    _noticeTimer = Timer(const Duration(seconds: 2), () {
      if (mounted) setState(() => _notice = null);
    });
  }

  Future<void> _onDetect(BarcodeCapture capture) async {
    if (_busy) return;
    final raw = capture.barcodes.firstOrNull?.rawValue;
    if (raw == null) return;
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
                    MobileScanner(
                      key: _scannerKey,
                      onDetect: _onDetect,
                      errorBuilder: (context, error) {
                        // Camera permission denied or not yet granted: show a
                        // clear explainer with a retry instead of a bare line.
                        if (error.errorCode ==
                            MobileScannerErrorCode.permissionDenied) {
                          return Center(
                            child: Padding(
                              padding: const EdgeInsets.all(32),
                              child: Column(
                                mainAxisSize: MainAxisSize.min,
                                children: [
                                  Icon(
                                    Icons.no_photography,
                                    size: 56,
                                    color: theme.colorScheme.error,
                                  ),
                                  const SizedBox(height: 16),
                                  Text(
                                    'Camera permission needed to scan',
                                    style: theme.textTheme.titleMedium,
                                  ),
                                  const SizedBox(height: 8),
                                  Text(
                                    'Allow camera access in the prompt. If denied before,'
                                    'enable it in system settings and retry.',
                                    textAlign: TextAlign.center,
                                    style: theme.textTheme.bodyMedium?.copyWith(
                                      color: theme.colorScheme.onSurfaceVariant,
                                    ),
                                  ),
                                  const SizedBox(height: 16),
                                  FilledButton.icon(
                                    onPressed: () {
                                      // Re-attach a fresh scanner so
                                      // mobile_scanner re-requests the camera
                                      // permission.
                                      setState(() => _scannerKey = UniqueKey());
                                    },
                                    icon: const Icon(Icons.refresh),
                                    label: const Text('Request permission'),
                                  ),
                                ],
                              ),
                            ),
                          );
                        }
                        return Center(
                          child: Text('Camera unavailable: $error'),
                        );
                      },
                    ),
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
