// screens/cloud_setup_screen.dart
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../models/server_config.dart';
import '../providers/server_provider.dart';
import '../services/net.dart';

const _hintSilver = TextStyle(color: Color(0xFFAAAAAA));

class CloudSetupScreen extends ConsumerStatefulWidget {
  const CloudSetupScreen({super.key});
  @override
  ConsumerState<CloudSetupScreen> createState() => _CloudSetupScreenState();
}

class _CloudSetupScreenState extends ConsumerState<CloudSetupScreen> {
  bool _cloudHttps = true;
  final _hostCtrl = TextEditingController();
  final _portCtrl = TextEditingController();
  final _userCtrl = TextEditingController();
  final _passCtrl = TextEditingController();
  bool _isConnecting = false;
  bool _showingCertDialog = false;

  @override
  void initState() {
    super.initState();
    _loadSaved();
  }

  @override
  void dispose() {
    _hostCtrl.dispose();
    _portCtrl.dispose();
    _userCtrl.dispose();
    _passCtrl.dispose();
    super.dispose();
  }

  Future<void> _loadSaved() async {
    final s = ref.read(settingsServiceProvider);
    final c = await s.getServerConfig();
    if (!mounted) return;
    final u = c.remoteUrl;
    if (u.isNotEmpty) {
      final uri = Uri.tryParse(u);
      if (uri != null) {
        _cloudHttps = uri.scheme == 'https';
        _hostCtrl.text = uri.host;
        if (uri.hasPort) _portCtrl.text = uri.port.toString();
      }
    }
    _userCtrl.text = c.remoteUsername;
  }

  Future<void> _tryConnect() async {
    final h = _hostCtrl.text.trim();
    if (h.isEmpty) {
      _showErr('Host required');
      return;
    }
    final p = _portCtrl.text.trim();
    final s = _cloudHttps ? 'https' : 'http';
    final pp = p.isNotEmpty ? ':$p' : '';
    final url = '$s://$h$pp';
    final u = _userCtrl.text.trim();
    final pw = _passCtrl.text;
    setState(() => _isConnecting = true);
    try {
      await ref.read(settingsServiceProvider).saveCloudServerConfig(url, u);
      await ref.read(serverProvider.notifier).connectCloud(url, u, pw);
      if (!mounted) return;
      final st = ref.read(serverProvider);
      if (st.isRunning) {
        Navigator.of(context).pushReplacementNamed('/home');
        return;
      }
      if (st.error == 'BAD_CERT') {
        final info = CertTrust.lastRejected;
        if (info != null) {
          setState(() => _isConnecting = false);
          await _showCert(h, url, u, pw, info);
          return;
        }
      }
      _showErr(st.error ?? 'Connection failed');
    } finally {
      if (mounted) setState(() => _isConnecting = false);
    }
  }

  Future<void> _showCert(
    String host,
    String url,
    String user,
    String pass,
    CertInfo info,
  ) async {
    if (_showingCertDialog) return;
    _showingCertDialog = true;
    final t = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Untrusted Certificate'),
        content: SingleChildScrollView(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                'The server at $host presented a certificate that is not '
                'trusted by this device.',
              ),
              const SizedBox(height: 14),
              const Text(
                'Certificate',
                style: TextStyle(fontWeight: FontWeight.w600),
              ),
              const SizedBox(height: 4),
              Text('Subject: ${info.subject}'),
              Text('Issued by: ${info.issuer}'),
              if (info.notAfter != null)
                Text('Expires: ${_fmtDate(info.notAfter!)}'),
              const SizedBox(height: 10),
              const Text(
                'Fingerprint (SHA-1)',
                style: TextStyle(fontWeight: FontWeight.w600),
              ),
              Text(
                info.formattedSha1,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              ),
              const SizedBox(height: 14),
              Text(
                'Only this exact certificate will be trusted, and only for '
                'this session. If the server presents any other certificate, '
                'the connection will be refused.',
                style: TextStyle(
                  color: Theme.of(ctx).colorScheme.onSurfaceVariant,
                  fontSize: 12,
                ),
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('Trust & Continue'),
          ),
        ],
      ),
    );
    _showingCertDialog = false;
    if (t == true && mounted) {
      setState(() => _isConnecting = true);
      try {
        // Pin ONLY this certificate; the next connection (and every later
        // one) must present the same fingerprint or it is refused.
        CertTrust.pin(info);
        await ref
            .read(settingsServiceProvider)
            .saveCloudServerConfig(url, user);
        await ref.read(serverProvider.notifier).connectCloud(url, user, pass);
        if (!mounted) return;
        final st = ref.read(serverProvider);
        if (st.isRunning) {
          Navigator.of(context).pushReplacementNamed('/home');
        } else {
          _showErr(st.error ?? 'Connection failed');
        }
      } finally {
        if (mounted) setState(() => _isConnecting = false);
      }
    }
  }

  static String _fmtDate(DateTime d) =>
      '${d.year}-${d.month.toString().padLeft(2, '0')}-'
      '${d.day.toString().padLeft(2, '0')}';

  void _showErr(String m) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(m),
        backgroundColor: Theme.of(context).colorScheme.error,
      ),
    );
  }

  @override
  Widget build(BuildContext ctx) {
    final ss = ref.watch(serverProvider);
    final b = Theme.of(ctx).colorScheme.primary;
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(32),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 500),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Icon(Icons.cloud, size: 64, color: b),
                  const SizedBox(height: 16),
                  Text(
                    'RCrm Media Library',
                    style: Theme.of(ctx).textTheme.headlineMedium,
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'Connect to a cloud WebDAV server',
                    style: Theme.of(ctx).textTheme.bodyMedium,
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 32),
                  Container(
                    decoration: BoxDecoration(
                      color: Theme.of(ctx).colorScheme.surface,
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Padding(
                      padding: const EdgeInsets.all(16),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [
                          // Wide cards: label on the left, segmented button
                          // right-aligned (Spacer). Narrow cards: button wraps
                          // to its own line, still right-aligned.
                          LayoutBuilder(
                            builder: (context, constraints) {
                              final label = Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  const Text('Protocol'),
                                  Text(
                                    _cloudHttps
                                        ? 'Encrypted connection'
                                        : 'Unencrypted connection',
                                    style: Theme.of(context).textTheme.bodySmall
                                        ?.copyWith(fontSize: 11),
                                  ),
                                ],
                              );
                              final button = SegmentedButton<bool>(
                                segments: const [
                                  ButtonSegment(
                                    value: true,
                                    label: Text('HTTPS'),
                                  ),
                                  ButtonSegment(
                                    value: false,
                                    label: Text('HTTP'),
                                  ),
                                ],
                                selected: {_cloudHttps},
                                style: const ButtonStyle(
                                  visualDensity: VisualDensity.compact,
                                ),
                                onSelectionChanged: ss.isRunning
                                    ? null
                                    : (v) {
                                        setState(() {
                                          _cloudHttps = v.first;
                                          if (_portCtrl.text.isEmpty ||
                                              _portCtrl.text ==
                                                  (_cloudHttps
                                                      ? '80'
                                                      : '443')) {
                                            _portCtrl.text = _cloudHttps
                                                ? '443'
                                                : '80';
                                          }
                                        });
                                      },
                              );
                              // ~300px fits label + spacing + both segments at
                              // 1.3x text scale; below that the button wraps.
                              if (constraints.maxWidth >= 300) {
                                return Row(
                                  children: [label, const Spacer(), button],
                                );
                              }
                              return Column(
                                crossAxisAlignment: CrossAxisAlignment.stretch,
                                children: [
                                  label,
                                  const SizedBox(height: 8),
                                  Align(
                                    alignment: Alignment.centerRight,
                                    child: button,
                                  ),
                                ],
                              );
                            },
                          ),
                          const SizedBox(height: 16),
                          Row(
                            children: [
                              Expanded(
                                flex: 3,
                                child: TextField(
                                  controller: _hostCtrl,
                                  decoration: const InputDecoration(
                                    labelText: 'Host',
                                    hintText: 'example.com',
                                    hintStyle: _hintSilver,
                                    prefixIcon: Icon(Icons.dns),
                                  ),
                                  enabled: !_isConnecting,
                                  textInputAction: TextInputAction.next,
                                ),
                              ),
                              const SizedBox(width: 12),
                              Expanded(
                                flex: 1,
                                child: TextField(
                                  controller: _portCtrl,
                                  decoration: InputDecoration(
                                    labelText: 'Port',
                                    hintText: _cloudHttps ? '443' : '80',
                                    hintStyle: _hintSilver,
                                  ),
                                  keyboardType: TextInputType.number,
                                  enabled: !_isConnecting,
                                ),
                              ),
                            ],
                          ),
                          const SizedBox(height: 12),
                          TextField(
                            controller: _userCtrl,
                            decoration: const InputDecoration(
                              labelText: 'Username',
                              hintStyle: _hintSilver,
                              prefixIcon: Icon(Icons.person),
                            ),
                            enabled: !_isConnecting,
                            textInputAction: TextInputAction.next,
                          ),
                          const SizedBox(height: 12),
                          TextField(
                            controller: _passCtrl,
                            decoration: const InputDecoration(
                              labelText: 'Password',
                              hintStyle: _hintSilver,
                              prefixIcon: Icon(Icons.lock),
                            ),
                            obscureText: true,
                            enabled: !_isConnecting,
                            onSubmitted: (_) => _tryConnect(),
                          ),
                          const SizedBox(height: 16),
                          FilledButton.icon(
                            onPressed: _isConnecting
                                ? null
                                : () => _tryConnect(),
                            icon: _isConnecting
                                ? const SizedBox(
                                    width: 20,
                                    height: 20,
                                    child: CircularProgressIndicator(
                                      strokeWidth: 2,
                                    ),
                                  )
                                : const Icon(Icons.link),
                            label: Text(
                              _isConnecting ? 'Connecting…' : 'Connect',
                            ),
                          ),
                          const SizedBox(height: 12),
                          TextButton(
                            onPressed: _isConnecting
                                ? null
                                : () => Navigator.of(
                                    context,
                                  ).pushReplacementNamed('/home'),
                            child: const Text(
                              'Skip — browse read-only library',
                            ),
                          ),
                          const SizedBox(height: 8),
                          TextButton(
                            onPressed: _isConnecting
                                ? null
                                : () async {
                                    await ref
                                        .read(settingsServiceProvider)
                                        .setDeployMode(DeployMode.local);
                                    if (mounted) {
                                      Navigator.of(
                                        context,
                                      ).pushReplacementNamed('/setup');
                                    }
                                  },
                            child: const Text('Switch to Local Deploy'),
                          ),
                        ],
                      ),
                    ),
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
