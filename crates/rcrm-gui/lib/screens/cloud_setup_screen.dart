// screens/cloud_setup_screen.dart
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../models/server_config.dart';
import '../providers/server_provider.dart';

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

  Future<void> _tryConnect({required bool allowBadCert}) async {
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
      if (!allowBadCert) {
        await ref.read(settingsServiceProvider).saveCloudServerConfig(url, u);
      }
      await ref
          .read(serverProvider.notifier)
          .connectCloud(url, u, pw, allowBadCert: allowBadCert);
      if (!mounted) return;
      final st = ref.read(serverProvider);
      if (st.isRunning) {
        Navigator.of(context).pushReplacementNamed('/home');
        return;
      }
      if (st.error == 'BAD_CERT' && !allowBadCert) {
        setState(() => _isConnecting = false);
        await _showCert(h, url, u, pw);
        return;
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
  ) async {
    if (_showingCertDialog) return;
    _showingCertDialog = true;
    final t = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Untrusted Certificate'),
        content: Text(
          'The server at $host uses a self-signed certificate. Trust and continue?',
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
        await ref
            .read(settingsServiceProvider)
            .saveCloudServerConfig(url, user);
        await ref
            .read(serverProvider.notifier)
            .connectCloud(url, user, pass, allowBadCert: true);
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
                  Row(
                    children: [
                      const Text('Protocol'),
                      const Spacer(),
                      SegmentedButton<bool>(
                        segments: const [
                          ButtonSegment(value: true, label: Text('HTTPS')),
                          ButtonSegment(value: false, label: Text('HTTP')),
                        ],
                        selected: {_cloudHttps},
                        onSelectionChanged: ss.isRunning
                            ? null
                            : (v) {
                                setState(() {
                                  _cloudHttps = v.first;
                                  if (_portCtrl.text.isEmpty ||
                                      _portCtrl.text ==
                                          (_cloudHttps ? '80' : '443')) {
                                    _portCtrl.text = _cloudHttps ? '443' : '80';
                                  }
                                });
                              },
                      ),
                    ],
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
                  const SizedBox(height: 16),
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
                  const SizedBox(height: 16),
                  TextField(
                    controller: _passCtrl,
                    decoration: const InputDecoration(
                      labelText: 'Password',
                      hintStyle: _hintSilver,
                      prefixIcon: Icon(Icons.lock),
                    ),
                    obscureText: true,
                    enabled: !_isConnecting,
                    onSubmitted: (_) => _tryConnect(allowBadCert: false),
                  ),
                  const SizedBox(height: 24),
                  FilledButton.icon(
                    onPressed: _isConnecting
                        ? null
                        : () => _tryConnect(allowBadCert: false),
                    icon: _isConnecting
                        ? const SizedBox(
                            width: 20,
                            height: 20,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : const Icon(Icons.link),
                    label: Text(_isConnecting ? 'Connecting…' : 'Connect'),
                  ),
                  const SizedBox(height: 12),
                  TextButton(
                    onPressed: _isConnecting
                        ? null
                        : () => Navigator.of(
                            context,
                          ).pushReplacementNamed('/home'),
                    child: const Text('Skip — browse read-only library'),
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
        ),
      ),
    );
  }
}
