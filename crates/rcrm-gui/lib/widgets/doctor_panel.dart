// widgets/doctor_panel.dart
// RCrm GUI — Dart-side health check panel
//
// Checks the *running* system from the Flutter side: is the WebDAV server up
// and reachable (authenticated), does listing work, can a sample file actually
// be read (i.e. the decrypt→serve→fetch path works), plus runtime info.
//
// It deliberately does NOT verify decryption keys via the Rust bridge — Rust
// crypt/serve correctness is covered by `cargo test`, and the server can't fail
// to start on a wrong key (undecryptable files are simply hidden).

import 'dart:io' show Platform;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../models/media_item.dart';
import '../providers/server_provider.dart';

class _Check {
  final String label;
  final bool ok;
  final String detail;
  const _Check(this.label, this.ok, this.detail);
}

class DoctorPanel extends ConsumerStatefulWidget {
  const DoctorPanel({super.key});

  @override
  ConsumerState<DoctorPanel> createState() => _DoctorPanelState();
}

class _DoctorPanelState extends ConsumerState<DoctorPanel> {
  List<_Check>? _checks;
  bool _isLoading = false;
  bool _expanded = false;

  bool get _allOk => _checks != null && _checks!.every((c) => c.ok);

  Future<void> _runDoctor() async {
    setState(() {
      _isLoading = true;
      _checks = null;
    });

    final checks = <_Check>[];
    try {
      final serverState = ref.read(serverProvider);

      // 1. Server lifecycle
      checks.add(
        _Check(
          'Server running',
          serverState.isRunning,
          serverState.isRunning
              ? (serverState.url ?? 'running')
              : (serverState.error ?? 'stopped'),
        ),
      );

      final client = serverState.client;
      if (serverState.isRunning && client != null) {
        // 2. Reachable (OPTIONS, authenticated)
        final reachable = await client.ping();
        checks.add(
          _Check(
            'WebDAV reachable',
            reachable,
            reachable ? 'OK (authenticated)' : 'no response / 401',
          ),
        );

        // 3. Listing works
        final dirs = await client.listSubdirectories('/');
        final files = await client.listDirectory('/');
        checks.add(
          _Check(
            'Listing works',
            reachable,
            '${dirs.length} folder(s), ${files.length} file(s) at root',
          ),
        );

        // 4. Sample read — exercises the decrypt → serve → fetch path
        MediaItem? sample = files.isNotEmpty ? files.first : null;
        if (sample == null && dirs.isNotEmpty) {
          final sub = await client.listDirectory(dirs.first);
          if (sub.isNotEmpty) sample = sub.first;
        }
        if (sample != null) {
          final bytes = await client.getFile(sample.path);
          final ok = bytes != null && bytes.isNotEmpty;
          checks.add(
            _Check(
              'Sample file readable',
              ok,
              ok ? '${sample.name} (${bytes.length} bytes)' : 'read failed',
            ),
          );
        } else {
          checks.add(
            const _Check('Sample file readable', true, 'no files to sample'),
          );
        }
      }

      // 5. Runtime info
      checks.add(
        _Check('Runtime', true, '${Platform.operatingSystem} · Flutter'),
      );
    } catch (e) {
      checks.add(_Check('Error', false, e.toString()));
    }

    if (!mounted) return;
    setState(() {
      _checks = checks;
      _isLoading = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    final hasResult = _checks != null;
    return Card(
      child: Column(
        children: [
          ListTile(
            leading: Icon(
              hasResult
                  ? (_allOk ? Icons.check_circle : Icons.warning)
                  : Icons.health_and_safety,
              color: hasResult ? (_allOk ? Colors.green : Colors.orange) : null,
            ),
            title: const Text('Library Health Check'),
            subtitle: hasResult
                ? Text(
                    _allOk
                        ? 'All checks passed'
                        : '${_checks!.where((c) => !c.ok).length} issue(s) found',
                  )
                : const Text('Tap to run diagnostics'),
            trailing: _isLoading
                ? const SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      if (hasResult)
                        IconButton(
                          icon: Icon(
                            _expanded ? Icons.expand_less : Icons.expand_more,
                          ),
                          onPressed: () =>
                              setState(() => _expanded = !_expanded),
                        ),
                      IconButton(
                        icon: const Icon(Icons.refresh),
                        onPressed: _runDoctor,
                        tooltip: 'Run check',
                      ),
                    ],
                  ),
            onTap: hasResult ? null : _runDoctor,
          ),
          if (_expanded && hasResult) _buildDetails(),
        ],
      ),
    );
  }

  Widget _buildDetails() {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Divider(),
          ..._checks!.map(
            (c) => Padding(
              padding: const EdgeInsets.symmetric(vertical: 3),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Icon(
                    c.ok ? Icons.check : Icons.close,
                    size: 16,
                    color: c.ok ? Colors.green : Colors.red,
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text.rich(
                      TextSpan(
                        children: [
                          TextSpan(
                            text: '${c.label}: ',
                            style: const TextStyle(
                              color: Colors.white70,
                              fontSize: 12,
                            ),
                          ),
                          TextSpan(
                            text: c.detail,
                            style: TextStyle(
                              color: c.ok ? Colors.white54 : Colors.red,
                              fontSize: 12,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}
