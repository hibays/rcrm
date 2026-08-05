// screens/settings_screen.dart
// RCrm GUI — settings screen
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:file_picker/file_picker.dart';
import '../models/server_config.dart';
import '../config/theme.dart';
import '../providers/server_provider.dart';
import '../providers/settings_provider.dart';
import '../services/net.dart';
import '../services/thumb_cache.dart';

const _hintSilver = TextStyle(color: RCrmColors.silver);

class SettingsScreen extends ConsumerStatefulWidget {
  const SettingsScreen({super.key});
  @override
  ConsumerState<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends ConsumerState<SettingsScreen> {
  int? _cacheBytes;
  DeployMode _deployMode = DeployMode.local;
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
    _loadCacheSize();
    _loadDeployMode();
  }

  @override
  void dispose() {
    _hostCtrl.dispose();
    _portCtrl.dispose();
    _userCtrl.dispose();
    _passCtrl.dispose();
    super.dispose();
  }

  Future<void> _loadCacheSize() async {
    final b = await ThumbCache.sizeBytes();
    if (mounted) setState(() => _cacheBytes = b);
  }

  Future<void> _loadDeployMode() async {
    final s = ref.read(settingsServiceProvider);
    final m = await s.getDeployMode();
    if (!mounted) return;
    setState(() => _deployMode = m);
    if (m == DeployMode.cloud) {
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
  }

  Future<void> _tryConnect() async {
    final h = _hostCtrl.text.trim();
    if (h.isEmpty) return;
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
      if (st.error == 'BAD_CERT') {
        final info = CertTrust.lastRejected;
        if (info != null) {
          setState(() => _isConnecting = false);
          await _showCert(h, url, u, pw, info);
        }
      }
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
        // Pin ONLY this certificate; every later connection must present the
        // same fingerprint or it is refused.
        CertTrust.pin(info);
        await ref
            .read(settingsServiceProvider)
            .saveCloudServerConfig(url, user);
        await ref.read(serverProvider.notifier).connectCloud(url, user, pass);
      } finally {
        if (mounted) setState(() => _isConnecting = false);
      }
    }
  }

  static String _fmtDate(DateTime d) =>
      '${d.year}-${d.month.toString().padLeft(2, '0')}-'
      '${d.day.toString().padLeft(2, '0')}';

  @override
  Widget build(BuildContext ctx) {
    final ui = ref.watch(uiSettingsProvider);
    final ss = ref.watch(serverProvider);
    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _sectionHeader('Server'),
          const SizedBox(height: 8),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: SegmentedButton<DeployMode>(
              segments: const [
                ButtonSegment(value: DeployMode.local, label: Text('Local')),
                ButtonSegment(value: DeployMode.cloud, label: Text('Cloud')),
              ],
              selected: {_deployMode},
              onSelectionChanged: (mode) async {
                setState(() => _deployMode = mode.first);
                await ref
                    .read(settingsServiceProvider)
                    .setDeployMode(mode.first);
                _loadDeployMode(); // reload cloud fields from persisted config
              },
            ),
          ),
          const SizedBox(height: 12),
          if (_deployMode == DeployMode.local) ...[
            _group([
              ListTile(
                leading: Icon(
                  Icons.circle,
                  size: 12,
                  // Running = orange (state indicator, the accent means
                  // something is happening). Stopped = neutral silver, not
                  // red — an unstarted server is a normal state, not an error.
                  color: ss.isRunning
                      ? RCrmColors.primary
                      : const Color(0xFF8A8A8A),
                ),
                title: Text(ss.isRunning ? 'Running' : 'Stopped'),
                subtitle: ss.url != null ? Text(ss.url!) : null,
                trailing: ss.isRunning
                    ? TextButton(
                        onPressed: () =>
                            ref.read(serverProvider.notifier).stop(),
                        child: const Text('Stop'),
                      )
                    : TextButton(
                        onPressed: () => Navigator.of(
                          ctx,
                        ).pushNamedAndRemoveUntil('/setup', (_) => false),
                        child: const Text('Start'),
                      ),
              ),
              if (ss.error != null)
                Padding(
                  padding: const EdgeInsets.all(12),
                  child: Text(
                    ss.error!,
                    style: TextStyle(
                      color: Theme.of(ctx).colorScheme.error,
                      fontSize: 12,
                    ),
                  ),
                ),
              ListTile(
                leading: const Icon(Icons.folder),
                title: const Text('Managed Directories'),
                trailing: const Icon(Icons.chevron_right),
                onTap: _editDirectories,
              ),
            ]),
          ] else ...[
            _group([
              // Cloud fields need breathing room — 16px horizontal padding
              // matches ListTile insets in the local branch; 12px vertical
              // keeps the card from feeling cramped.
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 12, 16, 12),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    // Label on the left, button right-aligned. On narrow cards (or
                    // large text scale) the button scales down via FittedBox instead
                    // of overflowing the card (mirrors cloud_setup_screen).
                    Row(
                      children: [
                        const Text('Protocol'),
                        const SizedBox(width: 12),
                        // Expanded (tight) makes the FittedBox fill all remaining
                        // width, so Alignment.centerRight pushes the button flush
                        // to the card edge. A loose Flexible would leave the
                        // FittedBox parked at the left of its slot instead.
                        Expanded(
                          child: FittedBox(
                            fit: BoxFit.scaleDown,
                            alignment: Alignment.centerRight,
                            child: SegmentedButton<bool>(
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
                                                (_cloudHttps ? '80' : '443')) {
                                          _portCtrl.text = _cloudHttps
                                              ? '443'
                                              : '80';
                                        }
                                      });
                                    },
                            ),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 12),
                    // Host/Port side-by-side on wide cards; stacked on narrow ones
                    // (the port field only gets ~80px otherwise and its label
                    // overflows at 1.3x text scale).
                    LayoutBuilder(
                      builder: (context, constraints) {
                        final host = TextField(
                          controller: _hostCtrl,
                          decoration: const InputDecoration(
                            labelText: 'Host',
                            hintText: 'example.com',
                            hintStyle: _hintSilver,
                            prefixIcon: Icon(Icons.dns),
                          ),
                          enabled: !ss.isRunning,
                        );
                        final port = TextField(
                          controller: _portCtrl,
                          decoration: InputDecoration(
                            labelText: 'Port',
                            hintText: _cloudHttps ? '443' : '80',
                            hintStyle: _hintSilver,
                          ),
                          keyboardType: TextInputType.number,
                          enabled: !ss.isRunning,
                        );
                        if (constraints.maxWidth >= 300) {
                          return Row(
                            children: [
                              Expanded(flex: 3, child: host),
                              const SizedBox(width: 12),
                              Expanded(flex: 1, child: port),
                            ],
                          );
                        }
                        return Column(
                          children: [host, const SizedBox(height: 12), port],
                        );
                      },
                    ),
                    const SizedBox(height: 12),
                    TextField(
                      controller: _userCtrl,
                      decoration: const InputDecoration(
                        labelText: 'Username',
                        hintStyle: _hintSilver,
                        prefixIcon: Icon(Icons.person),
                      ),
                      enabled: !ss.isRunning,
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
                      enabled: !ss.isRunning,
                    ),
                    const SizedBox(height: 16),
                    if (ss.isRunning) ...[
                      Row(
                        children: [
                          Icon(
                            Icons.check_circle,
                            color: Theme.of(ctx).colorScheme.primary,
                          ),
                          const SizedBox(width: 8),
                          Expanded(
                            child: Text(
                              'Connected to ${ss.url ?? ""}',
                              style: Theme.of(ctx).textTheme.bodyMedium,
                            ),
                          ),
                          TextButton(
                            onPressed: () =>
                                ref.read(serverProvider.notifier).stop(),
                            child: const Text('Disconnect'),
                          ),
                        ],
                      ),
                    ] else ...[
                      SizedBox(
                        width: double.infinity,
                        child: FilledButton.icon(
                          onPressed: _isConnecting ? null : () => _tryConnect(),
                          icon: _isConnecting
                              ? const SizedBox(
                                  width: 16,
                                  height: 16,
                                  child: CircularProgressIndicator(
                                    strokeWidth: 2,
                                  ),
                                )
                              : const Icon(Icons.link),
                          label: Text(
                            _isConnecting ? 'Connecting…' : 'Connect',
                          ),
                        ),
                      ),
                    ],
                    // BAD_CERT has its own untrusted-certificate dialog; don't
                    // also dump the raw marker string into the error text.
                    if (ss.error != null && ss.error != 'BAD_CERT') ...[
                      const SizedBox(height: 12),
                      Text(
                        ss.error!,
                        style: TextStyle(
                          color: Theme.of(ctx).colorScheme.error,
                          fontSize: 12,
                        ),
                      ),
                    ],
                  ],
                ),
              ),
            ]),
          ],
          const Divider(),
          _sectionHeader('Display'),
          const SizedBox(height: 8),
          _group([
            SwitchListTile(
              title: const Text('Video Hover Preview'),
              subtitle: const Text('Show preview clips on hover'),
              value: ui.previewEnabled,
              onChanged: (v) {
                ref.read(uiSettingsProvider.notifier).setPreviewEnabled(v);
              },
            ),
          ]),
          const SizedBox(height: 8),
          _group([
            _seg<String>(
              title: 'Image Grouping',
              selected: {ui.imageClassification},
              segments: const [
                ButtonSegment(value: 'folder', label: Text('Folder')),
                ButtonSegment(value: 'format', label: Text('Format')),
                ButtonSegment(value: 'none', label: Text('None')),
              ],
              onChanged: (v) {
                ref
                    .read(uiSettingsProvider.notifier)
                    .setImageClassification(v.first);
              },
            ),
          ]),
          const SizedBox(height: 8),
          _group([
            _seg<String>(
              title: 'Image Layout',
              subtitle: 'Masonry or uniform grid',
              selected: {ui.imageLayout},
              segments: const [
                ButtonSegment(value: 'masonry', label: Text('Masonry')),
                ButtonSegment(value: 'uniform', label: Text('Uniform')),
              ],
              onChanged: (v) {
                ref.read(uiSettingsProvider.notifier).setImageLayout(v.first);
              },
            ),
            const Divider(height: 1),
            _seg<String>(
              title: 'Default Video View',
              selected: {ui.videoLayout},
              segments: const [
                ButtonSegment(value: 'grid', label: Text('Grid')),
                ButtonSegment(value: 'list', label: Text('List')),
              ],
              onChanged: (v) {
                ref.read(uiSettingsProvider.notifier).setVideoLayout(v.first);
              },
            ),
          ]),
          const SizedBox(height: 8),
          _group([
            SwitchListTile(
              title: const Text('Picture-in-Picture'),
              subtitle: const Text(
                'Show a floating player when scrolling past the video',
              ),
              value: ui.pipEnabled,
              onChanged: (v) {
                ref.read(uiSettingsProvider.notifier).setPipEnabled(v);
              },
            ),
            const Divider(height: 1),
            _seg<String>(
              title: 'PiP Size',
              subtitle: 'Small compact window or full-width overlay',
              selected: {ui.pipSize},
              segments: const [
                ButtonSegment(value: 'normal', label: Text('Normal')),
                ButtonSegment(value: 'small', label: Text('Small')),
              ],
              onChanged: (v) {
                ref.read(uiSettingsProvider.notifier).setPipSize(v.first);
              },
            ),
          ]),
          const Divider(),
          _sectionHeader('Cache'),
          const SizedBox(height: 8),
          _group([
            SwitchListTile(
              title: const Text('Thumbnail Cache'),
              subtitle: const Text(
                'Cache video posters + image thumbnails on disk',
              ),
              value: ui.thumbCacheEnabled,
              onChanged: (v) async {
                await ref
                    .read(uiSettingsProvider.notifier)
                    .setThumbCacheEnabled(v);
                _loadCacheSize();
              },
            ),
            ListTile(
              leading: const Icon(Icons.sd_storage),
              title: const Text('Cache Size'),
              subtitle: Text(
                _cacheBytes == null
                    ? 'Calculating…'
                    : ThumbCache.human(_cacheBytes!),
              ),
              trailing: TextButton(
                onPressed: () async {
                  await ThumbCache.clear();
                  _loadCacheSize();
                },
                child: const Text('Clear'),
              ),
            ),
          ]),
          const Divider(),
          _sectionHeader('About'),
          const SizedBox(height: 8),
          _group([
            ListTile(
              leading: const Icon(Icons.info),
              title: const Text('RCrm Media Library'),
              subtitle: const Text('Version 1.0.0'),
            ),
          ]),
        ],
      ),
    );
  }

  /// Settings group container — flat tonal surface, no Card drop shadow.
  /// Uses [Material] (not a colored Container) so ListTile ink/ripples paint
  /// on it; a DecoratedBox in between would hide them (debug assertion).
  Widget _group(List<Widget> children) {
    return Material(
      // colorScheme.surface (#121212) — the same one layer above pitch
      // tone the home screen's album chips use. Keeps settings visually
      // continuous with the first screen instead of jumping to Char.
      color: Theme.of(context).colorScheme.surface,
      borderRadius: BorderRadius.circular(RCrmRadii.md),
      clipBehavior: Clip.antiAlias,
      child: Column(children: children),
    );
  }

  Widget _seg<T>({
    required String title,
    String? subtitle,
    required Set<T> selected,
    required List<ButtonSegment<T>> segments,
    required void Function(Set<T>) onChanged,
  }) {
    return LayoutBuilder(
      builder: (ctx, c) {
        if (c.maxWidth < 520) {
          return Padding(
            padding: const EdgeInsets.fromLTRB(16, 12, 16, 12),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(title, style: Theme.of(ctx).textTheme.bodyLarge),
                if (subtitle != null) ...[
                  const SizedBox(height: 2),
                  Text(
                    subtitle,
                    style: Theme.of(ctx).textTheme.bodyMedium?.copyWith(
                      color: Theme.of(ctx).colorScheme.onSurfaceVariant,
                    ),
                  ),
                ],
                const SizedBox(height: 10),
                Align(
                  alignment: Alignment.centerRight,
                  child: SegmentedButton<T>(
                    segments: segments,
                    selected: selected,
                    onSelectionChanged: onChanged,
                  ),
                ),
              ],
            ),
          );
        }
        return ListTile(
          title: Text(title),
          subtitle: subtitle != null ? Text(subtitle) : null,
          trailing: SegmentedButton<T>(
            segments: segments,
            selected: selected,
            onSelectionChanged: onChanged,
          ),
        );
      },
    );
  }

  Widget _sectionHeader(String t) => Padding(
    padding: const EdgeInsets.fromLTRB(16, 16, 16, 4),
    child: Text(
      t,
      style: Theme.of(context).textTheme.titleMedium?.copyWith(
        // Deeper neutral than the design-system Silver (#AAAAAA reads too
        // light for section titles). User preference: keep it dark.
        color: const Color(0xFF8A8A8A),
      ),
    ),
  );

  Future<void> _editDirectories() async {
    final s = ref.read(settingsServiceProvider);
    final c = await s.getServerConfig();
    if (!mounted) return;
    final newDirs = await showDialog<List<String>>(
      context: context,
      builder: (ctx) => _DirEditor(initialDirs: c.directories),
    );
    if (newDirs == null || !mounted) return;
    await s.saveServerConfig(c.copyWith(directories: newDirs));
    final ss = ref.read(serverProvider);
    if (ss.isRunning) {
      await ref.read(serverProvider.notifier).stop();
      if (!mounted) return;
      Navigator.of(context).pushNamedAndRemoveUntil('/setup', (_) => false);
    }
  }
}

class _DirEditor extends StatefulWidget {
  final List<String> initialDirs;
  const _DirEditor({required this.initialDirs});
  @override
  State<_DirEditor> createState() => _DirEditorState();
}

class _DirEditorState extends State<_DirEditor> {
  late List<String> _dirs;
  final _ctrl = TextEditingController();
  String? _err;

  @override
  void initState() {
    super.initState();
    _dirs = List.from(widget.initialDirs);
  }

  @override
  void dispose() {
    _ctrl.dispose();
    super.dispose();
  }

  String _display(String p) {
    var x = Uri.decodeComponent(p);
    while (x.length > 1 && x.endsWith('/')) {
      x = x.substring(0, x.length - 1);
    }
    return x.split(Platform.pathSeparator).last;
  }

  Future<void> _add() async {
    final i = _ctrl.text.trim();
    if (i.isEmpty) {
      setState(() => _err = 'Path cannot be empty');
      return;
    }
    final d = Directory(i);
    if (!await d.exists()) {
      if (mounted) setState(() => _err = 'Directory does not exist: $i');
      return;
    }
    setState(() {
      _err = null;
      if (!_dirs.contains(d.path)) _dirs.add(d.path);
      _ctrl.clear();
    });
  }

  void _remove(String p) => setState(() => _dirs.remove(p));
  Future<void> _pick() async {
    final r = await FilePicker.platform.getDirectoryPath();
    if (r != null && !_dirs.contains(r)) setState(() => _dirs.add(r));
  }

  @override
  Widget build(BuildContext ctx) => AlertDialog(
    title: const Text('Managed Directories'),
    content: SizedBox(
      width: double.maxFinite,
      child: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (_dirs.isNotEmpty) ...[
              ..._dirs.map(
                (d) => ListTile(
                  dense: true,
                  leading: const Icon(Icons.folder),
                  title: Text(_display(d)),
                  trailing: IconButton(
                    icon: const Icon(Icons.close, size: 18),
                    onPressed: () => _remove(d),
                  ),
                ),
              ),
              const Divider(),
            ],
            TextField(
              controller: _ctrl,
              decoration: InputDecoration(
                labelText: 'Add custom path',
                hintText: '/mnt/media or D:\\Media',
                hintStyle: _hintSilver,
                errorText: _err,
              ),
              onChanged: (_) {
                if (_err != null) setState(() => _err = null);
              },
              onSubmitted: (_) => _add(),
            ),
            const SizedBox(height: 8),
            Row(
              children: [
                TextButton.icon(
                  onPressed: _add,
                  icon: const Icon(Icons.add, size: 16),
                  label: const Text('Add'),
                ),
                const Spacer(),
                TextButton.icon(
                  onPressed: _pick,
                  icon: const Icon(Icons.folder_open, size: 16),
                  label: const Text('Browse'),
                ),
              ],
            ),
          ],
        ),
      ),
    ),
    actions: [
      TextButton(
        onPressed: () => Navigator.pop(context, _dirs),
        child: const Text('Save'),
      ),
    ],
  );
}
