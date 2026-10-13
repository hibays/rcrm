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
import '../services/screen_capture.dart';
import '../services/settings_service.dart';
import '../services/storage_access.dart';
import '../services/system_volume.dart';
import '../services/thumb_cache.dart';
import '../utils/thumb_cache_policy.dart';
import '../widgets/thumb_cache_dialog.dart';

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
    // Android only: the storage row follows the same notifier the setup screen
    // uses, so both update from the one read the resume observer makes when the
    // user comes back from Android's settings screen.
    StorageAccess.watch();
    StorageAccess.refresh();
    // Mobile only: the volume row's wording depends on what the device's
    // output can do (a fixed-volume sink cannot be bound, and the row says so),
    // so the reading is taken here and followed while this screen is up.
    if (SystemVolume.supported) {
      SystemVolume.watch();
      SystemVolume.read();
    }
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

  /// The cache's ONE entry point. Managing it and deleting all of it are two
  /// answers to the same question, so they are offered at the same moment, in the
  /// flow the tile opens — and each says what it does to the cache, since the
  /// difference between them is the whole reason the choice exists.
  /// The cache's ONE entry point: the grading is read first, then the choice is
  /// the user's — which tiers may be spent, or all of it — and only then does
  /// anything run. `preview()` plans without deleting, so what the dialog shows
  /// and what `manage()` carries out are the same plan.
  Future<void> _manageCache() async {
    // The dialog opens FIRST and the grading arrives into it: reading a cache
    // directory is disk work that must not hold a tap hostage — and in a widget
    // test it cannot complete at all, which is what made an awaiting version of
    // this impossible to test.
    final choice = await showDialog<ThumbCacheIntent>(
      context: context,
      builder: (_) => ThumbCacheDialog(
        plan: ThumbCache.preview(),
        initialLimitMb: ThumbCache.limitMb,
      ),
    );
    if (choice == null || !mounted) return;

    // One switch, three intents, no fields to read and guess at: `AutoTrim` and
    // `DeleteTiers` differ in the TYPE, which is where that difference belongs.
    // The chosen target is remembered (the dialog reads it back next time) and
    // applied here, to the clean-up the user just asked for — nothing runs by
    // itself.
    switch (choice) {
      case ClearAll():
        await ThumbCache.clear();
        _loadCacheSize();
        _snack('Cache cleared');
      case DeleteTiers(:final tiers):
        final done = await ThumbCache.manage(
          spend: tiers,
          dropWholeTiers: true,
        );
        _loadCacheSize();
        _snack(describeThumbCachePlan(done, formatBytes: ThumbCache.human));
      case AutoTrim(:final targetMb):
        await ref
            .read(uiSettingsProvider.notifier)
            .setThumbCacheLimitMb(targetMb);
        final done = await ThumbCache.manage(
          maxBytes: targetMb > 0 ? targetMb * 1024 * 1024 : null,
        );
        _loadCacheSize();
        _snack(describeThumbCachePlan(done, formatBytes: ThumbCache.human));
    }
  }

  void _snack(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text(message)));
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
              // Android-only, because the permission is: a desktop app reads
              // its folders with the user's own rights. The server opens those
              // directories by real path, so without this row's permission the
              // library is empty and nothing here can say why.
              if (StorageAccess.supported)
                ValueListenableBuilder<StorageAccessStatus?>(
                  valueListenable: StorageAccess.state,
                  builder: (context, status, _) => _storageAccessTile(status),
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
                ButtonSegment(value: 'none', label: Text('Ungrouped')),
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
          const SizedBox(height: 8),
          _group([
            _limitSlider(
              title: 'Jump History',
              subtitle:
                  'How many previous videos Back returns to; those videos are '
                  'also kept out of Related',
              value: ui.videoJumpHistoryLimit,
              min: kVideoJumpHistoryMin,
              max: kVideoJumpHistoryMax,
              onChanged: (v) {
                ref
                    .read(uiSettingsProvider.notifier)
                    .setVideoJumpHistoryLimit(v);
              },
            ),
            // A volume row exists only where the app may set the device's media
            // stream: on a phone that stream is what the hardware keys and every
            // other media app move, while a desktop's mixer is the user's own
            // business and its app-local slider is the expected behaviour. The
            // switch is read when a player opens (`video_player_screen.dart`), so
            // this row states a preference rather than poking a playing video.
            if (SystemVolume.supported) ...[
              const Divider(height: 1),
              _systemVolumeTile(ui.useSystemVolume),
            ],
          ]),
          // A privacy row exists only where the platform has a capture surface
          // the app can actually close: a desktop window's pixels are the OS's
          // business, and the switch would be a dead control there. What the
          // switch promises differs by platform and the subtitle says which
          // (`capturePolicyNote`) — iOS cannot refuse a still screenshot, and
          // claiming otherwise in the UI is the one thing this row must not do.
          if (ScreenCapture.supported) ...[
            const Divider(),
            _sectionHeader('Privacy'),
            const SizedBox(height: 8),
            _group([
              SwitchListTile(
                title: const Text('Allow Screenshots'),
                subtitle: Text(
                  capturePolicyNote(
                    canBlockScreenshots: ScreenCapture.canBlockScreenshots,
                  ),
                ),
                value: ui.allowScreenshots,
                onChanged: (v) {
                  ref.read(uiSettingsProvider.notifier).setAllowScreenshots(v);
                },
              ),
            ]),
          ],
          const Divider(),
          _sectionHeader('Casting'),
          const SizedBox(height: 8),
          _group([
            SwitchListTile(
              title: const Text('Cast Auto-Next'),
              subtitle: const Text(
                'When the TV goes idle (video ended or failed to start), show '
                'an up-next strip; untouched for 5s it plays the first one',
              ),
              value: ui.castAutoNext,
              onChanged: (v) {
                ref.read(uiSettingsProvider.notifier).setCastAutoNext(v);
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
            // ONE way in. What to do with the cache is a choice made INSIDE that
            // flow, not a second button beside it: managing and deleting
            // everything are two things the same person decides at the same
            // moment, and putting the drastic one on the same level as the
            // careful one made the careful one look like the exception.
            ListTile(
              leading: const Icon(Icons.sd_storage),
              title: const Text('Thumbnail cache'),
              subtitle: Text(
                _cacheBytes == null
                    ? 'Calculating…'
                    : '${ThumbCache.human(_cacheBytes!)} — managed by generation '
                          'time; the newest entries are kept',
              ),
              trailing: const Icon(Icons.chevron_right),
              onTap: _manageCache,
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

  /// The volume binding row — Settings → Display, mobile only.
  ///
  /// The subtitle follows the READING as well as the switch, because there are
  /// two ways this switch cannot keep its promise and both have to be said: an
  /// output whose volume is fixed (some TV boxes, car head units, HDMI sinks)
  /// cannot be set at all, and a device that never reported a reading is one the
  /// player will not bind to either — it keeps its own volume in both cases
  /// (`systemVolumeBindingNote`).
  Widget _systemVolumeTile(bool bound) {
    return ValueListenableBuilder<SystemVolumeReading?>(
      valueListenable: SystemVolume.state,
      builder: (_, reading, _) => SwitchListTile(
        title: const Text('System Volume'),
        subtitle: Text(
          systemVolumeBindingNote(
            bound: bound,
            readable: reading != null,
            fixedOutput: reading?.fixed ?? false,
          ),
        ),
        value: bound,
        onChanged: (v) {
          ref.read(uiSettingsProvider.notifier).setUseSystemVolume(v);
        },
      ),
    );
  }

  /// The storage row: what Android currently allows, and the one way to change
  /// it.
  ///
  /// State first, control second -- "allowed" is a fact about the device, not a
  /// switch this screen owns, so the granted row states it and offers nothing.
  /// While the status is still being read the row says so instead of
  /// disappearing, because a row that flickers out and back is worse than one
  /// honest sentence. The wording for each Android version comes from
  /// `storageAccessCopy`, the same function the setup screen's card uses -- and
  /// it is the SHORT line of it: a settings row is a row, not a card.
  ///
  /// ONE affordance: the button. A tappable row as well would be the same
  /// action twice, and the button is the half that says what will happen.
  Widget _storageAccessTile(StorageAccessStatus? status) {
    const leading = Icon(Icons.storage);
    if (status == null) {
      return const ListTile(
        leading: leading,
        title: Text('Storage Access'),
        subtitle: Text("Reading Android's storage permission..."),
      );
    }
    if (status.granted) {
      return const ListTile(
        leading: leading,
        title: Text('Storage Access'),
        subtitle: Text(
          'Allowed -- the local server can read the managed folders by path',
        ),
      );
    }
    final copy = storageAccessCopy(status);
    return ListTile(
      leading: Icon(
        Icons.folder_off,
        color: Theme.of(context).colorScheme.primary,
      ),
      title: Text(copy.title),
      subtitle: Text(copy.note),
      trailing: TextButton(
        onPressed: StorageAccess.request,
        child: Text(copy.actionLabel),
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

  /// Integer slider row, in the shape of [_seg]: on narrow cards a title with
  /// the value beside it, its subtitle under that and the slider below; on wide
  /// ones a `ListTile` with the slider and the value as its trailing control.
  ///
  /// Styled with the design system's slider tokens (docs/DESIGN.md → Sliders:
  /// Marquee Orange track and thumb, silver-transparent inactive track) — the
  /// same ones the player's seek slider uses.
  Widget _limitSlider({
    required String title,
    String? subtitle,
    required int value,
    required int min,
    required int max,
    required ValueChanged<int> onChanged,
  }) {
    final valueLabel = Text(
      '$value',
      style: Theme.of(
        context,
      ).textTheme.bodyLarge?.copyWith(color: RCrmColors.silver),
    );
    final slider = SliderTheme(
      data: SliderTheme.of(context).copyWith(
        activeTrackColor: RCrmColors.primary,
        inactiveTrackColor: RCrmColors.silverDim,
        thumbColor: RCrmColors.primary,
      ),
      child: Slider(
        value: value.toDouble(),
        min: min.toDouble(),
        max: max.toDouble(),
        // The setting is a count of entries, so the drag is snapped to whole
        // ones here. `divisions` is deliberately left null: 49 subdivisions
        // would draw 49 tick marks across the track.
        onChanged: (v) => onChanged(v.round()),
      ),
    );
    return LayoutBuilder(
      builder: (ctx, c) {
        if (c.maxWidth < 520) {
          return Padding(
            padding: const EdgeInsets.fromLTRB(16, 12, 16, 12),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Expanded(
                      child: Text(
                        title,
                        style: Theme.of(ctx).textTheme.bodyLarge,
                      ),
                    ),
                    valueLabel,
                  ],
                ),
                if (subtitle != null) ...[
                  const SizedBox(height: 2),
                  Text(
                    subtitle,
                    style: Theme.of(ctx).textTheme.bodyMedium?.copyWith(
                      color: Theme.of(ctx).colorScheme.onSurfaceVariant,
                    ),
                  ),
                ],
                const SizedBox(height: 4),
                slider,
              ],
            ),
          );
        }
        return ListTile(
          title: Text(title),
          subtitle: subtitle != null ? Text(subtitle) : null,
          trailing: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              SizedBox(width: 200, child: slider),
              const SizedBox(width: 8),
              valueLabel,
            ],
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
    final r = await FilePicker.getDirectoryPath();
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
