// screens/library_setup_screen.dart
// RCrm GUI — initial library mount folder selection screen
//
// Flow (mirrors the CLI `serve` verification, one password at a time):
//   1. User selects folders to mount.
//   2. Enter ONE password and press "Unlock & Enter".
//   3. The server is asked to start with the accumulated keys. start() verifies
//      every encrypted file against the keys (single Manager):
//        - all decrypt (or no encrypted files) -> server runs -> enter app.
//        - some stay locked -> server NOT started; keep the key if it helped,
//          clear the field, and ask for another password.
//   4. Passwords are in-memory only and never persisted.
import 'dart:io' show Platform;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:file_picker/file_picker.dart';

import '../models/server_config.dart';
import '../providers/server_provider.dart';

class LibrarySetupScreen extends ConsumerStatefulWidget {
  final List<String> initialDirs;
  const LibrarySetupScreen({super.key, this.initialDirs = const []});

  @override
  ConsumerState<LibrarySetupScreen> createState() => _LibrarySetupScreenState();
}

class _LibrarySetupScreenState extends ConsumerState<LibrarySetupScreen> {
  late List<String> _selectedDirs;
  final _passwordController = TextEditingController();
  // Keys accepted so far (each unlocked some files). In-memory only, never saved.
  final List<String> _passwords = [];
  int _lockedRemaining = 0; // encrypted files still locked by the accepted set
  bool _isLoading = false;
  String _statusText = '';
  String? _error;

  @override
  void initState() {
    super.initState();
    _selectedDirs = List.from(widget.initialDirs);
    // Also try to load the latest directories from SharedPreferences
    // (they may have been updated from the settings screen).
    _loadSavedDirs();
  }

  Future<void> _loadSavedDirs() async {
    final config = await ref.read(settingsServiceProvider).getServerConfig();
    if (!mounted) return;
    if (config.directories.isNotEmpty) {
      setState(() => _selectedDirs = List.from(config.directories));
    }
  }

  @override
  void dispose() {
    _passwordController.dispose();
    super.dispose();
  }

  bool get _hasFolders => _selectedDirs.isNotEmpty;

  Future<void> _pickFolder() async {
    final result = await FilePicker.platform.getDirectoryPath();
    if (result != null && !_selectedDirs.contains(result)) {
      setState(() => _selectedDirs.add(result));
    }
  }

  /// Human-readable folder name from a path or Android SAF content:// tree URI.
  /// Dot-prefixed hidden folders (e.g. ".xxx") and URL-encoded SAF segments
  /// (%2F, %3A) used to render blank with a naive split; decode first, then
  /// take the last path/colon segment.
  String _displayName(String path) {
    var p = path;
    try {
      p = Uri.decodeComponent(p);
    } catch (_) {}
    while (p.length > 1 && (p.endsWith('/') || p.endsWith('\\'))) {
      p = p.substring(0, p.length - 1);
    }
    final name = p.split(Platform.pathSeparator).last;
    return name.isEmpty ? path : name;
  }

  /// Try to start with the accumulated keys plus the just-entered one. The
  Future<void> _connect() async {
    if (!_hasFolders || _isLoading) return;
    final entered = _passwordController.text;
    setState(() {
      _isLoading = true;
      _statusText = 'Scanning directories…';
      _error = null;
    });
    final working = [..._passwords, if (entered.isNotEmpty) entered];
    final existing = await ref.read(settingsServiceProvider).getServerConfig();
    final config = existing.copyWith(
      directories: List.from(_selectedDirs),
      bindAddress: '127.0.0.1',
      port: 0,
      passwords: working,
    );
    // Password list is in-memory only — saveServerConfig persists dirs, not it.
    setState(() => _statusText = 'Verifying files…');
    await ref.read(serverProvider.notifier).start(config);
    if (!mounted) return;
    final st = ref.read(serverProvider);

    if (st.isRunning) {
      _passwordController.clear();
      _passwords.clear();
      _lockedRemaining = 0;
      setState(() => _statusText = 'Server ready — loading library…');
      Navigator.of(context).pushReplacementNamed('/home');
      return;
    }

    if (st.status == ServerStatus.locked) {
      // Rust caches encrypted file paths — only NEW passwords are verified.
      if (_passwords.isEmpty) {
        // First attempt, no files opened at all → wrong password.
        _error = entered.isEmpty
            ? 'Encrypted folders need a password.'
            : 'Wrong password.';
      } else if (st.locked == _lockedRemaining) {
        // This key didn't unlock anything new.
        _error = 'This key didn\'t unlock any files new. Type another.';
      } else {
        _passwords.add(entered);
        _error = '${st.locked} file(s) still locked — type another password.';
      }
      _lockedRemaining = st.locked;
      _passwordController.clear(); // don't keep the plaintext around
      setState(() => _isLoading = false);
      return;
    }

    // Hard error (-1) or anything else.
    setState(() {
      _isLoading = false;
      _error = st.error ?? 'Failed to start server';
    });
  }

  Future<void> _skip() async {
    // Save dirs for next launch (so they persist without password)
    if (_selectedDirs.isNotEmpty) {
      final existing = await ref
          .read(settingsServiceProvider)
          .getServerConfig();
      await ref
          .read(settingsServiceProvider)
          .saveServerConfig(
            existing.copyWith(directories: List.from(_selectedDirs)),
          );
    }
    if (!mounted) return;
    Navigator.of(context).pushReplacementNamed('/home');
  }

  @override
  Widget build(BuildContext context) {
    final addingMore = _passwords.isNotEmpty;
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
                  Icon(
                    Icons.play_circle_fill,
                    size: 64,
                    color: Theme.of(context).colorScheme.primary,
                  ),
                  const SizedBox(height: 16),
                  Text(
                    'RCrm Media Library',
                    style: Theme.of(context).textTheme.headlineMedium,
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 8),
                  Text(
                    _hasFolders
                        ? '${_selectedDirs.length} folder(s) selected'
                        : 'Select media folders to mount',
                    style: Theme.of(context).textTheme.bodyMedium,
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 32),

                  // Folder list as tonal group (no nested Card).
                  if (_selectedDirs.isNotEmpty)
                    Container(
                      decoration: BoxDecoration(
                        color: Theme.of(context).colorScheme.surface,
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Column(
                        children: _selectedDirs
                            .map(
                              (d) => ListTile(
                                dense: true,
                                leading: const Icon(Icons.folder, size: 20),
                                title: Text(
                                  _displayName(d),
                                  maxLines: 1,
                                  overflow: TextOverflow.ellipsis,
                                ),
                                subtitle: Text(
                                  d,
                                  maxLines: 1,
                                  overflow: TextOverflow.ellipsis,
                                ),
                                trailing: IconButton(
                                  icon: const Icon(Icons.close, size: 18),
                                  onPressed: () =>
                                      setState(() => _selectedDirs.remove(d)),
                                ),
                              ),
                            )
                            .toList(),
                      ),
                    ),
                  const SizedBox(height: 8),

                  OutlinedButton.icon(
                    onPressed: _pickFolder,
                    icon: const Icon(Icons.add),
                    label: const Text('Add Folder'),
                  ),
                  const SizedBox(height: 24),

                  if (_hasFolders) ...[
                    Container(
                      decoration: BoxDecoration(
                        color: Theme.of(context).colorScheme.surface,
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Padding(
                        padding: const EdgeInsets.all(16),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.stretch,
                          children: [
                            if (addingMore)
                              Padding(
                                padding: const EdgeInsets.only(bottom: 12),
                                child: Text(
                                  '${_passwords.length} password(s) accepted'
                                  '${_lockedRemaining > 0 ? '  ·  $_lockedRemaining still locked' : ''}',
                                  style: TextStyle(
                                    color: Theme.of(
                                      context,
                                    ).colorScheme.primary,
                                    fontSize: 13,
                                  ),
                                  textAlign: TextAlign.center,
                                ),
                              ),
                            TextField(
                              controller: _passwordController,
                              obscureText: true,
                              autofocus: _hasFolders,
                              onSubmitted: (_) => _connect(),
                              decoration: InputDecoration(
                                labelText: addingMore
                                    ? 'Next Decryption Password'
                                    : 'Decryption Password',
                                hintText: 'Leave empty for plaintext folders',
                                hintStyle: const TextStyle(color: Colors.grey),
                                border: const OutlineInputBorder(),
                                prefixIcon: const Icon(Icons.lock),
                              ),
                            ),
                            const SizedBox(height: 16),
                            FilledButton.icon(
                              onPressed: _isLoading ? null : _connect,
                              icon: _isLoading
                                  ? const SizedBox(
                                      width: 20,
                                      height: 20,
                                      child: CircularProgressIndicator(
                                        strokeWidth: 2,
                                      ),
                                    )
                                  : Icon(
                                      addingMore ? Icons.key : Icons.play_arrow,
                                    ),
                              label: Text(
                                _isLoading
                                    ? _statusText
                                    : (addingMore
                                          ? 'Add Password'
                                          : 'Unlock & Enter'),
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                    const SizedBox(height: 16),
                    if (_error != null)
                      Container(
                        padding: const EdgeInsets.all(12),
                        decoration: BoxDecoration(
                          color: Theme.of(
                            context,
                          ).colorScheme.error.withValues(alpha: 0.1),
                          borderRadius: BorderRadius.circular(8),
                        ),
                        child: Text(
                          _error!,
                          style: TextStyle(
                            color: Theme.of(context).colorScheme.error,
                            fontSize: 13,
                          ),
                        ),
                      ),
                  ],

                  if (_hasFolders) const SizedBox(height: 12),

                  if (!_hasFolders)
                    TextButton(
                      onPressed: _isLoading ? null : _skip,
                      child: const Text('Skip — mount later manually'),
                    ),
                  const SizedBox(height: 8),
                  TextButton.icon(
                    onPressed: () async {
                      final nav = Navigator.of(context);
                      await ref
                          .read(settingsServiceProvider)
                          .setDeployMode(DeployMode.cloud);
                      if (!mounted) return;
                      nav.pushReplacementNamed('/cloud-setup');
                    },
                    icon: const Icon(Icons.cloud, size: 16),
                    label: const Text('Switch to Cloud Deploy'),
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
