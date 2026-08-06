// app.dart

import 'dart:async';
import 'dart:convert';
import 'dart:io' show Platform;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'config/theme.dart';
import 'models/server_config.dart';
import 'providers/server_provider.dart';
import 'providers/settings_provider.dart';
import 'screens/cast_receiver_screen.dart';
import 'screens/cast_scan_screen.dart';
import 'screens/cloud_setup_screen.dart';
import 'screens/home_screen.dart';
import 'screens/library_setup_screen.dart';
import 'screens/settings_screen.dart';
import 'services/tv_detector.dart';
import 'widgets/double_back_exit.dart';
import 'widgets/desktop_title_bar.dart';

class RcrmApp extends ConsumerStatefulWidget {
  final String? savedConfig;
  const RcrmApp({super.key, this.savedConfig});

  @override
  ConsumerState<RcrmApp> createState() => _RcrmAppState();
}

class _RcrmAppState extends ConsumerState<RcrmApp> {
  final _navigatorKey = GlobalKey<NavigatorState>();
  DeployMode? _deployMode;
  bool _isTv = false;

  @override
  void initState() {
    super.initState();
    // Load persisted UI settings (image/video layout, columns, preview,
    // thumbnail cache) once at startup — without this they always reset to
    // defaults on launch. Also mirrors the cache flag into ThumbCache.enabled.
    ref.read(uiSettingsProvider.notifier).load();
    _loadDeployMode();
    isAndroidTv().then((tv) {
      if (mounted) setState(() => _isTv = tv);
    });
  }

  Future<void> _loadDeployMode() async {
    final mode = await ref.read(settingsServiceProvider).getDeployMode();
    if (mounted) setState(() => _deployMode = mode);
  }

  List<String> get _savedDirs {
    if (widget.savedConfig == null) return const [];
    try {
      final m = jsonDecode(widget.savedConfig!) as Map<String, dynamic>;
      return List<String>.from(m['directories'] ?? []);
    } catch (_) {
      return const [];
    }
  }

  @override
  Widget build(BuildContext context) {
    final isCloud = _deployMode == DeployMode.cloud;

    return MaterialApp(
      title: 'RCrm Media Library',
      navigatorKey: _navigatorKey,
      theme: RCrmTheme.dark,
      debugShowCheckedModeBanner: false,
      builder: (context, child) {
        if (Platform.isAndroid || Platform.isIOS) return child!;
        return TitleBarShell(child: child!);
      },
      home: _deployMode == null
          ? const DoubleBackExit(
              child: Scaffold(
                body: Center(child: CircularProgressIndicator()),
              ),
            )
          : _isTv
          ? const CastReceiverScreen()
          : isCloud
          ? const CloudSetupScreen()
          : LibrarySetupScreen(initialDirs: _savedDirs),
      routes: {
        '/setup': (context) => LibrarySetupScreen(initialDirs: _savedDirs),
        '/cloud-setup': (context) => const CloudSetupScreen(),
        '/home': (context) => const HomeScreen(),
        '/settings': (context) => const SettingsScreen(),
        '/cast-scan': (context) => const CastScanScreen(),
        '/cast-receiver': (context) => const CastReceiverScreen(showBack: true),
      },
    );
  }
}
