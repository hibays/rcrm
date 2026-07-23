// app.dart

import 'dart:convert';
import 'dart:io' show Platform;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'models/server_config.dart';
import 'providers/server_provider.dart';
import 'providers/settings_provider.dart';
import 'screens/cloud_setup_screen.dart';
import 'screens/home_screen.dart';
import 'screens/library_setup_screen.dart';
import 'screens/settings_screen.dart';
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

  @override
  void initState() {
    super.initState();
    // Load persisted UI settings (image/video layout, columns, preview,
    // thumbnail cache) once at startup — without this they always reset to
    // defaults on launch. Also mirrors the cache flag into ThumbCache.enabled.
    ref.read(uiSettingsProvider.notifier).load();
    _loadDeployMode();
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
      theme: _buildTheme(),
      debugShowCheckedModeBanner: false,
      builder: (context, child) {
        if (Platform.isAndroid || Platform.isIOS) return child!;
        return TitleBarShell(child: child!);
      },
      home: _deployMode == null
          ? const Scaffold(body: Center(child: CircularProgressIndicator()))
          : isCloud
          ? const CloudSetupScreen()
          : LibrarySetupScreen(initialDirs: _savedDirs),
      routes: {
        '/setup': (context) => LibrarySetupScreen(initialDirs: _savedDirs),
        '/cloud-setup': (context) => const CloudSetupScreen(),
        '/home': (context) => const HomeScreen(),
        '/settings': (context) => const SettingsScreen(),
      },
    );
  }

  ThemeData _buildTheme() {
    const brand = Color(0xFFFF6B00);
    final isDesktop =
        Platform.isWindows || Platform.isMacOS || Platform.isLinux;
    final base = ThemeData.dark().copyWith(
      scaffoldBackgroundColor: const Color(0xFF0E0E0E),
      colorScheme: const ColorScheme.dark(primary: brand),
      appBarTheme: const AppBarTheme(
        backgroundColor: Color(0xFF1A1A1A),
        elevation: 0,
      ),
      bottomNavigationBarTheme: const BottomNavigationBarThemeData(
        backgroundColor: Color(0xFF1A1A1A),
        selectedItemColor: Color(0xFFFF9900),
        unselectedItemColor: Colors.white54,
        type: BottomNavigationBarType.fixed,
      ),
      segmentedButtonTheme: SegmentedButtonThemeData(
        style: ButtonStyle(
          backgroundColor: WidgetStateProperty.resolveWith(
            (states) => states.contains(WidgetState.selected) ? brand : null,
          ),
          foregroundColor: WidgetStateProperty.resolveWith(
            (states) => states.contains(WidgetState.selected)
                ? Colors.black
                : Colors.white70,
          ),
        ),
      ),
    );
    if (!isDesktop) return base;
    return base.copyWith(
      textTheme: base.textTheme.apply(
        fontFamilyFallback: const ['Microsoft YaHei', 'PingFang SC', 'SimHei'],
      ),
    );
  }
}
