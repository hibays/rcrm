// app.dart

import 'dart:async';
import 'dart:convert';
import 'dart:io' show Platform;

import 'package:flutter_smart_dialog/flutter_smart_dialog.dart';
import 'package:material_ui/material_ui.dart';
import 'package:dynamic_color/dynamic_color.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'config/theme.dart';
import 'models/media_item.dart';
import 'models/server_config.dart';
import 'providers/server_provider.dart';
import 'providers/settings_provider.dart';
import 'screens/cast_receiver_screen.dart';
import 'screens/cast_scan_screen.dart';
import 'screens/cloud_setup_screen.dart';
import 'screens/home_screen.dart';
import 'screens/library_setup_screen.dart';
import 'screens/search_screen.dart';
import 'screens/settings_screen.dart';
import 'services/tv_detector.dart';
import 'utils/keywords.dart';
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
    // Anchor popups open downward from the target widget's bottom-left edge
    // (mirrors the native PopupMenuButton alignment). Player menus opt into
    // the upward variant per-call via SmartPopupMenu(openUpward: true).
    SmartDialog.config.attach = SmartConfigAttach(
      attachAlignmentType: SmartAttachAlignmentType.inside,
    );
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
    // Only the two appearance fields: watching the whole SettingsState would
    // rebuild this shell (and re-create both ThemeData objects) every time an
    // image column or a cache switch changed.
    final appearance = ref.watch(
      uiSettingsProvider.select((s) => (s.appearanceMode, s.appearanceAccent)),
    );
    final accent = RCrmAccent.fromKey(appearance.$2);
    final themeMode = switch (appearance.$1) {
      'day' => ThemeMode.light,
      'night' => ThemeMode.dark,
      _ => ThemeMode.system,
    };

    // Android 12+ wallpaper colours arrive asynchronously. Recording them
    // before the two ThemeData builds means Material You can be an accent like
    // any other; on every other platform both schemes are null and the swatch
    // is simply not offered.
    return DynamicColorBuilder(
      builder: (lightDynamic, darkDynamic) {
        RCrmColors.setSystemColors(
          light: lightDynamic?.primary,
          dark: darkDynamic?.primary,
        );
        return MaterialApp(
          title: 'RCrm Media Library',
          navigatorKey: _navigatorKey,
          navigatorObservers: [FlutterSmartDialog.observer],
          // Both are PURE builds. Which one Flutter picks (themeMode may be
          // system) is only known inside the builder below, where the runtime
          // RCrmColors snapshot is applied once.
          theme: RCrmTheme.build(accent: accent, brightness: Brightness.light),
          darkTheme: RCrmTheme.build(
            accent: accent,
            brightness: Brightness.dark,
          ),
          themeMode: themeMode,
          // AnimatedTheme lerps ThemeData over 200ms, and ColorScheme.lerp flips
          // `brightness` at the halfway point — while `RCrmColors` is a single
          // snapshot that can only hold one world. Mid-transition the page would
          // be half-cream with white ink (or half-dark with ink). An appearance
          // switch is a state change, not an animation: make it atomic.
          themeAnimationDuration: Duration.zero,
          debugShowCheckedModeBanner: false,
          builder: FlutterSmartDialog.init(
            builder: (context, child) {
              RCrmTheme.applyToContext(context, accent);
              if (Platform.isAndroid || Platform.isIOS) return child!;
              return TitleBarShell(child: child!);
            },
          ),
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
            // The one destination for a tag: the player's title chips, the
            // Home channel rows and search suggestions all come through here.
            // It is a SEARCH page on purpose — a tag is a query with a name.
            '/tag-search': (context) {
              final arg = ModalRoute.of(context)?.settings.arguments;
              return SearchScreen(
                tabFilter: MediaType.video,
                initialTag: arg is KeywordTag ? arg : null,
              );
            },
            '/cast-scan': (context) => const CastScanScreen(),
            '/cast-receiver': (context) =>
                const CastReceiverScreen(showBack: true),
          },
        );
      },
    );
  }
}
