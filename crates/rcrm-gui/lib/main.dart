// main.dart
import 'dart:io' show Platform;
import 'package:material_ui/material_ui.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:window_manager/window_manager.dart';
import 'package:media_kit/media_kit.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'app.dart';

import 'package:rcrm_gui/services/settings_service.dart';

import 'services/item_cache_limit.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  if (!Platform.isAndroid && !Platform.isIOS) {
    await windowManager.ensureInitialized();
    await windowManager.setTitleBarStyle(
      TitleBarStyle.hidden,
      windowButtonVisibility: false,
    );
  }
  // Images use Flutter's default LRU imageCache. Only small 400px thumbnails
  // persist (the viewer evicts its full-res image on close), so a single
  PaintingBinding.instance.imageCache.maximumSizeBytes =
      ItemCacheLimit.flutterImageCacheMaxBytes;
  PaintingBinding.instance.imageCache.maximumSize =
      ItemCacheLimit.flutterImageCacheMaxEntries;
  try {
    MediaKit.ensureInitialized();
  } catch (e) {
    debugPrint('MediaKit init error: $e');
  }
  try {
    final prefs = await SharedPreferences.getInstance();
    // The instance exists now, so the app shell can read the persisted
    // appearance synchronously and paint frame one in the user's own theme
    // instead of flashing the default.
    SettingsService.prime(prefs);
    runApp(
      ProviderScope(
        child: RcrmApp(savedConfig: prefs.getString('server_config')),
      ),
    );
  } catch (e) {
    debugPrint('Startup error: $e');
    runApp(
      const MaterialApp(
        home: Scaffold(body: Center(child: Text('Startup error'))),
      ),
    );
  }
}
