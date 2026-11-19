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

/// Windows only: hand the accessibility bridge an empty semantics tree.
///
/// The bridge is built lazily on the first WM_GETOBJECT probe — running from an
/// IDE that loads the Java Access Bridge is enough, no screen reader required.
/// Once built it mirrors every semantics change into a ui::AXTree, and a
/// framework bug (flutter/flutter#182444) can produce an update that references
/// nodes it never sent (or removes one mid-serialization). The tree then stays
/// corrupted for the life of the process and spews AXTree errors on every later
/// update — in release builds it can even terminate the process. The app offers
/// no screen-reader-specific accommodations (docs/PRODUCT.md), so on Windows we
/// keep the tree at its root node: nothing to add, remove, or desync. Every
/// other platform keeps its full, unmodified semantics.
Widget _desktopSemantics(Widget child) =>
    Platform.isWindows ? ExcludeSemantics(child: child) : child;

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
      _desktopSemantics(
        ProviderScope(
          child: RcrmApp(savedConfig: prefs.getString('server_config')),
        ),
      ),
    );
  } catch (e) {
    debugPrint('Startup error: $e');
    runApp(
      _desktopSemantics(
        const MaterialApp(
          home: Scaffold(body: Center(child: Text('Startup error'))),
        ),
      ),
    );
  }
}
