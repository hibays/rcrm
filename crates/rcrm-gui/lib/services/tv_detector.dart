// services/tv_detector.dart
// Android TV detection via a small MethodChannel in MainActivity.kt
// (UiModeManager UI_MODE_TYPE_TELEVISION). Non-Android platforms are never TV.

import 'dart:io' show Platform;

import 'package:rcrm_gui/services/platform_bridge.dart';

/// True when running on an Android TV device (leanback UI mode).
Future<bool> isAndroidTv() async {
  if (!Platform.isAndroid) return false;
  try {
    return await PlatformBridge.isTv();
  } catch (_) {
    return false;
  }
}
