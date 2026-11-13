// services/platform_bridge.dart
// The ONE typed boundary for the app's own platform channels.
//
// Flutter 3.50 made direct native interop (FFIgen Objective-C / JNIgen) stable
// and previewed Pigeon's FFI/JNI mode. None of them replaces the channels below:
//
//  * The 25 Rust exports in crates/rcrm-flutter-bridge are ALREADY direct
//    native interop — handwritten C-ABI + dart:ffi, synchronous, zero-copy,
//    callable from any isolate. FFIgen generates signatures only; it cannot
//    express this project's four ownership shapes (docs/API_REFERENCE.md),
//    the len-only Vec::from_raw_parts hand-off, the "never free on timeout"
//    rule, NativeFinalizer addresses, NativeCallable.listener callbacks, or the
//    runtime probe that treats the five mobile-decode symbols as absent on
//    desktop. Generating bindings there would be a downgrade.
//  * The channels below are lifecycle wrappers, not "Dart wants to call a Java
//    class": the native halves own an Activity/Context, a BroadcastReceiver,
//    a ContentObserver, an AVAudioSession, or an HWND. JNIgen would leak those
//    platform objects into Dart; Pigeon native interop is Preview, excludes
//    Windows/Linux, and its @FlutterApi path is exactly the native-to-Dart push
//    (rcrm/volume onChanged) that its own README lists as lifecycle-fragile.
//
// What CAN be evolved is the string-based plumbing the 3.50 announcement names:
// channel names, method names, argument keys, and untyped Map replies used to be
// scattered across seven Dart services and duplicated in Kotlin/Swift/C++.
// This file is the single, typed, mockable boundary. Behaviour is unchanged —
// same channel names, method names, StandardMessageCodec payloads and exception
// semantics — so the native halves and the existing mock tests stay untouched.
// When (if) native interop becomes viable, this is the only file to replace.

import 'package:flutter/services.dart';

/// Wire names shared with the native halves. A typo here is silent at runtime:
/// the call simply returns MissingPluginException. Keep in lockstep with
/// MainActivity.kt, the four *Channel.kt, the three iOS *Channel.swift, and
/// windows/runner/flutter_window.cpp.
abstract final class PlatformChannelNames {
  static const String window = 'rcrm/window';
  static const String tv = 'rcrm/tv';
  static const String orientation = 'rcrm/orientation';
  static const String screen = 'rcrm/screen';
  static const String volume = 'rcrm/volume';
  static const String storage = 'rcrm/storage';
  static const String app = 'rcrm/app';

  /// The complete contract. Pinned by test/platform_bridge_test.dart.
  static const List<String> all = <String>[
    window,
    tv,
    orientation,
    screen,
    volume,
    storage,
    app,
  ];
}

/// Every method name on those channels. Eleven in total: ten Dart→native and
/// one native→Dart push (onChanged).
abstract final class PlatformMethods {
  static const String startWindowDrag = 'startWindowDrag';
  static const String isTv = 'isTv';
  static const String follow = 'follow';
  static const String release = 'release';
  static const String setCaptureAllowed = 'setCaptureAllowed';
  static const String read = 'read';
  static const String setIndex = 'setIndex';
  static const String onChanged = 'onChanged';
  static const String status = 'status';
  static const String request = 'request';
  static const String exitApp = 'exitApp';

  static const List<String> dartToNative = <String>[
    startWindowDrag,
    isTv,
    follow,
    release,
    setCaptureAllowed,
    read,
    setIndex,
    status,
    request,
    exitApp,
  ];

  static const List<String> nativeToDart = <String>[onChanged];
}

/// Keys of the arguments Dart sends. Reply field names stay with the models
/// that decode them (StorageAccessStatus / SystemVolumeReading.fromPlatform).
abstract final class PlatformArgs {
  static const String allowed = 'allowed';
  static const String index = 'index';
}

/// Typed calls. Nothing here swallows exceptions: callers own their own
/// best-effort / fallback policy, exactly as before.
class PlatformBridge {
  PlatformBridge._();

  static const MethodChannel window = MethodChannel(PlatformChannelNames.window);
  static const MethodChannel tv = MethodChannel(PlatformChannelNames.tv);
  static const MethodChannel orientation = MethodChannel(
    PlatformChannelNames.orientation,
  );
  static const MethodChannel screen = MethodChannel(
    PlatformChannelNames.screen,
  );
  static const MethodChannel volume = MethodChannel(
    PlatformChannelNames.volume,
  );
  static const MethodChannel storage = MethodChannel(
    PlatformChannelNames.storage,
  );
  static const MethodChannel app = MethodChannel(PlatformChannelNames.app);

  /// Normalises an untyped codec reply into a String-keyed map, or null when
  /// the platform answered with something the models cannot read. Callers turn
  /// null into "no answer" (StorageAccessStatus.unknown / null reading), which
  /// is the same outcome the old `fromPlatform(Object?)` produced for a
  /// non-Map reply.
  static Map<String, Object?>? reply(Object? raw) {
    if (raw is! Map<Object?, Object?>) return null;
    final Map<String, Object?> typed = <String, Object?>{};
    for (final MapEntry<Object?, Object?> entry in raw.entries) {
      final Object? key = entry.key;
      if (key is! String) return null;
      typed[key] = entry.value;
    }
    return typed;
  }

  // ── rcrm/tv ────────────────────────────────────────────────────────────
  static Future<bool> isTv() async {
    final bool? answer = await tv.invokeMethod<bool>(PlatformMethods.isTv);
    return answer ?? false;
  }

  // ── rcrm/orientation ───────────────────────────────────────────────────
  static Future<void> followDevice(bool follow) =>
      orientation.invokeMethod<void>(
        follow ? PlatformMethods.follow : PlatformMethods.release,
      );

  // ── rcrm/screen ────────────────────────────────────────────────────────
  static Future<void> setCaptureAllowed(bool allowed) =>
      screen.invokeMethod<void>(
        PlatformMethods.setCaptureAllowed,
        <String, Object?>{PlatformArgs.allowed: allowed},
      );

  // ── rcrm/storage ───────────────────────────────────────────────────────
  static Future<Map<String, Object?>?> storageStatus() async =>
      reply(await storage.invokeMethod<Object?>(PlatformMethods.status));

  static Future<Map<String, Object?>?> requestStorageAccess() async =>
      reply(await storage.invokeMethod<Object?>(PlatformMethods.request));

  // ── rcrm/volume ────────────────────────────────────────────────────────
  static Future<Map<String, Object?>?> volumeRead() async =>
      reply(await volume.invokeMethod<Object?>(PlatformMethods.read));

  static Future<Map<String, Object?>?> volumeSetIndex(int index) async =>
      reply(
        await volume.invokeMethod<Object?>(
          PlatformMethods.setIndex,
          <String, Object?>{PlatformArgs.index: index},
        ),
      );

  /// Installs the ONE handler for the native→Dart push. Non-onChanged calls
  /// are ignored, and arguments are normalised before they reach the caller.
  static void watchVolumeChanges(
    void Function(Map<String, Object?> reading) onChanged,
  ) {
    volume.setMethodCallHandler((MethodCall call) async {
      if (call.method != PlatformMethods.onChanged) return null;
      final Map<String, Object?>? args = reply(call.arguments);
      if (args != null) onChanged(args);
      return null;
    });
  }

  static void stopWatchingVolumeChanges() {
    volume.setMethodCallHandler(null);
  }

  // ── rcrm/window (Windows runner only) ──────────────────────────────────
  static Future<void> startWindowDrag() =>
      window.invokeMethod<void>(PlatformMethods.startWindowDrag);

  // ── rcrm/app ───────────────────────────────────────────────────────────
  /// Fire-and-forget by design: the native half finishes the task and kills
  /// the process, so there is no reply worth awaiting.
  static void exitApp() {
    app.invokeMethod(PlatformMethods.exitApp);
  }
}
