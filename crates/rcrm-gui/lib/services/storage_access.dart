// services/storage_access.dart
// Android's "all files access" layer -- whether this app may read the media
// folders the user picks, and how it has to ask for that on each Android
// version.
//
// Why this exists at all: RCrm serves the library to the app itself from a
// read-only WebDAV server that is handed the chosen folders as REAL filesystem
// paths and decrypts files on the fly. Nothing here goes through MediaStore or
// the Storage Access Framework, so a per-folder document grant cannot work and
// media permissions are beside the point. The process itself must be allowed to
// open those paths, and Android has never had one API for that:
//
//  * Android 11+ (API >= 30) -- all-files access is an APP-OP, not a runtime
//    permission. There is no dialog: `requestPermissions` does nothing for
//    `MANAGE_EXTERNAL_STORAGE`, and declaring it in the manifest grants
//    nothing by itself. The only way in is the system settings screen, and
//    `Environment.isExternalStorageManager()` is the only honest answer to
//    "may I read?".
//  * Android 6-10 (API 23..29) -- an ordinary dangerous runtime permission
//    (`READ_EXTERNAL_STORAGE`). Android 10 additionally needs
//    `android:requestLegacyExternalStorage` in the manifest: it is the release
//    where scoped storage became the default while all-files access did not
//    exist yet.
//  * Android 5 and older (API < 23) -- granted at install. Nothing to ask.
//
// The Dart half owns three things and nothing else: it reads the status, it
// starts the platform's flow, and it re-reads the status when the app comes
// back to the foreground. That last one is not a nicety -- the settings screen
// is a different app's activity, so coming back is the ONLY signal that the
// user may have changed the answer. Nothing is held across the trip: a
// `MethodChannel.Result` kept while the user is away would pin a dead Activity
// (`StorageAccessChannel.kt`).
//
// Every read is defensive. A non-Android host, a garbled reply or a
// `MissingPluginException` must not throw out of this service, and must not
// claim access either: claiming access the app does not have is the exact
// failure this feature exists to remove, so a status that cannot be read
// becomes "no access, no version, nothing offered".

import 'dart:io' show Platform;

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart'
    show AppLifecycleState, WidgetsBinding, WidgetsBindingObserver;

/// Test seam for the Android-only branch below.
///
/// The tests run the desktop VM, where the real platform check is false -- so
/// neither the ask nor the channel call would be reachable from a test, and the
/// ask IS this feature. Only `test/storage_access_test.dart` writes it.
/// Untouched, it is exactly `Platform.isAndroid`.
@visibleForTesting
bool debugStorageAccessSupported = Platform.isAndroid;

/// The flow that would grant access on this device, told by the platform
/// instead of guessed from a version number here.
enum StorageAccessAction {
  /// Granted at install and not revocable (API < 23): there is nothing to ask.
  none,

  /// A runtime permission dialog (API 23..29).
  dialog,

  /// No dialog exists; the ask is the system settings screen (API >= 30).
  settings,
}

/// What the platform currently allows, as the native half reports it.
@immutable
class StorageAccessStatus {
  const StorageAccessStatus({
    required this.sdk,
    required this.granted,
    required this.action,
    required this.canAsk,
  });

  /// The answer when there is no answer: the platform is not Android, the
  /// channel is missing, or the reply could not be read.
  ///
  /// Deliberately claims nothing -- `granted` false is the safe direction
  /// (a wrong "granted" hides the ask this feature exists to show), the sdk is
  /// left at 0 rather than invented, and `action` is [StorageAccessAction.none]
  /// rather than a flow this device may not have.
  static const StorageAccessStatus unknown = StorageAccessStatus(
    sdk: 0,
    granted: false,
    action: StorageAccessAction.none,
    canAsk: false,
  );

  /// `Build.VERSION.SDK_INT`, or 0 when the platform did not say.
  final int sdk;

  /// Whether the app may read shared storage by real path right now.
  final bool granted;

  /// Which flow grants it on this device ([StorageAccessAction]).
  final StorageAccessAction action;

  /// Whether that flow may still be shown. False only for a permission the
  /// user has refused for good ("Android will not ask again"): the app can then
  /// only send them to its own settings page -- which is what [StorageAccess.request]
  /// does in that state.
  final bool canAsk;

  /// Reads a platform map without trusting a single field of it.
  ///
  /// All four fields have to be readable, and the whole reply falls back to
  /// [unknown] if any of them is not. A partly-read reply is refused on
  /// purpose: an unknown `action` with a valid `granted: true` would otherwise
  /// be reported as access the app may not have.
  static StorageAccessStatus fromPlatform(Object? reply) {
    if (reply is! Map) return unknown;
    final Object? sdk = reply['sdk'];
    final Object? granted = reply['granted'];
    final Object? canAsk = reply['canAsk'];
    final StorageAccessAction? action = _actionFrom(reply['action']);
    if (sdk is! int || granted is! bool || canAsk is! bool || action == null) {
      return unknown;
    }
    return StorageAccessStatus(
      sdk: sdk,
      granted: granted,
      action: action,
      canAsk: canAsk,
    );
  }

  static StorageAccessAction? _actionFrom(Object? raw) => switch (raw) {
    'none' => StorageAccessAction.none,
    'dialog' => StorageAccessAction.dialog,
    'settings' => StorageAccessAction.settings,
    _ => null,
  };

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is StorageAccessStatus &&
          other.sdk == sdk &&
          other.granted == granted &&
          other.action == action &&
          other.canAsk == canAsk;

  @override
  int get hashCode => Object.hash(sdk, granted, action, canAsk);

  @override
  String toString() =>
      'StorageAccessStatus(sdk: $sdk, granted: $granted, '
      'action: ${action.name}, canAsk: $canAsk)';
}

class StorageAccess {
  StorageAccess._();

  /// The channel both halves implement. Pinned here because a mismatch between
  /// this name and `StorageAccessChannel.kt` is silent.
  static const MethodChannel channel = MethodChannel('rcrm/storage');

  /// Where the ask is offered AND honoured. This permission is an Android
  /// one -- a desktop app reads its folders with the user's own rights and has
  /// no such thing to request -- so neither the ask nor the channel call
  /// happens there.
  static bool get supported => debugStorageAccessSupported;

  /// The status the UI follows: null until the first read answers.
  ///
  /// A [ValueNotifier] rather than a provider because the value arrives from
  /// the platform on a resume, not from a user action, and both screens that
  /// show it must update from the same single read.
  static final ValueNotifier<StorageAccessStatus?> state =
      ValueNotifier<StorageAccessStatus?>(null);

  /// The resume observer, registered once for the process by [watch].
  static _StorageAccessResumeWatcher? _watcher;

  /// Asks the platform what it allows right now.
  ///
  /// Never throws: a platform that cannot answer reports [StorageAccessStatus.unknown],
  /// which claims nothing and offers nothing.
  static Future<StorageAccessStatus> status() async {
    if (!supported) return StorageAccessStatus.unknown;
    try {
      final Object? reply = await channel.invokeMethod<Object?>('status');
      return StorageAccessStatus.fromPlatform(reply);
    } catch (_) {
      // MissingPluginException on a host without the native half, or a reply
      // the codec refused. Either way: no claim of access.
      return StorageAccessStatus.unknown;
    }
  }

  /// Reads the status and publishes it to [state].
  static Future<StorageAccessStatus> refresh() async {
    final StorageAccessStatus read = await status();
    state.value = read;
    return read;
  }

  /// Starts the flow this Android version needs -- a permission dialog, or the
  /// all-files-access settings screen, or (for a permission refused for good)
  /// the app's own settings page.
  ///
  /// Returns as soon as the platform has been asked to launch something: the
  /// answer is not a return value, because the user is about to leave the app.
  /// The status is re-read here so a no-op ask (already granted) still leaves
  /// [state] correct, and again on the next resume, which is when a settings
  /// trip actually lands.
  static Future<void> request() async {
    if (!supported) return;
    try {
      await channel.invokeMethod<Object?>('request');
    } catch (_) {
      // A platform that cannot launch anything is not an error: the re-read
      // below is what the UI believes.
    }
    await refresh();
  }

  /// Starts following the platform, and registers the ONE resume observer that
  /// makes this work.
  ///
  /// Coming back to the foreground is the only signal that the user returned
  /// from Android's settings screen (it is another activity, and the platform
  /// sends no result for it), so this is the mechanism, not a refresh nicety.
  /// Both screens that show the ask call it; it is idempotent, so the observer
  /// exists once per process and is never re-registered per build.
  static void watch() {
    if (!supported || _watcher != null) return;
    final _StorageAccessResumeWatcher watcher = _StorageAccessResumeWatcher();
    _watcher = watcher;
    WidgetsBinding.instance.addObserver(watcher);
  }

  /// Test-only: drops the observer and the last status so one test cannot start
  /// from what another one read. [watch] attaches it again.
  @visibleForTesting
  static void debugReset() {
    final _StorageAccessResumeWatcher? watcher = _watcher;
    if (watcher != null) {
      WidgetsBinding.instance.removeObserver(watcher);
      _watcher = null;
    }
    state.value = null;
  }
}

/// Re-reads the status whenever the app comes back to the foreground.
///
/// A plain [WidgetsBindingObserver] rather than a widget: the value belongs to
/// the app, and it has to keep arriving while the user is on a settings screen
/// with no Flutter frame on screen.
class _StorageAccessResumeWatcher with WidgetsBindingObserver {
  @override
  void didChangeAppLifecycleState(AppLifecycleState lifecycleState) {
    if (lifecycleState == AppLifecycleState.resumed) {
      StorageAccess.refresh();
    }
  }
}

/// What the ask says, on the version it is shown on.
@immutable
class StorageAccessCopy {
  const StorageAccessCopy({
    required this.title,
    required this.note,
    required this.body,
    required this.actionLabel,
  });

  final String title;

  /// One line, for the surfaces that have one line to give: a settings row is
  /// a row, not a card, and the full [body] under a trailing button is a wall
  /// of text in the middle of a list.
  final String note;

  /// The full explanation, for the setup screen's card -- where this is the
  /// first thing the user meets and the reason the app needs the permission at
  /// all is worth three sentences.
  final String body;

  final String actionLabel;
}

/// The copy for [status] -- a pure function, so every branch is assertable on
/// any host (the tests run the desktop VM, where no real Android status can be
/// produced).
///
/// It says what THIS Android version will really do, and it says why the app
/// needs it: the library is served to the app over a local server that opens
/// the folders by their real paths, so a per-folder document grant is not
/// enough. The three flows word it differently, and a refusal that Android
/// will not repeat gets its own wording and its own action -- a settings page,
/// because there is no dialog left to show.
StorageAccessCopy storageAccessCopy(StorageAccessStatus status) {
  switch (status.action) {
    case StorageAccessAction.settings:
      return const StorageAccessCopy(
        title: 'Allow access to all files',
        note:
            'Android 11+ has no dialog for this -- the app must be allowed '
            'to manage all files.',
        body:
            'Android 11 and later have no dialog for this. RCrm serves the '
            'library to the app itself from a local server that opens your '
            'folders by their real paths, so a per-folder document grant is not '
            'enough -- the app has to be allowed to manage all files, in the '
            'system settings.',
        actionLabel: 'Open Android settings',
      );

    case StorageAccessAction.dialog:
      if (!status.canAsk) {
        return const StorageAccessCopy(
          title: 'Storage access is turned off',
          note: 'Refused for good -- Android will not ask again.',
          body:
              'Android will not ask again: this permission was denied for good. '
              'Until the app is allowed to read storage in its own settings '
              'page, the folders you pick cannot be read -- the local server '
              'opens them by their real paths.',
          actionLabel: 'Open app settings',
        );
      }
      return const StorageAccessCopy(
        title: 'Allow access to your media folders',
        note: 'Android 6 to 10 grant storage access with a permission dialog.',
        body:
            'Android 6 to 10 grant storage access with a permission dialog, and '
            'picking a folder does not grant it. RCrm reads those folders by '
            'their real paths through a local server, which a per-folder '
            'document grant could not cover.',
        actionLabel: 'Allow storage access',
      );

    case StorageAccessAction.none:
      if (status.granted) {
        return const StorageAccessCopy(
          title: 'Storage access',
          note: 'Granted when the app was installed on this Android version.',
          body:
              'This Android version grants storage access when the app is '
              'installed, so there is nothing to allow here.',
          actionLabel: 'Check again',
        );
      }
      // The platform could not be read at all ([StorageAccessStatus.unknown]):
      // the ask only appears in this state, and it must not pretend to know
      // which Android version it is talking to.
      return const StorageAccessCopy(
        title: 'Storage access is unknown',
        note: 'This device did not report its storage permission.',
        body:
            'This device did not report its storage permission, so RCrm cannot '
            'tell whether it may read your folders. Picking one is still worth '
            'trying: if access is already granted, the library loads.',
        actionLabel: 'Check again',
      );
  }
}
