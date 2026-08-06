// widgets/double_back_exit.dart
// Android-only: "press back again to exit" guard for root screens (Zhihu
// style). The first back press on a root screen shows a hint instead of
// quitting; a second press within [DoubleBackGuard.interval] exits for real.
// This only applies where back would terminate the app — pushed screens keep
// their normal pop behavior.
//
// [DoubleBackExit] is a widget wrapper for screens that have no PopScope of
// their own. Screens that already own a PopScope (HomeScreen, for tab
// switching) must use [DoubleBackGuard] directly inside their existing
// onPopInvokedWithResult instead of nesting another PopScope — nesting would
// register both handlers on the same route and they would both fire.

import 'dart:io' show Platform;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// Shared "press back again to exit" state machine.
///
/// Used by [DoubleBackExit] and by root screens that already own a PopScope.
/// The screen's back handler must only call [handleBack] when the pop would
/// actually terminate the app (i.e. nothing else is left to handle it).
class DoubleBackGuard {
  static const interval = Duration(seconds: 2);

  /// Native exit hook: finishes the task and kills the process synchronously.
  /// Deterministic — unlike [SystemNavigator.pop] it cannot leave the Activity
  /// in a half-finished state that a relaunch would restore (which made the
  /// reopened app exit immediately).
  static const _exit = MethodChannel('rcrm/app');
  DateTime? _lastBackAt;

  /// Handle a back press. Returns true if the app should exit now (second
  /// press within [interval] already triggered the native exit).
  /// Returns false after [handleBack] — caller should then show [hint].
  bool handleBack() {
    final now = DateTime.now();
    final last = _lastBackAt;
    _lastBackAt = now;
    if (last != null && now.difference(last) <= interval) {
      try {
        _exit.invokeMethod('exitApp');
      } catch (_) {
        SystemNavigator.pop();
      }
      return true;
    }
    return false;
  }

  /// Forget the last back press. Call when the user performs an unrelated
  /// navigation (e.g. switches tab) so a later back press isn't mistakenly
  /// counted as the second press in the exit sequence.
  void reset() {
    _lastBackAt = null;
  }

  /// Show the "press back again to exit" snackbar.
  static void hint(BuildContext context) {
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(
        const SnackBar(
          content: Text('Press back again to exit'),
          duration: Duration(milliseconds: 1500),
          behavior: SnackBarBehavior.floating,
        ),
      );
  }
}

class DoubleBackExit extends StatefulWidget {
  final Widget child;
  const DoubleBackExit({super.key, required this.child});

  @override
  State<DoubleBackExit> createState() => _DoubleBackExitState();
}

class _DoubleBackExitState extends State<DoubleBackExit> {
  final _guard = DoubleBackGuard();

  @override
  Widget build(BuildContext context) {
    // Only the Android back button needs guarding. Desktop/iOS return the
    // child untouched (iOS has no back button; desktop has a window close).
    if (!Platform.isAndroid) return widget.child;

    return PopScope(
      canPop: false,
      onPopInvokedWithResult: (didPop, _) {
        if (didPop) return;
        if (_guard.handleBack()) return;
        DoubleBackGuard.hint(context);
      },
      child: widget.child,
    );
  }
}
