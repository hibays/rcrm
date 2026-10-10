// services/window_drag.dart
// Starting a window move from Dart for the app's own title bar.
//
// The app draws its title bar, so there is no caption to press. window_manager's
// [DragToMoveArea] / `startDragging()` asks Windows to run a move with
// `WM_SYSCOMMAND` + `SC_MOVE`, which Windows treats as a *keyboard* move:
// Windows 11 lets those snap, Windows 10's Aero Snap does not, so on Windows 10
// the window never snaps to a screen edge.
//
// The runner therefore hands the system a mouse-initiated non-client press
// instead (`WM_NCLBUTTONDOWN` with `HTCAPTION`) -- the same thing Electron, Tauri
// and winit do for their custom title bars -- which runs a real caption drag and
// snaps on both versions. See `windows/runner/flutter_window.cpp`.
//
// Only Windows needs this; Linux and macOS keep using [DragToMoveArea], which
// goes through X11 `_NET_WM_MOVERESIZE` and macOS `performWindowDragWithEvent:`.

import 'dart:io' show Platform;

import 'package:flutter/foundation.dart' show debugPrint;
import 'package:flutter/services.dart';
import 'package:window_manager/window_manager.dart';

/// The runner-side window channel (see `windows/runner/flutter_window.cpp`).
const MethodChannel _channel = MethodChannel('rcrm/window');

/// False once the runner has answered that it does not know the method, so an
/// older runner is asked exactly once.
bool _channelAvailable = true;

/// True when the app's own title bar has to start the drag itself.
bool get startsDragInDart => Platform.isWindows;

/// Begins a mouse-initiated window move, as if the user had pressed the title bar
/// of a normal window: the system runs the drag, so edge snapping, double-click
/// to maximize and the window menu all keep working.
///
/// Does nothing while the window is fullscreen - there is nothing to move and no
/// edge to snap to.
Future<void> startWindowDrag() async {
  if (!startsDragInDart) {
    await windowManager.startDragging();
    return;
  }
  if (await windowManager.isFullScreen()) return;
  if (!_channelAvailable) {
    // A runner without the channel (or one whose call failed once) still
    // deserves a draggable title bar: `WM_SYSCOMMAND` + `SC_MOVE` does not snap
    // on Windows 10, but losing the drag entirely is worse than losing the snap.
    await windowManager.startDragging();
    return;
  }
  try {
    await _channel.invokeMethod<void>('startWindowDrag');
  } on MissingPluginException {
    _channelAvailable = false;
    _reportFallbackOnce();
    await windowManager.startDragging();
  } on PlatformException {
    _channelAvailable = false;
    _reportFallbackOnce();
    await windowManager.startDragging();
  }
}

/// True once the degradation has been reported, so a runner without the channel
/// logs it once instead of on every pointer-down.
bool _fallbackReported = false;

void _reportFallbackOnce() {
  if (_fallbackReported) return;
  _fallbackReported = true;
  debugPrint(
    'window_drag: the runner has no startWindowDrag — dragging through '
    'window_manager instead (no edge snapping on Windows 10)',
  );
}