// test/window_drag_test.dart
// How the app's own title bar starts a window move, and how it degrades when the
// runner has no `rcrm/window` channel.
//
// The regression this pins: the first version returned early when the channel was
// unavailable — *before* the fallback — so on a runner without the channel the
// title bar dragged exactly once and then silently stopped working. The mock
// handler for `window_manager` also proves the fullscreen guard never posts a
// move (there is nothing to drag in fullscreen).
//
// Note on ordering: `window_drag.dart` keeps its "channel is unavailable" state
// in a library-level flag, which a test cannot reset, so the fallback case is
// deliberately the LAST test in this file.

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rcrm_gui/services/window_drag.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const runner = MethodChannel('rcrm/window');
  const plugin = MethodChannel('window_manager');
  final runnerCalls = <String>[];
  final pluginCalls = <String>[];

  void mockRunner(Future<Object?> Function(MethodCall) handler) {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(runner, handler);
  }

  void mockPlugin({required bool fullscreen}) {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(plugin, (call) async {
      pluginCalls.add(call.method);
      if (call.method == 'isFullScreen') return fullscreen;
      return null;
    });
  }

  setUp(() {
    runnerCalls.clear();
    pluginCalls.clear();
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(runner, null);
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(plugin, null);
  });

  test('fullscreen posts no move at all', () async {
    mockRunner((call) async {
      runnerCalls.add(call.method);
      return null;
    });
    mockPlugin(fullscreen: true);

    await startWindowDrag();

    expect(runnerCalls, isEmpty);
    expect(pluginCalls, ['isFullScreen']);
  });

  test('with the channel, the move goes through rcrm/window', () async {
    mockRunner((call) async {
      runnerCalls.add(call.method);
      return null;
    });
    mockPlugin(fullscreen: false);

    await startWindowDrag();

    expect(runnerCalls, ['startWindowDrag']);
    // The plugin is only asked about fullscreen; it is never asked to drag.
    expect(pluginCalls, ['isFullScreen']);
  });

  test('a runner without the channel falls back, and keeps falling back', () async {
    mockRunner((call) async {
      runnerCalls.add(call.method);
      throw MissingPluginException('no runner handler');
    });
    mockPlugin(fullscreen: false);

    // First drag: the channel refuses, so window_manager starts the move.
    await startWindowDrag();
    expect(pluginCalls, contains('startDragging'));

    // Second drag: this is the regression. The old code returned here without
    // reaching the fallback, so the title bar worked once and then went dead.
    pluginCalls.clear();
    await startWindowDrag();
    expect(
      pluginCalls,
      contains('startDragging'),
      reason: 'a channel that failed once must not disable dragging entirely',
    );
  });
}
