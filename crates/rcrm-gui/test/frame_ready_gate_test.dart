// test/frame_ready_gate_test.dart
// TDD for the event-driven frame gate. It opens on the NEW video's positive
// width event (never on a stale frame), honours a deadline fallback, and is
// generation-guarded so a superseded open cannot reveal a stale preview.

import 'package:flutter_test/flutter_test.dart';

import 'package:rcrm_gui/utils/frame_ready_gate.dart';

void main() {
  test('null and zero width do not open the gate', () async {
    var ready = 0;
    final gate = FrameReadyGate(() => ready++, deadline: const Duration(seconds: 5));
    gate.arm();
    gate.onWidth(null);
    gate.onWidth(0);
    await Future<void>.delayed(Duration.zero);
    expect(ready, 0);
    expect(gate.ready, isFalse);
    gate.cancel();
  });

  test('a positive width opens the gate once', () async {
    var ready = 0;
    final gate = FrameReadyGate(() => ready++, deadline: const Duration(seconds: 5));
    gate.arm();
    gate.onWidth(1280);
    expect(ready, 1);
    expect(gate.ready, isTrue);
    // A second event must not fire again.
    gate.onWidth(1280);
    expect(ready, 1);
    gate.cancel();
  });

  test('deadline opens the gate when no width ever arrives', () async {
    var ready = 0;
    final gate = FrameReadyGate(
      () => ready++,
      deadline: const Duration(milliseconds: 20),
    );
    gate.arm();
    await Future<void>.delayed(const Duration(milliseconds: 60));
    expect(ready, 1, reason: 'a stalled open must not hide the video forever');
    gate.cancel();
  });

  test('cancel prevents a pending deadline from firing', () async {
    var ready = 0;
    final gate = FrameReadyGate(
      () => ready++,
      deadline: const Duration(milliseconds: 20),
    );
    gate.arm();
    gate.cancel();
    await Future<void>.delayed(const Duration(milliseconds: 60));
    expect(ready, 0);
    expect(gate.ready, isFalse);
  });

  test('re-arming supersedes the previous generation', () async {
    var ready = 0;
    final gate = FrameReadyGate(
      () => ready++,
      deadline: const Duration(milliseconds: 20),
    );
    gate.arm();
    gate.arm(); // second open replaces the first
    await Future<void>.delayed(const Duration(milliseconds: 60));
    expect(ready, 1, reason: 'exactly one generation may fire');
    gate.cancel();
  });

  test('a stale width after cancel cannot open the gate', () async {
    var ready = 0;
    final gate = FrameReadyGate(() => ready++, deadline: const Duration(seconds: 5));
    gate.arm();
    gate.cancel();
    gate.onWidth(1920); // late event from the cancelled open
    expect(ready, 0);
  });
}
