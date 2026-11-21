// server_state_test.dart
// The server state is a sum type: the error lives in its own phase, so a new
// attempt cannot inherit the previous attempt's message.
import 'package:flutter_test/flutter_test.dart';

import 'package:rcrm_gui/providers/server_provider.dart';

void main() {
  test('an error belongs only to the error phase', () {
    final failed = ServerState(
      phase: const ServerError(message: 'Authentication failed'),
    );
    expect(failed.error, 'Authentication failed');
    expect(failed.isRunning, isFalse);
    expect(failed.url, isNull);
    expect(failed.client, isNull);
  });

  test('a retry cannot inherit the previous error', () {
    final failed = ServerState(
      phase: const ServerError(message: 'Authentication failed'),
    );
    // This is the exact regression: the old copyWith(error: null) kept the
    // message, so a successful retry still displayed "Authentication failed".
    final retried = ServerState(
      phase: ServerRunning(url: 'http://127.0.0.1:1'),
    );
    expect(failed.error, 'Authentication failed');
    expect(retried.error, isNull);
    expect(retried.isRunning, isTrue);
    expect(retried.url, 'http://127.0.0.1:1');
  });

  test('counts and progress are valid only in their own phase', () {
    const locked = ServerState(
      phase: ServerLocked(encrypted: 10, locked: 3, unlocked: 7),
    );
    expect(locked.encrypted, 10);
    expect(locked.locked, 3);
    expect(locked.unlocked, 7);
    expect(locked.progressText, isNull);
    expect(locked.error, isNull);

    final starting = ServerState(
      phase: const ServerStarting(progress: 'Verifying files… 2/10'),
    );
    expect(starting.progressText, 'Verifying files… 2/10');
    expect(starting.unlocked, 0);

    expect(const ServerState().error, isNull);
    expect(const ServerState().isRunning, isFalse);
  });
}
