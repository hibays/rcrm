// services/image_load_gate.dart
// The image decode gate: a fixed-length LIFO stack, not a FIFO queue, so the
// newest request (the picture on screen now) is served next. Releasing a slot
// hands it to the TOP; a full stack drops its BOTTOM (the oldest request); a
// repeat request for a queued image calls [restack] instead of pushing a second
// entry. Rationale and history: CHANGELOG 44, AGENTS.md.

import 'dart:async';

import 'package:flutter/foundation.dart' show visibleForTesting;

import 'item_cache_limit.dart';

class ImageLoadGate {
  ImageLoadGate._();
  static final ImageLoadGate instance = ImageLoadGate._();

  static final int _max = ItemCacheLimit.imageDecodeConcurrency;
  static final int _maxWaiting = ItemCacheLimit.imageDecodeQueueMax;

  final _runningTokens = <Completer<void>>{};

  /// Waiting tokens, oldest first: index 0 is the bottom (dropped first), the
  /// end is the top (served next).
  final _stack = <Completer<void>>[];

  /// Runs at once while there is room, otherwise waits at the TOP of the stack.
  /// Pushing onto a full stack drops the bottom entry (completed, never left
  /// pending, so its caller is not stuck).
  Completer<void> acquire() {
    assert(_maxWaiting > 0, 'a zero-depth stack would admit nothing');
    final c = Completer<void>();
    if (_runningTokens.length < _max) {
      _runningTokens.add(c);
      c.complete();
      return c;
    }
    if (_stack.length >= _maxWaiting) {
      final dropped = _stack.removeAt(0);
      if (!dropped.isCompleted) dropped.complete();
    }
    _stack.add(c);
    return c;
  }

  /// Moves a WAITING token to the top: the image was asked for again. A running
  /// or already-dropped token is not in the stack, so this is a no-op for it.
  void restack(Completer<void> token) {
    if (_stack.remove(token)) _stack.add(token);
  }

  /// Drops a token that never ran, or hands a running slot to the TOP.
  void done(Completer<void> token) {
    if (_stack.remove(token)) {
      if (!token.isCompleted) token.complete(); // unblock the stuck caller
      return;
    }
    if (_runningTokens.remove(token)) {
      if (_stack.isNotEmpty) {
        final next = _stack.removeLast(); // LIFO: the top, not the bottom
        _runningTokens.add(next);
        if (!next.isCompleted) next.complete();
      }
      return;
    }
  }

  @visibleForTesting
  int get runningCount => _runningTokens.length;

  @visibleForTesting
  int get waitingCount => _stack.length;
}
