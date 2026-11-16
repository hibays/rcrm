// services/image_load_gate.dart
// The image decode gate: a LIFO stack, not a FIFO queue, so the newest request
// (the picture on screen now) is served next. Releasing a slot hands it to the
// TOP; a repeat request for a queued image calls [restack] instead of pushing a
// second entry. Waiting requests are NOT capped or dropped: a dropped token is
// completed, and its caller then runs the decode — outside the concurrency cap
// and in request order, which is exactly the FIFO behaviour this gate exists to
// remove. Rationale and history: CHANGELOG 44, AGENTS.md.

import 'dart:async';

import 'package:flutter/foundation.dart' show visibleForTesting;

import 'item_cache_limit.dart';

class ImageLoadGate {
  ImageLoadGate._();
  static final ImageLoadGate instance = ImageLoadGate._();

  static final int _max = ItemCacheLimit.imageDecodeConcurrency;

  final _runningTokens = <Completer<void>>{};

  /// Waiting tokens, oldest first: index 0 is the bottom, the end is the top
  /// (served next). Nothing is evicted from here except by [done].
  final _stack = <Completer<void>>[];

  /// Runs at once while there is room, otherwise waits at the TOP of the stack.
  ///
  /// The stack is not capped: its entries are pending [Completer]s, so the
  /// bound that matters is the concurrency cap, and a waiting request must keep
  /// its future open until it is served (or abandoned via [done]).
  Completer<void> acquire() {
    final c = Completer<void>();
    if (_runningTokens.length < _max) {
      _runningTokens.add(c);
      c.complete();
      return c;
    }
    _stack.add(c);
    return c;
  }

  /// Moves a WAITING token to the top: the image was asked for again. A running
  /// or already-completed token is not in the stack, so this is a no-op for it.
  void restack(Completer<void> token) {
    if (_stack.remove(token)) _stack.add(token);
  }

  /// Removes a waiting token that was abandoned before its turn, or hands a
  /// running slot to the TOP.
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
