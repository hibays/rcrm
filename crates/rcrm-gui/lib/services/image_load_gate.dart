// services/image_load_gate.dart
// The image decode gate: a LIFO stack, not a FIFO queue, so the newest request
// (the picture on screen now) is served next. Releasing a slot hands it to the
// TOP; a repeat request for a queued image calls [restack] instead of pushing a
// second entry. Waiting requests are NOT capped, but an abandoned one is
// settled with `false` so its caller skips the decode instead of running it
// outside the concurrency cap (which would restore the old FIFO behaviour).
// A granted token settles with `true`. Rationale and history: CHANGELOG 44,
// AGENTS.md.

import 'dart:async';

import 'package:flutter/foundation.dart' show visibleForTesting;

import 'item_cache_limit.dart';

class ImageLoadGate {
  ImageLoadGate._();
  static final ImageLoadGate instance = ImageLoadGate._();

  static final int _max = ItemCacheLimit.imageDecodeConcurrency;

  // `true` = slot granted, decode now; `false` = abandoned while queued, skip.
  final _runningTokens = <Completer<bool>>{};

  /// Waiting tokens, oldest first: index 0 is the bottom, the end is the top
  /// (served next). Nothing is evicted from here except by [done].
  final _stack = <Completer<bool>>[];

  /// Runs at once while there is room, otherwise waits at the TOP of the stack.
  ///
  /// The stack is not capped: its entries are pending [Completer]s, so the
  /// bound that matters is the concurrency cap, and a waiting request must keep
  /// its future open until it is served (or abandoned via [done]).
  Completer<bool> acquire() {
    final c = Completer<bool>();
    if (_runningTokens.length < _max) {
      _runningTokens.add(c);
      c.complete(true);
      return c;
    }
    _stack.add(c);
    return c;
  }

  /// Moves a WAITING token to the top: the image was asked for again. A running
  /// or already-completed token is not in the stack, so this is a no-op for it.
  void restack(Completer<bool> token) {
    if (_stack.remove(token)) _stack.add(token);
  }

  /// Removes a waiting token that was abandoned before its turn, or hands a
  /// running slot to the TOP.
  void done(Completer<bool> token) {
    if (_stack.remove(token)) {
      // Settle with `false`, never `true`: the caller must skip its decode.
      // Settling with `true` would run it outside the concurrency cap — exactly
      // the FIFO behaviour this LIFO stack replaced.
      if (!token.isCompleted) token.complete(false);
      return;
    }
    if (_runningTokens.remove(token)) {
      if (_stack.isNotEmpty) {
        final next = _stack.removeLast(); // LIFO: the top, not the bottom
        _runningTokens.add(next);
        if (!next.isCompleted) next.complete(true);
      }
      return;
    }
  }

  @visibleForTesting
  int get runningCount => _runningTokens.length;

  @visibleForTesting
  int get waitingCount => _stack.length;
}
