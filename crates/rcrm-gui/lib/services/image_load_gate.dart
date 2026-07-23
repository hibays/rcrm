// services/image_load_gate.dart
// Concurrency gate for image decoding. At most [_max] decodes run at once
// (platform-tuned). A cell acquires a token before resolving its image and
// calls done(token) on first frame / error / dispose. Cells that scroll off
// before running just drop their queued token (freeing nothing, blocking
// no one), so visible cells are never starved and a freshly-opened grid
// never saturates the CPU (which froze the whole UI).
//
// Queue has a maximum depth safety net: when _waiters exceeds [_maxQueue] the
// oldest entry is evicted. Its _load() resumes on the completed token: if the
// cell is unmounted it bails immediately; if still mounted (e.g. off-screen
// within the grid cache extent) it decodes, but it was never in [_runningTokens]
// so it does not occupy a real slot — the concurrency limit stays intact.
// This prevents runaway queue accumulation from rapid scrolling.

import 'dart:async';
import 'item_cache_limit.dart';

class ImageLoadGate {
  ImageLoadGate._();
  static final ImageLoadGate instance = ImageLoadGate._();

  static final int _max = ItemCacheLimit.imageDecodeConcurrency;
  static final int _maxQueue = ItemCacheLimit.imageDecodeQueueMax;
  final _runningTokens = <Completer<void>>{};
  final _waiters = <Completer<void>>[];

  /// Acquire a slot. Await [Completer.future]; pass the token to [done] later.
  Completer<void> acquire() {
    final c = Completer<void>();
    if (_runningTokens.length < _max) {
      _runningTokens.add(c);
      c.complete();
    } else {
      // Safety net: if queue too deep, evict oldest waiter.
      if (_waiters.length >= _maxQueue) {
        final evicted = _waiters.removeAt(0);
        if (!evicted.isCompleted) evicted.complete();
      }
      _waiters.add(c);
    }
    return c;
  }

  /// Release the token. If it was still queued (cell scrolled off before its
  /// turn) it is simply dropped; if it was running, the slot is handed to the
  /// next waiter.
  void done(Completer<void> token) {
    // Was queued (or evicted), never actually ran.
    if (_waiters.remove(token)) {
      if (!token.isCompleted) token.complete(); // unblock the stuck _load()
      return;
    }
    // Was genuinely running → release the slot to the next waiter.
    if (_runningTokens.remove(token)) {
      if (_waiters.isNotEmpty) {
        final next = _waiters.removeAt(0);
        if (!next.isCompleted) next.complete();
        _runningTokens.add(next);
      }
      return;
    }
    // Token was neither running nor queued (e.g. evicted from queue, its
    // _load() resumed and called done() via _teardown). No-op: the real
    // slot was never occupied by this token.
  }
}
