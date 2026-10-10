// services/thumb_webp_worker.dart
// WebP thumbnail encoding off the UI isolate.
//
// DiskThumbImage._makeThumb produces raw RGBA pixels on the UI isolate (the
// engine's ui.Image cannot cross isolates), and the synchronous Rust FFI WebP
// encode would otherwise block the UI thread ~10-40ms per cold cell — the
// frame-drop source on a freshly-opened image wall. This service runs the
// encode in one long-lived worker isolate.
//
// Two ops, one per kind of input (the two Rust generators they call):
//   * [encodeRgba]            — RGBA pixels the engine already decoded
//     → `rcrm_encode_thumb_webp`. The one Dart must copy (dart:ui hands over
//     Dart memory), used for JPEG/PNG/WebP everywhere, for everything on
//     desktop, and for the software-decoded formats whose bytes our own Rust
//     decoder refused (the engine is a different decoder — see _makeThumb).
//   * [generateThumbFromImage] — the encoded AVIF/JXL/HEIC original
//     → `rcrm_generate_thumb_webp_from_image`, which decodes, downscales and
//     encodes inside Rust. Mobile only; no pixels enter Dart at all.
//
//   main:   calloc(rgba) → send [token, op, ptr, …]      (ints, zero-copy)
//   worker: view the SAME native buffer via Pointer.fromAddress, encode
//           → reply [token, outPtr, outLen]              (ints, zero-copy)
//   main:   wrap the output in a NativeFinalizer view
//
// The MAIN isolate owns every input buffer and is the only thing that frees it
// — the worker never does. The worker is handed the buffer for the duration of
// one request and the free happens when its reply proves the native call
// returned, or when that worker's exit event proves the isolate is gone.
// `Isolate.kill` cancels Dart execution, not a native frame already running, so
// anything earlier races a killed worker into freed memory, and letting both
// sides free the same pointer double-frees it.
//
// Copy budget: one memcpy into calloc for [encodeRgba], ZERO for
// [generateThumbFromImage]. The encoded output is never copied either way.

import 'dart:async';
import 'dart:ffi';
import 'dart:isolate';

import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';

import '../ffi/rust_bridge.dart';
import 'native_bytes.dart';

/// Mirrors Rust `webp::WebpBuf { data_len: usize, data: *mut u8 }`.
final class _WebpBuf extends Struct {
  @IntPtr()
  external int dataLen;
  external Pointer<Uint8> data;
}

/// Auto-frees Rust WebP output buffers when the Dart view is GC'd, so the
/// encoded bytes are returned to Dart with ZERO copies (native memory is
/// read in place; the finalizer releases it later).
Pointer<NativeFunction<RcrmFreeWebpBufC>>? _webpFreeFn;

void _ensureWebpFinalizer() {
  if (_webpFreeFn != null) return;
  final addr = RustBridge.freeWebpBufAddr;
  if (addr == 0) return;
  _webpFreeFn = Pointer<NativeFunction<RcrmFreeWebpBufC>>.fromAddress(addr);
}

final class _EncodeReply {
  final int bufPtr;
  final int len;
  const _EncodeReply(this.bufPtr, this.len);
}

/// Request tags for the worker protocol.
const int _opEncodeRgba = 0;
const int _opGenerateThumbFromImage = 1;

class ThumbWebpWorker {
  ThumbWebpWorker._();
  static final ThumbWebpWorker instance = ThumbWebpWorker._();

  SendPort? _port;

  /// The worker isolate itself, so a stuck one can be retired.
  Isolate? _isolate;

  /// Spawning the isolate is quick; the reply is not (see [_request]).
  static const Duration _handshakeTimeout = Duration(seconds: 5);
  static const Duration _replyTimeout = Duration(seconds: 15);
  ReceivePort? _replies;

  /// Termination port of the current worker (see [Isolate.spawn]'s `onExit`).
  ReceivePort? _exits;

  /// The isolate behind [_port]. Tracked separately from [_isolate] because
  /// retiring a worker clears [_isolate] to force a respawn while that isolate
  /// may still be inside a native call — and it is the authority on which input
  /// buffers are still being read.
  Isolate? _portOwner;

  /// Input buffers that are not provably free yet, each paired with the token it
  /// was sent under and the isolate that received it. The main isolate frees one
  /// as soon as EITHER the request's reply arrives (the native call has returned
  /// by then) or that isolate's exit event is observed. Buffers belonging to a
  /// live isolate stay parked, whatever else exits meanwhile.
  final List<(Isolate?, int, NativeBytes)> _orphans = [];

  /// Workers whose exit event has already been observed; an input buffer whose
  /// owner is in here can be freed immediately, because the only thing that
  /// could still read it is provably gone.
  final Set<Isolate> _exitedOwners = {};

  /// Retires the worker whose reply never came: kill it (so it stops burning a
  /// core) and park [owned] until that isolate is provably gone. The next
  /// request spawns a fresh worker, so one stuck encode no longer costs the
  /// following thumbnails a timeout.
  ///
  /// [owner] is the isolate the buffer was actually sent to, captured at send
  /// time — NOT whatever [_portOwner] holds now, which a concurrent retirement
  /// may already have moved on from.
  void _retireStuckWorker(NativeBytes owned, Isolate? owner, int token) {
    _isolate = null;
    _port = null;
    owner?.kill(priority: Isolate.immediate);
    _park(owned, owner, token);
  }

  /// Parks a buffer until [owner]'s exit event (or its late reply) releases it.
  /// A stale request whose worker was already superseded parks here too: the
  /// buffer was disowned at send time, so nothing else can free it.
  void _park(NativeBytes owned, Isolate? owner, int token) {
    _orphans.add((owner, token, owned));
    if (owner == null || _exitedOwners.contains(owner)) {
      // Nothing can still be reading it: free now instead of waiting for an exit
      // event that will never come again.
      _reclaimOrphans();
    }
  }

  /// Frees the parked buffers whose owner is provably gone.
  void _reclaimOrphans() {
    _orphans.removeWhere((entry) {
      final (owner, _, buffer) = entry;
      if (owner != null && !_exitedOwners.contains(owner)) return false;
      buffer.reclaim();
      return true;
    });
    _exitedOwners.removeWhere(
      (isolate) => !_orphans.any((entry) => entry.$1 == isolate),
    );
  }
  Completer<SendPort?>? _handshake;
  bool _dead = false;
  int _generation = 0;
  int _nextToken = 0;
  final Map<int, Completer<_EncodeReply>> _pending = {};

  /// Buffers whose request is still waiting for a reply, by token. The reply
  /// path frees them (the worker has returned from the native call by then);
  /// anything parked in [_orphans] is not listed here any more.
  final Map<int, NativeBytes> _inflight = {};
  Future<bool>? _spawnFuture;

  /// Encode [rgba] (w × h × 4) as lossy WebP via the worker isolate —
  /// `rcrm_encode_thumb_webp`, the pixel-input generator. Falls back to a
  /// synchronous encode on the caller thread when the worker is unavailable.
  ///
  /// **One copy, and only if it is needed.** The pixels arrive in a Dart buffer
  /// (`dart:ui` hands them over that way, and nothing can point Rust at a Dart
  /// heap object that the GC may move), so crossing into native memory costs
  /// exactly one copy. This makes sure it is exactly one: the copy happens after
  /// the worker is known to be usable, and if the send never reached the worker
  /// the synchronous fallback re-encodes from that *same* buffer instead of
  /// allocating a second one.
  Future<Uint8List?> encodeRgba(
    Uint8List rgba,
    int w,
    int h, {
    int quality = 82,
  }) async {
    if (!await _ensure()) {
      // No worker at all: the one copy happens inside [_encodeSync].
      return _encodeSync(rgba, w, h, quality: quality);
    }
    final owned = NativeBytes(
      calloc<Uint8>(rgba.length),
      rgba.length,
      rgba.length,
    );
    owned.view.setAll(0, rgba);
    Uint8List? out;
    try {
      final reply = await _request(owned, [
        _opEncodeRgba,
        owned.ptr.address,
        rgba.length,
        w,
        h,
        quality,
      ]);
      if (reply != null && reply.bufPtr != 0) {
        out = _attachFinalizerView(reply.bufPtr, reply.len);
      } else if (!owned.isDisowned) {
        // The worker never got it (send failed, or the worker died before the
        // hand-off): reuse this buffer rather than copying the pixels again.
        out = _encodeSync(rgba, w, h, quality: quality, reuse: owned);
      }
    } finally {
      // No-op once the worker owns the buffer (see [_request]).
      owned.free();
    }
    return out;
  }

  /// Builds a thumbnail **straight from the encoded original**: [head] holds
  /// AVIF/JXL/HEIC bytes in native memory and Rust decodes → downscales → encodes
  /// WebP (`rcrm_generate_thumb_webp_from_image`), so the pixels never enter
  /// the Dart heap — three full-frame copies saved per cached thumbnail.
  ///
  /// The image-input half of the pair; [encodeRgba] is the pixel half. Called
  /// by `DiskThumbImage._makeThumbInRust` for the on-disk thumbnail cache.
  /// Takes ownership of [head] — freed on every path, including this one
  /// failing. Returns null when the worker or the bridge cannot do it, and the
  /// caller then uses the general path (which fetches its own bytes).
  Future<Uint8List?> generateThumbFromImage(
    NativeBytes head, {
    required int targetWidth,
    required int kindHint,
    int quality = 82,
  }) async {
    if (RustBridge.generateThumbWebpFromImageAddr == 0 || targetWidth <= 0) {
      head.free();
      return null;
    }
    final address = head.ptr.address;
    final len = head.len;
    try {
      // No synchronous fallback on purpose: a full decode + encode on the UI
      // thread is exactly what this worker exists to avoid.
      if (!await _ensure()) return null;
      final reply = await _request(head, [
        _opGenerateThumbFromImage,
        address,
        len,
        targetWidth,
        quality,
        kindHint,
      ]);
      if (reply == null || reply.bufPtr == 0) return null;
      return _attachFinalizerView(reply.bufPtr, reply.len);
    } finally {
      // No-op once the worker owns the buffer (see [_request]).
      head.free();
    }
  }

  Future<bool> _ensure() {
    final port = _port;
    if (port != null && !_dead) return Future.value(true);
    return _spawnFuture ??= _spawn().whenComplete(() => _spawnFuture = null);
  }

  Future<bool> _spawn() async {
    _dead = false;
    _generation++;
    _replies?.close();
    final replies = ReceivePort();
    _replies = replies;
    final exits = ReceivePort();
    _exits = exits;
    final handshake = Completer<SendPort?>();
    _handshake = handshake;
    Isolate? spawned;
    try {
      spawned = await Isolate.spawn(
        thumbWebpWorkerMain,
        replies.sendPort,
        // Fires when the isolate is really gone — the only moment the buffers it
        // was handed become safe to free (see [_retireStuckWorker]).
        onExit: exits.sendPort,
      );
      final worker = spawned;
      _isolate = worker;
      _portOwner = worker;
      replies.listen(_onReply);
      exits.listen((_) {
        exits.close();
        _exitedOwners.add(worker);
        if (identical(_exits, exits)) {
          // The current worker died on its own: stop handing it work, so the
          // next request respawns instead of waiting out a full reply timeout on
          // a port nobody reads any more.
          _exits = null;
          _dead = true;
          _port = null;
          _isolate = null;
        }
        _reclaimOrphans();
      });
      final port = await handshake.future.timeout(_handshakeTimeout);
      _port = port;
      return port != null;
    } catch (_) {
      // Leave nothing behind: a half-spawned worker keeps a thread alive with an
      // open port, and `_isolate` would be overwritten by the next spawn, so it
      // could never be killed again.
      spawned?.kill(priority: Isolate.immediate);
      if (identical(_isolate, spawned)) {
        _isolate = null;
        _portOwner = null;
      }
      _port = null;
      _exits = null;
      _handshake = null;
      if (!handshake.isCompleted) handshake.complete(null);
      exits.close();
      replies.close();
      _dead = true;
      debugPrint(
        'ThumbWebpWorker: worker spawn failed — '
        'falling back to synchronous encodes',
      );
      return false;
    }
  }

  /// Sends one request. [owned] stays the MAIN isolate's responsibility (see the
  /// file comment): it is freed when the reply proves the worker returned from
  /// the native call, or when that worker's exit event proves it is gone.
  Future<_EncodeReply?> _request(NativeBytes owned, List<Object> payload) async {
    final gen = _generation;
    final token = ++_nextToken;
    // The isolate this buffer is really going to, captured before any await: a
    // concurrent retirement may move [_portOwner] on, and the buffer must stay
    // attached to whatever can still read it.
    final owner = _portOwner;
    final completer = Completer<_EncodeReply>();
    _pending[token] = completer;
    _inflight[token] = owned;
    try {
      _port!.send([token, ...payload]);
      // Park the free with the worker machinery: nothing here may touch the
      // buffer again (the caller's `free()` is a no-op once disowned).
      owned.disown();
      // Generous on purpose: one reply is a full decode + downscale + WebP
      // encode, and a 16–48 MP HEIC on a slow phone can take seconds. A too-tight
      // timeout costs the thumbnail (and a worker respawn), not a hang — the
      // caller falls back — but it looks exactly like "nothing decoded".
      return await completer.future.timeout(_replyTimeout);
    } on TimeoutException {
      _inflight.remove(token);
      // Only condemn the CURRENT worker; an older generation may already have
      // been respawned while this stale request was still pending. The buffer is
      // parked with the isolate that really received it either way, and nothing
      // frees it before that isolate is provably gone.
      if (gen == _generation) {
        _dead = true;
        debugPrint('ThumbWebpWorker: encode timed out — retiring the worker');
        _retireStuckWorker(owned, owner, token);
      } else {
        _park(owned, owner, token);
      }
      return null;
    } catch (_) {
      // The send never happened, so this side still owns the buffer and the
      // caller's `finally` frees it.
      _inflight.remove(token);
      return null;
    } finally {
      _pending.remove(token);
    }
  }

  void _onReply(dynamic msg) {
    final hs = _handshake;
    if (msg is SendPort) {
      if (hs != null && !hs.isCompleted) hs.complete(msg);
      return;
    }
    if (msg is int) {
      // -1: the worker could not load the bridge — fall back permanently.
      if (hs != null && !hs.isCompleted) hs.complete(null);
      _dead = true;
      debugPrint(
        'ThumbWebpWorker: bridge load failed in worker isolate — '
        'falling back to synchronous encodes',
      );
      return;
    }
    if (msg is List<dynamic>) {
      final token = msg[0] as int;
      // The worker reached this reply *after* returning from the native call, so
      // the buffer it was reading is free again — the fast path that keeps a
      // healthy worker from accumulating parked buffers.
      _releaseInput(token);
      final c = _pending.remove(token);
      if (c != null) {
        c.complete(_EncodeReply(msg[1] as int, msg[2] as int));
      } else {
        // Orphaned reply: the request timed out (15 s) and was parked, but the
        // worker still finished the encode. Free the Rust output so it does not
        // leak.
        final outPtr = msg[1] as int;
        if (outPtr != 0) {
          final bridge = _loadedBridge();
          if (bridge != null) {
            bridge.freeWebpBuf(Pointer<Void>.fromAddress(outPtr).cast<Void>());
          }
        }
      }
    }
  }

  /// Frees the input buffer of [token]: from the live map when the request is
  /// still outstanding, otherwise from the parked list it moved to on timeout.
  /// A reply is proof that the worker is not inside that call any more, which is
  /// what makes freeing here safe.
  void _releaseInput(int token) {
    final live = _inflight.remove(token);
    if (live != null) {
      live.reclaim();
      return;
    }
    _orphans.removeWhere((entry) {
      final (_, parkedToken, buffer) = entry;
      if (parkedToken != token) return false;
      buffer.reclaim();
      return true;
    });
  }

  /// Wrap the worker's native WebP output in a zero-copy Dart view; the
  /// finalizer frees the Rust buffer when the view is GC'd.
  static Uint8List? _attachFinalizerView(int bufPtr, int len) {
    final bridge = _loadedBridge();
    if (bridge == null) return null;
    final structPtr = Pointer<Void>.fromAddress(bufPtr).cast<_WebpBuf>();
    if (structPtr.ref.data == nullptr || len <= 0) {
      bridge.freeWebpBuf(structPtr.cast<Void>());
      return null;
    }
    _ensureWebpFinalizer();
    final fin = _webpFreeFn;
    if (fin != null) {
      return structPtr.ref.data.asTypedList(
        len,
        finalizer: fin,
        token: structPtr.cast<Void>(),
      );
    }
    // Fallback (finalizer unavailable): copy + free immediately.
    final bytes = Uint8List.fromList(structPtr.ref.data.asTypedList(len));
    bridge.freeWebpBuf(structPtr.cast<Void>());
    return bytes;
  }

  static RustBridge? _loadedBridge() {
    final b = RustBridge();
    if (!b.isLoaded) {
      try {
        b.load();
      } catch (_) {
        return null;
      }
    }
    return b;
  }

  /// Synchronous fallback (old behavior): encode on the caller's thread.
  /// Returns null if the bridge is unavailable or encoding fails.
  ///
  /// [reuse] is a buffer the caller already filled with [rgba]: passing it keeps
  /// the fallback at the same single copy as the worker path, instead of
  /// allocating and copying the pixels a second time. A reused buffer stays the
  /// caller's to free.
  static Uint8List? _encodeSync(
    Uint8List rgba,
    int w,
    int h, {
    int quality = 82,
    NativeBytes? reuse,
  }) {
    final bridge = _loadedBridge();
    if (bridge == null) return null;
    final owned =
        reuse ?? NativeBytes(calloc<Uint8>(rgba.length), rgba.length, rgba.length);
    if (reuse == null) owned.view.setAll(0, rgba);
    final ptr = bridge.encodeThumbWebp(owned.ptr, rgba.length, w, h, quality);
    if (reuse == null) owned.free();
    if (ptr == nullptr) return null;
    final buf = ptr.cast<_WebpBuf>().ref;
    final len = buf.dataLen;
    if (buf.data == nullptr || len <= 0) {
      bridge.freeWebpBuf(ptr);
      return null;
    }
    _ensureWebpFinalizer();
    final fin = _webpFreeFn;
    if (fin != null) {
      return buf.data.asTypedList(len, finalizer: fin, token: ptr);
    }
    final bytes = Uint8List.fromList(buf.data.asTypedList(len));
    bridge.freeWebpBuf(ptr);
    return bytes;
  }
}

/// Worker isolate entry point. Binds the two WebP symbols (plus the one-call
/// decoder when the build has it) and serves requests until the isolate dies.
/// All replies go back to [mainPort]; the first message is this isolate's
/// request port (handshake).
///
/// The worker frees the input buffer of every request: it owns it from the
/// moment the main isolate sent it, and only the worker knows when Rust has
/// finished reading it.
@pragma('vm:entry-point')
void thumbWebpWorkerMain(SendPort mainPort) {
  final requests = ReceivePort();
  try {
    RustBridge().load();
  } catch (_) {
    mainPort.send(-1);
    return;
  }
  mainPort.send(requests.sendPort);
  requests.listen((msg) {
    final req = msg as List<dynamic>;
    final token = req[0] as int;
    final op = req[1] as int;
    final input = Pointer<Uint8>.fromAddress(req[2] as int);
    Pointer<Void> out = nullptr;
    var outLen = 0;
    try {
      final bridge = RustBridge();
      if (op == _opEncodeRgba) {
        final result = bridge.encodeThumbWebp(
          input,
          req[3] as int,
          req[4] as int,
          req[5] as int,
          req[6] as int,
        );
        out = result;
        if (result != nullptr) outLen = result.cast<_WebpBuf>().ref.dataLen;
      } else {
        final generate = Pointer<NativeFunction<RcrmGenerateThumbWebpFromImageC>>
            .fromAddress(RustBridge.generateThumbWebpFromImageAddr)
            .asFunction<RcrmGenerateThumbWebpFromImageDart>();
        final result = generate(
          input,
          req[3] as int,
          req[4] as int,
          req[5] as int,
          req[6] as int,
        );
        out = result;
        if (result != nullptr) outLen = result.cast<_WebpBuf>().ref.dataLen;
      }
    } catch (_) {
      out = nullptr;
      outLen = 0;
    }
    // Rust borrowed the input for the call; the MAIN isolate owns that
    // allocation and frees it once this worker is provably done with it (its
    // reply, or this isolate's exit). Freeing it here would double-free it, and
    // a killed worker never reaches this code again to free it at all.
    mainPort.send([token, out.address, outLen]);
  });
}
