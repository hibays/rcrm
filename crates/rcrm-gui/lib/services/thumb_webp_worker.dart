// services/thumb_webp_worker.dart
// WebP thumbnail encoding off the UI isolate.
//
// DiskThumbImage._makeThumb produces raw RGBA pixels on the UI isolate (the
// engine's ui.Image cannot cross isolates), and the synchronous Rust FFI WebP
// encode would otherwise block the UI thread ~10-40ms per cold cell — the
// frame-drop source on a freshly-opened image wall. This service runs the
// encode in one long-lived worker isolate:
//
//   main:   calloc(rgba) → send [token, ptr, len, w, h, q]  (ints, zero-copy)
//   worker: view the SAME native buffer via Pointer.fromAddress, encode
//           → reply [token, outPtr, outLen]                (ints, zero-copy)
//   main:   free the input, wrap the output in a NativeFinalizer view
//
// Copy budget per thumbnail: 1 RGBA memcpy into calloc (same as before) and
// zero copies of the encoded WebP output. The FFI stall moves entirely off the
// UI thread. On any worker failure the call falls back to a synchronous
// encode on the caller's thread (the old behavior).

import 'dart:async';
import 'dart:ffi';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../ffi/rust_bridge.dart';

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

class ThumbWebpWorker {
  ThumbWebpWorker._();
  static final ThumbWebpWorker instance = ThumbWebpWorker._();

  SendPort? _port;
  ReceivePort? _replies;
  Completer<SendPort?>? _handshake;
  bool _dead = false;
  int _generation = 0;
  int _nextToken = 0;
  final Map<int, Completer<_EncodeReply>> _pending = {};
  Future<bool>? _spawnFuture;

  /// Encode [rgba] (w × h × 4) as lossy WebP via the worker isolate.
  /// Falls back to a synchronous encode on the caller thread when the worker
  /// is unavailable or a request fails.
  Future<Uint8List?> encode(
    Uint8List rgba,
    int w,
    int h, {
    int quality = 82,
  }) async {
    final reply = await _ensure() ? await _request(rgba, w, h, quality) : null;
    if (reply != null && reply.bufPtr != 0) {
      final bytes = _attachFinalizerView(reply.bufPtr, reply.len);
      if (bytes != null) return bytes;
    }
    return _encodeSync(rgba, w, h, quality: quality);
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
    final handshake = Completer<SendPort?>();
    _handshake = handshake;
    try {
      await Isolate.spawn(thumbWebpWorkerMain, replies.sendPort);
      replies.listen(_onReply);
      final port = await handshake.future.timeout(const Duration(seconds: 5));
      _port = port;
      return port != null;
    } catch (_) {
      _dead = true;
      _port = null;
      return false;
    }
  }

  Future<_EncodeReply?> _request(
    Uint8List rgba,
    int w,
    int h,
    int quality,
  ) async {
    final gen = _generation;
    final token = ++_nextToken;
    final completer = Completer<_EncodeReply>();
    _pending[token] = completer;
    final buf = calloc<Uint8>(rgba.length);
    buf.asTypedList(rgba.length).setAll(0, rgba);
    _port!.send([token, buf.address, rgba.length, w, h, quality]);
    try {
      return await completer.future.timeout(const Duration(seconds: 15));
    } on TimeoutException {
      // Only condemn the CURRENT worker; an older generation may have
      // already been respawned while a stale request was still pending.
      if (gen == _generation) _dead = true;
      return null;
    } finally {
      calloc.free(buf);
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
      return;
    }
    if (msg is List<dynamic>) {
      final c = _pending.remove(msg[0] as int);
      if (c != null) {
        c.complete(_EncodeReply(msg[1] as int, msg[2] as int));
      }
    }
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
  static Uint8List? _encodeSync(
    Uint8List rgba,
    int w,
    int h, {
    int quality = 82,
  }) {
    final bridge = _loadedBridge();
    if (bridge == null) return null;
    final data = calloc<Uint8>(rgba.length);
    data.asTypedList(rgba.length).setAll(0, rgba);
    final ptr = bridge.encodeThumbWebp(data, rgba.length, w, h, quality);
    calloc.free(data);
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

/// Worker isolate entry point. Binds the two WebP symbols and serves encode
/// requests until the isolate dies. All replies go back to [mainPort]; the
/// first message is this isolate's request port (handshake).
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
    try {
      final input = Pointer<Uint8>.fromAddress(req[1] as int);
      final len = req[2] as int;
      final w = req[3] as int;
      final h = req[4] as int;
      final q = req[5] as int;
      final out = RustBridge().encodeThumbWebp(input, len, w, h, q);
      final outLen = out.cast<_WebpBuf>().ref.dataLen;
      mainPort.send([token, out.address, outLen]);
    } catch (_) {
      mainPort.send([token, 0, 0]);
    }
  });
}
