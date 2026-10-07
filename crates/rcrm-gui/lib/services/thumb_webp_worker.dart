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
//     Dart memory), used for JPEG/PNG/WebP/HEIC everywhere and for everything
//     on desktop.
//   * [generateThumbFromImage] — the encoded AVIF/JXL original
//     → `rcrm_generate_thumb_webp_from_image`, which decodes, downscales and
//     encodes inside Rust. Mobile only; no pixels enter Dart at all.
//
//   main:   calloc(rgba) → send [token, op, ptr, …]      (ints, zero-copy)
//   worker: view the SAME native buffer via Pointer.fromAddress, encode
//           → reply [token, outPtr, outLen]              (ints, zero-copy)
//   main:   wrap the output in a NativeFinalizer view
//
// The worker OWNS the input buffer for the duration of a request and frees it
// when the call returns — including the timeout case, where the old code freed
// a buffer the worker could still be reading.
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
  ReceivePort? _replies;
  Completer<SendPort?>? _handshake;
  bool _dead = false;
  int _generation = 0;
  int _nextToken = 0;
  final Map<int, Completer<_EncodeReply>> _pending = {};
  Future<bool>? _spawnFuture;

  /// Encode [rgba] (w × h × 4) as lossy WebP via the worker isolate —
  /// `rcrm_encode_thumb_webp`, the pixel-input generator. Falls back to a
  /// synchronous encode on the caller thread when the worker is unavailable.
  Future<Uint8List?> encodeRgba(
    Uint8List rgba,
    int w,
    int h, {
    int quality = 82,
  }) async {
    final owned = NativeBytes(
      calloc<Uint8>(rgba.length),
      rgba.length,
      rgba.length,
    );
    owned.view.setAll(0, rgba);
    Uint8List? out;
    try {
      if (await _ensure()) {
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
        }
      }
    } finally {
      // No-op once the worker owns the buffer (see [_request]).
      owned.free();
    }
    return out ?? _encodeSync(rgba, w, h, quality: quality);
  }

  /// Builds a thumbnail **straight from the encoded original**: [head] holds
  /// AVIF/JXL bytes in native memory and Rust decodes → downscales → encodes
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
      debugPrint(
        'ThumbWebpWorker: worker spawn failed — '
        'falling back to synchronous encodes',
      );
      return false;
    }
  }

  /// Sends one request. The worker takes ownership of [owned] once the send
  /// succeeds: it frees the buffer when the FFI call returns, so a timeout here
  /// can never free memory the worker is still reading.
  Future<_EncodeReply?> _request(NativeBytes owned, List<Object> payload) async {
    final gen = _generation;
    final token = ++_nextToken;
    final completer = Completer<_EncodeReply>();
    _pending[token] = completer;
    var handedOver = false;
    try {
      _port!.send([token, ...payload]);
      // The worker frees it; nothing on this side may touch it again.
      handedOver = true;
      owned.disown();
      return await completer.future.timeout(const Duration(seconds: 5));
    } on TimeoutException {
      // Only condemn the CURRENT worker; an older generation may have
      // already been respawned while a stale request was still pending.
      if (gen == _generation) {
        _dead = true;
        debugPrint('ThumbWebpWorker: encode timed out — respawning');
      }
      return null;
    } catch (_) {
      return null;
    } finally {
      if (!handedOver) owned.free();
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
      final c = _pending.remove(msg[0] as int);
      if (c != null) {
        c.complete(_EncodeReply(msg[1] as int, msg[2] as int));
      } else {
        // Orphaned reply: the request timed out (5 s) and was removed from
        // _pending, but the worker still finished the encode. Free the Rust
        // output so it does not leak.
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
    } finally {
      // Rust borrowed the input for the call; the worker owns the allocation.
      calloc.free(input);
    }
    mainPort.send([token, out.address, outLen]);
  });
}
