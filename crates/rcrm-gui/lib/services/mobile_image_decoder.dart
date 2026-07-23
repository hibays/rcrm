// services/mobile_image_decoder.dart
// Software decode for AVIF/JXL via Rust FFI — no isolates needed.
// Rust copies data synchronously, spawns a thread, then calls back into
// Dart via NativeCallable.listener when done. The callback lands on the
// main isolate's event loop automatically, so UI work is safe.

import 'dart:async';
import 'dart:ffi';
import 'dart:typed_data' show Uint8List;
import 'dart:ui' as ui;

import 'package:ffi/ffi.dart';

import '../ffi/rust_bridge.dart';

final class _DB extends Struct {
  @Uint32()
  external int width;
  @Uint32()
  external int height;
  @Uint8()
  external int channels;
  @Size()
  external int dataLen;
  external Pointer<Uint8> data;
}

class MobileImageDecoder {
  MobileImageDecoder._();

  // ── Persistent NativeCallable ──────────────────────────────────

  // Single listener shared across all decode requests. Rust calls this
  // from a background thread; NativeCallable.listener schedules it on
  // the main isolate's event loop.
  static NativeCallable<Void Function(Pointer<Void>, Pointer<Void>)>? _callback;
  static bool _init = false;

  static void _ensureInit() {
    if (_init) return;
    _init = true;
    _callback =
        NativeCallable<Void Function(Pointer<Void>, Pointer<Void>)>.listener(
          _onDecodeResult,
        );
  }

  // ── Pending request tracking ────────────────────────────────────

  static final _pending = <int, Completer<ui.Codec?>>{};
  static int _nextId = 0;

  // ── Public decode entry ───────────────────────────────────────

  static Future<ui.Codec?> tryDecode(
    Uint8List bytes,
    String url, {
    int targetWidth = 0,
  }) async {
    final addr = switch (_fmt(url)) {
      'avif' => RustBridge.decodeAvifAsyncAddr,
      'jxl' => RustBridge.decodeJxlAsyncAddr,
      _ => 0,
    };
    if (addr == 0) return null;

    _ensureInit();

    final completer = Completer<ui.Codec?>();
    final id = ++_nextId;
    _pending[id] = completer;

    final decodeFn = Pointer<NativeFunction<RcrmDecodeAsyncC>>.fromAddress(
      addr,
    ).asFunction<RcrmDecodeAsyncDart>();

    final dp = calloc<Uint8>(bytes.length);
    dp.asTypedList(bytes.length).setAll(0, bytes);
    // Rust takes ownership of dp via Vec::from_raw_parts — never free it here.
    decodeFn(
      dp,
      bytes.length,
      targetWidth,
      _callback!.nativeFunction,
      Pointer<Void>.fromAddress(id),
    );

    return completer.future;
  }

  // ── Result callback (main isolate event loop) ──────────────────

  static void _onDecodeResult(Pointer<Void> bufPtr, Pointer<Void> ctx) {
    final id = ctx.address;
    final completer = _pending.remove(id);
    if (completer == null) {
      // Cancelled or orphaned — free the Rust buffer if present.
      if (bufPtr.address != 0) _free(bufPtr.cast<_DB>());
      return;
    }
    _processResult(bufPtr.cast<_DB>(), completer);
  }

  // ── Result processing (fire-and-forget async) ──────────────────

  static Future<void> _processResult(
    Pointer<_DB> buf,
    Completer<ui.Codec?> completer,
  ) async {
    try {
      if (buf.address == 0) {
        completer.complete(null);
        return;
      }
      final rgba = buf.ref.data.asTypedList(buf.ref.dataLen);
      final w = buf.ref.width;
      final h = buf.ref.height;
      final buffer = await ui.ImmutableBuffer.fromUint8List(rgba);
      // ImmutableBuffer owns its own copy — free the Rust buffer now.
      _free(buf);
      final descriptor = ui.ImageDescriptor.raw(
        buffer,
        width: w,
        height: h,
        pixelFormat: ui.PixelFormat.rgba8888,
      );
      final codec = await descriptor.instantiateCodec();
      completer.complete(codec);
    } catch (_) {
      completer.complete(null);
      _free(buf);
    }
  }

  // ── Free Rust DecodeBuf ────────────────────────────────────────

  static void _free(Pointer<_DB> buf) {
    final addr = RustBridge.freeDecodeBufAddr;
    if (addr == 0) return;
    Pointer<NativeFunction<Void Function(Pointer<_DB>)>>.fromAddress(
      addr,
    ).asFunction<void Function(Pointer<_DB>)>()(buf);
  }

  // ── helpers ───────────────────────────────────────────────────

  static String? _fmt(String url) {
    final p = Uri.parse(url).path;
    final d = p.lastIndexOf('.');
    if (d == -1) return null;
    final e = p.substring(d + 1).toLowerCase();
    return e == 'avif'
        ? 'avif'
        : e == 'jxl'
        ? 'jxl'
        : null;
  }
}
