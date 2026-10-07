// services/mobile_image_decoder.dart
// Software decode for AVIF/JXL via Rust FFI — no isolates needed.
// Rust copies data synchronously, spawns a thread, then calls back into
// Dart via NativeCallable.listener when done. The callback lands on the
// main isolate's event loop automatically, so UI work is safe.
//
// The compressed bytes are handed over **in native memory**: either the caller
// fetched them straight into a native buffer ([fetchForDecode] +
// [tryDecodeNative], zero copies) or they arrive as a Dart list and are copied
// into an exactly-sized buffer once ([tryDecode]). The decoded RGBA comes back
// as a native view in [MobileImageDecoder]'s result handling — the return path
// has never copied.

import 'dart:async';
import 'dart:ffi';
import 'dart:typed_data' show Uint8List;
import 'dart:ui' as ui;

import 'package:ffi/ffi.dart';

import '../ffi/rust_bridge.dart';
import 'native_bytes.dart';

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

  /// Software-decode AVIF/JXL [bytes] to a `ui.Codec`, or null when [url]
  /// is not an AVIF/JXL file (Flutter's built-in codec handles the rest).
  ///
  /// [format] overrides the URL-derived format detection. Needed when the
  /// extension is not in the URL path — e.g. the cast receiver fetches
  /// through a proxy URL (`/cast/stream?path=<real path>`) where the file
  /// extension lives in the query parameter.
  static Future<ui.Codec?> tryDecode(
    Uint8List bytes,
    String url, {
    int targetWidth = 0,
    String? format,
  }) async {
    final addr = _addrFor(format ?? _fmt(url));
    if (addr == 0) return null;

    // The decode ABI rebuilds its `Vec` from the length alone, so the buffer
    // must be exactly the payload: allocate it that way and copy once. Callers
    // that can fetch straight into native memory (see [fetchForDecode]) skip
    // even this copy.
    final buffer = calloc<Uint8>(bytes.length);
    buffer.asTypedList(bytes.length).setAll(0, bytes);
    return _dispatch(addr, buffer, bytes.length, targetWidth);
  }

  /// Decodes a payload that already lives in **native memory**, so the
  /// compressed bytes never enter the Dart heap.
  ///
  /// Takes ownership of [head]: every path leaves the buffer either with Rust
  /// (which frees it when the decode finishes) or freed here, so the caller
  /// must not touch it afterwards.
  static Future<ui.Codec?> tryDecodeNative(
    NativeBytes head,
    String url, {
    int targetWidth = 0,
    String? format,
  }) async {
    final addr = _addrFor(format ?? _fmt(url));
    if (addr == 0 || head.len == 0 || head.len != head.cap) {
      // `len != cap` cannot come from [fetchForDecode] (a whole-file fetch is
      // sized exactly); refusing beats handing Rust a buffer whose capacity
      // disagrees with its length.
      head.free();
      return null;
    }
    final data = head.ptr;
    final len = head.len;
    head.disown(); // Rust owns it from here on
    return _dispatch(addr, data, len, targetWidth);
  }

  /// Fetches [url] into native memory for a software decode — null when the
  /// copy-free path does not apply (not an AVIF/JXL file, no decoder in this
  /// build, or the server would not let the buffer be sized exactly). Callers
  /// then fall back to fetching Dart bytes and calling [tryDecode].
  ///
  /// Used by the three places that show an original: `AuthImage` (grid and
  /// strip), the viewer's full-res provider, and `DiskThumbImage`.
  static Future<NativeBytes?> fetchForDecode(String url) async {
    if (_addrFor(_fmt(url)) == 0) return null;
    final fetched = await fetchNativeBytes(url);
    return fetched.bytes;
  }

  /// Rust's `kind_hint` for [url]: 1 = AVIF, 2 = JXL, 0 = neither.
  static int kindHintFor(String url) => switch (_fmt(url)) {
    'avif' => 1,
    'jxl' => 2,
    _ => 0,
  };

  static int _addrFor(String? format) => switch (format) {
    'avif' => RustBridge.decodeAvifAsyncAddr,
    'jxl' => RustBridge.decodeJxlAsyncAddr,
    _ => 0,
  };

  /// How long a decode may take before it counts as unanswered. A lost
  /// callback (a decoder panic, a torn-down isolate) would otherwise leave the
  /// caller's future pending forever.
  static const Duration _decodeTimeout = Duration(seconds: 20);

  /// Hands one buffer to the decoder. Rust takes ownership of `data`.
  static Future<ui.Codec?> _dispatch(
    int addr,
    Pointer<Uint8> data,
    int len,
    int targetWidth,
  ) async {
    _ensureInit();

    final completer = Completer<ui.Codec?>();
    final id = ++_nextId;
    _pending[id] = completer;

    final decodeFn = Pointer<NativeFunction<RcrmDecodeAsyncC>>.fromAddress(
      addr,
    ).asFunction<RcrmDecodeAsyncDart>();

    decodeFn(
      data,
      len,
      targetWidth,
      _callback!.nativeFunction,
      Pointer<Void>.fromAddress(id),
    );

    try {
      return await completer.future.timeout(_decodeTimeout);
    } on TimeoutException {
      // Drop the completer only: the Rust thread still owns the buffer and
      // frees it when it finishes, and a late answer finds nothing to complete.
      _pending.remove(id);
      return null;
    }
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
    var freed = false;
    void freeOnce() {
      if (freed) return;
      freed = true;
      _free(buf);
    }

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
      freeOnce();
      final descriptor = ui.ImageDescriptor.raw(
        buffer,
        width: w,
        height: h,
        pixelFormat: ui.PixelFormat.rgba8888,
      );
      final codec = await descriptor.instantiateCodec();
      completer.complete(codec);
    } catch (_) {
      // The descriptor/instantiateCodec path can throw AFTER the buffer was
      // already freed above — freeOnce() keeps the catch path a single free,
      // so a decode failure can never double-free the Rust DecodeBuf.
      completer.complete(null);
      freeOnce();
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
