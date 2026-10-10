// services/mobile_image_decoder.dart
// Software decode for AVIF/JXL/HEIC via Rust FFI — no isolates needed.
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
import 'package:flutter/foundation.dart' show visibleForTesting;

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

  /// Bytes allocated at [data] — mirrors Rust's `DecodeBuf::cap`, which the
  /// decoder sets from the buffer it hands over (a `Vec` may have spare
  /// capacity). Freeing happens in Rust; this side only needs the layout to
  /// match field for field.
  @Size()
  external int cap;
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

  /// Software-decode AVIF/JXL/HEIC (the `mobile-decode` path) to a `ui.Codec`,
  /// or null when [url] is not one of those formats or this build has no
  /// decoder for it (Flutter's built-in codec handles the rest).
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
  /// (which frees it when the decode finishes) or freed here, so the caller must
  /// not touch it afterwards. The hand-off goes through [NativeTransfer], which
  /// can only carry a buffer that is exactly `len` bytes long — the old
  /// `len != cap` comparison is now a property of the type rather than a check
  /// whose comment had to explain why it refuses.
  static Future<ui.Codec?> tryDecodeNative(
    NativeBytes head,
    String url, {
    int targetWidth = 0,
    String? format,
  }) async {
    final addr = _addrFor(format ?? _fmt(url));
    // `len == 0` is decided before the transfer on purpose: a zero-length
    // allocation counts as "whole" (0 == 0), and a transfer built from it would
    // carry a pointer that may be null.
    final transfer = addr == 0 || head.len == 0 ? null : head.transferIfWhole();
    if (transfer == null) {
      head.free();
      return null;
    }
    transfer.disown(); // Rust owns it from here on
    return _dispatch(addr, transfer.ptr, transfer.len, targetWidth);
  }

  /// Fetches [url] into native memory for a software decode — null when the
  /// copy-free path does not apply (not a software-decoded format, no decoder
  /// for it in this build, or the server would not let the buffer be sized
  /// exactly). Callers then fall back to fetching Dart bytes and calling
  /// [tryDecode].
  ///
  /// [format] overrides the URL-derived format detection, exactly as it does in
  /// [tryDecode]/[tryDecodeNative]. Without it a caller whose URL hides the
  /// extension — the cast receiver's proxy URL carries the real path in its
  /// query string — would find no decoder address here and the copy-free path
  /// would never even be attempted.
  ///
  /// Used by the places that show an original: `AuthImage` (grid and strip),
  /// the viewer's full-res provider, `DiskThumbImage`, and the cast receiver.
  static Future<NativeBytes?> fetchForDecode(
    String url, {
    String? format,
  }) async {
    if (_addrFor(format ?? _fmt(url)) == 0) return null;
    final fetched = await fetchNativeBytes(url);
    return fetched.bytes;
  }

  /// The same fetch for the **thumbnail** path, which needs to know *why* it got
  /// nothing: `(bytes, retryWithCopy)`.
  ///
  /// - `(bytes, _)` — feed those bytes to the Rust fast path.
  /// - `(null, true)` — the copy-free hand-off did not apply (a response with no
  ///   usable length, e.g. chunked). The response is cancelled rather than read,
  ///   so nothing reusable came back: the caller fetches it the general way and
  ///   pays for the resource exactly once.
  /// - `(null, false)` — the network already answered (the request was refused, or
  ///   the body was empty), or this build has no Rust decoder for the format.
  ///   Downloading again cannot help in the first case; in the second the caller
  ///   falls through to the ENGINE, a different decoder that may well read what our
  ///   Rust build cannot — a HEIF the `heic` crate refuses without its `av1`/`unci`
  ///   features, or a container that is really JPEG/PNG. The decision belongs to
  ///   `DiskThumbImage._makeThumb`, which is the only caller.
  ///
  /// This is what [`NativeFetch.retryWithCopy`] is for; production used to
  /// ignore the flag and treat "cannot size the buffer" exactly like "not my
  /// format", which cost chunked servers their thumbnails.
  static Future<(NativeBytes?, bool)> fetchForThumb(String url) async {
    if (_addrFor(_fmt(url)) == 0) return (null, false);
    final fetched = await fetchNativeBytes(url);
    return (fetched.bytes, fetched.retryWithCopy);
  }

  /// Rust's `kind_hint` for [url]: 1 = AVIF, 2 = JXL, 3 = HEIC/HEIF, 0 = not
  /// one of them **or** no decoder for it in this build. Returning 0 in the
  /// latter case is what makes the thumbnail fast path fall back to the engine
  /// instead of asking Rust for a format it cannot read.
  static int kindHintFor(String url) {
    final fmt = _fmt(url);
    if (_addrFor(fmt) == 0) return 0;
    return switch (fmt) {
      'avif' => 1,
      'jxl' => 2,
      'heic' => 3,
      _ => 0,
    };
  }

  static int _addrFor(String? format) => switch (format) {
    'avif' => RustBridge.decodeAvifAsyncAddr,
    'jxl' => RustBridge.decodeJxlAsyncAddr,
    'heic' => RustBridge.decodeHeicAsyncAddr,
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

  /// Size of the `DecodeBuf` this side reads (Rust writes it). Pinned by a test
  /// so a field added on one side cannot silently shift the other's reads:
  /// width(4) + height(4) + channels(1) + padding + data_len + cap + data.
  @visibleForTesting
  static int get decodeBufStructSize => sizeOf<_DB>();

  static void _free(Pointer<_DB> buf) {
    final addr = RustBridge.freeDecodeBufAddr;
    if (addr == 0) return;
    Pointer<NativeFunction<Void Function(Pointer<_DB>)>>.fromAddress(
      addr,
    ).asFunction<void Function(Pointer<_DB>)>()(buf);
  }

  // ── helpers ───────────────────────────────────────────────────

  /// The software-decoded format for [url], or null when the engine should
  /// handle it. `heif` and `heic` are the same container (and the same Rust
  /// decoder), so both map to `heic`.
  static String? _fmt(String url) {
    final p = Uri.parse(url).path;
    final d = p.lastIndexOf('.');
    if (d == -1) return null;
    return switch (p.substring(d + 1).toLowerCase()) {
      'avif' => 'avif',
      'jxl' => 'jxl',
      'heic' || 'heif' => 'heic',
      _ => null,
    };
  }
}
