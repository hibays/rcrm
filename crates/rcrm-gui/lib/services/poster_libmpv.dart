// services/poster_libmpv.dart
// The libmpv poster backend: the poster is rendered INSIDE libmpv, in Rust.
//
// `rcrm_generate_poster_async` runs on a Rust thread — it loads the file with
// libmpv, seeks to each candidate position, draws the frame into native memory
// with the software renderer, blank-tests it and encodes it as WebP — and
// answers through a `NativeCallable`. No pixel, and no frame buffer, ever
// enters the Dart heap.
//
// Which platforms use it is `utils/poster_backend.dart`'s decision, not this
// file's: iOS cannot load its statically linked libmpv, so it keeps the
// media_kit backend (`poster_mpv.dart`), and a bridge built without the
// `libmpv-poster` feature falls back there too.

import 'dart:async';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../ffi/rust_bridge.dart';
import '../utils/poster_frame.dart';

/// Status codes the Rust export reports, mirroring `poster_status` in
/// `crates/rcrm-flutter-bridge/src/lib.rs`.
class _PosterStatus {
  static const int ok = 0;
  static const int noFrame = 1;
  static const int unavailable = 2;
}

/// What one libmpv run produced.
class LibMpvPosterResult {
  /// The poster bytes, or null when this run produced none.
  final Uint8List? bytes;

  /// True when the backend itself cannot run here (no usable libmpv in this
  /// build or on this machine). Every file would fail the same way, so the
  /// caller should switch to the media_kit backend instead of retrying.
  final bool unavailable;

  const LibMpvPosterResult({this.bytes, this.unavailable = false});
}

class LibMpvPoster {
  LibMpvPoster._();

  /// Rust answers on its own thread; `NativeCallable.listener` delivers the
  /// call to the main isolate's event loop, so the completer below can be
  /// completed without any isolate hand-off.
  static NativeCallable<Void Function(Pointer<Void>, Int32, Pointer<Void>)>?
  _callback;

  static final _pending = <int, Completer<LibMpvPosterResult>>{};
  static int _nextId = 0;

  /// How long a poster may take before it counts as unanswered.
  ///
  /// Longer than Rust's own 40 s job budget on purpose: the Rust side always
  /// answers (every stage has a deadline), so this only covers a callback lost
  /// to something genuinely broken — and it must not fire first, or a slow 4K
  /// poster over a network would be cancelled just before it arrived.
  static const Duration _timeout = Duration(seconds: 60);

  /// Render a poster for [url] with libmpv itself.
  ///
  /// [headers] is the §Authorization§ header the server wants; it reaches libmpv
  /// as §http-header-fields§ and never appears in the URL. [durationHint] is the
  /// length the library scan knows; libmpv reads the real duration itself and
  /// skips any candidate at or past it, so the hint only shapes the plan.
  ///
  /// Returns bytes, or §unavailable§ when this build/machine has no libmpv to
  /// render with. A null result with §unavailable == false§ simply means no
  /// usable frame was found for this file.
  static Future<LibMpvPosterResult> generate(
    String url, {
    required Map<String, String> headers,
    required Duration durationHint,
    int targetWidth = 640,
    int quality = 82,
  }) async {
    final address = RustBridge.libmpvPosterAddr;
    if (address == 0) {
      return const LibMpvPosterResult(unavailable: true);
    }
    _ensureCallback();

    final urlPtr = url.toNativeUtf8();
    final headersPtr = _headerBlock(headers).toNativeUtf8();
    // Where to look is the same rule as the media_kit backend's, so both look
    // at the same places; libmpv enforces the real length on top of it.
    final positionsPtr = posterSeekPlan(durationHint)
        .map((seconds) => seconds.toStringAsFixed(3))
        .join(',')
        .toNativeUtf8();
    final completer = Completer<LibMpvPosterResult>();
    final id = ++_nextId;
    _pending[id] = completer;
    try {
      Pointer<NativeFunction<RcrmGeneratePosterAsyncC>>.fromAddress(address)
          .asFunction<RcrmGeneratePosterAsyncDart>()(
        urlPtr,
        headersPtr,
        positionsPtr,
        targetWidth,
        quality,
        _callback!.nativeFunction,
        Pointer<Void>.fromAddress(id),
      );
    } finally {
      // Borrowed and copied by Rust before it returns.
      calloc.free(urlPtr);
      calloc.free(headersPtr);
      calloc.free(positionsPtr);
    }
    try {
      return await completer.future.timeout(_timeout);
    } on TimeoutException {
      // Drop the completer only: a late answer finds nothing to complete and
      // frees its own buffer (see [_onResult]).
      _pending.remove(id);
      return const LibMpvPosterResult();
    }
  }

  /// The header block Rust turns into libmpv's `http-header-fields`, in the
  /// same CRLF-separated shape the app's other HTTP tools take.
  static String _headerBlock(Map<String, String>? headers) {
    if (headers == null || headers.isEmpty) return '';
    return headers.entries
        .map((entry) => '${entry.key}: ${entry.value}')
        .join('\r\n');
  }

  static void _ensureCallback() {
    _callback ??=
        NativeCallable<
          Void Function(Pointer<Void>, Int32, Pointer<Void>)
        >.listener(_onResult);
  }

  static void _onResult(Pointer<Void> buffer, int status, Pointer<Void> ctx) {
    final completer = _pending.remove(ctx.address);
    if (completer == null) {
      // Cancelled or timed out: the Rust buffer is still ours to free.
      _free(buffer);
      return;
    }
    completer.complete(_decodeResult(buffer, status));
  }

  static LibMpvPosterResult _decodeResult(Pointer<Void> buffer, int status) {
    switch (status) {
      case _PosterStatus.ok:
        // Only an "ok" answer carries a buffer; anything else here is a bug in
        // the Rust side, and the buffer (if any) is freed rather than shown.
        final bytes = RustBridge.webpBufBytes(buffer.cast<RustWebpBuf>());
        return LibMpvPosterResult(bytes: bytes);
      case _PosterStatus.unavailable:
        return const LibMpvPosterResult(unavailable: true);
      case _PosterStatus.noFrame:
      default:
        _free(buffer);
        return const LibMpvPosterResult();
    }
  }

  static void _free(Pointer<Void> buffer) {
    if (buffer == nullptr) return;
    final bridge = RustBridge();
    if (!bridge.isLoaded) return;
    bridge.freeWebpBuf(buffer);
  }
}
