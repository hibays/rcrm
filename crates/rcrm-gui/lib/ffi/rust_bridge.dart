// ffi/rust_bridge.dart
// RCrm GUI — dart:ffi bindings to rcrm-flutter-bridge
//
// All symbols registered once here.  MobileImageDecoder reuses the
// same DynamicLibrary + cached function addresses.

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

/// Native layout of the Rust `WebpBuf` struct (data_len + data pointer),
/// returned by `rcrm_generate_qr_webp` and `rcrm_encode_thumb_webp`.
final class _QrWebpBuf extends Struct {
  @IntPtr()
  external int dataLen;
  external Pointer<Uint8> data;
}

// ── C function typedefs ──────────────────────────────────────────

typedef RcrmStartServerC =
    Int32 Function(
      Pointer<Utf8> dirsJson,
      Pointer<Utf8> password,
      Pointer<Utf8> bindAddr,
      Uint16 port,
    );
typedef RcrmStartServerDart =
    int Function(
      Pointer<Utf8> dirsJson,
      Pointer<Utf8> password,
      Pointer<Utf8> bindAddr,
      int port,
    );

typedef RcrmStopServerC = Int32 Function(Int32 handle);
typedef RcrmStopServerDart = int Function(int handle);

typedef RcrmGetServerUrlC = Pointer<Utf8> Function(Int32 handle);
typedef RcrmGetServerUrlDart = Pointer<Utf8> Function(int handle);

typedef RcrmGetServerStatusC = Int32 Function(Int32 handle);
typedef RcrmGetServerStatusDart = int Function(int handle);

typedef RcrmCryptFolderC =
    Int32 Function(Pointer<Utf8> path, Pointer<Utf8> password, Int32 isEncrypt);
typedef RcrmCryptFolderDart =
    int Function(Pointer<Utf8> path, Pointer<Utf8> password, int isEncrypt);

typedef RcrmLastVerifyC = Pointer<Utf8> Function();
typedef RcrmLastVerifyDart = Pointer<Utf8> Function();

typedef RcrmFreeStringC = Void Function(Pointer<Utf8> ptr);
typedef RcrmFreeStringDart = void Function(Pointer<Utf8> ptr);

typedef RcrmLastErrorC = Pointer<Utf8> Function();
typedef RcrmLastErrorDart = Pointer<Utf8> Function();

typedef RcrmGetAuthCredentialsC = Pointer<Utf8> Function(Int32 handle);
typedef RcrmGetAuthCredentialsDart = Pointer<Utf8> Function(int handle);

typedef RcrmVersionC = Pointer<Utf8> Function();
typedef RcrmVersionDart = Pointer<Utf8> Function();

typedef RcrmIsBlankFrameC = Int32 Function(Pointer<Uint8> data, IntPtr len);
typedef RcrmIsBlankFrameDart = int Function(Pointer<Uint8> data, int len);

typedef RcrmSetLogLevelC = Void Function(Uint8 level);
typedef RcrmSetLogLevelDart = void Function(int level);

typedef RcrmGenTvCertC = Pointer<Utf8> Function();
typedef RcrmGenTvCertDart = Pointer<Utf8> Function();

// ── QR decode (cast pairing scanning, all platforms) ──────────────

typedef RcrmDecodeQrC = Pointer<Utf8> Function(Pointer<Uint8> data, IntPtr len);
typedef RcrmDecodeQrDart = Pointer<Utf8> Function(Pointer<Uint8> data, int len);

typedef RcrmDecodeQrBgraC =
    Pointer<Utf8> Function(
      Pointer<Uint8> data,
      IntPtr len,
      Uint32 width,
      Uint32 height,
      Uint32 rowStride,
    );
typedef RcrmDecodeQrBgraDart =
    Pointer<Utf8> Function(
      Pointer<Uint8> data,
      int len,
      int width,
      int height,
      int rowStride,
    );

typedef RcrmDecodeQrLumaC =
    Pointer<Utf8> Function(
      Pointer<Uint8> data,
      IntPtr len,
      Uint32 width,
      Uint32 height,
      Uint32 rowStride,
    );
typedef RcrmDecodeQrLumaDart =
    Pointer<Utf8> Function(
      Pointer<Uint8> data,
      int len,
      int width,
      int height,
      int rowStride,
    );

// ── Mobile image decoder typedefs (shared with MobileImageDecoder) ──

/// Native callback: Rust calls this from a background thread after decode.
/// Dart side uses `NativeCallable.listener` so the call is routed to the
/// main isolate's event loop automatically.
typedef RcrmDecodeResultC = Void Function(Pointer<Void> buf, Pointer<Void> ctx);

/// Async decode: copies data synchronously, spawns thread, returns
/// immediately. Result delivered via `callback`.
typedef RcrmDecodeAsyncC =
    Void Function(
      Pointer<Uint8> data,
      IntPtr len,
      Uint32 tw,
      Pointer<NativeFunction<RcrmDecodeResultC>> callback,
      Pointer<Void> ctx,
    );
typedef RcrmDecodeAsyncDart =
    void Function(
      Pointer<Uint8> data,
      int len,
      int tw,
      Pointer<NativeFunction<RcrmDecodeResultC>> callback,
      Pointer<Void> ctx,
    );

typedef RcrmFreeDecodeBufC = Void Function(Pointer<Void> ptr);
typedef RcrmFreeDecodeBufDart = void Function(Pointer<Void> ptr);

// ── Thumbnail WebP encoding (all platforms) ──────────────────

typedef RcrmWebpBufC =
    Pointer<Void> Function(
      Pointer<Uint8> data,
      IntPtr len,
      Uint32 width,
      Uint32 height,
      Uint8 quality,
    );
typedef RcrmWebpBufDart =
    Pointer<Void> Function(
      Pointer<Uint8> data,
      int len,
      int width,
      int height,
      int quality,
    );

typedef RcrmGenerateQrWebpC =
    Pointer<Void> Function(Pointer<Uint8> data, IntPtr len);
typedef RcrmGenerateQrWebpDart =
    Pointer<Void> Function(Pointer<Uint8> data, int len);

typedef RcrmFreeWebpBufC = Void Function(Pointer<Void> ptr);
typedef RcrmFreeWebpBufDart = void Function(Pointer<Void> ptr);

// ── Bridge class ─────────────────────────────────────────────────

class RustBridge {
  static RustBridge? _instance;
  DynamicLibrary? _lib;
  bool _loaded = false;

  late RcrmStartServerDart startServer;
  late RcrmStopServerDart stopServer;
  late RcrmGetServerUrlDart getServerUrl;
  late RcrmGetServerStatusDart getServerStatus;
  late RcrmCryptFolderDart cryptFolder;
  late RcrmLastVerifyDart lastVerify;
  late RcrmGetAuthCredentialsDart getAuthCredentials;
  late RcrmFreeStringDart freeString;
  late RcrmLastErrorDart lastError;
  late RcrmVersionDart version;
  late RcrmSetLogLevelDart _setLogLevelFfi;
  late RcrmIsBlankFrameDart isBlankFrame;
  late RcrmGenTvCertDart _genTvCert;
  late RcrmDecodeQrDart _decodeQr;
  late RcrmDecodeQrBgraDart _decodeQrBgra;
  late RcrmDecodeQrLumaDart _decodeQrLuma;
  late RcrmWebpBufDart encodeThumbWebp;
  late RcrmFreeWebpBufDart freeWebpBuf;
  late RcrmGenerateQrWebpDart _generateQrWebp;

  /// Raw function addresses for MobileImageDecoder (cached, avoid per-decode
  /// dlsym).
  static int decodeAvifAsyncAddr = 0;
  static int decodeJxlAsyncAddr = 0;
  static int freeDecodeBufAddr = 0;

  /// Raw address of `rcrm_free_webp_buf`, for the NativeFinalizer that
  /// auto-frees WebP output buffers when the Dart view is GC'd (zero-copy
  /// return path).
  static int freeWebpBufAddr = 0;

  /// The native library handle — MobileImageDecoder reuses this to avoid a
  /// second dlopen. null until [load] is called.
  DynamicLibrary? get nativeLib => _lib;

  factory RustBridge() {
    _instance ??= RustBridge._();
    return _instance!;
  }

  RustBridge._();

  bool get isLoaded => _loaded;

  void load() {
    if (_loaded) return;

    if (Platform.isAndroid) {
      _lib = DynamicLibrary.open('librcrm_flutter_bridge.so');
    } else if (Platform.isIOS) {
      _lib = DynamicLibrary.process();
    } else if (Platform.isWindows) {
      _lib = DynamicLibrary.open('rcrm_flutter_bridge.dll');
    } else if (Platform.isLinux) {
      _lib = DynamicLibrary.open('librcrm_flutter_bridge.so');
    } else if (Platform.isMacOS) {
      _lib = DynamicLibrary.open('librcrm_flutter_bridge.dylib');
    } else {
      throw UnsupportedError(
        'Unsupported platform: ${Platform.operatingSystem}',
      );
    }
    _bindFunctions();
    _loaded = true;
  }

  void _bindFunctions() {
    startServer = _lib!.lookupFunction<RcrmStartServerC, RcrmStartServerDart>(
      'rcrm_start_server',
    );
    stopServer = _lib!.lookupFunction<RcrmStopServerC, RcrmStopServerDart>(
      'rcrm_stop_server',
    );
    getServerUrl = _lib!
        .lookupFunction<RcrmGetServerUrlC, RcrmGetServerUrlDart>(
          'rcrm_get_server_url',
        );
    getServerStatus = _lib!
        .lookupFunction<RcrmGetServerStatusC, RcrmGetServerStatusDart>(
          'rcrm_get_server_status',
        );
    cryptFolder = _lib!.lookupFunction<RcrmCryptFolderC, RcrmCryptFolderDart>(
      'rcrm_crypt_folder',
    );
    lastVerify = _lib!.lookupFunction<RcrmLastVerifyC, RcrmLastVerifyDart>(
      'rcrm_last_verify',
    );
    freeString = _lib!.lookupFunction<RcrmFreeStringC, RcrmFreeStringDart>(
      'rcrm_free_string',
    );
    getAuthCredentials = _lib!
        .lookupFunction<RcrmGetAuthCredentialsC, RcrmGetAuthCredentialsDart>(
          'rcrm_get_auth_credentials',
        );
    lastError = _lib!.lookupFunction<RcrmLastErrorC, RcrmLastErrorDart>(
      'rcrm_last_error',
    );
    version = _lib!.lookupFunction<RcrmVersionC, RcrmVersionDart>(
      'rcrm_version',
    );
    isBlankFrame = _lib!
        .lookupFunction<RcrmIsBlankFrameC, RcrmIsBlankFrameDart>(
          'rcrm_is_blank_frame',
        );
    _setLogLevelFfi = _lib!
        .lookupFunction<RcrmSetLogLevelC, RcrmSetLogLevelDart>(
          'rcrm_set_log_level',
        );
    _genTvCert = _lib!.lookupFunction<RcrmGenTvCertC, RcrmGenTvCertDart>(
      'rcrm_generate_tv_cert',
    );
    _decodeQr = _lib!.lookupFunction<RcrmDecodeQrC, RcrmDecodeQrDart>(
      'rcrm_decode_qr',
    );
    _decodeQrBgra = _lib!
        .lookupFunction<RcrmDecodeQrBgraC, RcrmDecodeQrBgraDart>(
          'rcrm_decode_qr_bgra',
        );
    _decodeQrLuma = _lib!
        .lookupFunction<RcrmDecodeQrLumaC, RcrmDecodeQrLumaDart>(
          'rcrm_decode_qr_luma',
        );
    encodeThumbWebp = _lib!.lookupFunction<RcrmWebpBufC, RcrmWebpBufDart>(
      'rcrm_encode_thumb_webp',
    );
    freeWebpBuf = _lib!.lookupFunction<RcrmFreeWebpBufC, RcrmFreeWebpBufDart>(
      'rcrm_free_webp_buf',
    );
    _generateQrWebp = _lib!
        .lookupFunction<RcrmGenerateQrWebpC, RcrmGenerateQrWebpDart>(
          'rcrm_generate_qr_webp',
        );
    freeWebpBufAddr = _lib!
        .lookup<NativeFunction<RcrmFreeWebpBufC>>('rcrm_free_webp_buf')
        .address;
    // mobile-decode gated — present on mobile builds; absent on desktop.
    // Decode symbols are #[cfg(mobile-decode)] gated — absent on desktop.
    // On mobile a missing symbol is a build bug: let it throw (fail-fast).
    if (Platform.isAndroid || Platform.isIOS) {
      decodeAvifAsyncAddr = _lib!
          .lookup<NativeFunction<RcrmDecodeAsyncC>>('rcrm_decode_avif_async')
          .address;
      decodeJxlAsyncAddr = _lib!
          .lookup<NativeFunction<RcrmDecodeAsyncC>>('rcrm_decode_jxl_async')
          .address;
      freeDecodeBufAddr = _lib!
          .lookup<NativeFunction<RcrmFreeDecodeBufC>>('rcrm_free_decode_buf')
          .address;
    } else {
      try {
        decodeAvifAsyncAddr = _lib!
            .lookup<NativeFunction<RcrmDecodeAsyncC>>('rcrm_decode_avif_async')
            .address;
      } catch (_) {}
      try {
        decodeJxlAsyncAddr = _lib!
            .lookup<NativeFunction<RcrmDecodeAsyncC>>('rcrm_decode_jxl_async')
            .address;
      } catch (_) {}
      try {
        freeDecodeBufAddr = _lib!
            .lookup<NativeFunction<RcrmFreeDecodeBufC>>('rcrm_free_decode_buf')
            .address;
      } catch (_) {}
    }
  }

  // ── Convenience methods ──────────────────────────────────────

  String? _readString(Pointer<Utf8> ptr) {
    if (ptr == nullptr) return null;
    final result = ptr.toDartString();
    freeString(ptr);
    return result;
  }

  String? _getLastError() => _readString(lastError());

  /// Overwrite a native UTF-8 buffer with zeros, then free it. Used for
  /// password buffers so the plaintext doesn't linger in freed native heap.
  void _zeroAndFree(Pointer<Utf8> ptr) {
    final n = ptr.length; // strlen (content bytes, excluding null terminator)
    final bytes = ptr.cast<Uint8>();
    for (var i = 0; i <= n; i++) {
      bytes[i] = 0; // wipe content + null terminator
    }
    calloc.free(ptr);
  }

  /// Start the WebDAV server. Returns handle (>0) or -1.
  int startWebDavServer({
    required List<String> directories,
    required List<String> passwords,
    String bindAddress = '127.0.0.1',
    int port = 8080,
  }) {
    final dirsJson = jsonEncode(directories);
    final pwJson = jsonEncode(passwords); // ["pw1","pw2"] — multi-password
    final dirsPtr = dirsJson.toNativeUtf8();
    final pwPtr = pwJson.toNativeUtf8();
    final bindPtr = bindAddress.toNativeUtf8();
    final result = startServer(dirsPtr, pwPtr, bindPtr, port);
    calloc.free(dirsPtr);
    _zeroAndFree(pwPtr); // wipe plaintext passwords before free
    calloc.free(bindPtr);
    return result;
  }

  /// Stop the WebDAV server.
  bool stopWebDavServer(int handle) => stopServer(handle) == 0;

  /// Get the server URL (e.g. "http://127.0.0.1:8080/").
  String? getServerUrlString(int handle) => _readString(getServerUrl(handle));

  /// Get server status: 2=running, 1=starting, 0=idle, -1=error, -2=locked.
  int getServerStatusValue(int handle) => getServerStatus(handle);

  /// Encrypt or decrypt a folder.
  bool cryptFolderOp(String path, String password, {required bool encrypt}) {
    final pathPtr = path.toNativeUtf8();
    final pwPtr = password.toNativeUtf8();
    final result = cryptFolder(pathPtr, pwPtr, encrypt ? 1 : 0);
    calloc.free(pathPtr);
    _zeroAndFree(pwPtr); // wipe plaintext password before free
    return result == 0;
  }

  /// Read the result of the most recent startWebDavServer verification:
  /// {encrypted, locked}. `locked` = encrypted files no key opened.
  Map<String, dynamic>? lastVerifyResult() {
    final jsonStr = _readString(lastVerify());
    if (jsonStr == null) return null;
    try {
      return jsonDecode(jsonStr) as Map<String, dynamic>;
    } catch (_) {
      return null;
    }
  }

  /// Get the bridge library version.  String? getBridgeVersion() => _readString(version());

  /// Get server auth credentials as a map: {"username": "...", "password": "..."}.
  Map<String, String>? getAuthCredentialsMap(int handle) {
    final ptr = getAuthCredentials(handle);
    final jsonStr = _readString(ptr);
    if (jsonStr == null) return null;
    try {
      final map = jsonDecode(jsonStr) as Map<String, dynamic>;
      return {
        'username': map['username'] as String,
        'password': map['password'] as String,
      };
    } catch (_) {
      return null;
    }
  }

  /// Get the last error message.
  String? getLastErrorMessage() => _getLastError();

  /// Set the Rust-side log level. 0=silent, 1=errors, 2=info, 3=debug.
  void setLogLevel(int level) {
    if (!_loaded) return;
    _setLogLevelFfi(level.clamp(0, 3));
  }

  /// Generate a self-signed TLS cert + PKCS#8 key for the TV cast receiver.
  /// Returns {"cert": ..., "key": ...} or {} on failure. The PEM strings use
  /// CRLF line endings (rcgen output) — the caller must write them verbatim.
  Map<String, String> generateTvCert() {
    if (!_loaded) return const {};
    final ptr = _genTvCert();
    final jsonStr = _readString(ptr); // frees the native string
    if (jsonStr == null) return const {};
    try {
      final map = jsonDecode(jsonStr) as Map<String, dynamic>;
      final cert = map['cert'] as String?;
      final key = map['key'] as String?;
      if (cert == null || key == null) return const {};
      return {'cert': cert, 'key': key};
    } catch (_) {
      return const {};
    }
  }

  /// Decode the first QR code from a JPEG camera frame.
  ///
  /// Returns the QR payload text, or null when no QR code is readable.
  /// [jpeg] is copied into native heap for the call and freed automatically;
  /// safe to reuse the same buffer afterwards.
  String? decodeQrFromJpeg(Uint8List jpeg) {
    if (!_loaded || jpeg.isEmpty) return null;
    final ptr = calloc<Uint8>(jpeg.length);
    ptr.asTypedList(jpeg.length).setAll(0, jpeg);
    try {
      return _parseQrResult(_readString(_decodeQr(ptr, jpeg.length)));
    } finally {
      calloc.free(ptr);
    }
  }

  /// Decode the first QR code from a raw BGRA8888 frame (the format iOS'
  /// frame stream emits). [rowStride] is the byte distance between row
  /// starts (iOS CVPixelBuffer rows are 64-byte aligned, so bytesPerRow
  /// can exceed width*4). Same contract as [decodeQrFromJpeg].
  String? decodeQrFromBgra(
    Uint8List bgra,
    int width,
    int height,
    int rowStride,
  ) {
    if (!_loaded || bgra.isEmpty) return null;
    final ptr = calloc<Uint8>(bgra.length);
    ptr.asTypedList(bgra.length).setAll(0, bgra);
    try {
      return _parseQrResult(
        _readString(_decodeQrBgra(ptr, bgra.length, width, height, rowStride)),
      );
    } finally {
      calloc.free(ptr);
    }
  }

  /// Decode the first QR code from a greyscale frame (e.g. the Y plane of a
  /// yuv420 frame-stream image). [rowStride] is the byte distance between
  /// row starts (CameraX Y rows are padded). Same contract as
  /// [decodeQrFromJpeg].
  String? decodeQrFromLuma(
    Uint8List luma,
    int width,
    int height,
    int rowStride,
  ) {
    if (!_loaded || luma.isEmpty) return null;
    final ptr = calloc<Uint8>(luma.length);
    ptr.asTypedList(luma.length).setAll(0, luma);
    try {
      return _parseQrResult(
        _readString(_decodeQrLuma(ptr, luma.length, width, height, rowStride)),
      );
    } finally {
      calloc.free(ptr);
    }
  }

  String? _parseQrResult(String? json) {
    if (json == null) return null;
    try {
      final map = jsonDecode(json) as Map<String, dynamic>;
      return map['content'] as String?;
    } catch (_) {
      return null;
    }
  }

  /// Generate a pairing QR code as lossless WebP bytes (2048×2048).
  ///
  /// Returns null when the bridge is unavailable or generation fails. The
  /// returned view is backed by the Rust buffer with a finalizer that frees
  /// it on GC — safe to hand to Image.memory and drop.
  Uint8List? generateQrWebp(String payload) {
    if (!_loaded || payload.isEmpty) return null;
    // UTF-8 bytes (payloads are ASCII today, but stay correct if a QR name
    // ever carries non-ASCII — the length must match the native buffer).
    final bytes = utf8.encode(payload);
    final ptr = calloc<Uint8>(bytes.length);
    ptr.asTypedList(bytes.length).setAll(0, bytes);
    try {
      final out = _generateQrWebp(ptr, bytes.length);
      if (out == nullptr) return null;
      final buf = out.cast<_QrWebpBuf>().ref;
      if (buf.data == nullptr || buf.dataLen <= 0) {
        freeWebpBuf(out);
        return null;
      }
      final len = buf.dataLen;
      final addr = freeWebpBufAddr;
      if (addr != 0) {
        final fin = Pointer<NativeFunction<RcrmFreeWebpBufC>>.fromAddress(addr);
        return buf.data.asTypedList(len, finalizer: fin, token: out);
      }
      final copy = Uint8List.fromList(buf.data.asTypedList(len));
      freeWebpBuf(out);
      return copy;
    } finally {
      calloc.free(ptr);
    }
  }
}
