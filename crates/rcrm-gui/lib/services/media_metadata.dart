// services/media_metadata.dart
// EXIF / track metadata for the media info panels.
//
// Bytes in, model out: the file is fetched over the same authenticated HTTP
// client the viewer uses and the bytes land **straight in native memory** — the
// network writes them once, into the very buffer Rust parses — so the FFI
// hand-off copies nothing (nom-exif parses in RAM; nothing plaintext ever
// touches disk). The JSON reply is mapped onto a small immutable model. One
// entry point serves images and video/audio containers, so the player can reuse
// it as-is.
//
// Results are cached per URL+kind, so reopening an info sheet is free — but
// only answers that came from real bytes are cached: a fetch that failed or a
// parser that never answered must be retried on the next open instead of being
// remembered as "this file has no information" for the rest of the session.

import 'dart:async';
import 'dart:convert';
import 'dart:ffi';

import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';

import '../ffi/rust_bridge.dart';
import 'native_bytes.dart';

/// What the caller believes the bytes are. [auto] trusts the container header.
enum MetadataKind {
  auto(0),
  image(1),
  track(2);

  const MetadataKind(this.code);
  final int code;
}

/// Camera / capture fields, only the ones the file actually carried.
@immutable
class ExifInfo {
  final String? make;
  final String? model;
  final String? lens;
  final String? software;

  /// Wall-clock capture time (EXIF has no timezone unless the file stored one).
  final DateTime? capturedAt;
  final String? capturedOffset;

  final int? iso;
  final double? fNumber;
  final double? exposureTime; // seconds
  final double? focalLength; // mm
  final int? focalLength35mm;
  final double? exposureBias; // EV
  final bool? flash;

  final int? orientation;
  final int? pixelWidth;
  final int? pixelHeight;

  final double? latitude;
  final double? longitude;
  final double? altitude; // metres

  /// The file embeds a motion-photo video track (Pixel/Samsung style).
  final bool embeddedTrack;

  const ExifInfo({
    this.make,
    this.model,
    this.lens,
    this.software,
    this.capturedAt,
    this.capturedOffset,
    this.iso,
    this.fNumber,
    this.exposureTime,
    this.focalLength,
    this.focalLength35mm,
    this.exposureBias,
    this.flash,
    this.orientation,
    this.pixelWidth,
    this.pixelHeight,
    this.latitude,
    this.longitude,
    this.altitude,
    this.embeddedTrack = false,
  });

  bool get hasLocation => latitude != null && longitude != null;

  /// True when there is something worth showing in a camera section. Stored
  /// pixel dimensions deliberately do NOT count: they belong to the technical
  /// line, and counting them here made the sheet take the "has camera" path
  /// while rendering an empty block — and then suppress the honest
  /// "No camera information" that belongs there.
  bool get hasCamera =>
      _notBlank(make) || _notBlank(model) || _notBlank(lens) || hasExposure;

  bool get hasExposure =>
      iso != null ||
      fNumber != null ||
      exposureTime != null ||
      focalLength != null;

  /// "vivo X100 Pro" — the model often already repeats the make.
  String? get cameraName {
    final m = make?.trim();
    final d = model?.trim();
    if (_notBlank(d) && _notBlank(m)) {
      return d!.toLowerCase().startsWith(m!.toLowerCase()) ? d : '$m $d';
    }
    return _notBlank(d) ? d : (_notBlank(m) ? m : null);
  }

  /// Stored pixel size as the file records it. The decoded size is the one to
  /// show when both are known (orientation is applied at decode time).
  bool get hasPixelSize =>
      pixelWidth != null && pixelHeight != null && pixelWidth! > 0;

  static bool _notBlank(String? s) => s != null && s.trim().isNotEmpty;

  static ExifInfo? fromJson(Map<String, dynamic>? json) {
    if (json == null || json.isEmpty) return null;
    // Type-checked field by field: one wrong-typed value must not discard the
    // rest of the document.
    double? d(String k) {
      final v = json[k];
      return v is num ? v.toDouble() : null;
    }

    int? i(String k) {
      final v = json[k];
      return v is num ? v.round() : null;
    }

    String? s(String k) {
      final v = json[k];
      return v is String && v.trim().isNotEmpty ? v.trim() : null;
    }

    return ExifInfo(
      make: s('make'),
      model: s('model'),
      lens: s('lens'),
      software: s('software'),
      capturedAt: parseExifDateTime(s('capturedAt')),
      capturedOffset: s('capturedOffset'),
      iso: i('iso'),
      fNumber: d('fNumber'),
      exposureTime: d('exposureTime'),
      focalLength: d('focalLength'),
      focalLength35mm: i('focalLength35mm'),
      exposureBias: d('exposureBias'),
      flash: json['flash'] as bool?,
      orientation: i('orientation'),
      pixelWidth: i('pixelWidth'),
      pixelHeight: i('pixelHeight'),
      latitude: _gps(json, 'lat'),
      longitude: _gps(json, 'lon'),
      altitude: _gps(json, 'altitude'),
      embeddedTrack: json['embeddedTrack'] == true,
    );
  }

  /// EXIF stamps are `YYYY-MM-DD HH:MM:SS` (no timezone); `DateTime.parse`
  /// accepts the space separator, and an unparseable string is simply absent.
  @visibleForTesting
  static DateTime? parseExifDateTime(String? raw) {
    if (raw == null) return null;
    return DateTime.tryParse(raw.replaceFirst(' ', 'T'));
  }

  static double? _gps(Map<String, dynamic> json, String key) {
    final gps = json['gps'];
    if (gps is! Map) return null;
    return (gps[key] as num?)?.toDouble();
  }
}

/// Container metadata for video / audio sources.
@immutable
class TrackInfo {
  final String? make;
  final String? model;
  final String? software;
  final String? author;
  final int? durationMs;
  final int? width;
  final int? height;
  final DateTime? createdAt;
  final String? gpsIso6709;

  const TrackInfo({
    this.make,
    this.model,
    this.software,
    this.author,
    this.durationMs,
    this.width,
    this.height,
    this.createdAt,
    this.gpsIso6709,
  });

  bool get hasAny =>
      make != null ||
      model != null ||
      software != null ||
      author != null ||
      durationMs != null ||
      (width != null && height != null) ||
      createdAt != null ||
      gpsIso6709 != null;

  static TrackInfo? fromJson(Map<String, dynamic>? json) {
    if (json == null || json.isEmpty) return null;
    String? s(String k) {
      final v = json[k];
      return v is String && v.trim().isNotEmpty ? v.trim() : null;
    }

    int? i(String k) {
      final v = json[k];
      return v is num ? v.round() : null;
    }

    return TrackInfo(
      make: s('make'),
      model: s('model'),
      software: s('software'),
      author: s('author'),
      durationMs: i('durationMs'),
      width: i('width'),
      height: i('height'),
      createdAt: ExifInfo.parseExifDateTime(s('createdAt')),
      gpsIso6709: s('gpsIso6709'),
    );
  }
}

/// The parsed result. `kind` is what the container turned out to be:
/// `image`, `track`, or `unknown` when the bytes could not be identified.
@immutable
class MediaMetadata {
  final String kind;
  final ExifInfo? exif;
  final TrackInfo? track;
  final String? error;

  const MediaMetadata({
    this.kind = 'unknown',
    this.exif,
    this.track,
    this.error,
  });

  static const none = MediaMetadata();

  bool get isImage => kind == 'image';
  bool get isTrack => kind == 'track';

  /// True when the bytes were identified **and** parsed. Only then may the UI
  /// state an absence ("no camera information", "no location information")
  /// instead of staying silent: a failed parse carries [error], and a fetch
  /// that never got there is [none] with no error at all.
  bool get parsed => error == null && (isImage || isTrack);

  /// Parsed successfully as an image, but the file carries no camera data.
  bool get imageWithoutCamera => isImage && !(exif?.hasCamera ?? false);

  static MediaMetadata fromJsonString(String? json) {
    if (json == null || json.isEmpty) return none;
    try {
      final map = jsonDecode(json) as Map<String, dynamic>;
      return MediaMetadata(
        kind: map['kind'] as String? ?? 'unknown',
        exif: ExifInfo.fromJson(map['exif'] as Map<String, dynamic>?),
        track: TrackInfo.fromJson(map['track'] as Map<String, dynamic>?),
        error: map['error'] as String?,
      );
    } catch (_) {
      return none;
    }
  }
}

/// Fetches and parses metadata, cached per (url, kind).
class MediaMetadataService {
  MediaMetadataService._();

  /// EXIF lives near the start of the file, so only the head is fetched: a
  /// 200 MB TIFF must not be pulled into RAM to read a date.
  static const int maxFetchBytes = 4 * 1024 * 1024;

  static const int _cacheCap = 64;
  static final Map<String, Future<MediaMetadata>> _cache = {};

  /// How long the Rust parser may take before the request is treated as
  /// unanswered. Parsing a 4 MB head is milliseconds of work; this only exists
  /// so a lost callback cannot hang the sheet forever.
  static const Duration _parseTimeout = Duration(seconds: 10);

  /// Metadata for [url]. Never throws: unreachable bytes, a missing bridge
  /// symbol or a parse failure all come back as an empty result, so the UI has
  /// exactly one shape to render.
  static Future<MediaMetadata> forUrl(
    String url, {
    MetadataKind kind = MetadataKind.auto,
  }) {
    final key = '${kind.code}|$url';
    final cached = _cache[key];
    if (cached != null) return cached;
    late final Future<MediaMetadata> future;
    future = _load(url, kind).then(
      (meta) {
        if (meta != null) return meta;
        // No answer to remember: drop the entry so the next open retries.
        if (identical(_cache[key], future)) _cache.remove(key);
        return MediaMetadata.none;
      },
      onError: (Object e, StackTrace _) {
        debugPrint('metadata: $url -> $e');
        if (identical(_cache[key], future)) _cache.remove(key);
        return MediaMetadata.none;
      },
    );
    _cache[key] = future;
    if (_cache.length > _cacheCap) _cache.remove(_cache.keys.first);
    return future;
  }

  /// Drop cached results — used by tests and when the library is re-scanned.
  @visibleForTesting
  static void clearCache() => _cache.clear();

  /// Null when no answer could be obtained (fetch failed, parser timed out).
  static Future<MediaMetadata?> _load(String url, MetadataKind kind) async {
    final NativeBytes? head;
    try {
      head = await _fetchHeadNative(url);
    } catch (e) {
      debugPrint('metadata: $url -> $e');
      return null;
    }
    if (head == null) return null; // refused / unreachable — retryable
    if (head.len == 0) {
      // A genuinely empty file: an authoritative "nothing to read".
      head.free();
      return MediaMetadata.none;
    }
    // From here the buffer belongs to Rust (which frees it) or is freed inside
    // [_parseNative] — this function never touches it again.
    return _parseNative(head, kind);
  }

  /// Fetches the head of [url] **into native memory** — the bytes are written
  /// once, by the network, straight into the buffer Rust reads, so the FFI
  /// hand-off below costs no copy. Null when no answer could be obtained (the
  /// request failed, or the server refused it); a head with `len == 0` is a
  /// real, authoritative "this file is empty".
  static Future<NativeBytes?> _fetchHeadNative(String url) async {
    final fetched = await fetchNativeBytes(url, headBytes: maxFetchBytes);
    // A metadata head is always exactly `maxFetchBytes`, so "unsized" cannot
    // happen here; treat both null flavours as a retryable non-answer.
    return fetched.bytes;
  }

  /// Test hook for [_fetchHeadNative]. Production hands the buffer straight to
  /// Rust and never exposes it, so this is the only way to prove what really
  /// landed in native memory. The caller owns the result and must `free()` it.
  @visibleForTesting
  static Future<NativeBytes?> fetchHead(String url) => _fetchHeadNative(url);

  // ── FFI: async parse on a Rust thread ─────────────────────────────

  static NativeCallable<Void Function(Pointer<Utf8>, Pointer<Void>)>?
  _callback;
  static final Map<int, Completer<MediaMetadata>> _pending = {};
  static int _nextId = 0;

  static void _ensureInit() {
    _callback ??=
        NativeCallable<Void Function(Pointer<Utf8>, Pointer<Void>)>.listener(
          _onParsed,
        );
  }

  /// Null when the parser never answered (timeout) — a retryable non-answer,
  /// not a fact about the file.
  static Future<MediaMetadata?> _parseNative(
    NativeBytes head,
    MetadataKind kind,
  ) async {
    final address = RustBridge.mediaMetadataAsyncAddr;
    // An older bridge without the export will not grow it mid-session: that is
    // a stable "no metadata", not something worth retrying.
    if (address == 0) {
      head.free();
      return MediaMetadata.none;
    }
    _ensureInit();

    final completer = Completer<MediaMetadata>();
    final id = ++_nextId;
    _pending[id] = completer;

    final parse = Pointer<NativeFunction<RcrmMetadataAsyncC>>.fromAddress(
      address,
    ).asFunction<RcrmMetadataAsyncDart>();

    // The one call that moves ownership. The buffer was filled by the network,
    // so nothing is copied here; after this returns Rust owns it and frees it
    // when the parse finishes — including after the timeout below, which is why
    // that path must not free anything either.
    try {
      parse(
        head.ptr,
        head.len,
        head.cap,
        kind.code,
        _callback!.nativeFunction,
        Pointer<Void>.fromAddress(id),
      );
    } catch (_) {
      // Unreachable by construction: the pointer, the lengths and the callback
      // are all non-null/valid by this point. Drop the request rather than free
      // a buffer Rust may already own.
      _pending.remove(id);
      rethrow;
    }
    head.disown();

    try {
      return await completer.future.timeout(_parseTimeout);
    } on TimeoutException {
      // Drop the completer: a late Rust answer then finds nothing to complete
      // and frees its JSON (see [_onParsed]). Returning null keeps the URL
      // out of the cache so reopening the sheet asks again.
      _pending.remove(id);
      return null;
    }
  }

  static void _onParsed(Pointer<Utf8> jsonPtr, Pointer<Void> ctx) {
    final completer = _pending.remove(ctx.address);
    final bridge = RustBridge();
    String? json;
    if (jsonPtr.address != 0) {
      json = jsonPtr.toDartString();
      if (bridge.isLoaded) bridge.freeString(jsonPtr);
    }
    completer?.complete(MediaMetadata.fromJsonString(json));
  }
}
