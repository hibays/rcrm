// services/native_bytes.dart
// Fetching media straight into NATIVE memory.
//
// Every byte that reaches Rust has to exist in native memory, and the obvious
// shape — fetch a Dart `Uint8List`, then `calloc` + `setAll` it into a buffer —
// copies the whole payload a second time for nothing. This helper streams the
// response into a calloc'd buffer instead, so the payload is written exactly
// once (by the network, into the buffer Rust is about to read) and the FFI
// hand-off copies nothing at all.
//
// **Who uses it:**
//   * `media_metadata.dart` — the EXIF/track head for the viewer's info sheet
//     (`headBytes`: a Range request, never the whole file).
//   * `mobile_image_decoder.dart` → `fetchForDecode` — the compressed original
//     for the software AVIF/JXL decoder, used by `AuthImage`, the full-res
//     viewer provider and `DiskThumbImage`.
//   * `disk_thumb_image.dart` → `ThumbWebpWorker.generateThumb` — the
//     compressed original for the on-disk thumbnail cache, where Rust decodes,
//     downscales and encodes WebP without the pixels entering Dart.
//
// Ownership is single and explicit: whoever holds a [NativeBytes] either
// `free()`s it, or `disown()`s it because Rust took over the allocation.

import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'net.dart';

/// A payload that lives in native memory (see the file comment).
class NativeBytes {
  final Pointer<Uint8> ptr;

  /// Bytes filled — 0 for a genuinely empty response.
  final int len;

  /// Bytes actually allocated. Rust rebuilds the allocation with this when it
  /// takes ownership, and a whole-file fetch requires `len == cap` because the
  /// decoders' ABI reconstructs their `Vec` from the length alone.
  final int cap;

  bool _owned;

  NativeBytes(this.ptr, this.len, this.cap) : _owned = true;

  void free() {
    if (_owned && ptr != nullptr) calloc.free(ptr);
    _owned = false;
  }

  /// Marks the buffer as Rust's: nothing on this side may free it again.
  void disown() => _owned = false;

  /// A view over the filled bytes, for tests and for Dart APIs that need a
  /// list (production hands [ptr] to Rust instead).
  Uint8List get view => ptr.asTypedList(len);
}

/// Outcome of [fetchNativeBytes].
class NativeFetch {
  /// The buffer, when one was produced.
  final NativeBytes? bytes;

  /// True when the copy-free path did not apply for a reason a plain Dart fetch
  /// could still get past — the server declared no usable `Content-Length`, so
  /// the buffer could not be sized exactly. False for a refused, unreachable or
  /// truncated response, where retrying the same request changes nothing.
  final bool retryWithCopy;

  const NativeFetch(this.bytes, {this.retryWithCopy = false});

  /// The request itself failed (or was refused): nothing was read.
  static const refused = NativeFetch(null);

  /// The response arrived but could not be sized copy-free.
  static const unsized = NativeFetch(null, retryWithCopy: true);
}

/// Fetches [url] into native memory, with the same auth header the rest of the
/// app uses.
///
/// [headBytes] sends `Range: bytes=0-(headBytes-1)` and allocates exactly that
/// — a metadata head, which must never pull a 200 MB file into RAM.
///
/// Without it the whole body is fetched, and the buffer is sized from the
/// server's `Content-Length`: a response of unknown length, or one that does
/// not fill the buffer exactly, comes back as [NativeFetch.unsized] because
/// handing Rust a buffer whose capacity disagrees with its length would be
/// unsound. `Content-Encoding` disqualifies it too — the declared length would
/// describe the compressed bytes while the stream yields decoded ones.
Future<NativeFetch> fetchNativeBytes(
  String url, {
  int? headBytes,
  int maxBytes = 512 << 20,
}) async {
  final HttpClientRequest request;
  try {
    request = await sharedHttpClient.getUrl(Uri.parse(Uri.encodeFull(url)));
  } catch (_) {
    return NativeFetch.refused;
  }
  final auth = sharedAuthHeader;
  if (auth != null) {
    request.headers.set('Authorization', auth['Authorization']!);
  }
  if (headBytes != null) {
    request.headers.set(HttpHeaders.rangeHeader, 'bytes=0-${headBytes - 1}');
  }
  final HttpClientResponse response;
  try {
    response = await request.close();
  } catch (_) {
    return NativeFetch.refused;
  }
  if (response.statusCode != 200 && response.statusCode != 206) {
    await response.drain<void>();
    return NativeFetch.refused;
  }

  int? cap;
  if (headBytes != null) {
    cap = headBytes;
  } else {
    final encoding = response.headers.value(HttpHeaders.contentEncodingHeader);
    final declared = response.contentLength;
    // A declared zero is an authoritative empty body, not an unknown length.
    if (encoding == null && declared >= 0 && declared <= maxBytes) {
      cap = declared;
    }
  }
  if (cap == null) {
    await response.drain<void>();
    return NativeFetch.unsized;
  }

  final buffer = calloc<Uint8>(cap);
  final view = buffer.asTypedList(cap);
  var filled = 0;
  try {
    // Leaving the loop cancels the subscription, which is what we want once the
    // ask is satisfied (the Range header or the declared length is the ask).
    await for (final chunk in response) {
      final room = cap - filled;
      if (chunk.length >= room) {
        view.setRange(filled, filled + room, chunk);
        filled = cap;
        break;
      }
      view.setRange(filled, filled + chunk.length, chunk);
      filled += chunk.length;
    }
  } catch (_) {
    calloc.free(buffer);
    return NativeFetch.refused;
  }
  if (headBytes == null && filled != cap) {
    // Short read: the capacity no longer describes the payload.
    calloc.free(buffer);
    return NativeFetch.unsized;
  }
  if (filled == 0) {
    calloc.free(buffer);
    return NativeFetch(NativeBytes(nullptr, 0, 0));
  }
  return NativeFetch(NativeBytes(buffer, filled, cap));
}
