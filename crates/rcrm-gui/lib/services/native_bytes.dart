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
//     for the software AVIF/JXL/HEIC decoder, used by `AuthImage`, the full-res
//     viewer provider and `DiskThumbImage`.
//   * `disk_thumb_image.dart` → `ThumbWebpWorker.generateThumb` — the
//     compressed original for the on-disk thumbnail cache, where Rust decodes,
//     downscales and encodes WebP without the pixels entering Dart.
//
// Ownership is single and explicit: whoever holds a [NativeBytes] either
// `free()`s it, or `disown()`s it because Rust took over the allocation. The
// routes to Rust differ in what the ABI demands, and the types say which is
// which: the ownership-taking exports (decode, metadata) rebuild their `Vec`
// from the length alone, so they take a [NativeTransfer] — obtainable only from
// a whole-file buffer — while the borrowing exports read a plain [NativeBytes]
// the caller frees afterwards.

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

  /// Bytes actually allocated — for a whole-file fetch this equals [len].
  ///
  /// It is never handed to Rust as a capacity: both ownership-taking ABIs
  /// rebuild their `Vec` from the length alone, so the only sound input is an
  /// allocation of exactly [len] bytes. This field exists so this side can tell
  /// the two shapes apart (see [transferIfWhole]); it is not a promise to Rust.
  final int cap;

  bool _owned;

  /// Set by the first free, whichever path performs it. `reclaim()` runs from
  /// exit handlers and reply handlers that can both observe the same buffer, so
  /// the guard is what keeps a double free from happening at all.
  bool _freed = false;

  NativeBytes(this.ptr, this.len, this.cap) : _owned = true;

  void free() {
    if (_owned && !_freed && ptr != nullptr) {
      _freed = true;
      calloc.free(ptr);
    }
    _owned = false;
  }

  /// Marks the buffer as Rust's: nothing on this side may free it again.
  void disown() => _owned = false;

  /// Whether the buffer has been handed to Rust (or to a worker that owns it).
  /// False means this side still holds the allocation.
  bool get isDisowned => !_owned;

  /// Frees a buffer that was [disown]ed, once the consumer is **provably**
  /// finished with it: either that consumer replied (it has left the call that
  /// was reading the buffer) or its isolate's exit event has been observed (an
  /// isolate that has terminated cannot still be reading — whereas killing one
  /// does not cancel a native call already in flight). Idempotent, because those
  /// two events can both happen for the same buffer.
  void reclaim() {
    if (_freed || ptr == nullptr) return;
    _freed = true;
    calloc.free(ptr);
    _owned = false;
  }

  /// A view over the filled bytes, for tests and for Dart APIs that need a
  /// list (production hands [ptr] to Rust instead).
  Uint8List get view => ptr.asTypedList(len);

  /// The hand-over shape for a buffer Rust is meant to free, or null when this
  /// one is not shaped for it.
  ///
  /// The ownership-taking ABIs rebuild their `Vec` from the **length** alone,
  /// so the buffer must have been allocated with exactly [len] bytes. Only a
  /// whole-file fetch is (a head may be filled only part way, and its
  /// allocation is the ask, not the payload), and this is the only way to get a
  /// [NativeTransfer] — so no call site *can* hand Rust a partial buffer,
  /// however it was reached. Callers that get null fall back to the retryable
  /// "not reusable" path instead of sending a capacity that might be a lie.
  NativeTransfer? transferIfWhole() =>
      len == cap ? NativeTransfer._(this) : null;
}

/// A [NativeBytes] that may be handed to an export which takes ownership.
///
/// Only [NativeBytes.transferIfWhole] produces one, and that refuses anything
/// but a whole-file buffer, so "the allocation is exactly [len] bytes" holds by
/// construction here — the ABI's precondition is a property of the type rather
/// than a comment someone has to honour. Rust then frees the allocation on
/// every path (including its refusals), so [free] after the call would be a
/// double free: the raw pointer and the length are what the call takes, and
/// nothing else on this side may touch the buffer afterwards.
final class NativeTransfer {
  final NativeBytes _bytes;

  NativeTransfer._(this._bytes)
    : assert(
        _bytes.len == _bytes.cap,
        'a partial buffer cannot be transferred',
      );

  /// Address of the allocation — exactly [len] bytes of it.
  Pointer<Uint8> get ptr => _bytes.ptr;

  /// Bytes to hand over, and the size the buffer was allocated with.
  int get len => _bytes.len;

  /// Frees the buffer while this side still owns it — for the paths that fail
  /// before the call (no export, for instance). After the call Rust owns it and
  /// this is a no-op, exactly like [NativeBytes.free] on a disowned buffer.
  /// Idempotent, and it does not resurrect a buffer another route reclaimed.
  void free() => _bytes.free();

  /// Marks the buffer as Rust's, *before* the call, so every path out of the
  /// hand-off — a throw included — leaves it to Rust rather than abandoned.
  void disown() => _bytes.disown();
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
/// Fetches [url] straight into native memory (copy-free path) — see the header
/// for when the result is authoritative.
///
/// **Deadlines are load-bearing.** `sharedHttpClient` bounds only the *connect*
/// phase (`connectionTimeout`) and pooled-idle sockets (`idleTimeout`); a server
/// that accepts and then goes silent keeps a response body open forever. Callers
/// hold an `ImageLoadGate` token across this call, so a wedged fetch would pin
/// the whole grid's thumbnail slots (6 desktop / 2 mobile) and the library would
/// look frozen. [stallTimeout] caps the silence between chunks, [totalTimeout]
/// caps the whole body — both end in `NativeFetch.refused`, never in a hang.
Future<NativeFetch> fetchNativeBytes(
  String url, {
  int? headBytes,
  int maxBytes = 512 << 20,
  Duration stallTimeout = const Duration(seconds: 15),
  Duration totalTimeout = const Duration(seconds: 120),
}) async {
  // ONE budget for the whole request, not one per phase: `getUrl`, `close` and the
  // body loop each starting a fresh `totalTimeout` let a server that accepts and
  // then stalls hold an ImageLoadGate token for ~4 minutes, which is the freeze
  // this method exists to prevent.
  final deadline = DateTime.now().add(totalTimeout);
  Duration remaining() {
    final left = deadline.difference(DateTime.now());
    return left.isNegative ? Duration.zero : left;
  }

  final HttpClientRequest request;
  try {
    // Parse, do NOT re-encode (`Uri.encodeFull` here was the bug). Its
    // ECMA-262 `encodeURI` mask escapes `%`, and callers legitimately hand over
    // URLs that are ALREADY percent-encoded: the cast proxy builds its stream
    // URL as `?path=${Uri.encodeQueryComponent(path)}`
    // (`cast_receiver.dart:637-638`), so re-encoding sent `path=%252Fphotos%2F…`
    // and the proxy's `startsWith('/')` check answered 400 — the copy-free path
    // was never taken for ANY cast image. `Uri.parse` normalises a raw URL
    // instead: spaces and non-ASCII still get escaped, while existing `%XX`
    // escapes are preserved and canonicalised.
    //
    // `MediaItem.url` is canonical (`utils/media_url.dart`): every decoded path
    // segment was encoded exactly once there, so a literal `%20` in a file name
    // arrives here as `%2520`. Encoding again would request `%252520` (a 404).
    // The media model owns that conversion; a caller that hands over a decoded
    // path would still lose the distinction between `%20` and a space, which is
    // why every fetch path takes `MediaItem.url` rather than a path.
    request = await sharedHttpClient
        .getUrl(Uri.parse(url))
        .timeout(remaining());
  } catch (_) {
    return NativeFetch.refused;
  }
  // The map exists but is not guaranteed to carry the key; a missing header
  // must not turn into a null-check throw on the fetch path.
  final token = sharedAuthHeader?['Authorization'];
  if (token != null) request.headers.set('Authorization', token);
  if (headBytes != null) {
    request.headers.set(HttpHeaders.rangeHeader, 'bytes=0-${headBytes - 1}');
  }
  final HttpClientResponse response;
  try {
    response = await request.close().timeout(remaining());
  } catch (_) {
    return NativeFetch.refused;
  }
  if (response.statusCode != 200 && response.statusCode != 206) {
    await response.drain<void>().timeout(remaining()).catchError((_) {});
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
    // Do NOT drain here. Reading the body just to throw it away costs a full
    // download — and a full server-side decryption — that every caller then
    // repeats with the general path, which is exactly the double download the
    // old comment claimed could not happen. Cancelling closes the connection
    // instead, so the fallback pays for the resource once.
    try {
      final sub = response.listen(null);
      await sub.cancel().timeout(remaining());
    } catch (_) {
      // A response that refuses to be cancelled is not worth hanging for.
    }
    return NativeFetch.unsized;
  }

  final buffer = calloc<Uint8>(cap);
  final view = buffer.asTypedList(cap);
  var filled = 0;
  try {
    // `timeout` on the stream (rather than on the future around this loop) is
    // deliberate: it raises *inside* the loop, so the subscription is cancelled
    // before the handler below frees the buffer. Timing out a future would leave
    // the loop writing into freed memory.
    //
    // The loop is NOT left early once the ask is satisfied: a server that
    // under-declares `Content-Length` keeps sending, and stopping at `cap` would
    // hand Rust a truncated prefix that looks like a whole file. Reading to the
    // end of a well-behaved body costs nothing, and anything past `cap` is a
    // mismatch worth refusing.
    await for (final chunk in response.timeout(
      stallTimeout,
      onTimeout: (sink) =>
          sink.addError(TimeoutException('stalled for $stallTimeout')),
    )) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('body exceeded $totalTimeout');
      }
      if (filled == cap) {
        // Only a whole-file fetch can be lied to: `cap` then came from the
        // declared Content-Length, so a further byte means the buffer would be a
        // silently truncated prefix. With `headBytes` the cap IS the ask — a
        // server answering a Range request with 200 and the whole body is
        // normal, and stopping at the cap is the point.
        if (headBytes != null) break;
        calloc.free(buffer);
        return NativeFetch.unsized;
      }
      final room = cap - filled;
      if (chunk.length >= room) {
        view.setRange(filled, filled + room, chunk);
        filled = cap;
        if (headBytes != null) break;
        if (chunk.length > room) {
          // This very chunk already carried the extra bytes.
          calloc.free(buffer);
          return NativeFetch.unsized;
        }
        // Exactly filled: keep reading so the next chunk (if any) is caught above
        // instead of being silently dropped.
        continue;
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
