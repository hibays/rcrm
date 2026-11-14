// services/bounded_fetch.dart
// The Dart-bytes fetch: an original read into a Dart list, with deadlines that
// actually bound the *body*.
//
// `sharedHttpClient` bounds only the connect phase (`connectionTimeout`) and
// pooled idle sockets (`idleTimeout`); neither bounds an in-flight body, so a
// server that accepts the request and then goes silent leaves the future pending
// forever — it neither completes nor errors. The copy-free path has always been
// bounded (`fetchNativeBytes` in `native_bytes.dart`); this is the same bound
// for the callers that need the bytes as a Dart list: `AuthImage`, the viewer's
// full-res provider, and `DiskThumbImage`'s thumbnailing fallback.
//
// **Why the bound is load-bearing.** Both of those image paths hold an
// `ImageLoadGate` token across the fetch. A wedged response would never let
// `PooledImage.onError` fire, so the token is never released: the cell spins
// forever and, with as many such cells as the gate's width (2 on mobile), the
// whole image wall stops loading.
//
// **Timeouts are exceptions, not sentinels.** Every caller's error handling is
// exception-driven: `PooledImage` retries with backoff and then paints its error
// tile, and the viewer's `_FullResImageProvider.onErr` evicts the cache entry.
// Returning null instead would leave the cell in exactly the spinning state this
// file exists to prevent.

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'net.dart';

/// Silence between two body chunks that counts as a stalled server. Mirrors the
/// default in `fetchNativeBytes`.
const Duration kBoundedFetchStall = Duration(seconds: 15);

/// Budget for one whole request, from `getUrl` to the last body byte. Mirrors
/// the default in `fetchNativeBytes`.
const Duration kBoundedFetchDeadline = Duration(seconds: 120);

/// Fetches [url] into a Dart list, with the shared auth header, bounded end to
/// end. Returns the body bytes of a 200 (or 206, for a ranged request) and
/// throws otherwise.
///
/// [range] is an optional `Range` header value, e.g. `bytes=0-4095`. The
/// server is allowed to answer a range that covers the whole file with 200
/// (not 206), so both 200 and 206 are accepted for ranged requests — the
/// [maxBytes] cap is what keeps a "small range" call from downloading (and
/// buffering) a much larger body if a server ignores the range, including the
/// trailer ranges `live_photo.dart` extracts, where a wrong/oversized body
/// would otherwise be handed to the player.
/// [maxBytes] optionally caps the collected body; exceeding it throws instead
/// of buffering an unbounded response. [truncateToMax] changes that to "keep
/// exactly the first [maxBytes] bytes" — for a *probe* that only reads a head
/// (live-photo XMP, animated-format header, HEIC box scan), a server that
/// ignores Range and answers 200 with the whole file still yields exactly the
/// bytes a compliant 206 would have returned. Payload extraction must NOT use
/// it: a truncated trailer would be the wrong bytes, not a smaller truth.
/// [stallTimeout] caps the silence between chunks; [totalTimeout] caps the
/// whole request. A server that refuses or goes quiet raises `HttpException` /
/// `TimeoutException` respectively — never a pending future.
///
/// The body is read by hand rather than with
/// `consolidateHttpClientResponseBytes`: only a *stream* timeout errors inside
/// the read loop, which is what cancels the subscription and its socket. A
/// `.timeout()` around the consolidating future does not — it abandons a
/// subscription that keeps the connection pinned, which is why this loop exists
/// instead of that one-liner.
Future<Uint8List> fetchBoundedBytes(
  String url, {
  String? range,
  int? maxBytes,
  bool truncateToMax = false,
  Duration stallTimeout = kBoundedFetchStall,
  Duration totalTimeout = kBoundedFetchDeadline,
}) async {
  // ONE budget for the whole request rather than one per phase. A fresh
  // `totalTimeout` on `getUrl`, on `close` and on the body loop would let a
  // server that is slow once and silent afterwards hold a decode slot for three
  // times the documented deadline.
  final deadline = DateTime.now().add(totalTimeout);
  Duration remaining() {
    final left = deadline.difference(DateTime.now());
    return left.isNegative ? Duration.zero : left;
  }

  // The URL is canonical by construction (`utils/media_url.dart`): every path
  // segment was encoded exactly once when the caller built its `MediaItem`.
  // Parse only — re-encoding here is what made a literal `%20` filename work
  // through this path while media_kit requested a file with a space. `Uri.parse`
  // still normalises a raw URL (spaces and non-ASCII) and preserves existing
  // `%XX`, so an already encoded URL (the cast proxy's `?path=...`) is safe too.
  final uri = Uri.parse(url);
  final request = await sharedHttpClient.getUrl(uri).timeout(remaining());
  if (range != null) request.headers.set(HttpHeaders.rangeHeader, range);
  // The map exists but is not guaranteed to carry the key; a missing header must
  // not turn into a null-check throw on the fetch path.
  final token = sharedAuthHeader?['Authorization'];
  if (token != null) request.headers.set('Authorization', token);
  final response = await request.close().timeout(remaining());
  if (response.statusCode != 200 && response.statusCode != 206) {
    // Read the body off the socket so the connection can return to the pool
    // instead of being torn down — but only for as long as one stall, because
    // the caller is waiting for this error, not for a body it will discard.
    final drainBudget = remaining() < stallTimeout ? remaining() : stallTimeout;
    await response.drain<void>().timeout(drainBudget).catchError((_) {});
    throw HttpException('HTTP ${response.statusCode} fetching $url', uri: uri);
  }
  final builder = BytesBuilder(copy: false);
  await for (final chunk in response.timeout(
    stallTimeout,
    onTimeout: (sink) => sink.addError(
      TimeoutException('stalled for $stallTimeout fetching $url'),
    ),
  )) {
    if (DateTime.now().isAfter(deadline)) {
      throw TimeoutException('body exceeded $totalTimeout fetching $url');
    }
    builder.add(chunk);
    if (maxBytes != null && builder.length > maxBytes) {
      if (truncateToMax) {
        // A head probe only wants a prefix. Returning it (and cancelling the
        // rest of the stream) is the honest equivalent of a compliant 206,
        // while never buffering more than the cap.
        return Uint8List.sublistView(builder.takeBytes(), 0, maxBytes);
      }
      throw HttpException(
        'response exceeded $maxBytes bytes fetching $url',
        uri: uri,
      );
    }
  }
  return builder.takeBytes();
}

/// The size of [url] in bytes, with the shared auth header, bounded end to
/// end. Returns 0 when the server does not say.
///
/// A HEAD, so the body is never transferred — the size is the only thing the
/// caller wants.
Future<int> fetchBoundedContentLength(
  String url, {
  Duration stallTimeout = kBoundedFetchStall,
  Duration totalTimeout = kBoundedFetchDeadline,
}) async {
  final deadline = DateTime.now().add(totalTimeout);
  Duration remaining() {
    final left = deadline.difference(DateTime.now());
    return left.isNegative ? Duration.zero : left;
  }

  final uri = Uri.parse(url);
  final request = await sharedHttpClient.headUrl(uri).timeout(remaining());
  final token = sharedAuthHeader?['Authorization'];
  if (token != null) request.headers.set('Authorization', token);
  final response = await request.close().timeout(remaining());
  if (response.statusCode != 200) {
    final drainBudget = remaining() < stallTimeout ? remaining() : stallTimeout;
    await response.drain<void>().timeout(drainBudget).catchError((_) {});
    throw HttpException('HTTP ${response.statusCode} fetching $url', uri: uri);
  }
  final raw = response.headers.value('content-length');
  final n = raw == null ? 0 : (int.tryParse(raw) ?? 0);
  return n > 0 ? n : 0;
}
