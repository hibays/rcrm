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
/// end. Returns the body bytes of a 200 (possibly empty) and throws otherwise.
///
/// [stallTimeout] caps the silence between chunks; [totalTimeout] caps the whole
/// request. A server that refuses or goes quiet raises `HttpException` /
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
  // The map exists but is not guaranteed to carry the key; a missing header must
  // not turn into a null-check throw on the fetch path.
  final token = sharedAuthHeader?['Authorization'];
  if (token != null) request.headers.set('Authorization', token);
  final response = await request.close().timeout(remaining());
  if (response.statusCode != 200) {
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
  }
  return builder.takeBytes();
}
