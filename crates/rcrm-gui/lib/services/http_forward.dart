// services/http_forward.dart
// Shared request-forwarding core for the two LAN-casting hops:
// * CastReceiver's localhost media proxy (TV-side: mpv → server)
// * CastHttpsRelay (phone-side: TV → loopback server)
//
// Both do the same thing: copy Authorization/Range onto an upstream request,
// relay the status plus a small allow-list of media-relevant response
// headers, then pipe the body through without buffering it in memory.

import 'dart:async';
import 'dart:io';

/// Streams the upstream response for [req] into `req.response`.
///
/// Forwards the client's Range header and relays status code plus the
/// media-relevant headers (content type/length, accept-ranges, content-range)
/// so range-based seeking keeps working end to end. Throws when the upstream
/// request fails; the caller owns turning that into an error response.
Future<void> forwardHttpRequest(
  HttpClient client,
  Uri uri,
  HttpRequest req, {
  String? authHeader,
}) async {
  final upReq = await client.getUrl(uri);
  if (authHeader != null) {
    upReq.headers.set(HttpHeaders.authorizationHeader, authHeader);
  }
  final range = req.headers.value(HttpHeaders.rangeHeader);
  if (range != null) upReq.headers.set(HttpHeaders.rangeHeader, range);
  final upRes = await upReq.close();
  final res = req.response;
  res.statusCode = upRes.statusCode;
  for (final name in const [
    HttpHeaders.contentTypeHeader,
    HttpHeaders.contentLengthHeader,
    HttpHeaders.acceptRangesHeader,
    HttpHeaders.contentRangeHeader,
  ]) {
    final value = upRes.headers.value(name);
    if (value != null) res.headers.set(name, value);
  }
  await upRes.pipe(res);
}
