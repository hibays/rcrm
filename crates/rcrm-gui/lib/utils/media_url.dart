// utils/media_url.dart
//
// ONE rule for turning a decoded WebDAV path into a fetchable URL.
//
// `MediaItem.path` comes from a PROPFIND `href` after exactly one
// `Uri.decodeFull`: a file named `foo%20bar.wmv` has the three characters
// `%20` in it, while a file named `foo bar.wmv` has a space. Both must
// survive the round trip, so a path is encoded per SEGMENT with
// [Uri.encodeComponent]:
//
// * `Uri.encodeFull` leaves `#`, `?`, `&` and `+` alone, so those names would
//   still split the URL into a fragment or query;
// * `Uri.pathSegments` decodes first and would turn the literal `%20` into a
//   space, losing the only thing that tells the two files apart.
//
// Every fetch path consumes `MediaItem.url` and parses it ONCE (`Uri.parse`).
// Re-encoding an already canonical URL is how a literal `%` becomes `%25`
// twice (and how the video player once 404'd on a name that images displayed).
// This file is the only place that encoding happens.

/// Encode a decoded WebDAV path for use as a URL path.
///
/// Splitting on `/` (rather than using `Uri.pathSegments`) is deliberate: the
/// input is already decoded, and [Uri.encodeComponent] is what turns a literal
/// `%` into `%25`, a space into `%20`, and `#` into `%23`. Empty segments are
/// preserved — a doubled slash is harmless to the server and must not silently
/// change the path the caller gave us.
String encodeMediaPath(String path) =>
    path.split('/').map(Uri.encodeComponent).join('/');

/// The canonical URL for [path] on [baseUrl].
///
/// [baseUrl] is a clean server base (no credentials — e.g.
/// `WebDavClient.authenticatedBaseUrl`) and may or may not end in `/`; [path]
/// is the DECODED WebDAV path (what `MediaItem.path` stores). The result is
/// encoded exactly once and is what every fetch path should receive.
String mediaUrl(String baseUrl, String path) {
  final base = baseUrl.replaceFirst(RegExp(r'/+$'), '');
  final p = path.startsWith('/') ? path : '/$path';
  return '$base${encodeMediaPath(p)}';
}

/// [url] without its `user:password@` part, for tools that authenticate with a
/// header (ffmpeg's `-headers`).
///
/// The path is already canonical and is carried verbatim: decoding and
/// re-encoding it here is what would turn a literal `%20` filename into a
/// request for a file with a space.
String withoutUrlCredentials(String url) {
  final uri = Uri.parse(url);
  if (!uri.hasAuthority || uri.userInfo.isEmpty) return uri.toString();
  final path = uri.path.isEmpty ? '/' : uri.path;
  final query = uri.hasQuery ? '?${uri.query}' : '';
  return '${uri.origin}$path$query';
}
