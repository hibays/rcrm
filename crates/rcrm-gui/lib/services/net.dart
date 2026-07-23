// services/net.dart
// One shared HttpClient for all Dart-side fetches from the local WebDAV server
// (thumbnails + full-res viewer). A bounded connection pool caps how many
// requests hit the server at once — each GET triggers server-side decryption,
// so too many concurrent connections saturate it and stall the UI. Keep-alive
// also lets connections be reused instead of churning a new one per request.

import 'dart:io';

final bool _isMobile = Platform.isAndroid || Platform.isIOS;

final HttpClient sharedHttpClient = HttpClient()
  ..maxConnectionsPerHost = _isMobile ? 13 : 31
  ..connectionTimeout = const Duration(seconds: 20)
  ..idleTimeout = const Duration(seconds: 10)
  ..badCertificateCallback = (_, _, _) => true;

/// Shared Basic Auth header set once on server start.
Map<String, String>? sharedAuthHeader;

/// Set the shared auth header from the WebDAV client.
void setSharedAuth(Map<String, String>? header) {
  sharedAuthHeader = header;
}
