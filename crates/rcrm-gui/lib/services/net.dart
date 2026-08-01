// services/net.dart
// One shared HttpClient for all Dart-side fetches from the WebDAV server
// (thumbnails + full-res viewer). A bounded connection pool caps how many
// requests hit the server at once — each GET triggers server-side decryption,
// so too many concurrent connections saturate it and stall the UI. Keep-alive
// also lets connections be reused instead of churning a new one per request.
//
// Certificate policy: NOTHING is trusted by default. When a server presents
// an untrusted certificate, the connection is rejected and the certificate is
// recorded in [CertTrust.lastRejected]. The user may confirm THAT exact
// certificate (shown with subject/issuer/fingerprint in the dialog); only its
// fingerprint is pinned, session-scoped, in-memory. Any other certificate —
// including a different one presented by the same host later — is rejected.

import 'dart:io';

final bool _isMobile = Platform.isAndroid || Platform.isIOS;

/// Snapshot of an untrusted certificate offered for user confirmation.
class CertInfo {
  final String sha1; // fingerprint (X509Certificate.sha1, hex)
  final String subject;
  final String issuer;
  final DateTime? notBefore;
  final DateTime? notAfter;

  const CertInfo({
    required this.sha1,
    required this.subject,
    required this.issuer,
    this.notBefore,
    this.notAfter,
  });

  factory CertInfo.fromX509(X509Certificate cert) => CertInfo(
    sha1: _hex(cert.sha1),
    subject: cert.subject,
    issuer: cert.issuer,
    notBefore: cert.startValidity,
    notAfter: cert.endValidity,
  );

  static String _hex(List<int> bytes) =>
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  /// Fingerprint grouped in 4-char blocks for readability, e.g.
  /// "AB12 CD34 EF56 ...".
  String get formattedSha1 =>
      sha1.replaceAllMapped(RegExp(r'.{4}'), (m) => '${m.group(0)} ').trim();
}

/// Certificate pinning store — session-scoped, in-memory only.
///
/// A user confirms ONE untrusted certificate per session; only that exact
/// certificate (by SHA-1 fingerprint) is accepted. Everything else is
/// rejected. Nothing is ever trusted "by default".
class CertTrust {
  CertTrust._();

  static final Set<String> _pinned = <String>{};

  /// Most recently rejected untrusted certificate, for the confirm dialog.
  static CertInfo? lastRejected;

  /// SHA-1 fingerprint (hex) of the certificate most recently ACCEPTED via
  /// pinning. Used to hand the current server's fingerprint to the cast TV
  /// during pairing (trust chain: user confirmed on phone → phone → TV).
  static String? lastAcceptedSha1;

  static bool isPinned(String sha1) => _pinned.contains(sha1);

  /// Pins exactly the certificate the user confirmed — nothing else.
  static void pin(CertInfo info) => _pinned.add(info.sha1);

  static bool get hasPinned => _pinned.isNotEmpty;

  static void clear() {
    _pinned.clear();
    lastRejected = null;
    lastAcceptedSha1 = null;
  }
}

bool _certCallback(X509Certificate cert, String host, int port) {
  final sha1 = CertInfo._hex(cert.sha1);
  if (CertTrust.isPinned(sha1)) {
    CertTrust.lastAcceptedSha1 = sha1;
    return true;
  }
  CertTrust.lastRejected = CertInfo.fromX509(cert);
  return false;
}

/// An HttpClient that rejects every untrusted certificate unless the user has
/// explicitly pinned THAT certificate (see [CertTrust]). Never trusts-all.
HttpClient createTrustAwareHttpClient() =>
    HttpClient()..badCertificateCallback = _certCallback;

final HttpClient sharedHttpClient = createTrustAwareHttpClient()
  ..maxConnectionsPerHost = _isMobile ? 13 : 31
  ..connectionTimeout = const Duration(seconds: 20)
  ..idleTimeout = const Duration(seconds: 10);

/// Shared Basic Auth header set once on server start.
Map<String, String>? sharedAuthHeader;

/// Set the shared auth header from the WebDAV client.
void setSharedAuth(Map<String, String>? header) {
  sharedAuthHeader = header;
}
