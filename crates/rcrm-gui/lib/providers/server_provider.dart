// providers/server_provider.dart
import 'dart:async';
import 'dart:io' show HandshakeException;
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../ffi/rust_bridge.dart';
import '../models/server_config.dart';
import '../services/settings_service.dart';
import '../services/thumbnail_service.dart';
import '../services/net.dart';
import '../services/webdav_client.dart';
import '../services/cast_https_relay.dart';

// ── State ────────────────────────────────────────────────────

enum ServerStatus { stopped, starting, running, error, locked }

class ServerState {
  final ServerStatus status;
  final int handle;
  final String? url;
  final String? error;
  final WebDavClient? client;
  // When status == locked: how many encrypted files no entered key could open.
  final int locked;
  // Total encrypted files seen by the last verification (the all-locked baseline).
  final int encrypted;

  const ServerState({
    this.status = ServerStatus.stopped,
    this.handle = -1,
    this.url,
    this.error,
    this.client,
    this.locked = 0,
    this.encrypted = 0,
  });

  bool get isRunning => status == ServerStatus.running;

  ServerState copyWith({
    ServerStatus? status,
    int? handle,
    String? url,
    String? error,
    WebDavClient? client,
    int? locked,
    int? encrypted,
  }) => ServerState(
    status: status ?? this.status,
    handle: handle ?? this.handle,
    url: url ?? this.url,
    error: error ?? this.error,
    client: client ?? this.client,
    locked: locked ?? this.locked,
    encrypted: encrypted ?? this.encrypted,
  );
}

// ── Provider ─────────────────────────────────────────────────

class ServerNotifier extends Notifier<ServerState> {
  @override
  ServerState build() => const ServerState();

  SettingsService get _settings => ref.read(settingsServiceProvider);
  RustBridge get _bridge => ref.read(rustBridgeProvider);

  Future<void> start(ServerConfig config) async {
    if (state.status == ServerStatus.running) return;
    if (config.isCloud) {
      await connectCloud(
        config.remoteUrl,
        config.remoteUsername,
        config.remotePassword,
      );
      return;
    }
    await _startLocal(config);
  }

  Future<void> connectCloud(
    String url,
    String username,
    String password,
  ) async {
    if (state.status == ServerStatus.running) return;
    if (!_bridge.isLoaded) _bridge.load();
    // Clear any certificate from a previous attempt so BAD_CERT below can only
    // be produced by THIS connection's rejection.
    CertTrust.lastRejected = null;
    state = state.copyWith(status: ServerStatus.starting, error: null);
    WebDavClient? client;
    try {
      client = WebDavClient(
        baseUrl: url,
        username: username,
        password: password,
      );
      setSharedAuth(client.authHeader);
      final pingResult = await client.pingStatusCode();
      if (pingResult == null) {
        client.dispose(); // failed connection — don't leak the HttpClient
        state = state.copyWith(
          status: ServerStatus.error,
          error: 'Cloud server not reachable. Check URL and port.',
        );
        return;
      }
      if (pingResult == 401 || pingResult == 403) {
        client.dispose();
        state = state.copyWith(
          status: ServerStatus.error,
          error: 'Authentication failed. Check username and password.',
        );
        return;
      }
      if (pingResult != 200) {
        client.dispose();
        state = state.copyWith(
          status: ServerStatus.error,
          error: 'Server returned HTTP $pingResult.',
        );
        return;
      }
      state = state.copyWith(
        status: ServerStatus.running,
        url: url,
        error: null,
        client: client,
      );
    } on HandshakeException catch (_) {
      client?.dispose();
      // 'BAD_CERT' means an untrusted certificate was rejected and is waiting
      // in CertTrust.lastRejected for the confirmation dialog. If the
      // handshake failed for another reason (lastRejected is null), surface
      // the raw failure instead of offering a bogus cert dialog.
      state = state.copyWith(
        status: ServerStatus.error,
        error: CertTrust.lastRejected != null
            ? 'BAD_CERT'
            : 'TLS handshake failed. The server may not support secure '
                  'connections, or the certificate is invalid.',
      );
    } catch (e) {
      client?.dispose();
      state = state.copyWith(status: ServerStatus.error, error: e.toString());
    }
  }

  Future<void> _startLocal(ServerConfig config) async {
    if (state.status == ServerStatus.running) return;
    state = state.copyWith(status: ServerStatus.starting, error: null);
    try {
      if (!_bridge.isLoaded) _bridge.load();
      // Local server logs exposes private infomation so set silent.
      _bridge.setLogLevel(0);
      // Start local background server.
      final handle = _bridge.startWebDavServer(
        directories: config.directories,
        passwords: config.passwords,
        bindAddress: config.bindAddress,
        port: config.port,
      );
      if (handle <= 0) {
        state = state.copyWith(
          status: ServerStatus.error,
          error: _bridge.getLastErrorMessage() ?? 'Unknown error',
        );
        return;
      }
      while (true) {
        await Future.delayed(const Duration(milliseconds: 100));
        final st = _bridge.getServerStatusValue(handle);
        if (st == 1) continue;
        if (st == -2) {
          final v = _bridge.lastVerifyResult();
          state = ServerState(
            status: ServerStatus.locked,
            handle: handle,
            locked: (v?['locked'] as num?)?.toInt() ?? 0,
            encrypted: (v?['encrypted'] as num?)?.toInt() ?? 0,
          );
          return;
        }
        if (st == -1) {
          state = state.copyWith(
            status: ServerStatus.error,
            error: _bridge.getLastErrorMessage() ?? 'Unknown error',
          );
          return;
        }
        if (st != 2) {
          state = state.copyWith(
            status: ServerStatus.error,
            error: 'Unexpected server status: $st',
          );
          return;
        }

        // Server is running
        final url = _bridge.getServerUrlString(handle);
        if (url == null) {
          state = state.copyWith(
            status: ServerStatus.error,
            error: 'Failed to get URL',
          );
          return;
        }
        final creds = _bridge.getAuthCredentialsMap(handle);
        final client = WebDavClient(
          baseUrl: url,
          username: creds?['username'],
          password: creds?['password'],
        );
        // Share auth with thumbnail service and HttpClient fetchers
        setSharedAuth(client.authHeader);

        // Verify server is responding
        if (!await client.ping()) {
          client.dispose();
          state = state.copyWith(
            status: ServerStatus.error,
            error: 'Server not responding',
          );
          return;
        }
        state = state.copyWith(
          status: ServerStatus.running,
          handle: handle,
          url: url,
          error: null,
          client: client,
        );
        return;
      }
    } catch (e) {
      state = state.copyWith(status: ServerStatus.error, error: e.toString());
    }
  }

  /// Stop the local WebDAV server.
  Future<void> stop() async {
    if (state.handle > 0) _bridge.stopWebDavServer(state.handle);
    final client = state.client;
    state = const ServerState();
    client?.dispose();
  }

  Future<void> startWithSavedConfig() async {
    final config = await _settings.getServerConfig();
    if (config.isCloud) {
      if (config.remoteUrl.isEmpty) {
        state = state.copyWith(
          status: ServerStatus.stopped,
          error: 'No cloud server URL configured',
        );
        return;
      }
      await connectCloud(config.remoteUrl, config.remoteUsername, '');
      return;
    }
    if (config.directories.isEmpty) {
      state = state.copyWith(
        status: ServerStatus.stopped,
        error: 'No media directories configured',
      );
      return;
    }
    await start(config);
  }
}

final settingsServiceProvider = Provider<SettingsService>(
  (ref) => SettingsService(),
);
final rustBridgeProvider = Provider<RustBridge>((ref) => RustBridge());
final thumbnailServiceProvider = Provider<ThumbnailService>(
  (_) => ThumbnailService(),
);
final serverProvider = NotifierProvider<ServerNotifier, ServerState>(
  ServerNotifier.new,
);

/// Phone-side HTTPS relay used when casting with a loopback-only local
/// server (the TV cannot reach 127.0.0.1, so the phone forwards media
/// requests over TLS). Singleton for the whole app session.
final castHttpsRelayProvider = Provider<CastHttpsRelay>(
  (ref) => CastHttpsRelay(rustBridge: ref.watch(rustBridgeProvider)),
);
