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
import '../services/media_metadata.dart';

// ── State ────────────────────────────────────────────────────

enum ServerStatus { stopped, starting, running, error, locked }

class ServerState {
  final ServerStatus status;
  final int handle;
  final String? url;
  final String? error;
  final WebDavClient? client;
  // When status == locked: how many encrypted files no key could open.
  final int locked;
  // Total encrypted files seen by the last verification (the all-locked baseline).
  final int encrypted;
  // Files unlocked so far. Rust is the authority; Dart keeps no password list.
  final int unlocked;
  // Latest progress text pushed by Rust during a start.
  final String? progressText;

  const ServerState({
    this.status = ServerStatus.stopped,
    this.handle = -1,
    this.url,
    this.error,
    this.client,
    this.locked = 0,
    this.encrypted = 0,
    this.unlocked = 0,
    this.progressText,
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
    int? unlocked,
    String? progressText,
  }) => ServerState(
    status: status ?? this.status,
    handle: handle ?? this.handle,
    url: url ?? this.url,
    error: error ?? this.error,
    client: client ?? this.client,
    locked: locked ?? this.locked,
    encrypted: encrypted ?? this.encrypted,
    unlocked: unlocked ?? this.unlocked,
    progressText: progressText ?? this.progressText,
  );
}

// ── Provider ─────────────────────────────────────────────────

class ServerNotifier extends Notifier<ServerState> {
  @override
  ServerState build() => const ServerState();

  SettingsService get _settings => ref.read(settingsServiceProvider);
  RustBridge get _bridge => ref.read(rustBridgeProvider);

  Future<void> start(ServerConfig config, {String? password}) async {
    if (state.status == ServerStatus.running) return;
    if (config.isCloud) {
      await connectCloud(
        config.remoteUrl,
        config.remoteUsername,
        config.remotePassword,
      );
      return;
    }
    await _startLocal(config, password: password);
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

  Future<void> _startLocal(ServerConfig config, {String? password}) async {
    // A second start while one is in flight would create two subscribers to
    // the shared event stream and two writers of `state`. Refuse it.
    if (state.status == ServerStatus.running ||
        state.status == ServerStatus.starting) {
      return;
    }
    // Do not clear `sharedAuthHeader` here: a previous session's credentials
    // are cleared by stop(), and clearing here would strip auth from in-flight
    // requests if a restart is ever triggered while a server is live. A new
    // successful start overwrites it on RUNNING anyway.
    // The library is (re)established here, so this is where previously cached
    // metadata stops applying: the identity is part of the cache key, so a
    // re-scan (different roots, or another server) invalidates by itself instead
    // of relying on somebody calling clearCache. Bind address and port are
    // deliberately excluded — a per-launch port would make every launch look like
    // a different library for no reason.
    MediaMetadataService.setLibraryIdentity(
      'local|${config.directories.join('|')}',
    );
    state = state.copyWith(
      status: ServerStatus.starting,
      error: null,
      progressText: 'Scanning directories…',
    );
    StreamSubscription<ServerEvent>? sub;
    try {
      if (!_bridge.isLoaded) _bridge.load();
      // Local server logs exposes private infomation so set silent.
      _bridge.setLogLevel(0);
      // The one newly typed password travels with the start call; Rust owns
      // every key and keeps earlier ones derived across attempts.

      // Rust pushes progress and the terminal verdict. No polling: the event
      // carrying -2/-1/2 is emitted at the moment the decision is made.
      final terminal = Completer<ServerEvent>();
      sub = RustBridge.serverEvents.listen((ev) {
        if (ev.code == ServerEventCode.progress) {
          if (!terminal.isCompleted) {
            state = state.copyWith(
              progressText: ev.a == 0
                  ? 'Scanning directories…'
                  : 'Verifying files… ${ev.b}/${ev.c}',
            );
          }
          return;
        }
        if (!terminal.isCompleted) terminal.complete(ev);
      });

      final handle = _bridge.startWebDavServer(
        directories: config.directories,
        password: password ?? '',
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
      final ev = await terminal.future.timeout(
        const Duration(minutes: 5),
        onTimeout: () => const ServerEvent(-99, 0, 0, 0),
      );
      switch (ev.code) {
        case ServerEventCode.running:
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
        case ServerEventCode.locked:
          state = ServerState(
            status: ServerStatus.locked,
            handle: handle,
            encrypted: ev.a,
            locked: ev.b,
            unlocked: ev.c,
          );
        case ServerEventCode.error:
          state = state.copyWith(
            status: ServerStatus.error,
            error: _bridge.getLastErrorMessage() ?? 'Unknown error',
          );
        case ServerEventCode.stopped:
          state = const ServerState();
        default:
          // Unknown code or the 5-minute timeout. The Rust startup may still
          // be running and could bind a server whose verdict we will never
          // deliver (the subscription is cancelled in `finally`). Cancel it
          // before leaving the state so it cannot serve orphaned media.
          _bridge.stopWebDavServer(handle);
          state = state.copyWith(
            status: ServerStatus.error,
            error: 'Server start did not produce a result',
          );
      }
    } catch (e) {
      state = state.copyWith(status: ServerStatus.error, error: e.toString());
    } finally {
      await sub?.cancel();
    }
  }

  /// Stop the local WebDAV server.
  Future<void> stop() async {
    if (state.handle > 0) _bridge.stopWebDavServer(state.handle);
    final client = state.client;
    state = const ServerState();
    client?.dispose();
    setSharedAuth(null);
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
      // Same declaration as the local path: this is the moment a *cloud* library is
      // established, so previously cached metadata stops applying. The URL and the
      // account identify it; the password is deliberately not part of the identity
      // (a re-entered password is the same library).
      MediaMetadataService.setLibraryIdentity(
        'cloud|${config.remoteUrl}|${config.remoteUsername}',
      );
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
