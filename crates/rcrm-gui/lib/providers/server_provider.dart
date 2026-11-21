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

/// What the server is doing. Each phase carries only the data valid for it:
/// an error is a variant with a message, never a nullable field on the state.
/// A running server therefore cannot hold a stale error, and there is no
/// `copyWith(error: null)` that silently keeps the previous one.
sealed class ServerPhase {
  const ServerPhase();
}

final class ServerStopped extends ServerPhase {
  const ServerStopped();
}

final class ServerStarting extends ServerPhase {
  const ServerStarting({this.progress});
  final String? progress;
}

final class ServerRunning extends ServerPhase {
  const ServerRunning({this.url, this.client});
  // Production always has both; nullable so tests can drive isRunning-only
  // states without standing up a WebDAV client.
  final String? url;
  final WebDavClient? client;
}

final class ServerLocked extends ServerPhase {
  const ServerLocked({
    required this.encrypted,
    required this.locked,
    required this.unlocked,
  });
  // How many encrypted files no key could open / were seen / were opened.
  // Rust is the authority; Dart keeps no password list.
  final int encrypted;
  final int locked;
  final int unlocked;
}

final class ServerError extends ServerPhase {
  const ServerError({required this.message});
  final String message;
}

class ServerState {
  const ServerState({this.phase = const ServerStopped(), this.handle = -1});

  /// The current phase — the single source of truth for what data is valid.
  final ServerPhase phase;
  /// Rust session id, shared by starting/running/locked. Kept across a locked
  /// retry so `stop()` can still cancel the in-flight startup.
  final int handle;

  bool get isRunning => phase is ServerRunning;
  String? get error => switch (phase) {
    ServerError(:final message) => message,
    _ => null,
  };
  String? get url => switch (phase) {
    ServerRunning(:final url) => url,
    _ => null,
  };
  WebDavClient? get client => switch (phase) {
    ServerRunning(:final client) => client,
    _ => null,
  };
  int get encrypted => switch (phase) {
    ServerLocked(:final encrypted) => encrypted,
    _ => 0,
  };
  int get locked => switch (phase) {
    ServerLocked(:final locked) => locked,
    _ => 0,
  };
  int get unlocked => switch (phase) {
    ServerLocked(:final unlocked) => unlocked,
    _ => 0,
  };
  String? get progressText => switch (phase) {
    ServerStarting(:final progress) => progress,
    _ => null,
  };
}

// ── Provider ─────────────────────────────────────────────────

class ServerNotifier extends Notifier<ServerState> {
  @override
  ServerState build() => const ServerState();

  SettingsService get _settings => ref.read(settingsServiceProvider);
  RustBridge get _bridge => ref.read(rustBridgeProvider);

  Future<void> start(ServerConfig config, {String? password}) async {
    if (state.isRunning) return;
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
    if (state.isRunning) return;
    if (!_bridge.isLoaded) _bridge.load();
    // Clear any certificate from a previous attempt so BAD_CERT below can only
    // be produced by THIS connection's rejection.
    CertTrust.lastRejected = null;
    state = ServerState(phase: const ServerStarting(), handle: state.handle);
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
        state = ServerState(
          phase: const ServerError(
            message: 'Cloud server not reachable. Check URL and port.',
          ),
          handle: state.handle,
        );
        return;
      }
      if (pingResult == 401 || pingResult == 403) {
        client.dispose();
        state = ServerState(
          phase: const ServerError(
            message: 'Authentication failed. Check username and password.',
          ),
          handle: state.handle,
        );
        return;
      }
      if (pingResult != 200) {
        client.dispose();
        state = ServerState(
          phase: ServerError(message: 'Server returned HTTP $pingResult.'),
          handle: state.handle,
        );
        return;
      }
      state = ServerState(
        phase: ServerRunning(url: url, client: client),
        handle: state.handle,
      );
    } on HandshakeException catch (_) {
      client?.dispose();
      // 'BAD_CERT' means an untrusted certificate was rejected and is waiting
      // in CertTrust.lastRejected for the confirmation dialog. If the
      // handshake failed for another reason (lastRejected is null), surface
      // the raw failure instead of offering a bogus cert dialog.
      state = ServerState(
        phase: ServerError(
          message: CertTrust.lastRejected != null
              ? 'BAD_CERT'
              : 'TLS handshake failed. The server may not support secure '
                    'connections, or the certificate is invalid.',
        ),
        handle: state.handle,
      );
    } catch (e) {
      client?.dispose();
      state = ServerState(
        phase: ServerError(message: e.toString()),
        handle: state.handle,
      );
    }
  }

  Future<void> _startLocal(ServerConfig config, {String? password}) async {
    // A second start while one is in flight would create two subscribers to
    // the shared event stream and two writers of `state`. Refuse it.
    if (state.isRunning || state.phase is ServerStarting) {
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
    state = ServerState(
      phase: const ServerStarting(progress: 'Scanning directories…'),
      handle: state.handle,
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
            state = ServerState(
              phase: ServerStarting(
                progress: ev.a == 0
                    ? 'Scanning directories…'
                    : 'Verifying files… ${ev.b}/${ev.c}',
              ),
              handle: state.handle,
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
        state = ServerState(
          phase: ServerError(
            message: _bridge.getLastErrorMessage() ?? 'Unknown error',
          ),
          handle: state.handle,
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
            state = ServerState(
              phase: const ServerError(message: 'Failed to get URL'),
              handle: state.handle,
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
            state = ServerState(
              phase: const ServerError(message: 'Server not responding'),
              handle: state.handle,
            );
            return;
          }
          state = ServerState(
            phase: ServerRunning(url: url, client: client),
            handle: handle,
          );
        case ServerEventCode.locked:
          state = ServerState(
            phase: ServerLocked(
              encrypted: ev.a,
              locked: ev.b,
              unlocked: ev.c,
            ),
            handle: handle,
          );
        case ServerEventCode.error:
          state = ServerState(
            phase: ServerError(
              message: _bridge.getLastErrorMessage() ?? 'Unknown error',
            ),
            handle: state.handle,
          );
        case ServerEventCode.stopped:
          state = const ServerState();
        default:
          // Unknown code or the 5-minute timeout. The Rust startup may still
          // be running and could bind a server whose verdict we will never
          // deliver (the subscription is cancelled in `finally`). Cancel it
          // before leaving the state so it cannot serve orphaned media.
          _bridge.stopWebDavServer(handle);
          state = ServerState(
            phase: const ServerError(
              message: 'Server start did not produce a result',
            ),
            handle: state.handle,
          );
      }
    } catch (e) {
      state = ServerState(
        phase: ServerError(message: e.toString()),
        handle: state.handle,
      );
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
        state = ServerState(
          phase: const ServerError(
            message: 'No cloud server URL configured',
          ),
          handle: state.handle,
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
      state = ServerState(
        phase: const ServerError(message: 'No media directories configured'),
        handle: state.handle,
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
