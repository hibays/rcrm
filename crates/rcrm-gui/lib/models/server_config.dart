// models/server_config.dart
// RCrm GUI — server configuration model

/// Deployment mode: local Rust server or remote cloud WebDAV.
enum DeployMode { local, cloud }

class ServerConfig {
  final DeployMode deployMode;
  final List<String> directories;
  final String bindAddress;
  final int port;
  // In-memory only — NEVER serialized. May hold several keys
  // because different files can use different passwords (mirrors the CLI).
  final List<String> passwords;
  // Cloud mode: remote WebDAV server URL + credentials.
  // remotePassword is in-memory only, never serialized.
  final String remoteUrl;
  final String remoteUsername;
  final String remotePassword;

  const ServerConfig({
    this.deployMode = DeployMode.local,
    this.directories = const [],
    this.bindAddress = '127.0.0.1',
    this.port = 8080,
    this.passwords = const [],
    this.remoteUrl = '',
    this.remoteUsername = '',
    this.remotePassword = '',
  });

  bool get isLocal => deployMode == DeployMode.local;
  bool get isCloud => deployMode == DeployMode.cloud;

  // NOTE: passwords + remotePassword are deliberately NOT serialized. They are
  // held only in memory for the current session and never written to disk.
  Map<String, dynamic> toJson() => {
    'deployMode': deployMode.name,
    'directories': directories,
    'bindAddress': bindAddress,
    'port': port,
    'remoteUrl': remoteUrl,
    'remoteUsername': remoteUsername,
  };

  factory ServerConfig.fromJson(Map<String, dynamic> json) {
    final modeStr = json['deployMode'] as String?;
    return ServerConfig(
      deployMode: modeStr == 'cloud' ? DeployMode.cloud : DeployMode.local,
      directories: List<String>.from(json['directories'] ?? []),
      bindAddress: json['bindAddress'] ?? '127.0.0.1',
      port: json['port'] ?? 8080,
      // Loaded config is always password-free; the user re-enters each session.
      passwords: const [],
      remoteUrl: json['remoteUrl'] ?? '',
      remoteUsername: json['remoteUsername'] ?? '',
      remotePassword: '',
    );
  }

  ServerConfig copyWith({
    DeployMode? deployMode,
    List<String>? directories,
    String? bindAddress,
    int? port,
    List<String>? passwords,
    String? remoteUrl,
    String? remoteUsername,
    String? remotePassword,
  }) {
    return ServerConfig(
      deployMode: deployMode ?? this.deployMode,
      directories: directories ?? this.directories,
      bindAddress: bindAddress ?? this.bindAddress,
      port: port ?? this.port,
      passwords: passwords ?? this.passwords,
      remoteUrl: remoteUrl ?? this.remoteUrl,
      remoteUsername: remoteUsername ?? this.remoteUsername,
      remotePassword: remotePassword ?? this.remotePassword,
    );
  }
}
