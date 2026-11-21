// models/server_config.dart
// RCrm GUI — server configuration model

/// Deployment mode: local Rust server or remote cloud WebDAV.
enum DeployMode { local, cloud }

class ServerConfig {
  final DeployMode deployMode;
  final List<String> directories;
  final String bindAddress;
  final int port;
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
    this.remoteUrl = '',
    this.remoteUsername = '',
    this.remotePassword = '',
  });

  bool get isLocal => deployMode == DeployMode.local;
  bool get isCloud => deployMode == DeployMode.cloud;

  // NOTE: remotePassword is deliberately NOT serialized. Decryption passwords
  // are never held by Dart at all — Rust owns the keyring.
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
    String? remoteUrl,
    String? remoteUsername,
    String? remotePassword,
  }) {
    return ServerConfig(
      deployMode: deployMode ?? this.deployMode,
      directories: directories ?? this.directories,
      bindAddress: bindAddress ?? this.bindAddress,
      port: port ?? this.port,
      remoteUrl: remoteUrl ?? this.remoteUrl,
      remoteUsername: remoteUsername ?? this.remoteUsername,
      remotePassword: remotePassword ?? this.remotePassword,
    );
  }
}
