// src/serve/tls.rs
// rcrm - TLS configuration for the FTPS server.
// Copyleft (©) 2024-2025 hibays
//
// Provides:
//   * `TlsProvider` — either an auto-generated ephemeral self-signed
//     certificate (zero-config, regenerated on every startup) or a
//     user-supplied PEM cert+key pair loaded from disk.
//   * `build_server_config()` — assembles a `rustls::ServerConfig` using
//     the `ring` crypto provider (no C compiler required, works on
//     Windows out of the box).

use std::io;
use std::path::Path;
use std::sync::Arc;

use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

// =======================
// rcgen-based ephemeral self-signed certificate
// =======================

/// Generate an ephemeral self-signed certificate valid for "localhost"
/// and 127.0.0.1. The certificate and key live only in process memory
/// and are discarded on server shutdown.
pub fn generate_ephemeral_cert() -> io::Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
	use rcgen::{CertificateParams, KeyPair};

	// Subject Alternative Names: cover loopback access patterns.
	let san: Vec<String> = vec![
		"localhost".to_string(),
		"ip:127.0.0.1".to_string(),
		"ip:::1".to_string(),
	];

	let mut params = CertificateParams::new(san)
		.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("rcgen params: {}", e)))?;
	// Short validity — this cert is regenerated on every startup.
	params.not_before = time::OffsetDateTime::now_utc();
	params.not_after = params.not_before + time::Duration::days(7);

	let key_pair = KeyPair::generate()
		.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("rcgen keygen: {}", e)))?;

	let cert = params.self_signed(&key_pair).map_err(|e| {
		io::Error::new(
			io::ErrorKind::InvalidData,
			format!("rcgen self_signed: {}", e),
		)
	})?;

	// Convert rcgen's output to rustls pki_types.
	let cert_der = CertificateDer::from(cert.der().to_vec());
	let key_der = PrivateKeyDer::try_from(key_pair.serialize_der())
		.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("key der: {}", e)))?;

	Ok((cert_der, key_der))
}

// =======================
// Load user-provided PEM files
// =======================

/// Load a PEM-encoded certificate chain and private key from disk.
/// `cert_path` may contain multiple certificates (chain). `key_path`
/// contains a single private key.
pub fn load_pem_cert_and_key(
	cert_path: &Path,
	key_path: &Path,
) -> io::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
	let cert_pem = std::fs::read(cert_path)?;
	let key_pem = std::fs::read(key_path)?;

	let mut cert_reader = io::Cursor::new(cert_pem);
	let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
		.collect::<Result<Vec<_>, _>>()
		.map_err(|e| {
			io::Error::new(
				io::ErrorKind::InvalidData,
				format!("failed to parse cert PEM: {}", e),
			)
		})?;
	if certs.is_empty() {
		return Err(io::Error::new(
			io::ErrorKind::InvalidData,
			"no certificates found in cert file",
		));
	}

	let mut key_reader = io::Cursor::new(key_pem);
	let key = rustls_pemfile::private_key(&mut key_reader)
		.map_err(|e| {
			io::Error::new(
				io::ErrorKind::InvalidData,
				format!("failed to parse key PEM: {}", e),
			)
		})?
		.ok_or_else(|| {
			io::Error::new(
				io::ErrorKind::InvalidData,
				"no private key found in key file",
			)
		})?;

	Ok((certs, key))
}

// =======================
// Build rustls::ServerConfig
// =======================

/// Build a `rustls::ServerConfig` from a certificate chain and private
/// key, using the `ring` crypto provider and TLS 1.2 + 1.3. No client
/// authentication is required.
pub fn build_server_config(
	certs: Vec<CertificateDer<'static>>,
	key: PrivateKeyDer<'static>,
) -> io::Result<Arc<ServerConfig>> {
	let provider = Arc::new(rustls::crypto::ring::default_provider());
	let config = ServerConfig::builder_with_provider(provider)
		.with_safe_default_protocol_versions()
		.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
		.with_no_client_auth()
		.with_single_cert(certs, key)
		.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
	Ok(Arc::new(config))
}

/// Convenience: build a `ServerConfig` using an auto-generated ephemeral
/// self-signed certificate.
pub fn build_ephemeral_config() -> io::Result<Arc<ServerConfig>> {
	let (cert, key) = generate_ephemeral_cert()?;
	build_server_config(vec![cert], key)
}

/// Convenience: build a `ServerConfig` from user-provided PEM files.
pub fn build_config_from_pem_files(
	cert_path: &Path,
	key_path: &Path,
) -> io::Result<Arc<ServerConfig>> {
	let (certs, key) = load_pem_cert_and_key(cert_path, key_path)?;
	build_server_config(certs, key)
}
