// src/tls_cert.rs
// Self-signed certificate generation for the TV cast receiver.
//
// The Dart side needs a TLS server certificate for the cast control port.
// dart:io's SecurityContext cannot generate keys, so we generate one here
// (ECDSA P-256 via rcgen) and hand the PEM bytes back to Dart.
//
// Security notes:
// - The private key leaves Rust as PKCS#8 PEM, is written by Dart into the
//   app-private directory (never world-readable), and is reused across app
//   restarts so a phone only needs to pair once per TV.
// - The key is wrapped in Zeroizing on the Rust side so no plaintext lingers
//   in Rust heap.

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SerialNumber};
use zeroize::Zeroizing;

/// Generate a fresh self-signed ECDSA P-256 certificate + PKCS#8 private key.
///
/// Returns `(cert_pem, key_pem)`.
pub fn generate() -> Result<(String, Zeroizing<String>), String> {
	let key_pair = KeyPair::generate().map_err(|e| e.to_string())?;
	let mut params = CertificateParams::new(Vec::<String>::new()).map_err(|e| e.to_string())?;
	let mut dn = DistinguishedName::new();
	dn.push(DnType::CommonName, "rcrm-tv");
	params.distinguished_name = dn;
	params.serial_number = Some(SerialNumber::from_slice(&random_serial()));
	params.not_before = rcgen::date_time_ymd(2024, 1, 1);
	params.not_after = rcgen::date_time_ymd(2034, 1, 1);
	// Self-signed device cert: not a CA, no key usages that imply one.
	params.is_ca = rcgen::IsCa::NoCa;
	let cert = params.self_signed(&key_pair).map_err(|e| e.to_string())?;
	let key = Zeroizing::new(key_pair.serialize_pem());
	Ok((cert.pem(), key))
}

fn random_serial() -> Vec<u8> {
	rand::random::<u128>().to_be_bytes().to_vec()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn generates_valid_pem() {
		let (cert, key) = generate().expect("generate");
		assert!(
			cert.starts_with("-----BEGIN CERTIFICATE-----"),
			"cert PEM header"
		);
		assert!(
			cert.contains("-----END CERTIFICATE-----"),
			"cert PEM footer"
		);
		assert!(
			key.starts_with("-----BEGIN PRIVATE KEY-----"),
			"key PEM header (PKCS#8)"
		);
		assert!(key.contains("-----END PRIVATE KEY-----"), "key PEM footer");
		// Base64 body must be plausible DER (>200 bytes, base64 alphabet only).
		fn body_len(pem: &str, header: &str, footer: &str) -> usize {
			let normalized = pem.replace("\r\n", "\n").trim_end().to_string();
			let body = normalized
				.strip_prefix(header)
				.and_then(|s| s.strip_suffix(footer))
				.expect("pem body")
				.replace('\n', "");
			assert!(
				body.chars()
					.all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c)),
				"base64 alphabet"
			);
			body.len()
		}
		assert!(
			body_len(
				&cert,
				"-----BEGIN CERTIFICATE-----",
				"-----END CERTIFICATE-----"
			) > 200
		);
		assert!(
			body_len(
				&key,
				"-----BEGIN PRIVATE KEY-----",
				"-----END PRIVATE KEY-----"
			) > 100
		);
	}

	#[test]
	fn generates_unique_serials() {
		let (c1, _) = generate().expect("c1");
		let (c2, _) = generate().expect("c2");
		assert_ne!(c1, c2, "two certs must differ (random serial/key)");
	}
}
