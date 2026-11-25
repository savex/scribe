use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

use crate::{hex, NetError};

/// The client TLS settings: ring, TLS 1.2 and 1.3, and the OS verifier or a pin. Also used by
/// the Postgres backend, so everything that leaves the host checks certificates the same way.
pub fn config(pin_sha256: Option<&str>) -> Result<Arc<rustls::ClientConfig>, NetError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier: Arc<dyn ServerCertVerifier> = match pin_sha256 {
        Some(pin) => Arc::new(Pinned {
            pin: parse_pin(pin)?,
            provider: provider.clone(),
        }),
        None => Arc::new(
            rustls_platform_verifier::Verifier::new(provider.clone())
                .map_err(|e| NetError::Tls("the system trust store".into(), e.to_string()))?,
        ),
    };
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| NetError::Tls("settings".into(), e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// 64 hex digits (colons allowed, as `openssl -fingerprint` prints them).
pub fn parse_pin(pin: &str) -> Result<[u8; 32], NetError> {
    let digits: String = pin.chars().filter(|c| *c != ':').collect();
    if digits.len() != 64 {
        return Err(NetError::Pin(format!(
            "expected 64 hex digits (SHA-256), got {}",
            digits.len()
        )));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digits[2 * i..2 * i + 2], 16)
            .map_err(|_| NetError::Pin(format!("`{pin}` is not hex")))?;
    }
    Ok(out)
}

/// Accepts exactly the certificate with this SHA-256; still checks the handshake signature.
#[derive(Debug)]
struct Pinned {
    pin: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let got = ring::digest::digest(&ring::digest::SHA256, end_entity.as_ref());
        if got.as_ref() == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "the server certificate (SHA-256 {}) does not match pin_sha256",
                hex(got.as_ref())
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
