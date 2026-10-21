//! TLS for the proxy: a certificate authority of its own, and the certificates it signs.
//!
//! A proxy that only tunnels `CONNECT` cannot see what is inside the tunnel, so nothing about
//! an https site can be logged, changed or scanned. The proxy therefore answers `CONNECT` with a
//! certificate of its own for the host that was asked for, and the browser is told to trust the
//! proxy's authority. The authority is written to disk so it can be installed in a browser.

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;

/// The authority the proxy signs its certificates with.
pub struct Authority {
    key_pair: KeyPair,
    certificate: rcgen::Certificate,
    /// The file the certificate was written to, so the UI can point at it.
    pub path: PathBuf,
    /// Per-host cached leaf TLS configs so parallel browser connections share one keygen.
    cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

/// A resolver that always hands out the one certificate it was built with.
#[derive(Debug)]
struct OneCert(Arc<CertifiedKey>);

impl ResolvesServerCert for OneCert {
    fn resolve(&self, _hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

impl Authority {
    /// Builds an authority and writes its certificate where the user can reach it.
    ///
    /// The certificate is the public half; the key stays in memory, so the file on disk is enough
    /// to trust the proxy but not enough to sign anything else.
    pub fn generate() -> Result<Self, String> {
        let key_pair = KeyPair::generate().map_err(|e| e.to_string())?;
        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|e| e.to_string())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "Gulpsuite Proxy Authority");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Gulpsuite");
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let certificate = params.self_signed(&key_pair).map_err(|e| e.to_string())?;

        let path = certificate_path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(mut file) = std::fs::File::create(&path) {
            let _ = file.write_all(certificate.pem().as_bytes());
        }
        let der_path = path.with_extension("der");
        if let Ok(mut file) = std::fs::File::create(&der_path) {
            let _ = file.write_all(certificate.der());
        }

        Ok(Authority {
            key_pair,
            certificate,
            path,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// The authority's certificate, in the form a browser can install.
    pub fn pem(&self) -> String {
        self.certificate.pem()
    }

    /// Only this session's CA is exempted in the isolated integrated browser.
    pub fn spki_pin(&self) -> String {
        use base64::Engine;
        let digest = ring::digest::digest(&ring::digest::SHA256, &self.key_pair.public_key_der());
        base64::engine::general_purpose::STANDARD.encode(digest.as_ref())
    }

    /// The authority's own certificate, for a client that has to trust it.
    pub fn certificate_der(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.certificate.der().to_vec())
    }

    /// A certificate for one host, signed by the authority.
    pub fn leaf(&self, host: &str) -> Result<CertifiedKey, String> {
        let key_pair = KeyPair::generate().map_err(|e| e.to_string())?;
        let mut params = CertificateParams::new(vec![host.to_string()])
            .map_err(|e| e.to_string())?;
        params
            .distinguished_name
            .push(DnType::CommonName, host.to_string());
        let certificate = params
            .signed_by(&key_pair, &self.certificate, &self.key_pair)
            .map_err(|e| e.to_string())?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        let signing = rustls::crypto::ring::sign::any_supported_type(&key).map_err(|e| e.to_string())?;
        Ok(CertifiedKey::new(
            // Include the session CA so Chromium can match its scoped SPKI pin.
            vec![CertificateDer::from(certificate.der().to_vec()), self.certificate_der()],
            signing,
        ))
    }

    /// The server side of a TLS connection to a client, for one host.
    pub fn server_config(&self, host: &str) -> Result<ServerConfig, String> {
        let config = self.server_config_arc(host)?;
        Ok((*config).clone())
    }

    /// Cached `Arc<ServerConfig>` per host so parallel browser `CONNECT` tunnels do not
    /// regenerate a fresh keypair on every subresource connection.
    pub fn server_config_arc(&self, host: &str) -> Result<Arc<ServerConfig>, String> {
        if let Ok(guard) = self.cache.lock() {
            if let Some(cached) = guard.get(host) {
                return Ok(cached.clone());
            }
        }
        let key = Arc::new(self.leaf(host)?);
        let config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(OneCert(key))),
        );
        if let Ok(mut guard) = self.cache.lock() {
            if guard.len() >= 512 {
                guard.clear();
            }
            guard.insert(host.to_string(), config.clone());
        }
        Ok(config)
    }
}

/// Where the authority's certificate is written.
///
/// The application support directory is the one place on macOS a user can find and install from.
pub fn certificate_path() -> PathBuf {
    // No shared /tmp certificate export when the user data path is unavailable.
    crate::platform_paths::data_dir()
        .map(|dir| dir.join("gulpsuite-proxy-ca.pem"))
        .unwrap_or_default()
}

static DEFAULT_CLIENT_CONFIG: std::sync::LazyLock<Arc<rustls::ClientConfig>> =
    std::sync::LazyLock::new(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    });

/// Shared `Arc<ClientConfig>` when no custom roots are supplied, avoiding cloning 140+ root CAs
/// on every HTTPS probe or proxy connection.
pub fn client_config_arc(
    extra: &[CertificateDer<'static>],
) -> Result<Arc<rustls::ClientConfig>, String> {
    if extra.is_empty() {
        return Ok(DEFAULT_CLIENT_CONFIG.clone());
    }
    Ok(Arc::new(client_config_with(extra)?))
}

/// The client side of a TLS connection to an origin, trusting the system roots.
pub fn client_config() -> Result<rustls::ClientConfig, String> {
    Ok((**DEFAULT_CLIENT_CONFIG).clone())
}

/// The same, with extra authorities to trust on top of the system roots.
///
/// A private authority is the usual reason: an origin that serves a certificate from its own
/// certificate authority is otherwise not reachable.
pub fn client_config_with(extra: &[CertificateDer<'static>]) -> Result<rustls::ClientConfig, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for root in extra {
        roots
            .add(root.clone())
            .map_err(|e| format!("cannot trust the extra authority: {e}"))?;
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_authority_signs_a_certificate_for_a_host() {
        let authority = Authority::generate().expect("authority");
        let key = authority.leaf("example.test").expect("leaf");
        assert_eq!(key.cert.len(), 2, "leaf plus session CA in the chain");
        assert!(
            authority.pem().contains("BEGIN CERTIFICATE"),
            "the authority has a certificate in PEM form"
        );
    }

    #[test]
    fn the_server_config_is_built_for_a_host() {
        let authority = Authority::generate().expect("authority");
        assert!(
            authority.server_config("example.test").is_ok(),
            "a server configuration should be possible"
        );
    }

    #[test]
    fn the_client_config_trusts_the_system_roots() {
        assert!(client_config().is_ok());
    }
}
