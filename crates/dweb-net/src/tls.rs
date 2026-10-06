//! TLS without certificate authorities.
//!
//! Site servers present a self-signed certificate made from their site key.
//! The resolver accepts it only if the certificate's key is exactly the
//! `site_key` the registry holds for the name, and TLS 1.3 itself proves the
//! server holds the matching private key. Names, dates and issuers in the
//! certificate are ignored: the registry is the only authority.
//!
//! Towards the browser, the resolver uses a local certificate authority that
//! exists only on the user's machine and is trusted only by the dedicated
//! browser profile.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow};
use dweb_protocol::{PublicKey, SecretKey};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ED25519,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};

const ALPN_HTTP1: &[u8] = b"http/1.1";
const ED25519_OID: &str = "1.3.101.112";

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A self-signed certificate for a site key.
pub fn site_certificate(
    site_key: &SecretKey,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let pkcs8 = site_key.to_pkcs8_der()?;
    let der = PrivatePkcs8KeyDer::from(pkcs8.clone());
    let kp = KeyPair::from_pkcs8_der_and_sign_algo(&der, &PKCS_ED25519)?;
    let mut params = CertificateParams::new(vec!["dweb-site".to_string()])?;
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(
        DnType::CommonName,
        format!("dweb site {}", site_key.public()),
    );
    let cert = params.self_signed(&kp)?;
    Ok((
        cert.der().clone(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8)),
    ))
}

/// TLS server config for a site server. TLS 1.3 only.
pub fn site_server_config(site_key: &SecretKey) -> Result<Arc<ServerConfig>> {
    let (cert, key) = site_certificate(site_key)?;
    let mut cfg = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    cfg.alpn_protocols = vec![ALPN_HTTP1.to_vec()];
    Ok(Arc::new(cfg))
}

/// Extracts the Ed25519 public key from a certificate.
pub fn certificate_ed25519_key(cert: &CertificateDer<'_>) -> Result<PublicKey> {
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref())
        .map_err(|e| anyhow!("bad certificate: {e}"))?;
    let spki = parsed.public_key();
    if spki.algorithm.algorithm.to_id_string() != ED25519_OID {
        return Err(anyhow!("certificate key is not Ed25519"));
    }
    let bytes: [u8; 32] = spki
        .subject_public_key
        .data
        .as_ref()
        .try_into()
        .map_err(|_| anyhow!("bad Ed25519 key length"))?;
    Ok(PublicKey(bytes))
}

/// Accepts only a server whose certificate carries exactly `expected`.
#[derive(Debug)]
struct PinnedVerifier {
    expected: PublicKey,
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let key = certificate_ed25519_key(end_entity)
            .map_err(|e| rustls::Error::General(e.to_string()))?;
        if key != self.expected {
            return Err(rustls::Error::General(format!(
                "server key {key} does not match the registry's site key {}",
                self.expected
            )));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not allowed".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // This is the step that proves the server holds the private key.
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

/// TLS client config that trusts exactly one site key and nothing else.
pub fn pinned_client_config(expected: PublicKey) -> Result<Arc<ClientConfig>> {
    let p = provider();
    let verifier = PinnedVerifier {
        expected,
        algs: p.signature_verification_algorithms,
    };
    let mut cfg = ClientConfig::builder_with_provider(p)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![ALPN_HTTP1.to_vec()];
    Ok(Arc::new(cfg))
}

/// Connects to a site server and checks it holds `site_key`.
pub async fn connect_pinned<S>(
    stream: S,
    name: &str,
    site_key: PublicKey,
) -> Result<tokio_rustls::client::TlsStream<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let connector = tokio_rustls::TlsConnector::from(pinned_client_config(site_key)?);
    let sni = ServerName::try_from(name.to_string())
        .unwrap_or_else(|_| ServerName::try_from("dweb-site".to_string()).expect("valid"));
    connector
        .connect(sni, stream)
        .await
        .context("site failed key verification")
}

/// The resolver's local certificate authority.
pub struct LocalCa {
    issuer: Issuer<'static, KeyPair>,
    cert_pem: String,
    cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl LocalCa {
    fn params() -> Result<CertificateParams> {
        let mut p = CertificateParams::new(Vec::<String>::new())?;
        p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "dweb local resolver CA");
        dn.push(DnType::OrganizationName, "dweb (this computer only)");
        p.distinguished_name = dn;
        Ok(p)
    }

    /// Loads the CA from `dir`, creating it on first run. The private key is
    /// written with owner-only permissions and never leaves this machine;
    /// `ca.pem` holds only the public certificate for the browser profile.
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        let key_path = dir.join("ca-key.pem");
        let cert_path = dir.join("ca.pem");
        let (key, cert_pem) = if key_path.exists() && cert_path.exists() {
            let key = KeyPair::from_pem(&std::fs::read_to_string(&key_path)?)?;
            (key, std::fs::read_to_string(&cert_path)?)
        } else {
            let key = KeyPair::generate()?;
            let cert = Self::params()?.self_signed(&key)?;
            let _ = std::fs::remove_file(&key_path);
            crate::write_private_file(&key_path, key.serialize_pem().as_bytes())?;
            std::fs::write(&cert_path, cert.pem())?;
            (key, cert.pem())
        };
        Ok(Self {
            issuer: Issuer::new(Self::params()?, key),
            cert_pem,
            cache: Mutex::new(HashMap::new()),
        })
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// TLS server config presenting a certificate for `name`, signed by this CA.
    pub fn server_config(&self, name: &str) -> Result<Arc<ServerConfig>> {
        if let Some(c) = self.cache.lock().expect("ca cache").get(name) {
            return Ok(c.clone());
        }
        let leaf_key = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![name.to_string()])?;
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, name);
        let cert = params.signed_by(&leaf_key, &self.issuer)?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let mut cfg = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key)?;
        cfg.alpn_protocols = vec![ALPN_HTTP1.to_vec()];
        let cfg = Arc::new(cfg);
        self.cache
            .lock()
            .expect("ca cache")
            .insert(name.to_string(), cfg.clone());
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn handshake(server_key: &SecretKey, pinned: PublicKey) -> Result<Vec<u8>> {
        let acceptor = tokio_rustls::TlsAcceptor::from(site_server_config(server_key)?);
        let (a, b) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            if let Ok(mut s) = acceptor.accept(a).await {
                let _ = s.write_all(b"hi").await;
                let _ = s.shutdown().await;
            }
        });
        let mut c = connect_pinned(b, "alice.xyz", pinned).await?;
        let mut out = vec![];
        c.read_to_end(&mut out).await?;
        server.await?;
        Ok(out)
    }

    #[tokio::test]
    async fn pinned_key_accepted_other_rejected() {
        crate::init();
        let site = SecretKey::generate().unwrap();
        let other = SecretKey::generate().unwrap();
        assert_eq!(handshake(&site, site.public()).await.unwrap(), b"hi");
        assert!(handshake(&site, other.public()).await.is_err());
    }

    #[test]
    fn site_cert_carries_site_key() {
        let site = SecretKey::generate().unwrap();
        let (cert, _) = site_certificate(&site).unwrap();
        assert_eq!(certificate_ed25519_key(&cert).unwrap(), site.public());
    }

    #[test]
    fn local_ca_persists() {
        let dir = std::env::temp_dir().join(format!("dweb-ca-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let a = LocalCa::load_or_create(&dir).unwrap();
        let b = LocalCa::load_or_create(&dir).unwrap();
        assert_eq!(a.cert_pem(), b.cert_pem());
        b.server_config("alice.xyz").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
