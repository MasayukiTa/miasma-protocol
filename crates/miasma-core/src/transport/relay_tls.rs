//! What certificate the relay presents on this network, and whether the daemon's
//! TLS settings accept it.
//!
//! A network that inspects HTTPS answers for the relay with a certificate it
//! signed itself. iroh only reports that the relay connection failed, so this
//! makes the same handshake once with the same TLS settings the endpoint uses
//! (OS store plus the configured extra CA), reads the certificate the relay
//! presents, and says who issued it and whether that issuer is a public CA
//! (the Mozilla root set) or not. Nothing is sent after the handshake.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use iroh::tls::CaTlsConfig;
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};
use serde::{Deserialize, Serialize};

/// The relay's certificate as seen from this computer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayCert {
    /// The name of the CA that signed it (common name, else organisation).
    pub issuer: String,
    /// Whether that CA is one of the public (Mozilla) roots. `false` on a
    /// network that re-signs HTTPS.
    pub public_ca: bool,
    /// Whether the endpoint's TLS settings accept the certificate.
    pub trusted: bool,
}

#[derive(Debug)]
struct Recorder {
    inner: Arc<dyn ServerCertVerifier>,
    public: Arc<dyn ServerCertVerifier>,
    seen: Mutex<Option<(Vec<u8>, bool, bool)>>,
}

impl ServerCertVerifier for Recorder {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let ours = self
            .inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp, now);
        let public = self
            .public
            .verify_server_cert(end_entity, intermediates, server_name, ocsp, now)
            .is_ok();
        *self.seen.lock().unwrap() = Some((end_entity.to_vec(), ours.is_ok(), public));
        ours
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(m, c, d)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(m, c, d)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// The issuer's name from a DER certificate.
pub fn issuer_name(der: &[u8]) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let issuer = cert.issuer();
    let cn = issuer
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .map(|s| s.to_owned());
    let org = || {
        issuer
            .iter_organization()
            .next()
            .and_then(|a| a.as_str().ok())
            .map(|s| s.to_owned())
    };
    let name = cn.or_else(org).unwrap_or_else(|| issuer.to_string());
    Some(name)
}

/// Handshake with `host:port` using `tls` (what the endpoint trusts) and report
/// the certificate. `Err` when nothing was presented (no TCP, no TLS).
pub async fn probe(
    host: &str,
    port: u16,
    tls: &CaTlsConfig,
    limit: Duration,
) -> Result<RelayCert, String> {
    let provider: Arc<CryptoProvider> = Arc::new(rustls::crypto::ring::default_provider());
    let inner = tls
        .server_cert_verifier(provider.clone())
        .map_err(|e| e.to_string())?;
    let public = CaTlsConfig::embedded()
        .server_cert_verifier(provider.clone())
        .map_err(|e| e.to_string())?;
    let rec = Arc::new(Recorder {
        inner,
        public,
        seen: Mutex::new(None),
    });
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(rec.clone())
        .with_no_client_auth();
    let name = ServerName::try_from(host.to_owned()).map_err(|e| e.to_string())?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let attempt = async {
        let tcp = tokio::net::TcpStream::connect((host, port))
            .await
            .map_err(|e| e.to_string())?;
        // A rejected certificate ends the handshake with an error; the
        // certificate has been recorded by then, so the error is not the answer.
        let _ = connector.connect(name, tcp).await;
        Ok::<(), String>(())
    };
    tokio::time::timeout(limit, attempt)
        .await
        .map_err(|_| "timed out".to_owned())??;
    let seen = rec.seen.lock().unwrap().take();
    match seen {
        Some((der, trusted, public_ca)) => Ok(RelayCert {
            issuer: issuer_name(&der).unwrap_or_default(),
            public_ca,
            trusted,
        }),
        None => Err("the relay presented no certificate".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
    use rustls::pki_types::PrivateKeyDer;

    /// A throw-away CA named like an inspecting gateway's, and a leaf for
    /// `localhost` signed by it.
    pub(crate) fn make_ca_and_leaf() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Test Inspection CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();
        (
            ca.der().to_vec(),
            leaf.der().to_vec(),
            leaf_key.serialize_der(),
        )
    }

    async fn serve(leaf: Vec<u8>, key: Vec<u8>) -> u16 {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(leaf)],
                PrivateKeyDer::try_from(key).unwrap(),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                let a = acceptor.clone();
                tokio::spawn(async move {
                    let _ = a.accept(s).await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn an_unknown_issuer_is_reported_and_not_trusted() {
        let (_ca, leaf, key) = make_ca_and_leaf();
        let port = serve(leaf, key).await;
        let r = probe(
            "localhost",
            port,
            &CaTlsConfig::embedded(),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
        assert_eq!(r.issuer, "Test Inspection CA");
        assert!(!r.public_ca);
        assert!(!r.trusted);
    }

    #[tokio::test]
    async fn the_extra_ca_makes_it_trusted_but_it_stays_non_public() {
        let (ca, leaf, key) = make_ca_and_leaf();
        let port = serve(leaf, key).await;
        let tls = CaTlsConfig::embedded().with_extra_roots([CertificateDer::from(ca)]);
        let r = probe("localhost", port, &tls, Duration::from_secs(10))
            .await
            .unwrap();
        assert!(r.trusted);
        assert!(!r.public_ca);
        assert_eq!(r.issuer, "Test Inspection CA");
    }

    /// A stand-in for the OS store that holds exactly the given roots.
    struct FixedRoots(Vec<CertificateDer<'static>>);
    impl crate::transport::iroh_direct::OsTrust for FixedRoots {
        fn tls(&self, extra: Vec<CertificateDer<'static>>) -> CaTlsConfig {
            CaTlsConfig::custom_roots(self.0.iter().cloned().chain(extra))
        }
    }

    #[tokio::test]
    async fn a_ca_missing_from_the_os_store_is_refused_and_the_extra_ca_file_parses() {
        use crate::transport::iroh_direct::{parse_ca_roots, OsTrust};
        let (ca, leaf, key) = make_ca_and_leaf();
        let port = serve(leaf, key).await;
        // A store that holds another CA, not this one: refused. With it: accepted.
        let (unrelated_ca, _, _) = make_ca_and_leaf();
        let store = FixedRoots(vec![CertificateDer::from(unrelated_ca)]).tls(vec![]);
        let r = probe("localhost", port, &store, Duration::from_secs(10))
            .await
            .unwrap();
        assert!(!r.trusted);
        let with_ca = FixedRoots(vec![CertificateDer::from(ca.clone())]).tls(vec![]);
        let r = probe("localhost", port, &with_ca, Duration::from_secs(10))
            .await
            .unwrap();
        assert!(r.trusted);
        // The extra CA file may be DER or PEM; garbage is refused.
        assert_eq!(parse_ca_roots(&ca).unwrap().len(), 1);
        let pem = format!(
            "-----BEGIN CERTIFICATE-----
{}
-----END CERTIFICATE-----
",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ca)
        );
        assert_eq!(parse_ca_roots(pem.as_bytes()).unwrap().len(), 1);
        assert!(parse_ca_roots(b"not a certificate").is_err());
    }

    #[tokio::test]
    async fn nothing_listening_is_an_error() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        assert!(probe(
            "localhost",
            port,
            &CaTlsConfig::embedded(),
            Duration::from_secs(5)
        )
        .await
        .is_err());
    }
}
