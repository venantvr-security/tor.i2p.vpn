//! Le pont d'interception : deux poignées de main TLS dos à dos, et entre les
//! deux une boucle de transactions HTTP/1.1 qu'on observe au passage.
//!
//! ```mermaid
//! sequenceDiagram
//!     participant C as Client
//!     participant P as Pont (this)
//!     participant U as Amont (via Tor/I2P/direct)
//!     C->>P: TLS (feuille signée par la CA locale)
//!     P->>U: TLS (SNI = hôte, cert amont accepté et relevé)
//!     loop tant que la connexion tient
//!         C->>P: requête HTTP/1.1
//!         P->>U: requête relayée à l'identique
//!         U->>P: réponse HTTP/1.1
//!         P->>C: réponse relayée à l'identique
//!         Note over P: journalise URL, code, titre
//!     end
//! ```
//!
//! Une fois le TLS client établi avec notre certificat, il n'y a plus de repli
//! possible vers un tunnel opaque : l'interception d'une connexion est donc au
//! mieux best-effort. En cas d'anomalie de cadrage, on ferme les deux côtés
//! plutôt que de risquer de corrompre le flux — jamais on ne réécrit les octets.

use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::debug;

use crate::catalogue::extract_title;

use super::http::{self, Body};
use super::Mitm;

/// Au-delà de cette part de réponse, on cesse de chercher un titre.
const TITLE_SNIFF_LIMIT: usize = 64 * 1024;

/// Construit la configuration TLS cliente qui accepte n'importe quel certificat
/// amont, tout en négociant HTTP/1.1.
///
/// La passerelle est le point de confiance : l'exploitant a explicitement choisi
/// d'intercepter ces hôtes. Beaucoup de services cachés présentent d'ailleurs un
/// certificat auto-signé, l'adresse `.onion` faisant foi à leur place. On accepte
/// donc, mais on relève l'empreinte du certificat présenté, seule information qui
/// permette de repérer plus tard un changement suspect.
pub fn upstream_config() -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert {
            provider: Arc::clone(&provider),
        }))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

/// Mène l'interception d'une connexion, du double TLS à sa fermeture.
pub async fn run(
    mitm: Arc<Mitm>,
    client: TcpStream,
    upstream: TcpStream,
    host: String,
    port: u16,
    idle: Duration,
) {
    if let Err(err) = bridge(&mitm, client, upstream, &host, port, idle).await {
        debug!(%host, %err, "interception close");
    }
}

async fn bridge(
    mitm: &Arc<Mitm>,
    client: TcpStream,
    upstream: TcpStream,
    host: &str,
    port: u16,
    idle: Duration,
) -> anyhow::Result<()> {
    // Côté client : on présente la feuille signée par la CA locale.
    let server_config = mitm.ca().server_config_for(host)?;
    let acceptor = TlsAcceptor::from(server_config);
    let mut client_tls = acceptor.accept(client).await?;

    // Côté amont : SNI = hôte, certificat accepté puis relevé.
    let connector = TlsConnector::from(Arc::clone(mitm.upstream_config()));
    let server_name = ServerName::try_from(host.to_string())?;
    let mut upstream_tls = connector.connect(server_name, upstream).await?;

    if let Some(fp) = peer_fingerprint(upstream_tls.get_ref().1.peer_certificates()) {
        mitm.note_certificate(host, fp);
    }
    mitm.note_connection();

    let authority = if port == 443 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };

    let outcome = transactions(mitm, &mut client_tls, &mut upstream_tls, &authority, idle).await;

    // Fermeture propre du TLS client : envoyer `close_notify` évite au client une
    // erreur « EOF inattendu » — nombre de clients HTTP la remontent en dur. On
    // ferme au mieux : la connexion se termine de toute façon.
    let _ = client_tls.shutdown().await;
    let _ = upstream_tls.shutdown().await;
    outcome
}

/// La boucle de transactions elle-même, sur les deux flux déjà déchiffrés.
async fn transactions<C, U>(
    mitm: &Arc<Mitm>,
    client_tls: &mut C,
    upstream_tls: &mut U,
    authority: &str,
    idle: Duration,
) -> anyhow::Result<()>
where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        let Some(request) = http::read_head(client_tls).await? else {
            return Ok(()); // le client a raccroché proprement
        };
        let (method, uri, version) = match request.request_parts() {
            Some(parts) => (
                parts.0.to_string(),
                parts.1.to_string(),
                parts.2.to_string(),
            ),
            None => return Ok(()),
        };
        let is_head = method.eq_ignore_ascii_case("HEAD");

        // Requête vers l'amont, à l'octet près.
        upstream_tls.write_all(&request.raw).await?;
        let req_body = http::request_body(&request);
        http::forward_body(client_tls, upstream_tls, req_body, None).await?;
        upstream_tls.flush().await?;

        // Réponse de l'amont.
        let response = match tokio::time::timeout(idle, http::read_head(upstream_tls)).await {
            Ok(result) => match result? {
                Some(head) => head,
                None => return Ok(()),
            },
            Err(_) => return Ok(()),
        };
        let status = response.response_status().unwrap_or(0);

        client_tls.write_all(&response.raw).await?;
        let resp_body = http::response_body(&response, status, is_head);

        // On ne cherche un titre que si la réponse est du HTML en clair.
        let mut collected: Vec<u8> = Vec::new();
        let want_title = mitm.capture_titles() && looks_like_html(&response);
        {
            let mut sink = |bytes: &[u8]| {
                if want_title && collected.len() < TITLE_SNIFF_LIMIT {
                    collected.extend_from_slice(bytes);
                }
            };
            let sink: http::Sink<'_> = if want_title { Some(&mut sink) } else { None };
            tokio::time::timeout(
                idle,
                http::forward_body(upstream_tls, client_tls, resp_body, sink),
            )
            .await
            .map_err(|_| anyhow::anyhow!("délai dépassé sur le corps de réponse"))??;
        }
        client_tls.flush().await?;

        // Journal : URL complète (chemin compris, c'est tout l'intérêt du MITM),
        // code de statut, titre lorsqu'il a été trouvé.
        let url = if uri.starts_with('/') {
            format!("https://{authority}{uri}")
        } else {
            uri.clone()
        };
        let titre = if want_title {
            let text = String::from_utf8_lossy(&collected);
            extract_title(&text)
        } else {
            None
        };
        mitm.record_visit(&url, status, titre);

        // Fin de connexion si l'un des deux côtés l'a demandée, ou si la réponse
        // n'était délimitée que par la fermeture.
        if resp_body == Body::UntilClose
            || wants_close(version.as_str(), request.header("connection"))
            || wants_close("HTTP/1.1", response.header("connection"))
        {
            return Ok(());
        }
    }
}

/// La réponse annonce-t-elle du HTML non compressé ?
fn looks_like_html(head: &http::Head) -> bool {
    let html = head
        .header("content-type")
        .map(|ct| ct.to_ascii_lowercase().contains("text/html"))
        .unwrap_or(false);
    let compressed = head
        .header("content-encoding")
        .map(|ce| {
            let ce = ce.to_ascii_lowercase();
            !ce.trim().is_empty() && ce.trim() != "identity"
        })
        .unwrap_or(false);
    html && !compressed
}

/// Décide de la fermeture selon la version et l'en-tête `Connection`.
fn wants_close(version: &str, connection: Option<&str>) -> bool {
    match connection.map(|c| c.to_ascii_lowercase()) {
        Some(value) if value.contains("close") => true,
        Some(value) if value.contains("keep-alive") => false,
        // Par défaut : HTTP/1.1 garde la connexion, HTTP/1.0 la ferme.
        _ => !version.eq_ignore_ascii_case("HTTP/1.1"),
    }
}

/// Empreinte SHA-256 du certificat de tête présenté par l'amont.
fn peer_fingerprint(certs: Option<&[CertificateDer<'_>]>) -> Option<String> {
    let leaf = certs?.first()?;
    let digest = Sha256::digest(leaf.as_ref());
    Some(
        digest
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// Vérificateur de certificat serveur qui accepte tout, mais valide malgré tout
/// la signature de poignée de main : sans quoi le TLS lui-même serait cassé.
#[derive(Debug)]
struct AcceptAnyServerCert {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_is_decided_by_version_and_header() {
        assert!(!wants_close("HTTP/1.1", None));
        assert!(wants_close("HTTP/1.0", None));
        assert!(wants_close("HTTP/1.1", Some("close")));
        assert!(!wants_close("HTTP/1.0", Some("keep-alive")));
    }

    #[test]
    fn html_is_recognised_only_when_not_compressed() {
        let head = |raw: &[u8]| {
            let text = String::from_utf8_lossy(raw);
            let mut lines = text.split("\r\n");
            let start_line = lines.next().unwrap().to_string();
            let headers = lines
                .filter(|l| !l.is_empty())
                .filter_map(|l| l.split_once(':'))
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                .collect();
            http::Head {
                raw: raw.to_vec(),
                start_line,
                headers,
            }
        };
        assert!(looks_like_html(&head(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
        )));
        assert!(!looks_like_html(&head(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\n"
        )));
        assert!(!looks_like_html(&head(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        )));
    }

    #[test]
    fn a_fingerprint_is_hex_with_colons() {
        let cert = CertificateDer::from(vec![0u8; 16]);
        let fp = peer_fingerprint(Some(&[cert])).unwrap();
        assert_eq!(fp.matches(':').count(), 31);
        assert!(peer_fingerprint(None).is_none());
    }

    // --- Interception de bout en bout -------------------------------------

    use crate::catalogue::Catalogue;
    use base64::Engine;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{RootCertStore, ServerConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Décode le corps DER d'un unique bloc PEM `CERTIFICATE`.
    fn pem_der(pem: &str) -> Vec<u8> {
        let body: String = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .concat();
        base64::engine::general_purpose::STANDARD
            .decode(body.trim())
            .unwrap()
    }

    /// Lance une origine TLS auto-signée qui répond une page HTML une seule fois.
    async fn origin_https() -> std::net::SocketAddr {
        let certified = rcgen::generate_simple_self_signed(vec!["test.local".to_string()]).unwrap();
        let cert = CertificateDer::from(certified.cert.der().to_vec());
        let key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            // On consomme la requête que le pont nous a relayée.
            let _ = http::read_head(&mut tls).await.unwrap();
            let body = b"<html><head><title>Bonjour du .onion</title></head><body>ok</body></html>";
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            tls.write_all(head.as_bytes()).await.unwrap();
            tls.write_all(body).await.unwrap();
            tls.flush().await.unwrap();
        });
        addr
    }

    #[tokio::test]
    async fn a_tls_get_is_intercepted_relayed_and_journaled() {
        crate::install_crypto_provider();

        let dir = std::env::temp_dir().join(format!("tiv-bridge-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let catalogue = Arc::new(Catalogue::load(&dir.join("catalogue.jsonl"), 100));
        let mitm = Mitm::new(&dir, Arc::clone(&catalogue)).unwrap();

        // Client de confiance : il n'accepte que notre CA locale.
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(pem_der(mitm.ca().cert_pem())))
            .unwrap();
        let client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        let origin = origin_https().await;

        // Le pont accepte le client sur cette écoute et compose vers l'origine.
        let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bridge_addr = client_listener.local_addr().unwrap();
        let mitm_for_bridge = Arc::clone(&mitm);
        tokio::spawn(async move {
            let (client, _) = client_listener.accept().await.unwrap();
            let upstream = TcpStream::connect(origin).await.unwrap();
            run(
                mitm_for_bridge,
                client,
                upstream,
                "test.local".to_string(),
                443,
                Duration::from_secs(5),
            )
            .await;
        });

        // Le client parle TLS au pont, qui lui présente une feuille signée par
        // la CA qu'il a installée : la validation doit passer sans exception.
        let connector = TlsConnector::from(Arc::new(client_config));
        let tcp = TcpStream::connect(bridge_addr).await.unwrap();
        let name = ServerName::try_from("test.local").unwrap();
        let mut tls = connector.connect(name, tcp).await.unwrap();
        tls.write_all(
            b"GET /forum/thread?id=42 HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
        let mut reponse = Vec::new();
        tls.read_to_end(&mut reponse).await.unwrap();
        let texte = String::from_utf8_lossy(&reponse);
        assert!(texte.starts_with("HTTP/1.1 200"), "réponse : {texte}");
        assert!(texte.contains("Bonjour du .onion"), "corps relayé intact");

        // Le journal a retenu l'URL complète — chemin et requête compris —,
        // le code de statut et le titre : c'est tout l'apport du MITM.
        let entries = catalogue.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].url, "https://test.local/forum/thread?id=42");
        assert_eq!(entries[0].code, Some(200));
        assert_eq!(entries[0].titre.as_deref(), Some("Bonjour du .onion"));

        // Et l'empreinte du certificat amont a bien été relevée.
        let status = mitm.status(&crate::config::Config::default());
        assert_eq!(status.certificates.len(), 1);
        assert_eq!(status.certificates[0].host, "test.local");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
