//! Écoute SOCKS5 (RFC 1928 + RFC 1929).
//!
//! Seul `CONNECT` est implémenté : `BIND` et `UDP ASSOCIATE` n'ont aucun sens
//! pour Tor ni pour I2P, et constitueraient un vecteur de fuite sur le chemin
//! clearnet.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info};

use crate::config::ProxyCredentials;
use crate::routing::Target;
use crate::state::AppState;

use super::Session;

const VERSION: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const METHOD_NONE: u8 = 0x00;
const METHOD_USERPASS: u8 = 0x02;
const METHOD_UNACCEPTABLE: u8 = 0xff;
/// Un client incapable d'achever sa poignée de main dans ce délai est lâché.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

pub async fn listen(state: Arc<AppState>, bind: &str) -> Result<()> {
    let listener = TcpListener::bind(bind).await?;
    info!(bind = %listener.local_addr()?, "écoute SOCKS5 prête");
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                debug!(%err, "échec de l'acceptation SOCKS5");
                continue;
            }
        };
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let _ = stream.set_nodelay(true);
            handle(state, stream, peer).await;
        });
    }
}

async fn handle(state: Arc<AppState>, mut stream: TcpStream, peer: SocketAddr) {
    let session = Session::new(Arc::clone(&state), peer, "socks5");
    let credentials = state.config().proxy.credentials.clone();

    let target = match tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        handshake(&mut stream, credentials.as_ref()),
    )
    .await
    {
        Ok(Ok(target)) => target,
        Ok(Err(err)) => {
            session.note_protocol_error(err.to_string());
            return;
        }
        Err(_) => {
            session.note_protocol_error("délai de poignée de main dépassé");
            return;
        }
    };

    match session.establish(&target, None).await {
        Ok(connected) => {
            // Le client peut disparaître entre l'ouverture du tunnel et notre
            // réponse : l'enregistrement doit alors être clos, pas laissé actif.
            if let Err(err) = reply(&mut stream, 0x00).await {
                session.note_aborted(&target, &connected.backend_id, err.to_string());
                debug!(peer = %peer, %err, "tunnel abandonné avant le relais");
                return;
            }
            session.relay(&target, stream, connected).await;
        }
        Err(err) => {
            let _ = reply(&mut stream, err.socks5_reply()).await;
            let _ = stream.shutdown().await;
            debug!(peer = %peer, reason = %err.message(), "requête SOCKS5 refusée");
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum HandshakeError {
    #[error("le client ne parle pas SOCKS5 (octet de version {0})")]
    BadVersion(u8),
    #[error("le client n'a proposé aucune méthode d'authentification acceptable")]
    NoAcceptableMethod,
    #[error("échec de l'authentification")]
    AuthFailed,
    #[error("commande 0x{0:02x} non prise en charge (seul CONNECT est disponible)")]
    UnsupportedCommand(u8),
    #[error("type d'adresse 0x{0:02x} inconnu")]
    UnknownAddressType(u8),
    #[error("le nom d'hôte de destination n'est pas de l'UTF-8 valide")]
    BadHostname,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Déroule la salutation, l'authentification optionnelle puis la requête CONNECT.
async fn handshake(
    stream: &mut TcpStream,
    credentials: Option<&ProxyCredentials>,
) -> Result<Target, HandshakeError> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(HandshakeError::BadVersion(head[0]));
    }
    let mut methods = vec![0u8; head[1] as usize];
    stream.read_exact(&mut methods).await?;

    let wanted = if credentials.is_some() {
        METHOD_USERPASS
    } else {
        METHOD_NONE
    };
    if !methods.contains(&wanted) {
        stream.write_all(&[VERSION, METHOD_UNACCEPTABLE]).await?;
        return Err(HandshakeError::NoAcceptableMethod);
    }
    stream.write_all(&[VERSION, wanted]).await?;

    if let Some(credentials) = credentials {
        authenticate(stream, credentials).await?;
    }

    let mut request = [0u8; 4];
    stream.read_exact(&mut request).await?;
    if request[0] != VERSION {
        return Err(HandshakeError::BadVersion(request[0]));
    }
    if request[1] != CMD_CONNECT {
        reply(stream, 0x07).await?;
        return Err(HandshakeError::UnsupportedCommand(request[1]));
    }

    let host = match request[3] {
        0x01 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            IpAddr::V4(Ipv4Addr::from(octets)).to_string()
        }
        0x04 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            IpAddr::V6(Ipv6Addr::from(octets)).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            stream.read_exact(&mut name).await?;
            String::from_utf8(name).map_err(|_| HandshakeError::BadHostname)?
        }
        other => {
            reply(stream, 0x08).await?;
            return Err(HandshakeError::UnknownAddressType(other));
        }
    };

    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    Ok(Target::new(host, u16::from_be_bytes(port)))
}

/// Sous-négociation identifiant/mot de passe de la RFC 1929.
async fn authenticate(
    stream: &mut TcpStream,
    credentials: &ProxyCredentials,
) -> Result<(), HandshakeError> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    let mut username = vec![0u8; head[1] as usize];
    stream.read_exact(&mut username).await?;
    let mut password_len = [0u8; 1];
    stream.read_exact(&mut password_len).await?;
    let mut password = vec![0u8; password_len[0] as usize];
    stream.read_exact(&mut password).await?;

    let ok = constant_time_eq(&username, credentials.username.as_bytes())
        & constant_time_eq(&password, credentials.password.as_bytes());
    // La version de la sous-négociation vaut 0x01, et non celle de SOCKS.
    stream
        .write_all(&[0x01, if ok { 0x00 } else { 0x01 }])
        .await?;
    if ok {
        Ok(())
    } else {
        Err(HandshakeError::AuthFailed)
    }
}

/// Compare sans divulguer la position de la première différence.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Répond à la requête CONNECT. L'adresse liée n'a aucun sens pour un proxy qui
/// n'écoute jamais : on renvoie donc le remplissage à zéro.
async fn reply(stream: &mut TcpStream, code: u8) -> std::io::Result<()> {
    stream
        .write_all(&[VERSION, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn constant_time_comparison_matches_semantics() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secreT"));
        assert!(!constant_time_eq(b"secret", b"secret2"));
        assert!(constant_time_eq(b"", b""));
    }

    /// Monte une écoute réelle pour dérouler un échange SOCKS5 complet.
    async fn spawn_gateway(config: Config) -> SocketAddr {
        let dir = std::env::temp_dir().join(format!(
            "tiv-socks-{}-{}",
            std::process::id(),
            config.proxy.socks5_bind.clone().unwrap_or_default().len()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(AppState::new(config, dir.join("config.toml")));
        tokio::spawn(async move {
            loop {
                let (stream, peer) = listener.accept().await.unwrap();
                let state = Arc::clone(&state);
                tokio::spawn(async move { handle(state, stream, peer).await });
            }
        });
        addr
    }

    #[tokio::test]
    async fn a_denied_destination_gets_a_socks_failure_reply() {
        // 127.0.0.1 est privée : le routage la refuse avant tout appel amont.
        let addr = spawn_gateway(Config::default()).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);

        client
            .write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], 0x05);
        // 0x02 = connexion interdite par les règles.
        assert_eq!(reply[1], 0x02);
    }

    #[tokio::test]
    async fn bind_and_udp_associate_are_refused() {
        let addr = spawn_gateway(Config::default()).await;
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0u8; 2];
        client.read_exact(&mut method).await.unwrap();

        // 0x02 = BIND
        client
            .write_all(&[0x05, 0x02, 0x00, 0x01, 1, 1, 1, 1, 0x00, 0x50])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x07);
    }

    #[tokio::test]
    async fn credentials_are_enforced_when_configured() {
        let mut config = Config::default();
        config.proxy.credentials = Some(ProxyCredentials {
            username: "pi".into(),
            password: "raspberry".into(),
        });
        let addr = spawn_gateway(config).await;

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut method = [0u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x02]);

        let mut auth = vec![0x01, 2];
        auth.extend_from_slice(b"pi");
        auth.push(5);
        auth.extend_from_slice(b"wrong");
        client.write_all(&auth).await.unwrap();
        let mut auth_reply = [0u8; 2];
        client.read_exact(&mut auth_reply).await.unwrap();
        assert_eq!(auth_reply, [0x01, 0x01]);
    }

    #[tokio::test]
    async fn a_client_offering_only_no_auth_is_rejected_when_auth_is_required() {
        let mut config = Config::default();
        config.proxy.credentials = Some(ProxyCredentials {
            username: "pi".into(),
            password: "raspberry".into(),
        });
        let addr = spawn_gateway(config).await;

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0xff]);
    }
}
