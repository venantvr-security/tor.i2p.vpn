//! Établissement de la connexion vers le backend retenu.
//!
//! Chaque backend finit par rendre un simple `TcpStream` déjà connecté — et,
//! pour les backends proxifiés, déjà sorti de la poignée de main amont — si
//! bien que la couche de relais ignore totalement sur quel réseau circule le
//! trafic.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::{Backend, BackendKind};
use crate::routing::{is_private, Host, Target};

/// Longueur maximale d'un nom d'hôte dans une requête SOCKS5.
const MAX_DOMAIN_LEN: usize = 255;

#[derive(Debug, Error)]
pub enum UpstreamError {
    #[error("connexion refusée par l'amont")]
    ConnectionRefused,
    #[error("réseau injoignable")]
    NetworkUnreachable,
    #[error("hôte injoignable")]
    HostUnreachable,
    #[error("délai de connexion dépassé")]
    Timeout,
    #[error("échec de la résolution de nom")]
    ResolutionFailed,
    #[error("destination non routable")]
    NotRoutable,
    #[error("requête rejetée par le proxy amont : {0}")]
    Rejected(String),
    #[error("protocole inattendu côté proxy amont : {0}")]
    Protocol(String),
    #[error("ce backend n'accepte aucun trafic")]
    Blocked,
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl UpstreamError {
    /// Octet de réponse SOCKS5 correspondant à cet échec (RFC 1928 §6).
    pub fn socks5_reply(&self) -> u8 {
        match self {
            UpstreamError::ConnectionRefused => 0x05,
            UpstreamError::NetworkUnreachable => 0x03,
            UpstreamError::HostUnreachable | UpstreamError::ResolutionFailed => 0x04,
            UpstreamError::Timeout => 0x06,
            UpstreamError::Blocked | UpstreamError::NotRoutable => 0x02,
            _ => 0x01,
        }
    }

    /// Statut HTTP à renvoyer sur l'écoute proxy.
    pub fn http_status(&self) -> (u16, &'static str) {
        match self {
            UpstreamError::Timeout => (504, "Gateway Timeout"),
            UpstreamError::Blocked | UpstreamError::NotRoutable => (403, "Forbidden"),
            _ => (502, "Bad Gateway"),
        }
    }

    fn from_io(err: io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::ConnectionRefused => UpstreamError::ConnectionRefused,
            io::ErrorKind::TimedOut => UpstreamError::Timeout,
            io::ErrorKind::AddrNotAvailable => UpstreamError::HostUnreachable,
            _ => UpstreamError::Io(err),
        }
    }
}

/// Se connecte à `target` en passant par `backend`.
pub async fn connect(
    backend: &Backend,
    target: &Target,
    connect_timeout: Duration,
    block_private: bool,
) -> Result<TcpStream, UpstreamError> {
    let attempt = async {
        match &backend.kind {
            BackendKind::Block => Err(UpstreamError::Blocked),
            BackendKind::Direct => connect_direct(target, block_private).await,
            BackendKind::Socks5 {
                address,
                username,
                password,
            } => {
                let stream = dial_upstream(address).await?;
                socks5_handshake(stream, target, username.as_deref(), password.as_deref()).await
            }
            BackendKind::HttpConnect { address } => {
                let stream = dial_upstream(address).await?;
                http_connect_handshake(stream, target).await
            }
        }
    };

    match tokio::time::timeout(connect_timeout, attempt).await {
        Ok(result) => result,
        Err(_) => Err(UpstreamError::Timeout),
    }
}

/// Ouvre la connexion depuis cette machine, en résolvant le nom localement.
async fn connect_direct(target: &Target, block_private: bool) -> Result<TcpStream, UpstreamError> {
    let addresses: Vec<SocketAddr> = match &target.host {
        Host::Ip(ip) => vec![SocketAddr::new(*ip, target.port)],
        Host::Name(name) => tokio::net::lookup_host((name.as_str(), target.port))
            .await
            .map_err(|_| UpstreamError::ResolutionFailed)?
            .collect(),
    };
    if addresses.is_empty() {
        return Err(UpstreamError::ResolutionFailed);
    }

    // Un nom public peut très bien résoudre vers le LAN : on revérifie après
    // résolution pour que le DNS ne devienne jamais un contournement de la
    // politique de routage.
    let candidates: Vec<SocketAddr> = if block_private {
        addresses
            .into_iter()
            .filter(|addr| !is_private(&addr.ip()))
            .collect()
    } else {
        addresses
    };
    if candidates.is_empty() {
        return Err(UpstreamError::NotRoutable);
    }

    let mut last = UpstreamError::HostUnreachable;
    for addr in candidates {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Err(err) => last = UpstreamError::from_io(err),
        }
    }
    Err(last)
}

async fn dial_upstream(address: &str) -> Result<TcpStream, UpstreamError> {
    let stream = TcpStream::connect(address)
        .await
        .map_err(UpstreamError::from_io)?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// Poignée de main client RFC 1928, avec authentification RFC 1929 optionnelle.
///
/// Les noms d'hôte sont transmis tels quels afin que l'amont (Tor, i2pd) fasse
/// la résolution à l'intérieur de son propre réseau, au lieu de laisser fuiter
/// une requête DNS depuis ici.
async fn socks5_handshake(
    mut stream: TcpStream,
    target: &Target,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<TcpStream, UpstreamError> {
    let use_auth = username.is_some();
    let greeting: &[u8] = if use_auth {
        &[0x05, 0x02, 0x00, 0x02]
    } else {
        &[0x05, 0x01, 0x00]
    };
    stream.write_all(greeting).await?;

    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply[0] != 0x05 {
        return Err(UpstreamError::Protocol(format!(
            "version SOCKS {} dans la réponse de méthode",
            reply[0]
        )));
    }
    match reply[1] {
        0x00 => {}
        0x02 => {
            let (Some(username), Some(password)) = (username, password) else {
                return Err(UpstreamError::Rejected(
                    "l'amont exige des identifiants, or aucun n'est configuré".into(),
                ));
            };
            authenticate(&mut stream, username, password).await?;
        }
        0xff => {
            return Err(UpstreamError::Rejected(
                "l'amont a rejeté toutes les méthodes d'authentification".into(),
            ))
        }
        other => {
            return Err(UpstreamError::Protocol(format!(
                "méthode d'authentification 0x{other:02x} non prise en charge"
            )))
        }
    }

    let mut request = vec![0x05, 0x01, 0x00];
    match &target.host {
        Host::Name(name) => {
            if name.len() > MAX_DOMAIN_LEN {
                return Err(UpstreamError::NotRoutable);
            }
            request.push(0x03);
            request.push(name.len() as u8);
            request.extend_from_slice(name.as_bytes());
        }
        Host::Ip(std::net::IpAddr::V4(ip)) => {
            request.push(0x01);
            request.extend_from_slice(&ip.octets());
        }
        Host::Ip(std::net::IpAddr::V6(ip)) => {
            request.push(0x04);
            request.extend_from_slice(&ip.octets());
        }
    }
    request.extend_from_slice(&target.port.to_be_bytes());
    stream.write_all(&request).await?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(UpstreamError::Protocol(format!(
            "version SOCKS {} dans la réponse de connexion",
            head[0]
        )));
    }
    if head[1] != 0x00 {
        return Err(socks5_reply_to_error(head[1]));
    }
    // L'adresse liée doit être consommée même si elle ne nous sert à rien.
    match head[3] {
        0x01 => drain(&mut stream, 4 + 2).await?,
        0x04 => drain(&mut stream, 16 + 2).await?,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            drain(&mut stream, len[0] as usize + 2).await?;
        }
        other => {
            return Err(UpstreamError::Protocol(format!(
                "type d'adresse 0x{other:02x} inconnu"
            )))
        }
    }
    Ok(stream)
}

async fn authenticate(
    stream: &mut TcpStream,
    username: &str,
    password: &str,
) -> Result<(), UpstreamError> {
    if username.len() > 255 || password.len() > 255 {
        return Err(UpstreamError::Rejected(
            "les identifiants SOCKS5 sont limités à 255 octets".into(),
        ));
    }
    let mut packet = vec![0x01, username.len() as u8];
    packet.extend_from_slice(username.as_bytes());
    packet.push(password.len() as u8);
    packet.extend_from_slice(password.as_bytes());
    stream.write_all(&packet).await?;

    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply[1] != 0x00 {
        return Err(UpstreamError::Rejected(
            "l'amont a refusé les identifiants SOCKS5".into(),
        ));
    }
    Ok(())
}

async fn drain(stream: &mut TcpStream, len: usize) -> Result<(), UpstreamError> {
    let mut sink = vec![0u8; len];
    stream.read_exact(&mut sink).await?;
    Ok(())
}

pub fn socks5_reply_to_error(code: u8) -> UpstreamError {
    match code {
        0x02 => UpstreamError::Rejected("connexion interdite par les règles de l'amont".into()),
        0x03 => UpstreamError::NetworkUnreachable,
        0x04 => UpstreamError::HostUnreachable,
        0x05 => UpstreamError::ConnectionRefused,
        0x06 => UpstreamError::Timeout,
        0x07 => UpstreamError::Rejected("commande non prise en charge".into()),
        0x08 => UpstreamError::Rejected("type d'adresse non pris en charge".into()),
        other => UpstreamError::Rejected(format!("réponse amont 0x{other:02x}")),
    }
}

/// `CONNECT hôte:port HTTP/1.1` vers un proxy HTTP amont (celui d'i2pd).
async fn http_connect_handshake(
    mut stream: TcpStream,
    target: &Target,
) -> Result<TcpStream, UpstreamError> {
    let authority = target.to_string();
    let request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: keep-alive\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;

    let mut buffer = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    // On lit strictement jusqu'à la fin du bloc d'en-têtes, afin de laisser
    // intact dans la socket le corps du tunnel qui suit.
    while !buffer.ends_with(b"\r\n\r\n") {
        if buffer.len() > 8 * 1024 {
            return Err(UpstreamError::Protocol(
                "en-têtes démesurés renvoyés par le proxy amont".into(),
            ));
        }
        let read = stream.read(&mut byte).await?;
        if read == 0 {
            return Err(UpstreamError::Protocol(
                "le proxy amont a coupé pendant le CONNECT".into(),
            ));
        }
        buffer.push(byte[0]);
    }

    let head = String::from_utf8_lossy(&buffer);
    let status_line = head.lines().next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| {
            UpstreamError::Protocol(format!("ligne de statut mal formée `{status_line}`"))
        })?;
    if !(200..300).contains(&status) {
        return Err(UpstreamError::Rejected(format!(
            "le CONNECT amont a répondu {status}"
        )));
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn socks_reply_codes_map_to_errors() {
        assert!(matches!(
            socks5_reply_to_error(0x04),
            UpstreamError::HostUnreachable
        ));
        assert!(matches!(
            socks5_reply_to_error(0x06),
            UpstreamError::Timeout
        ));
        assert_eq!(UpstreamError::Timeout.socks5_reply(), 0x06);
        assert_eq!(UpstreamError::Blocked.http_status().0, 403);
    }

    /// Serveur SOCKS5 minimal qui accepte tout et renvoie au test, via un
    /// canal, la requête qu'il a reçue.
    async fn fake_socks5_server() -> (SocketAddr, tokio::sync::oneshot::Receiver<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            socket.read_exact(&mut greeting).await.unwrap();
            socket.write_all(&[0x05, 0x00]).await.unwrap();

            let mut head = [0u8; 5];
            socket.read_exact(&mut head).await.unwrap();
            let mut domain = vec![0u8; head[4] as usize + 2];
            socket.read_exact(&mut domain).await.unwrap();
            let mut request = head.to_vec();
            request.extend_from_slice(&domain);
            let _ = tx.send(request);

            socket
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            // On garde le tunnel ouvert le temps que le client termine.
            let mut sink = [0u8; 1];
            let _ = socket.read(&mut sink).await;
        });
        (addr, rx)
    }

    #[tokio::test]
    async fn socks5_handshake_forwards_the_hostname_verbatim() {
        let (addr, rx) = fake_socks5_server().await;
        let backend = Backend {
            id: "tor".into(),
            label: "Tor".into(),
            enabled: true,
            kind: BackendKind::Socks5 {
                address: addr.to_string(),
                username: None,
                password: None,
            },
        };
        let target = Target::new("example.onion", 443);
        let stream = connect(&backend, &target, Duration::from_secs(5), true)
            .await
            .expect("la poignée de main devrait réussir");
        drop(stream);

        let request = rx.await.unwrap();
        assert_eq!(&request[..4], &[0x05, 0x01, 0x00, 0x03]);
        assert_eq!(request[4] as usize, "example.onion".len());
        assert_eq!(&request[5..5 + 13], b"example.onion");
        assert_eq!(&request[request.len() - 2..], &443u16.to_be_bytes());
    }

    #[tokio::test]
    async fn block_backend_never_dials() {
        let backend = Backend {
            id: "off".into(),
            label: "Blocked".into(),
            enabled: true,
            kind: BackendKind::Block,
        };
        let err = connect(
            &backend,
            &Target::new("example.com", 80),
            Duration::from_secs(1),
            true,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, UpstreamError::Blocked));
    }

    #[tokio::test]
    async fn direct_backend_refuses_private_destinations() {
        let backend = Backend {
            id: "vpn".into(),
            label: "VPN".into(),
            enabled: true,
            kind: BackendKind::Direct,
        };
        let err = connect(
            &backend,
            &Target::new("127.0.0.1", 9),
            Duration::from_secs(1),
            true,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, UpstreamError::NotRoutable));
    }
}
