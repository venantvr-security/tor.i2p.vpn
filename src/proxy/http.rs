//! Écoute proxy HTTP.
//!
//! Deux formes sont acceptées :
//!   * `CONNECT hôte:port` — un tunnel opaque, utilisé pour HTTPS ;
//!   * `GET http://hôte/chemin` — une requête à URI absolue, réécrite en forme
//!     d'origine puis transmise.
//!
//! Une seule requête est servie par connexion : l'en-tête est réécrit avec
//! `Connection: close` et tout ce qui suit est relayé tel quel. Le proxy reste
//! ainsi un tuyau d'octets, et non un analyseur posé sur le trafic utilisateur.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use base64::Engine;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info};

use crate::config::ProxyCredentials;
use crate::routing::Target;
use crate::state::AppState;

use super::Session;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// On refuse les blocs d'en-têtes absurdes au lieu de les mettre en tampon.
const MAX_HEAD_BYTES: usize = 32 * 1024;
const MAX_HEADER_LINES: usize = 200;

pub async fn listen(state: Arc<AppState>, bind: &str) -> Result<()> {
    let listener = TcpListener::bind(bind).await?;
    info!(bind = %listener.local_addr()?, "écoute proxy HTTP prête");
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                debug!(%err, "échec de l'acceptation HTTP");
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

async fn handle(state: Arc<AppState>, stream: TcpStream, peer: SocketAddr) {
    let session = Session::new(Arc::clone(&state), peer, "http");
    let credentials = state.config().proxy.credentials.clone();
    let mut reader = BufReader::new(stream);

    let request = match tokio::time::timeout(HANDSHAKE_TIMEOUT, read_head(&mut reader)).await {
        Ok(Ok(request)) => request,
        Ok(Err(err)) => {
            let _ = write_status(reader.get_mut(), 400, "Bad Request", &err.to_string()).await;
            session.note_protocol_error(err.to_string());
            return;
        }
        Err(_) => {
            session.note_protocol_error("délai dépassé sur l'en-tête de requête");
            return;
        }
    };

    if let Some(expected) = credentials.as_ref() {
        if !request.authorised(expected) {
            let _ = write_proxy_auth_required(reader.get_mut()).await;
            session.note_protocol_error("échec de l'authentification proxy");
            return;
        }
    }

    let target = match request.target() {
        Some(target) => target,
        None => {
            let _ = write_status(
                reader.get_mut(),
                400,
                "Bad Request",
                "cette écoute n'accepte que CONNECT ou une requête à URI absolue",
            )
            .await;
            session.note_protocol_error("aucune destination exploitable dans la requête");
            return;
        }
    };

    let connected = match session.establish(&target).await {
        Ok(connected) => connected,
        Err(err) => {
            let (code, reason) = err.http_status();
            let _ = write_status(reader.get_mut(), code, reason, &err.message()).await;
            debug!(peer = %peer, reason = %err.message(), "requête HTTP refusée");
            return;
        }
    };

    // Tout ce que le client a mis en pipeline derrière l'en-tête est transmis
    // sans y toucher.
    let pending = reader.buffer().to_vec();
    let mut client = reader.into_inner();
    let mut upstream = connected;

    if request.is_connect {
        if client
            .write_all(b"HTTP/1.1 200 Connection established\r\nProxy-Agent: tiv-gateway\r\n\r\n")
            .await
            .is_err()
        {
            return;
        }
        if !pending.is_empty() && upstream.stream.write_all(&pending).await.is_err() {
            return;
        }
    } else {
        let head = request.forwarded_head();
        if upstream.stream.write_all(head.as_bytes()).await.is_err() {
            return;
        }
        if !pending.is_empty() && upstream.stream.write_all(&pending).await.is_err() {
            return;
        }
    }

    session.relay(&target, client, upstream).await;
}

#[derive(Debug, thiserror::Error)]
enum HeadError {
    #[error("ligne de requête mal formée")]
    MalformedRequestLine,
    #[error("en-tête de requête trop volumineux")]
    TooLarge,
    #[error("le client a coupé avant d'envoyer une requête")]
    Closed,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug)]
struct Request {
    method: String,
    uri: String,
    version: String,
    headers: Vec<(String, String)>,
    is_connect: bool,
}

impl Request {
    /// Destination demandée, tirée de la cible de requête ou de l'en-tête `Host`.
    fn target(&self) -> Option<Target> {
        if self.is_connect {
            return split_authority(&self.uri, 443);
        }
        if let Some(rest) = self
            .uri
            .strip_prefix("http://")
            .or_else(|| self.uri.strip_prefix("https://"))
        {
            let default_port = if self.uri.starts_with("https://") {
                443
            } else {
                80
            };
            let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
            // On retire l'éventuel userinfo, qu'il ne faut jamais transmettre.
            let authority = authority.rsplit('@').next().unwrap_or(authority);
            return split_authority(authority, default_port);
        }
        // Une forme d'origine sans URI absolue est une requête adressée au proxy
        // lui-même, pas quelque chose que l'on peut router : on se rabat sur
        // l'en-tête `Host` s'il est présent.
        self.header("host")
            .and_then(|host| split_authority(host, 80))
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn authorised(&self, expected: &ProxyCredentials) -> bool {
        let Some(value) = self.header("proxy-authorization") else {
            return false;
        };
        let Some(encoded) = value
            .strip_prefix("Basic ")
            .or_else(|| value.strip_prefix("basic "))
        else {
            return false;
        };
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else {
            return false;
        };
        let expected_pair = format!("{}:{}", expected.username, expected.password);
        constant_time_eq(&decoded, expected_pair.as_bytes())
    }

    /// Reconstruit l'en-tête en forme d'origine, sans les en-têtes propres au proxy.
    fn forwarded_head(&self) -> String {
        let path = origin_form(&self.uri);
        let mut head = format!("{} {} {}\r\n", self.method, path, self.version);
        for (name, value) in &self.headers {
            let lower = name.to_ascii_lowercase();
            // Les en-têtes saut par saut et ceux propres au proxy s'arrêtent ici.
            if matches!(
                lower.as_str(),
                "proxy-connection" | "proxy-authorization" | "proxy-authenticate" | "connection"
            ) {
                continue;
            }
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str("Connection: close\r\n\r\n");
        head
    }
}

fn origin_form(uri: &str) -> String {
    for prefix in ["http://", "https://"] {
        if let Some(rest) = uri.strip_prefix(prefix) {
            return match rest.find('/') {
                Some(idx) => rest[idx..].to_string(),
                None => "/".to_string(),
            };
        }
    }
    uri.to_string()
}

/// Découpe `hôte:port`, `hôte` ou `[v6]:port`.
fn split_authority(authority: &str, default_port: u16) -> Option<Target> {
    let authority = authority.trim();
    if authority.is_empty() {
        return None;
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = tail
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(default_port);
        return Some(Target::new(host, port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => {
            let port = port.parse().ok()?;
            Some(Target::new(host, port))
        }
        _ => Some(Target::new(authority, default_port)),
    }
}

async fn read_head(reader: &mut BufReader<TcpStream>) -> Result<Request, HeadError> {
    let mut budget = MAX_HEAD_BYTES;
    let request_line = read_line(reader, &mut budget).await?;
    if request_line.is_empty() {
        return Err(HeadError::Closed);
    }
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or(HeadError::MalformedRequestLine)?
        .to_string();
    let uri = parts
        .next()
        .ok_or(HeadError::MalformedRequestLine)?
        .to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();
    if !version.starts_with("HTTP/") {
        return Err(HeadError::MalformedRequestLine);
    }

    let mut headers = Vec::new();
    loop {
        let line = read_line(reader, &mut budget).await?;
        if line.is_empty() {
            break;
        }
        if headers.len() >= MAX_HEADER_LINES {
            return Err(HeadError::TooLarge);
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }

    let is_connect = method.eq_ignore_ascii_case("CONNECT");
    Ok(Request {
        method,
        uri,
        version,
        headers,
        is_connect,
    })
}

async fn read_line(
    reader: &mut BufReader<TcpStream>,
    budget: &mut usize,
) -> Result<String, HeadError> {
    let mut raw = Vec::new();
    let read = reader.read_until(b'\n', &mut raw).await?;
    if read == 0 {
        return Err(HeadError::Closed);
    }
    *budget = budget.checked_sub(read).ok_or(HeadError::TooLarge)?;
    while raw.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        raw.pop();
    }
    Ok(String::from_utf8_lossy(&raw).into_owned())
}

async fn write_status(
    stream: &mut TcpStream,
    code: u16,
    reason: &str,
    detail: &str,
) -> std::io::Result<()> {
    let body = format!("{code} {reason}\n{detail}\n");
    let response = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

async fn write_proxy_auth_required(stream: &mut TcpStream) -> std::io::Result<()> {
    let response = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"tiv-gateway\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::Host;

    fn request(method: &str, uri: &str, headers: &[(&str, &str)]) -> Request {
        Request {
            method: method.to_string(),
            uri: uri.to_string(),
            version: "HTTP/1.1".to_string(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            is_connect: method.eq_ignore_ascii_case("CONNECT"),
        }
    }

    #[test]
    fn connect_targets_default_to_port_443() {
        let target = request("CONNECT", "example.onion:443", &[])
            .target()
            .unwrap();
        assert_eq!(target.to_string(), "example.onion:443");
        let target = request("CONNECT", "example.onion", &[]).target().unwrap();
        assert_eq!(target.port, 443);
    }

    #[test]
    fn absolute_uris_are_split_into_host_and_port() {
        let target = request("GET", "http://stats.i2p/index.html", &[])
            .target()
            .unwrap();
        assert_eq!(target.host, Host::Name("stats.i2p".into()));
        assert_eq!(target.port, 80);

        let target = request("GET", "http://example.com:8080/x?y=1", &[])
            .target()
            .unwrap();
        assert_eq!(target.port, 8080);
    }

    #[test]
    fn userinfo_is_never_kept_in_the_target() {
        let target = request("GET", "http://user:pass@example.com/x", &[])
            .target()
            .unwrap();
        assert_eq!(target.host, Host::Name("example.com".into()));
    }

    #[test]
    fn ipv6_authorities_are_parsed() {
        let target = split_authority("[2606:4700::1111]:8443", 80).unwrap();
        assert_eq!(target.port, 8443);
        assert_eq!(target.to_string(), "[2606:4700::1111]:8443");
    }

    #[test]
    fn origin_form_keeps_the_path_and_query() {
        assert_eq!(origin_form("http://example.com/a/b?c=d"), "/a/b?c=d");
        assert_eq!(origin_form("http://example.com"), "/");
        assert_eq!(origin_form("/already/origin"), "/already/origin");
    }

    #[test]
    fn the_forwarded_head_drops_proxy_headers() {
        let head = request(
            "GET",
            "http://example.com/x",
            &[
                ("Host", "example.com"),
                ("Proxy-Connection", "keep-alive"),
                ("Proxy-Authorization", "Basic c2VjcmV0"),
                ("User-Agent", "curl/8"),
            ],
        )
        .forwarded_head();

        assert!(head.starts_with("GET /x HTTP/1.1\r\n"));
        assert!(head.contains("Host: example.com\r\n"));
        assert!(head.contains("User-Agent: curl/8\r\n"));
        assert!(!head.to_lowercase().contains("proxy-connection"));
        assert!(!head.to_lowercase().contains("proxy-authorization"));
        assert!(head.ends_with("Connection: close\r\n\r\n"));
    }

    #[test]
    fn basic_proxy_authentication_is_checked() {
        let credentials = ProxyCredentials {
            username: "pi".into(),
            password: "raspberry".into(),
        };
        let good = base64::engine::general_purpose::STANDARD.encode("pi:raspberry");
        assert!(request(
            "GET",
            "http://example.com/",
            &[("Proxy-Authorization", &format!("Basic {good}"))]
        )
        .authorised(&credentials));

        let bad = base64::engine::general_purpose::STANDARD.encode("pi:wrong");
        assert!(!request(
            "GET",
            "http://example.com/",
            &[("Proxy-Authorization", &format!("Basic {bad}"))]
        )
        .authorised(&credentials));

        assert!(!request("GET", "http://example.com/", &[]).authorised(&credentials));
    }
}
