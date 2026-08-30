//! Cadrage HTTP/1.1, juste assez pour relayer fidèlement et observer.
//!
//! Le pont d'interception lit une requête, la transmet à l'amont, lit la
//! réponse, la renvoie au client, et recommence tant que la connexion tient.
//! Ce module fournit la brique commune : lire un bloc d'en-têtes, en déduire
//! comment le corps est délimité, puis recopier ce corps à l'octet près tout en
//! en donnant une copie du contenu à qui veut l'observer.
//!
//! Les octets sont recopiés *tels quels* — l'en-tête d'origine, le cadrage des
//! fragments *chunked* — de sorte que l'interception n'altère jamais rien. Seul
//! le *contenu* (dé-fragmenté) est donné à l'observateur, jamais les octets
//! réécrits : la passerelle regarde, elle ne réécrit pas.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Plafond du bloc d'en-têtes, aligné sur l'écoute proxy en clair.
const MAX_HEAD_BYTES: usize = 32 * 1024;
/// Taille des morceaux recopiés pour un corps à longueur connue.
const COPY_CHUNK: usize = 16 * 1024;

/// Observateur du contenu recopié : il reçoit le contenu utile, jamais le
/// cadrage, et doit être `Send` pour circuler dans une tâche tokio.
pub type Sink<'a> = Option<&'a mut (dyn FnMut(&[u8]) + Send)>;

/// Un bloc d'en-têtes lu, conservé brut pour être retransmis à l'identique.
#[derive(Debug, Clone)]
pub struct Head {
    pub raw: Vec<u8>,
    pub start_line: String,
    pub headers: Vec<(String, String)>,
}

impl Head {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// `(méthode, cible, version)` d'une ligne de requête.
    pub fn request_parts(&self) -> Option<(&str, &str, &str)> {
        let mut parts = self.start_line.split_whitespace();
        let method = parts.next()?;
        let uri = parts.next()?;
        let version = parts.next().unwrap_or("HTTP/1.1");
        Some((method, uri, version))
    }

    /// Code de statut d'une ligne de réponse `HTTP/1.1 200 OK`.
    pub fn response_status(&self) -> Option<u16> {
        self.start_line
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .filter(|code| (100..=599).contains(code))
    }
}

/// Manière dont le corps d'un message est délimité.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Body {
    /// Aucun corps (GET sans corps, 204, 304, réponse à HEAD…).
    None,
    /// Longueur annoncée par `Content-Length`.
    Fixed(u64),
    /// Découpage `Transfer-Encoding: chunked`.
    Chunked,
    /// Le corps court jusqu'à la fermeture de la connexion.
    UntilClose,
}

/// Erreur de cadrage : on retombe alors en relais opaque, jamais on ne casse.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("bloc d'en-têtes trop volumineux")]
    HeadTooLarge,
    #[error("cadrage chunked invalide")]
    BadChunk,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Lit un bloc d'en-têtes complet. Renvoie `None` sur une fermeture propre
/// avant le moindre octet — la connexion est simplement terminée.
pub async fn read_head<R>(reader: &mut R) -> Result<Option<Head>, FrameError>
where
    R: AsyncRead + Unpin,
{
    let mut raw = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        let read = reader.read(&mut byte).await?;
        if read == 0 {
            if raw.is_empty() {
                return Ok(None);
            }
            // Fermeture au milieu d'un en-tête : rien d'exploitable.
            return Err(FrameError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "en-tête tronqué",
            )));
        }
        raw.push(byte[0]);
        if raw.ends_with(b"\r\n\r\n") {
            break;
        }
        if raw.len() > MAX_HEAD_BYTES {
            return Err(FrameError::HeadTooLarge);
        }
    }

    let text = String::from_utf8_lossy(&raw);
    let mut lines = text.split("\r\n");
    let start_line = lines.next().unwrap_or_default().to_string();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    Ok(Some(Head {
        raw,
        start_line,
        headers,
    }))
}

/// Délimitation du corps d'une requête : uniquement si elle l'annonce.
pub fn request_body(head: &Head) -> Body {
    body_from_headers(head).unwrap_or(Body::None)
}

/// Délimitation du corps d'une réponse, selon RFC 9112 §6.
///
/// Les réponses 1xx, 204 et 304, ainsi que toute réponse à une requête HEAD,
/// n'ont jamais de corps, quels que soient leurs en-têtes.
pub fn response_body(head: &Head, status: u16, to_head_request: bool) -> Body {
    if to_head_request || status == 204 || status == 304 || (100..200).contains(&status) {
        return Body::None;
    }
    match body_from_headers(head) {
        Some(body) => body,
        // Ni longueur ni chunked : le corps court jusqu'à la fermeture.
        None => Body::UntilClose,
    }
}

/// Lit `Transfer-Encoding` puis `Content-Length`. Le premier l'emporte, comme
/// l'exige la RFC lorsque les deux sont présents.
fn body_from_headers(head: &Head) -> Option<Body> {
    if let Some(te) = head.header("transfer-encoding") {
        if te
            .to_ascii_lowercase()
            .split(',')
            .any(|t| t.trim() == "chunked")
        {
            return Some(Body::Chunked);
        }
    }
    if let Some(len) = head.header("content-length") {
        if let Ok(n) = len.trim().parse::<u64>() {
            return Some(Body::Fixed(n));
        }
    }
    None
}

/// Recopie le corps de `reader` vers `writer`, à l'octet près, en confiant une
/// copie du *contenu* à `sink` (pour l'extraction du titre).
///
/// `sink` ne reçoit que le contenu utile — jamais le cadrage des fragments — et
/// n'est jamais appelé au-delà de ce dont l'observateur a besoin : l'appelant
/// cesse de fournir un `sink` dès qu'il a fini d'observer.
pub async fn forward_body<R, W>(
    reader: &mut R,
    writer: &mut W,
    body: Body,
    mut sink: Sink<'_>,
) -> Result<(), FrameError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match body {
        Body::None => Ok(()),
        Body::Fixed(len) => copy_fixed(reader, writer, len, &mut sink).await,
        Body::UntilClose => copy_until_close(reader, writer, &mut sink).await,
        Body::Chunked => copy_chunked(reader, writer, &mut sink).await,
    }
}

async fn copy_fixed<R, W>(
    reader: &mut R,
    writer: &mut W,
    mut remaining: u64,
    sink: &mut Sink<'_>,
) -> Result<(), FrameError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; COPY_CHUNK];
    while remaining > 0 {
        let want = remaining.min(COPY_CHUNK as u64) as usize;
        let read = reader.read(&mut buffer[..want]).await?;
        if read == 0 {
            return Err(FrameError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "corps plus court que Content-Length",
            )));
        }
        writer.write_all(&buffer[..read]).await?;
        feed(sink, &buffer[..read]);
        remaining -= read as u64;
    }
    Ok(())
}

async fn copy_until_close<R, W>(
    reader: &mut R,
    writer: &mut W,
    sink: &mut Sink<'_>,
) -> Result<(), FrameError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; COPY_CHUNK];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            return Ok(());
        }
        writer.write_all(&buffer[..read]).await?;
        feed(sink, &buffer[..read]);
    }
}

/// Recopie un corps `chunked` en préservant le cadrage, mais en ne donnant à
/// l'observateur que le contenu dé-fragmenté.
async fn copy_chunked<R, W>(
    reader: &mut R,
    writer: &mut W,
    sink: &mut Sink<'_>,
) -> Result<(), FrameError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let size_line = read_line(reader).await?;
        writer.write_all(&size_line).await?;
        // La taille précède un éventuel `;extension` ; seule la partie hexa compte.
        let size_text = String::from_utf8_lossy(&size_line);
        let hex = size_text.trim().split(';').next().unwrap_or("").trim();
        let size = u64::from_str_radix(hex, 16).map_err(|_| FrameError::BadChunk)?;

        if size == 0 {
            // Dernier fragment : recopier les éventuels trailers jusqu'à la
            // ligne vide finale, puis terminer.
            loop {
                let line = read_line(reader).await?;
                writer.write_all(&line).await?;
                if line == b"\r\n" || line == b"\n" || line.is_empty() {
                    break;
                }
            }
            return Ok(());
        }

        copy_fixed(reader, writer, size, sink).await?;
        // Le CRLF qui clôt le fragment.
        let crlf = read_line(reader).await?;
        writer.write_all(&crlf).await?;
    }
}

/// Lit une ligne terminée par LF, CRLF inclus, sans la décoder.
async fn read_line<R>(reader: &mut R) -> Result<Vec<u8>, FrameError>
where
    R: AsyncRead + Unpin,
{
    let mut line = Vec::with_capacity(32);
    let mut byte = [0u8; 1];
    loop {
        let read = reader.read(&mut byte).await?;
        if read == 0 {
            if line.is_empty() {
                return Err(FrameError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "fin de flux dans un corps chunked",
                )));
            }
            return Ok(line);
        }
        line.push(byte[0]);
        if byte[0] == b'\n' {
            return Ok(line);
        }
        if line.len() > MAX_HEAD_BYTES {
            return Err(FrameError::BadChunk);
        }
    }
}

fn feed(sink: &mut Sink<'_>, bytes: &[u8]) {
    if let Some(sink) = sink.as_mut() {
        sink(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    async fn head_of(bytes: &[u8]) -> Head {
        let mut reader = Cursor::new(bytes.to_vec());
        read_head(&mut reader).await.unwrap().unwrap()
    }

    #[tokio::test]
    async fn a_request_head_is_parsed() {
        let head = head_of(b"GET /a?b=1 HTTP/1.1\r\nHost: x.onion\r\nAccept: */*\r\n\r\n").await;
        let (method, uri, version) = head.request_parts().unwrap();
        assert_eq!((method, uri, version), ("GET", "/a?b=1", "HTTP/1.1"));
        assert_eq!(head.header("host"), Some("x.onion"));
        assert_eq!(request_body(&head), Body::None);
    }

    #[tokio::test]
    async fn read_head_reports_clean_eof() {
        let mut reader = Cursor::new(Vec::new());
        assert!(read_head(&mut reader).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn response_framing_follows_the_rfc() {
        let cl = head_of(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n").await;
        assert_eq!(response_body(&cl, 200, false), Body::Fixed(5));
        // Réponse à un HEAD : jamais de corps, malgré Content-Length.
        assert_eq!(response_body(&cl, 200, true), Body::None);

        let ch = head_of(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n").await;
        assert_eq!(response_body(&ch, 200, false), Body::Chunked);

        let bare = head_of(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n").await;
        assert_eq!(response_body(&bare, 200, false), Body::UntilClose);

        let no_body = head_of(b"HTTP/1.1 304 Not Modified\r\n\r\n").await;
        assert_eq!(response_body(&no_body, 304, false), Body::None);
    }

    #[tokio::test]
    async fn a_fixed_body_is_copied_verbatim_and_observed() {
        let mut reader = Cursor::new(b"hello world".to_vec());
        let mut out = Vec::new();
        let mut seen = Vec::new();
        {
            let mut sink = |bytes: &[u8]| seen.extend_from_slice(bytes);
            forward_body(&mut reader, &mut out, Body::Fixed(11), Some(&mut sink))
                .await
                .unwrap();
        }
        assert_eq!(out, b"hello world");
        assert_eq!(seen, b"hello world");
    }

    #[tokio::test]
    async fn a_chunked_body_is_reframed_verbatim_but_observed_decoded() {
        // « Wiki » puis « pedia » en deux fragments.
        let raw = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        let mut reader = Cursor::new(raw.to_vec());
        let mut out = Vec::new();
        let mut seen = Vec::new();
        {
            let mut sink = |bytes: &[u8]| seen.extend_from_slice(bytes);
            forward_body(&mut reader, &mut out, Body::Chunked, Some(&mut sink))
                .await
                .unwrap();
        }
        // Le flux ressort à l'identique, cadrage compris…
        assert_eq!(out, raw);
        // …mais l'observateur n'a vu que le contenu recomposé.
        assert_eq!(seen, b"Wikipedia");
    }

    #[tokio::test]
    async fn a_short_fixed_body_is_an_error() {
        let mut reader = Cursor::new(b"abc".to_vec());
        let mut out = Vec::new();
        let outcome = forward_body(&mut reader, &mut out, Body::Fixed(10), None).await;
        assert!(matches!(outcome, Err(FrameError::Io(_))));
    }
}
