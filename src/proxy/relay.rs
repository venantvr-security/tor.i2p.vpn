//! Copie bidirectionnelle entre la socket cliente et la socket amont, avec
//! comptage des octets et garde-fou sur l'inactivité.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::metrics::BackendCounters;

/// 16 Kio maintient l'empreinte mémoire raisonnable avec quelques centaines de
/// tunnels simultanés sur un Raspberry Pi.
const BUFFER_SIZE: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, Default)]
pub struct Transferred {
    pub up: u64,
    pub down: u64,
}

/// Fait circuler les octets dans les deux sens jusqu'à la fermeture d'un côté
/// ou le déclenchement du délai d'inactivité.
///
/// Les compteurs sont renvoyés même lorsque le relais se termine sur une
/// erreur : un transfert échoué affiche ainsi de vrais chiffres dans
/// l'interface.
pub async fn relay(
    client: TcpStream,
    upstream: TcpStream,
    counters: Arc<BackendCounters>,
    idle_timeout: Duration,
) -> (Transferred, io::Result<()>) {
    let (client_read, client_write) = client.into_split();
    let (upstream_read, upstream_write) = upstream.into_split();

    let up = Arc::new(AtomicU64::new(0));
    let down = Arc::new(AtomicU64::new(0));

    let upload = pump(
        client_read,
        upstream_write,
        Arc::clone(&up),
        Arc::clone(&counters),
        Direction::Up,
        idle_timeout,
    );
    let download = pump(
        upstream_read,
        client_write,
        Arc::clone(&down),
        Arc::clone(&counters),
        Direction::Down,
        idle_timeout,
    );

    let outcome = tokio::try_join!(upload, download).map(|_| ());
    (
        Transferred {
            up: up.load(Ordering::Relaxed),
            down: down.load(Ordering::Relaxed),
        },
        outcome,
    )
}

#[derive(Clone, Copy)]
enum Direction {
    Up,
    Down,
}

async fn pump<R, W>(
    mut reader: R,
    mut writer: W,
    total: Arc<AtomicU64>,
    counters: Arc<BackendCounters>,
    direction: Direction,
    idle_timeout: Duration,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; BUFFER_SIZE];
    loop {
        let read = match tokio::time::timeout(idle_timeout, reader.read(&mut buffer)).await {
            Ok(result) => result?,
            Err(_) => {
                // Demi-fermeture, pour que le pair apprenne que le tunnel est
                // terminé au lieu d'attendre indéfiniment.
                let _ = writer.shutdown().await;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "délai d'inactivité dépassé",
                ));
            }
        };
        if read == 0 {
            let _ = writer.shutdown().await;
            return Ok(());
        }
        writer.write_all(&buffer[..read]).await?;
        let read = read as u64;
        total.fetch_add(read, Ordering::Relaxed);
        match direction {
            Direction::Up => counters.bytes_up.fetch_add(read, Ordering::Relaxed),
            Direction::Down => counters.bytes_down.fetch_add(read, Ordering::Relaxed),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// Lance un serveur d'écho et renvoie son adresse.
    async fn echo_server() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = socket.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                    let _ = w.shutdown().await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn bytes_are_counted_in_both_directions() {
        let echo = echo_server().await;

        let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();

        let counters = Arc::new(BackendCounters::default());
        let counters_for_relay = Arc::clone(&counters);
        let relay_task = tokio::spawn(async move {
            let (client, _) = client_listener.accept().await.unwrap();
            let upstream = TcpStream::connect(echo).await.unwrap();
            relay(client, upstream, counters_for_relay, Duration::from_secs(5)).await
        });

        let mut client = TcpStream::connect(client_addr).await.unwrap();
        client.write_all(b"hello relay").await.unwrap();
        client.shutdown().await.unwrap();
        let mut echoed = Vec::new();
        client.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"hello relay");

        let (transferred, outcome) = relay_task.await.unwrap();
        assert!(outcome.is_ok(), "le relais s'est terminé sur {outcome:?}");
        assert_eq!(transferred.up, 11);
        assert_eq!(transferred.down, 11);
        assert_eq!(counters.bytes_up.load(Ordering::Relaxed), 11);
        assert_eq!(counters.bytes_down.load(Ordering::Relaxed), 11);
    }

    #[tokio::test]
    async fn an_idle_tunnel_is_torn_down() {
        let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let silent_addr = silent.local_addr().unwrap();
        tokio::spawn(async move {
            // On garde la connexion ouverte sans jamais rien émettre.
            let (socket, _) = silent.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(socket);
        });

        let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let relay_task = tokio::spawn(async move {
            let (client, _) = client_listener.accept().await.unwrap();
            let upstream = TcpStream::connect(silent_addr).await.unwrap();
            relay(
                client,
                upstream,
                Arc::new(BackendCounters::default()),
                Duration::from_millis(120),
            )
            .await
        });

        let _client = TcpStream::connect(client_addr).await.unwrap();
        let (_, outcome) = relay_task.await.unwrap();
        assert_eq!(outcome.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }
}
