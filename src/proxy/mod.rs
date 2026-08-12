//! Le plan de données : accepter les clients, décider où part le trafic, le relayer.
//!
//! ```mermaid
//! sequenceDiagram
//!     participant C as Client
//!     participant L as Écoute SOCKS5/HTTP
//!     participant R as Routeur
//!     participant U as Backend amont
//!     C->>L: poignée de main + destination
//!     L->>R: route(destination)
//!     alt refus
//!         R-->>L: Deny(motif)
//!         L-->>C: réponse d'erreur
//!     else autorisé
//!         R-->>L: backend retenu
//!         L->>U: connexion (SOCKS5, CONNECT ou directe)
//!         U-->>L: tunnel établi
//!         L-->>C: réponse de succès
//!         L->>L: relais bidirectionnel avec comptage
//!     end
//! ```

pub mod http;
pub mod relay;
pub mod socks5;
pub mod upstream;

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::metrics::{now_ms, BackendCounters, ConnectionRecord, ConnectionStatus};
use crate::routing::{DenyReason, Target, Verdict};
use crate::state::{AppState, CapacityPermit};
use upstream::UpstreamError;

/// Démarre toutes les écoutes proxy activées. Ne rend la main qu'une fois
/// qu'elles se sont toutes arrêtées.
pub async fn serve(state: Arc<AppState>) -> anyhow::Result<()> {
    let config = state.config();
    let mut listeners = Vec::new();

    if let Some(bind) = config.proxy.socks5_bind.clone() {
        let state = Arc::clone(&state);
        listeners.push(tokio::spawn(async move {
            if let Err(err) = socks5::listen(state, &bind).await {
                warn!(%err, "l'écoute SOCKS5 s'est arrêtée");
            }
        }));
    }
    if let Some(bind) = config.proxy.http_bind.clone() {
        let state = Arc::clone(&state);
        listeners.push(tokio::spawn(async move {
            if let Err(err) = http::listen(state, &bind).await {
                warn!(%err, "l'écoute proxy HTTP s'est arrêtée");
            }
        }));
    }
    if listeners.is_empty() {
        warn!("aucune écoute proxy activée : seule l'interface d'administration sera servie");
    }
    for listener in listeners {
        let _ = listener.await;
    }
    Ok(())
}

/// Raison pour laquelle une connexion n'a pas pu être établie.
#[derive(Debug)]
pub enum SessionError {
    Denied(DenyReason),
    AtCapacity,
    Upstream(UpstreamError),
}

impl SessionError {
    pub fn socks5_reply(&self) -> u8 {
        match self {
            SessionError::Denied(_) => 0x02,
            SessionError::AtCapacity => 0x01,
            SessionError::Upstream(err) => err.socks5_reply(),
        }
    }

    pub fn http_status(&self) -> (u16, &'static str) {
        match self {
            SessionError::Denied(_) => (403, "Forbidden"),
            SessionError::AtCapacity => (503, "Service Unavailable"),
            SessionError::Upstream(err) => err.http_status(),
        }
    }

    pub fn message(&self) -> String {
        match self {
            SessionError::Denied(reason) => reason.as_str().to_string(),
            SessionError::AtCapacity => "limite de connexions atteinte".to_string(),
            SessionError::Upstream(err) => err.to_string(),
        }
    }
}

/// Une connexion qui a atteint son backend et n'attend plus que le relais.
pub struct Connected {
    pub stream: TcpStream,
    pub backend_id: String,
    counters: Arc<BackendCounters>,
    _permit: CapacityPermit,
}

/// Une connexion cliente, du premier octet jusqu'à l'enregistrement de clôture.
pub struct Session {
    state: Arc<AppState>,
    id: u64,
    client: SocketAddr,
    protocol: &'static str,
    started: Instant,
    started_ms: u64,
}

impl Session {
    pub fn new(state: Arc<AppState>, client: SocketAddr, protocol: &'static str) -> Self {
        let id = state.metrics.next_id();
        Session {
            state,
            id,
            client,
            protocol,
            started: Instant::now(),
            started_ms: now_ms(),
        }
    }

    /// Route `target`, puis compose vers le backend retenu.
    pub async fn establish(&self, target: &Target) -> Result<Connected, SessionError> {
        let config = self.state.config();
        let decision = self.state.router().route(target, &config.backends);

        if let Verdict::Deny(reason) = decision.verdict {
            self.state
                .metrics
                .backend(&decision.backend_id)
                .denied
                .fetch_add(1, Ordering::Relaxed);
            self.write_record(
                target,
                Some(&decision.backend_id),
                decision.matched_rule.as_deref(),
                ConnectionStatus::Denied,
                Default::default(),
                Some(reason.as_str().to_string()),
            );
            debug!(target = %target, reason = reason.as_str(), "connexion refusée");
            return Err(SessionError::Denied(reason));
        }

        let Some(permit) = self.state.try_acquire() else {
            self.state.metrics.note_capacity_rejection();
            self.write_record(
                target,
                Some(&decision.backend_id),
                decision.matched_rule.as_deref(),
                ConnectionStatus::Failed,
                Default::default(),
                Some("limite de connexions atteinte".to_string()),
            );
            warn!(
                limit = config.proxy.max_connections,
                "connexion refusée : la limite est atteinte"
            );
            return Err(SessionError::AtCapacity);
        };

        let backend = config
            .backend(&decision.backend_id)
            .expect("le routage a déjà vérifié que ce backend existe");
        let counters = self.state.metrics.backend(&decision.backend_id);

        let dial_started = Instant::now();
        let outcome = upstream::connect(
            backend,
            target,
            Duration::from_millis(config.proxy.connect_timeout_ms),
            config.routing.block_private_ranges,
        )
        .await;
        let latency_ms = dial_started.elapsed().as_millis() as u64;

        match outcome {
            Ok(stream) => {
                counters.connections_total.fetch_add(1, Ordering::Relaxed);
                counters.connections_active.fetch_add(1, Ordering::Relaxed);
                self.state
                    .metrics
                    .observe_connect(&decision.backend_id, latency_ms);
                self.write_record(
                    target,
                    Some(&decision.backend_id),
                    decision.matched_rule.as_deref(),
                    ConnectionStatus::Active,
                    Default::default(),
                    None,
                );
                info!(
                    id = self.id,
                    protocol = self.protocol,
                    backend = %decision.backend_id,
                    target = %target,
                    latency_ms,
                    "tunnel ouvert"
                );
                Ok(Connected {
                    stream,
                    backend_id: decision.backend_id,
                    counters,
                    _permit: permit,
                })
            }
            Err(err) => {
                counters.errors.fetch_add(1, Ordering::Relaxed);
                self.write_record(
                    target,
                    Some(&decision.backend_id),
                    decision.matched_rule.as_deref(),
                    ConnectionStatus::Failed,
                    Default::default(),
                    Some(err.to_string()),
                );
                warn!(
                    id = self.id,
                    backend = %decision.backend_id,
                    target = %target,
                    %err,
                    "échec de la connexion amont"
                );
                Err(SessionError::Upstream(err))
            }
        }
    }

    /// Relaie jusqu'à la fermeture d'un des deux côtés, puis clôt
    /// l'enregistrement de la connexion.
    pub async fn relay(&self, target: &Target, client: TcpStream, connected: Connected) {
        let config = self.state.config();
        let Connected {
            stream,
            backend_id,
            counters,
            _permit,
        } = connected;

        let (transferred, outcome) = relay::relay(
            client,
            stream,
            Arc::clone(&counters),
            Duration::from_secs(config.proxy.idle_timeout_s.max(5)),
        )
        .await;

        counters.connections_active.fetch_sub(1, Ordering::Relaxed);
        let detail = match &outcome {
            Ok(()) => None,
            Err(err) => Some(err.to_string()),
        };
        self.write_record(
            target,
            Some(&backend_id),
            None,
            ConnectionStatus::Closed,
            transferred,
            detail,
        );
        debug!(
            id = self.id,
            backend = %backend_id,
            up = transferred.up,
            down = transferred.down,
            "tunnel fermé"
        );
    }

    /// Consigne un échec survenu avant le routage, typiquement une poignée de
    /// main cliente invalide.
    pub fn note_protocol_error(&self, detail: impl Into<String>) {
        self.state.metrics.record(ConnectionRecord {
            id: self.id,
            started_ms: self.started_ms,
            client: self.client.to_string(),
            target: "-".to_string(),
            protocol: self.protocol,
            backend: None,
            rule: None,
            status: ConnectionStatus::Failed,
            bytes_up: 0,
            bytes_down: 0,
            duration_ms: self.started.elapsed().as_millis() as u64,
            detail: Some(detail.into()),
        });
    }

    fn write_record(
        &self,
        target: &Target,
        backend: Option<&str>,
        rule: Option<&str>,
        status: ConnectionStatus,
        transferred: relay::Transferred,
        detail: Option<String>,
    ) {
        self.state.metrics.record(ConnectionRecord {
            id: self.id,
            started_ms: self.started_ms,
            client: self.client.to_string(),
            target: target.to_string(),
            protocol: self.protocol,
            backend: backend.map(str::to_string),
            rule: rule.map(str::to_string),
            status,
            bytes_up: transferred.up,
            bytes_down: transferred.down,
            duration_ms: self.started.elapsed().as_millis() as u64,
            detail,
        });
    }
}
