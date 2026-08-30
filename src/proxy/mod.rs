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

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::catalogue::{self, ResponseWatch};
use crate::metrics::{now_ms, BackendCounters, ConnectionRecord, ConnectionStatus};
use crate::routing::{DenyReason, Host, Target, Verdict};
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
    /// URL consignée au journal, lorsqu'il est actif. Le relais s'en sert pour
    /// rattacher le code HTTP et le titre découverts dans le flux descendant.
    catalogue_url: Option<String>,
    counters: Arc<BackendCounters>,
    _permit: CapacityPermit,
    _active: ActiveGuard,
}

/// Décrémente le compteur de connexions actives quoi qu'il arrive.
///
/// Sans ce garde, un abandon entre l'établissement du tunnel et le relais —
/// typiquement un client qui raccroche pendant qu'on lui répond — laisserait la
/// jauge gonflée jusqu'au redémarrage.
struct ActiveGuard {
    counters: Arc<BackendCounters>,
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.counters
            .connections_active
            .fetch_sub(1, Ordering::Relaxed);
    }
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
    ///
    /// `url` porte l'URL complète lorsque l'écoute la connaît — c'est le cas du
    /// proxy HTTP en URI absolue. En SOCKS5 elle est reconstruite à partir de
    /// l'hôte et du port, faute de mieux : la poignée de main ne transporte pas
    /// de chemin.
    pub async fn establish(
        &self,
        target: &Target,
        url: Option<&str>,
    ) -> Result<Connected, SessionError> {
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
                    catalogue_url: self.note_visit(target, url),
                    backend_id: decision.backend_id,
                    counters: Arc::clone(&counters),
                    _permit: permit,
                    _active: ActiveGuard { counters },
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
    ///
    /// `intercept_eligible` n'est vrai que pour un tunnel opaque (SOCKS5, ou
    /// CONNECT côté HTTP) : c'est le seul cas où le client s'apprête à parler
    /// TLS et où l'interception a un sens. Une requête HTTP en clair, elle, est
    /// déjà entièrement journalisée sans rien déchiffrer.
    pub async fn relay(
        &self,
        target: &Target,
        client: TcpStream,
        connected: Connected,
        intercept_eligible: bool,
    ) {
        let config = self.state.config();

        // Branche d'interception : uniquement pour les hôtes de la liste blanche,
        // sur un tunnel TLS. Le pont tient le tunnel jusqu'à sa fermeture.
        if intercept_eligible {
            if let Some(host) = crate::mitm::host_to_intercept(&config, target) {
                self.relay_intercepted(target, client, connected, host)
                    .await;
                return;
            }
        }

        let Connected {
            stream,
            backend_id,
            catalogue_url,
            counters,
            _permit,
            _active,
        } = connected;

        // Le renifleur ne regarde que le flux descendant, et abandonne dès le
        // premier octet qui n'est pas du HTTP en clair : le tunnel reste un
        // tuyau d'octets, pas un analyseur posé sur le trafic de l'utilisateur.
        let watch = catalogue_url.map(|url| {
            ResponseWatch::new(
                Arc::clone(&self.state.catalogue),
                url,
                config.catalogue.capture_titles,
            )
        });

        let (transferred, outcome) = relay::relay(
            client,
            stream,
            Arc::clone(&counters),
            Duration::from_secs(config.proxy.idle_timeout_s.max(5)),
            watch,
        )
        .await;

        // La jauge de connexions actives est rendue par `ActiveGuard`.
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

    /// Relaie une connexion en l'interceptant : le pont MITM tient les deux
    /// poignées de main TLS et journalise le HTTP en clair qui circule entre.
    ///
    /// Le permis de capacité et le garde de connexion active restent vivants
    /// toute la durée du pont ; les compteurs d'octets par backend ne sont pas
    /// alimentés ici — l'interception échange sa comptabilité fine contre la
    /// visibilité applicative.
    async fn relay_intercepted(
        &self,
        target: &Target,
        client: TcpStream,
        connected: Connected,
        host: String,
    ) {
        let config = self.state.config();
        let Connected {
            stream,
            backend_id,
            catalogue_url: _,
            counters: _,
            _permit,
            _active,
        } = connected;

        let idle = Duration::from_secs(config.proxy.idle_timeout_s.max(5));
        crate::mitm::bridge::run(
            Arc::clone(&self.state.mitm),
            client,
            stream,
            host,
            target.port,
            idle,
        )
        .await;

        self.write_record(
            target,
            Some(&backend_id),
            None,
            ConnectionStatus::Closed,
            Default::default(),
            Some("connexion interceptée".to_string()),
        );
    }

    /// Consigne la destination au journal, s'il est actif, et renvoie l'URL
    /// retenue pour que le relais puisse l'enrichir.
    fn note_visit(&self, target: &Target, url: Option<&str>) -> Option<String> {
        if !self.state.config().catalogue.enabled {
            return None;
        }
        let host = match &target.host {
            Host::Name(name) => name.clone(),
            // Les crochets d'une IPv6 font partie de l'autorité de l'URL.
            Host::Ip(IpAddr::V6(ip)) => format!("[{ip}]"),
            Host::Ip(ip) => ip.to_string(),
        };
        let url = catalogue::url_for(&host, target.port, url);
        self.state.catalogue.visit(&url);
        Some(url)
    }

    /// Consigne un tunnel abandonné entre son établissement et le relais, quand
    /// le client raccroche pendant qu'on lui répond.
    pub fn note_aborted(&self, target: &Target, backend_id: &str, detail: impl Into<String>) {
        self.write_record(
            target,
            Some(backend_id),
            None,
            ConnectionStatus::Failed,
            Default::default(),
            Some(detail.into()),
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
