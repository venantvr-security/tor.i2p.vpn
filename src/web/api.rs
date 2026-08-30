//! Gestionnaires de l'API JSON.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::info;

use crate::auth;
use crate::catalogue;
use crate::config::Config;
use crate::health::{self, HealthReport, HealthState};
use crate::metrics::MetricsSnapshot;
use crate::routing::{Target, Verdict};
use crate::state::AppState;
use crate::tor_control::TorStatus;

use super::{ApiError, ApiResult};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

pub async fn get_config(State(state): State<Arc<AppState>>) -> Json<Config> {
    Json(state.config().redacted())
}

#[derive(Serialize)]
pub struct ConfigApplied {
    /// Écoutes dont l'adresse a changé et qui exigent un redémarrage du conteneur.
    pub restart_required: Vec<String>,
}

pub async fn put_config(
    State(state): State<Arc<AppState>>,
    Json(mut config): Json<Config>,
) -> ApiResult<Json<ConfigApplied>> {
    let previous = state.config();
    config.unredact_from(&previous);
    let restart_required = state
        .apply_config(config)
        .map_err(|err| ApiError::bad_request(format!("{err:#}")))?;
    info!(
        ?restart_required,
        "configuration mise à jour depuis l'interface web"
    );
    Ok(Json(ConfigApplied { restart_required }))
}

/// Contrôle une configuration sans l'enregistrer, pour un retour immédiat dans
/// le formulaire.
pub async fn validate_config(
    State(state): State<Arc<AppState>>,
    Json(mut config): Json<Config>,
) -> ApiResult<Json<serde_json::Value>> {
    config.unredact_from(&state.config());
    match config.validate() {
        Ok(()) => Ok(Json(json!({ "valid": true }))),
        Err(err) => Ok(Json(json!({ "valid": false, "error": format!("{err:#}") }))),
    }
}

#[derive(Deserialize)]
pub struct PasswordChange {
    pub current: String,
    pub new: String,
}

pub async fn change_password(
    State(state): State<Arc<AppState>>,
    Json(request): Json<PasswordChange>,
) -> ApiResult<Response> {
    let mut config = (*state.config()).clone();
    let current_hash = config
        .auth
        .password_hash
        .clone()
        .ok_or_else(|| ApiError::bad_request("aucun mot de passe n'est configuré"))?;
    if !auth::verify_password(&current_hash, &request.current) {
        return Err(ApiError::unauthorized(
            "le mot de passe actuel est incorrect",
        ));
    }
    config.auth.password_hash = Some(
        auth::hash_password(&request.new).map_err(|err| ApiError::bad_request(err.to_string()))?,
    );
    // Faire tourner la clé de signature déconnecte toutes les autres sessions.
    config.auth.session_secret = Some(auth::generate_secret());
    let ttl = config.auth.ttl_hours();
    let secret = config
        .auth
        .session_secret
        .clone()
        .expect("le secret vient d'être défini");
    state
        .apply_config(config)
        .map_err(|err| ApiError::bad_request(err.to_string()))?;
    info!("mot de passe administrateur modifié");
    super::issue_session(&secret, ttl)
}

// ---------------------------------------------------------------------------
// État et métriques
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct Status {
    pub version: &'static str,
    pub uptime_s: u64,
    pub active_connections: usize,
    pub max_connections: usize,
    pub listeners: Listeners,
    pub backends: Vec<BackendSummary>,
    pub default_backend: String,
    pub rules: usize,
    pub tor_control_enabled: bool,
    pub health_enabled: bool,
}

#[derive(Serialize)]
pub struct Listeners {
    pub socks5: Option<String>,
    pub http: Option<String>,
    pub admin: String,
}

#[derive(Serialize)]
pub struct BackendSummary {
    pub id: String,
    pub label: String,
    pub kind: &'static str,
    pub enabled: bool,
    pub address: Option<String>,
}

pub async fn status(State(state): State<Arc<AppState>>) -> Json<Status> {
    let config = state.config();
    let snapshot = state.metrics.snapshot();
    Json(Status {
        version: env!("CARGO_PKG_VERSION"),
        uptime_s: snapshot.uptime_s,
        active_connections: state.active_connections(),
        max_connections: config.proxy.max_connections,
        listeners: Listeners {
            socks5: config.proxy.socks5_bind.clone(),
            http: config.proxy.http_bind.clone(),
            admin: config.server.admin_bind.clone(),
        },
        backends: config
            .backends
            .iter()
            .map(|backend| BackendSummary {
                id: backend.id.clone(),
                label: backend.label.clone(),
                kind: backend.kind_name(),
                enabled: backend.enabled,
                address: backend.upstream_address().map(str::to_string),
            })
            .collect(),
        default_backend: config.routing.default_backend.clone(),
        rules: config.routing.rules.iter().filter(|r| r.enabled).count(),
        tor_control_enabled: config.tor_control.enabled,
        health_enabled: config.health.enabled,
    })
}

#[derive(Serialize)]
pub struct LiveSnapshot {
    pub active_connections: usize,
    pub max_connections: usize,
    #[serde(flatten)]
    pub metrics: MetricsSnapshot,
}

pub fn live_snapshot(state: &AppState) -> LiveSnapshot {
    LiveSnapshot {
        active_connections: state.active_connections(),
        max_connections: state.config().proxy.max_connections,
        metrics: state.metrics.snapshot(),
    }
}

pub async fn metrics(State(state): State<Arc<AppState>>) -> Json<LiveSnapshot> {
    Json(live_snapshot(&state))
}

pub async fn prometheus(State(state): State<Arc<AppState>>) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        state.metrics.prometheus(),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

pub async fn health(State(state): State<Arc<AppState>>) -> Json<HealthState> {
    let config = state.config();
    Json(state.health.state(config.health.enabled))
}

pub async fn run_health(State(state): State<Arc<AppState>>) -> Json<HealthReport> {
    let config = state.config();
    Json(health::run_probes(&state.health, &config).await)
}

// ---------------------------------------------------------------------------
// Tor control
// ---------------------------------------------------------------------------

pub async fn tor_status(State(state): State<Arc<AppState>>) -> Json<TorStatus> {
    let config = state.config();
    Json(state.tor.status(&config.tor_control).await)
}

pub async fn tor_newnym(State(state): State<Arc<AppState>>) -> ApiResult<Json<serde_json::Value>> {
    let config = state.config();
    state
        .tor
        .new_identity(&config.tor_control)
        .await
        .map_err(|err| ApiError::bad_request(format!("{err:#}")))?;
    info!("nouvelle identité Tor demandée");
    Ok(Json(json!({ "ok": true })))
}

pub async fn tor_close_circuit(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let config = state.config();
    state
        .tor
        .close_circuit(&config.tor_control, &id)
        .await
        .map_err(|err| ApiError::bad_request(format!("{err:#}")))?;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Journal des destinations
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct CatalogueEntry {
    pub url: String,
    pub code: Option<u16>,
    pub titre: Option<String>,
    pub vu: u64,
    /// « tor », « i2p » ou « standard », déduit du suffixe de la destination.
    pub reseau: &'static str,
}

#[derive(Serialize)]
pub struct CatalogueView {
    pub enabled: bool,
    pub capture_titles: bool,
    pub max_entries: usize,
    /// Bornes acceptées par la configuration, pour que l'interface les impose
    /// au lieu de laisser l'utilisateur découvrir le refus à l'enregistrement.
    pub min_allowed: usize,
    pub max_allowed: usize,
    pub count: usize,
    pub entries: Vec<CatalogueEntry>,
}

pub async fn catalogue(State(state): State<Arc<AppState>>) -> Json<CatalogueView> {
    let config = state.config();
    let entries: Vec<CatalogueEntry> = state
        .catalogue
        .entries()
        .into_iter()
        .map(|entry| CatalogueEntry {
            reseau: entry.reseau(),
            url: entry.url,
            code: entry.code,
            titre: entry.titre,
            vu: entry.vu,
        })
        .collect();
    Json(CatalogueView {
        enabled: config.catalogue.enabled,
        capture_titles: config.catalogue.capture_titles,
        max_entries: state.catalogue.max_entries(),
        min_allowed: catalogue::MIN_ENTRIES,
        max_allowed: catalogue::MAX_ENTRIES,
        count: entries.len(),
        entries,
    })
}

/// Efface le journal, en mémoire comme sur disque.
pub async fn purge_catalogue(
    State(state): State<Arc<AppState>>,
) -> ApiResult<Json<serde_json::Value>> {
    state
        .catalogue
        .purge()
        .map_err(|err| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    info!("journal des destinations effacé");
    Ok(Json(json!({ "count": 0 })))
}

// ---------------------------------------------------------------------------
// Bac à sable de routage
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RouteQuery {
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

fn default_port() -> u16 {
    443
}

#[derive(Serialize)]
pub struct RouteAnswer {
    pub target: String,
    pub backend: String,
    pub backend_label: Option<String>,
    pub rule: Option<String>,
    pub allowed: bool,
    pub reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Interception TLS
// ---------------------------------------------------------------------------

/// État de l'interception, pour la page dédiée.
pub async fn mitm_status(State(state): State<Arc<AppState>>) -> Json<crate::mitm::MitmStatus> {
    let config = state.config();
    Json(state.mitm.status(&config))
}

/// Sert le certificat public de la CA, à installer comme racine de confiance.
pub async fn mitm_ca(State(state): State<Arc<AppState>>) -> Response {
    let pem = state.mitm.ca().cert_pem().to_string();
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/x-pem-file"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"passerelle-interception-ca.pem\"",
            ),
        ],
        pem,
    )
        .into_response()
}

#[derive(Serialize)]
pub struct CaRegenerated {
    pub fingerprint: String,
}

/// Régénère la CA. Rupture assumée : toute racine déjà installée devient caduque.
pub async fn mitm_regenerate_ca(
    State(state): State<Arc<AppState>>,
) -> ApiResult<Json<CaRegenerated>> {
    let fingerprint = state
        .mitm
        .regenerate_ca()
        .map_err(|err| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("{err:#}")))?;
    info!("CA d'interception régénérée");
    Ok(Json(CaRegenerated { fingerprint }))
}

/// Simule la table de routage : « où partirait ce nom d'hôte ? ».
pub async fn test_route(
    State(state): State<Arc<AppState>>,
    Json(query): Json<RouteQuery>,
) -> ApiResult<Json<RouteAnswer>> {
    let host = query.host.trim();
    if host.is_empty() {
        return Err(ApiError::bad_request("un nom d'hôte est requis"));
    }
    let config = state.config();
    let target = Target::new(host, query.port);
    let decision = state.router().route(&target, &config.backends);
    let (allowed, reason) = match &decision.verdict {
        Verdict::Allow => (true, None),
        Verdict::Deny(reason) => (false, Some(reason.as_str().to_string())),
    };
    Ok(Json(RouteAnswer {
        target: target.to_string(),
        backend_label: config
            .backend(&decision.backend_id)
            .map(|b| b.label.clone()),
        backend: decision.backend_id,
        rule: decision.matched_rule,
        allowed,
        reason,
    }))
}
