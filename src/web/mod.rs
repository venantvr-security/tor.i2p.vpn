//! Surface HTTP d'administration : gestion de session, API JSON, flux temps
//! réel et SPA embarquée.

pub mod api;
pub mod assets;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use futures_util::stream::Stream;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_http::compression::CompressionLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

use crate::auth;
use crate::metrics::SAMPLE_PERIOD_S;
use crate::state::AppState;

/// Corps d'erreur JSON uniforme.
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        ApiError {
            status,
            message: message.into(),
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

pub fn now_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

pub fn router(state: Arc<AppState>) -> Router {
    let protected = Router::new()
        .route("/api/config", get(api::get_config).put(api::put_config))
        .route("/api/config/validate", post(api::validate_config))
        .route("/api/status", get(api::status))
        .route("/api/metrics", get(api::metrics))
        .route("/api/metrics/prometheus", get(api::prometheus))
        .route("/api/health", get(api::health))
        .route("/api/health/run", post(api::run_health))
        .route("/api/tor", get(api::tor_status))
        .route("/api/tor/newnym", post(api::tor_newnym))
        .route("/api/tor/circuits/{id}/close", post(api::tor_close_circuit))
        .route(
            "/api/catalogue",
            get(api::catalogue).delete(api::purge_catalogue),
        )
        .route("/api/routing/test", post(api::test_route))
        .route("/api/password", put(api::change_password))
        .route("/api/stream", get(stream))
        .route("/api/logout", post(logout))
        .route_layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            require_auth,
        ));

    let public = Router::new()
        .route("/api/session", get(session))
        .route("/api/login", post(login))
        .route("/api/setup", post(setup));

    Router::new()
        .merge(public)
        .merge(protected)
        .fallback(assets::serve)
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct LoginRequest {
    pub password: String,
}

#[derive(Serialize)]
struct SessionInfo {
    authenticated: bool,
    /// Vrai tant qu'aucun mot de passe administrateur n'a été défini.
    setup_required: bool,
}

async fn session(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Json<SessionInfo> {
    let config = state.config();
    Json(SessionInfo {
        authenticated: authenticated(&state, &headers),
        setup_required: config.auth.password_hash.is_none(),
    })
}

/// Point d'entrée de première initialisation : utilisable uniquement tant
/// qu'aucun mot de passe n'existe.
async fn setup(
    State(state): State<Arc<AppState>>,
    Json(request): Json<LoginRequest>,
) -> ApiResult<Response> {
    let mut config = (*state.config()).clone();
    if config.auth.password_hash.is_some() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "un mot de passe administrateur est déjà configuré",
        ));
    }
    config.auth.password_hash = Some(
        auth::hash_password(&request.password)
            .map_err(|err| ApiError::bad_request(err.to_string()))?,
    );
    if config.auth.session_secret.is_none() {
        config.auth.session_secret = Some(auth::generate_secret());
    }
    let ttl = config.auth.ttl_hours();
    let secret = config
        .auth
        .session_secret
        .clone()
        .expect("le secret vient d'être défini");
    state
        .apply_config(config)
        .map_err(|err| ApiError::bad_request(err.to_string()))?;
    info!("mot de passe administrateur configuré");

    issue_session(&secret, ttl)
}

async fn login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(request): Json<LoginRequest>,
) -> ApiResult<Response> {
    let client = peer.ip().to_string();
    if let Some(seconds) = state.login_guard.locked_for(&client) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            format!("trop de tentatives échouées, réessayez dans {seconds} s"),
        ));
    }

    let config = state.config();
    let Some(hash) = config.auth.password_hash.as_deref() else {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "aucun mot de passe administrateur n'est encore configuré",
        ));
    };
    if !auth::verify_password(hash, &request.password) {
        state.login_guard.record_failure(&client);
        warn!(%client, "échec de connexion à l'administration");
        return Err(ApiError::unauthorized("mot de passe invalide"));
    }
    state.login_guard.record_success(&client);

    let secret = config.auth.session_secret.clone().ok_or_else(|| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "secret de session manquant",
        )
    })?;
    issue_session(&secret, config.auth.ttl_hours())
}

pub fn issue_session(secret: &str, ttl_hours: u64) -> ApiResult<Response> {
    let token = auth::issue_token(secret, ttl_hours, now_s())
        .map_err(|err| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    let cookie = auth::cookie_value(&token, ttl_hours * 3600);
    Ok((
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(json!({ "authenticated": true })),
    )
        .into_response())
}

async fn logout() -> Response {
    (
        StatusCode::OK,
        [(header::SET_COOKIE, auth::clear_cookie_value())],
        Json(json!({ "authenticated": false })),
    )
        .into_response()
}

fn authenticated(state: &AppState, headers: &HeaderMap) -> bool {
    let config = state.config();
    let Some(secret) = config.auth.session_secret.as_deref() else {
        return false;
    };
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(auth::token_from_cookie_header)
        .is_some_and(|token| auth::verify_token(secret, token, now_s()).is_ok())
}

async fn require_auth(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    if authenticated(&state, request.headers()) {
        return next.run(request).await;
    }
    let setup_required = state.config().auth.password_hash.is_none();
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "error": if setup_required {
                "initialisation requise"
            } else {
                "authentification requise"
            },
            "setup_required": setup_required,
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Flux temps réel
// ---------------------------------------------------------------------------

/// Métriques poussées en SSE, une trame par période d'échantillonnage.
///
/// Le flux transporte les adresses des clients et leurs destinations : la
/// session est donc revérifiée à chaque trame, sans quoi une connexion ouverte
/// continuerait d'émettre après une déconnexion ou l'expiration du jeton.
async fn stream(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let token = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(auth::token_from_cookie_header)
        .map(str::to_string);

    let stream = futures_util::stream::unfold((state, token), |(state, token)| async move {
        tokio::time::sleep(Duration::from_secs(SAMPLE_PERIOD_S)).await;

        let secret = state.config().auth.session_secret.clone();
        let still_valid = match (&secret, &token) {
            (Some(secret), Some(token)) => auth::verify_token(secret, token, now_s()).is_ok(),
            _ => false,
        };
        if !still_valid {
            // Terminer le flux force le navigateur à repasser par l'API, qui
            // lui répondra 401 et le renverra sur l'écran de connexion.
            return None;
        }

        let payload = api::live_snapshot(&state);
        let event = Event::default()
            .event("metrics")
            .json_data(payload)
            .unwrap_or_else(|_| Event::default().comment("échec de sérialisation"));
        Some((Ok(event), (state, token)))
    });

    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}
