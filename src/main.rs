//! tiv-gateway — proxy multi-protocole vers Tor, I2P et un chemin VPN/clearnet,
//! avec une interface web de configuration et de supervision.
//!
//! Tor et I2P sont supposés déjà installés et démarrés sur la machine hôte ;
//! ce processus se contente de leur relayer le trafic et de rendre compte de ce
//! qu'il observe.

mod auth;
mod config;
mod health;
mod metrics;
mod proxy;
mod routing;
mod state;
mod tor_control;
mod web;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::config::{config_path, Config};
use crate::state::AppState;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("TIV_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    install_crypto_provider();

    let path = config_path();
    let mut config = Config::load_or_create(&path)
        .with_context(|| format!("lecture de la configuration depuis {}", path.display()))?;
    info!(path = %path.display(), "configuration chargée");

    if bootstrap_secrets(&mut config)? {
        config.save(&path)?;
    }
    config.validate()?;

    let admin_bind = config.server.admin_bind.clone();
    let setup_required = config.auth.password_hash.is_none();
    let state = Arc::new(AppState::new(config, path));

    tokio::spawn(sampler(Arc::clone(&state)));
    tokio::spawn(health::health_loop(Arc::clone(&state)));
    tokio::spawn(proxy::serve(Arc::clone(&state)));

    if setup_required {
        warn!(
            "aucun mot de passe administrateur défini : ouvrez l'interface web pour \
             en créer un, ou renseignez TIV_ADMIN_PASSWORD avant le premier démarrage"
        );
    }

    let listener = TcpListener::bind(&admin_bind)
        .await
        .with_context(|| format!("écoute de l'interface d'administration sur {admin_bind}"))?;
    info!(bind = %listener.local_addr()?, "interface d'administration prête");

    axum::serve(
        listener,
        web::router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("l'interface d'administration s'est arrêtée de façon inattendue")?;

    info!("arrêt en cours");
    Ok(())
}

/// Installe le fournisseur cryptographique de rustls, une seule fois.
///
/// `ring` plutôt que le fournisseur par défaut : il se compile sans cmake ni
/// perl, ce qui rend l'image Docker ARM64 constructible sur un Raspberry Pi
/// comme en émulation.
///
/// Cet appel est indispensable *avant* toute construction de client HTTP :
/// reqwest panique sinon, et le profil de production compile avec
/// `panic = "abort"`. On le rend donc idempotent et appelable depuis les sondes
/// elles-mêmes, plutôt que de dépendre de l'ordre d'initialisation.
pub fn install_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // Une erreur signifie qu'un fournisseur est déjà en place : rien à faire.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Génère les secrets qui doivent exister avant la première requête.
///
/// Renvoie `true` si la configuration a changé et doit être réenregistrée.
fn bootstrap_secrets(config: &mut Config) -> Result<bool> {
    let mut dirty = false;
    if config.auth.session_secret.is_none() {
        config.auth.session_secret = Some(auth::generate_secret());
        dirty = true;
    }
    // Permet à un déploiement non interactif (CasaOS, compose) de démarrer
    // directement protégé, sans passer par l'écran d'initialisation.
    if config.auth.password_hash.is_none() {
        if let Ok(password) = std::env::var("TIV_ADMIN_PASSWORD") {
            if !password.is_empty() {
                config.auth.password_hash = Some(
                    auth::hash_password(&password)
                        .context("le mot de passe fourni dans TIV_ADMIN_PASSWORD a été refusé")?,
                );
                info!("mot de passe administrateur repris de TIV_ADMIN_PASSWORD");
                dirty = true;
            }
        }
    }
    Ok(dirty)
}

/// Alimente la série temporelle de débit affichée par le tableau de bord.
async fn sampler(state: Arc<AppState>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(crate::metrics::SAMPLE_PERIOD_S));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        state.metrics.sample();
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(err) => warn!(%err, "impossible d'écouter SIGTERM"),
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}
