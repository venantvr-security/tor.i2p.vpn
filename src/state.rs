//! État partagé à l'exécution.
//!
//! La configuration vit derrière un `ArcSwap` : les lecteurs du plan de données
//! ne bloquent jamais, et un enregistrement depuis l'interface web prend effet
//! dès la connexion suivante, sans redémarrer la moindre écoute.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::Result;
use arc_swap::ArcSwap;

use crate::config::Config;
use crate::health::HealthRegistry;
use crate::metrics::Metrics;
use crate::routing::Router;
use crate::tor_control::TorControl;

pub struct AppState {
    pub config_path: PathBuf,
    config: ArcSwap<Config>,
    router: ArcSwap<Router>,
    pub metrics: Arc<Metrics>,
    pub health: Arc<HealthRegistry>,
    pub tor: Arc<TorControl>,
    pub login_guard: Arc<crate::auth::LoginGuard>,
    active: Arc<AtomicUsize>,
}

impl AppState {
    pub fn new(config: Config, config_path: PathBuf) -> Self {
        let router = Router::from_config(&config);
        AppState {
            config_path,
            config: ArcSwap::from_pointee(config),
            router: ArcSwap::from_pointee(router),
            metrics: Arc::new(Metrics::new()),
            health: Arc::new(HealthRegistry::new()),
            tor: Arc::new(TorControl::new()),
            login_guard: Arc::new(crate::auth::LoginGuard::new()),
            active: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn config(&self) -> Arc<Config> {
        self.config.load_full()
    }

    pub fn router(&self) -> Arc<Router> {
        self.router.load_full()
    }

    /// Valide, persiste puis bascule à chaud une nouvelle configuration.
    ///
    /// Les adresses d'écoute sont la seule chose qui ne peut pas changer à
    /// chaud ; l'appelant en est informé pour pouvoir prévenir l'exploitant.
    pub fn apply_config(&self, config: Config) -> Result<Vec<String>> {
        config.validate()?;
        let previous = self.config();
        config.save(&self.config_path)?;

        let mut restart_needed = Vec::new();
        if previous.server.admin_bind != config.server.admin_bind {
            restart_needed.push("écoute d'administration".to_string());
        }
        if previous.proxy.socks5_bind != config.proxy.socks5_bind {
            restart_needed.push("écoute SOCKS5".to_string());
        }
        if previous.proxy.http_bind != config.proxy.http_bind {
            restart_needed.push("écoute proxy HTTP".to_string());
        }

        self.router.store(Arc::new(Router::from_config(&config)));
        self.config.store(Arc::new(config));
        Ok(restart_needed)
    }

    pub fn active_connections(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    /// Réserve un créneau de connexion, ou `None` si le plafond est atteint.
    pub fn try_acquire(&self) -> Option<CapacityPermit> {
        let max = self.config().proxy.max_connections;
        let mut current = self.active.load(Ordering::Relaxed);
        loop {
            if current >= max {
                return None;
            }
            match self.active.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Some(CapacityPermit {
                        active: Arc::clone(&self.active),
                    })
                }
                Err(observed) => current = observed,
            }
        }
    }
}

/// Libère son créneau de connexion lors de sa destruction.
pub struct CapacityPermit {
    active: Arc<AtomicUsize>,
}

impl Drop for CapacityPermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MatchType;

    /// Chaque test obtient son propre répertoire : ils tournent en parallèle et
    /// écrivent tous leur configuration sur disque.
    fn state() -> AppState {
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("tiv-test-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        AppState::new(Config::default(), dir.join("config.toml"))
    }

    #[test]
    fn capacity_is_capped_and_released_on_drop() {
        let state = state();
        let mut config = Config::default();
        config.proxy.max_connections = 2;
        state.apply_config(config).unwrap();

        let a = state.try_acquire().unwrap();
        let b = state.try_acquire().unwrap();
        assert!(state.try_acquire().is_none());
        assert_eq!(state.active_connections(), 2);
        drop(a);
        assert!(state.try_acquire().is_some());
        drop(b);
    }

    #[test]
    fn applying_a_config_rebuilds_the_router() {
        let state = state();
        assert_eq!(
            state
                .router()
                .route(
                    &crate::routing::Target::new("a.onion", 80),
                    &state.config().backends
                )
                .backend_id,
            "tor"
        );

        let mut config = Config::default();
        config.routing.rules[0].match_type = MatchType::Exact;
        config.routing.rules[0].pattern = "exact.onion".into();
        state.apply_config(config).unwrap();

        assert_eq!(
            state
                .router()
                .route(
                    &crate::routing::Target::new("a.onion", 80),
                    &state.config().backends
                )
                .backend_id,
            "direct"
        );
    }

    #[test]
    fn an_invalid_config_is_rejected_without_being_applied() {
        let state = state();
        let mut config = Config::default();
        config.routing.default_backend = "ghost".into();
        assert!(state.apply_config(config).is_err());
        assert_eq!(state.config().routing.default_backend, "direct");
    }

    #[test]
    fn changing_a_bind_address_reports_the_listener_to_restart() {
        let state = state();
        let mut config = Config::default();
        config.proxy.socks5_bind = Some("0.0.0.0:1081".into());
        let restart = state.apply_config(config).unwrap();
        assert_eq!(restart, vec!["écoute SOCKS5"]);
    }
}
