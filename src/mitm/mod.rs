//! Interception TLS optionnelle : un mode à part, désactivé par défaut.
//!
//! Le reste de la passerelle ne fait que *déplacer* des octets chiffrés sans les
//! lire. Ce module fait l'inverse, et l'assume : pour les seuls hôtes que
//! l'exploitant a explicitement inscrits, il termine le TLS avec un certificat
//! forgé par une [autorité locale](ca), rouvre un TLS vers la vraie destination,
//! et lit le HTTP/1.1 en clair qui circule entre les deux — URL complètes, codes,
//! titres — avant de tout relayer à l'identique.
//!
//! ```mermaid
//! flowchart LR
//!     T[Connexion 443<br/>vers un hôte surveillé] --> D{Interception<br/>activée ?}
//!     D -- non --> R[Relais opaque habituel]
//!     D -- oui --> B[Pont MITM<br/>double TLS + lecture HTTP]
//!     B --> J[(Journal enrichi<br/>URL + code + titre)]
//!     B --> F[(Empreintes de<br/>certificats vues)]
//! ```
//!
//! **Garde-fous.** L'interception ne vise que les hôtes d'une liste blanche
//! explicite (jamais tout le trafic), ne s'applique qu'au TLS (port 443 ; le
//! trafic déjà en clair n'en a pas besoin), et repose sur une CA dont la clé ne
//! quitte jamais le volume. La casser — épinglage de certificat, applications
//! qui refusent une racine ajoutée — ne concerne alors que les hôtes choisis.

pub mod bridge;
pub mod ca;
pub mod http;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use arc_swap::ArcSwap;
use rustls::ClientConfig;
use serde::Serialize;

use crate::catalogue::Catalogue;
use crate::config::Config;
use crate::routing::{Host, Target};
use ca::LocalCa;

/// Ports considérés comme du TLS et donc interceptables. Le trafic en clair est
/// déjà lisible par le journal : l'intercepter n'apporterait rien.
const TLS_PORTS: [u16; 1] = [443];

/// L'état vivant de l'interception : la CA, la configuration TLS amont, les
/// compteurs et les empreintes de certificats déjà vues.
pub struct Mitm {
    dir: PathBuf,
    /// La CA peut être régénérée à chaud ; les lecteurs ne bloquent jamais.
    ca: ArcSwap<LocalCa>,
    upstream: Arc<ClientConfig>,
    catalogue: Arc<Catalogue>,
    capture_titles: AtomicBool,
    connections: AtomicU64,
    requests: AtomicU64,
    /// Dernière empreinte de certificat vue par hôte. Un changement inattendu
    /// sur un service surveillé mérite un coup d'œil : saisie, clone, MITM tiers.
    seen_certs: Mutex<BTreeMap<String, String>>,
}

impl Mitm {
    /// Prépare l'interception, en chargeant ou créant la CA locale.
    ///
    /// Réussit toujours à rendre un état exploitable : même sans interception
    /// active, l'interface doit pouvoir présenter et régénérer la CA.
    pub fn new(dir: &Path, catalogue: Arc<Catalogue>) -> Result<Arc<Self>> {
        let ca = LocalCa::load_or_create(dir)?;
        Ok(Arc::new(Mitm {
            dir: dir.to_path_buf(),
            ca: ArcSwap::from_pointee(ca),
            upstream: bridge::upstream_config(),
            catalogue,
            capture_titles: AtomicBool::new(true),
            connections: AtomicU64::new(0),
            requests: AtomicU64::new(0),
            seen_certs: Mutex::new(BTreeMap::new()),
        }))
    }

    pub fn ca(&self) -> Arc<LocalCa> {
        self.ca.load_full()
    }

    pub fn upstream_config(&self) -> &Arc<ClientConfig> {
        &self.upstream
    }

    pub fn capture_titles(&self) -> bool {
        self.capture_titles.load(Ordering::Relaxed)
    }

    /// Aligne les réglages dérivés de la configuration (relève des titres).
    pub fn sync_from_config(&self, config: &Config) {
        self.capture_titles
            .store(config.catalogue.capture_titles, Ordering::Relaxed);
    }

    /// Régénère la CA. Toute racine déjà installée côté client cesse alors
    /// d'être reconnue : c'est une rupture, l'interface doit prévenir.
    pub fn regenerate_ca(&self) -> Result<String> {
        let fresh = LocalCa::generate(&self.dir)?;
        let fingerprint = fresh.fingerprint().to_string();
        self.ca.store(Arc::new(fresh));
        Ok(fingerprint)
    }

    pub fn note_connection(&self) {
        self.connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Retient l'empreinte du certificat présenté par un hôte amont.
    pub fn note_certificate(&self, host: &str, fingerprint: String) {
        self.seen_certs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(host.to_ascii_lowercase(), fingerprint);
    }

    /// Consigne une transaction interceptée dans le journal des destinations.
    pub fn record_visit(&self, url: &str, status: u16, titre: Option<String>) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.catalogue.visit(url);
        let code = (status > 0).then_some(status);
        if code.is_some() || titre.is_some() {
            self.catalogue.observe(url, code, titre);
        }
    }

    /// Photographie pour l'API, complétée des champs de la configuration vivante.
    pub fn status(&self, config: &Config) -> MitmStatus {
        let ca = self.ca();
        let certificates = self
            .seen_certs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(host, fingerprint)| SeenCertificate {
                host: host.clone(),
                fingerprint: fingerprint.clone(),
            })
            .collect();
        MitmStatus {
            enabled: config.mitm.enabled,
            hosts: config.mitm.hosts.clone(),
            capture_titles: self.capture_titles(),
            ca_fingerprint: ca.fingerprint().to_string(),
            connections: self.connections.load(Ordering::Relaxed),
            requests: self.requests.load(Ordering::Relaxed),
            certificates,
        }
    }
}

/// Décide si une destination doit être interceptée, et sous quel nom d'hôte.
///
/// N'intercepte que : mode actif, destination nommée (jamais une IP brute),
/// port TLS, et hôte présent dans la liste blanche.
pub fn host_to_intercept(config: &Config, target: &Target) -> Option<String> {
    if !config.mitm.enabled {
        return None;
    }
    if !TLS_PORTS.contains(&target.port) {
        return None;
    }
    let Host::Name(host) = &target.host else {
        return None;
    };
    config.mitm.intercepts(host).then(|| host.clone())
}

#[derive(Serialize)]
pub struct MitmStatus {
    pub enabled: bool,
    pub hosts: Vec<String>,
    pub capture_titles: bool,
    pub ca_fingerprint: String,
    pub connections: u64,
    pub requests: u64,
    pub certificates: Vec<SeenCertificate>,
}

#[derive(Serialize)]
pub struct SeenCertificate {
    pub host: String,
    pub fingerprint: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn config_with(hosts: &[&str], enabled: bool) -> Config {
        let mut config = Config::default();
        config.mitm.enabled = enabled;
        config.mitm.hosts = hosts.iter().map(|h| h.to_string()).collect();
        config
    }

    #[test]
    fn nothing_is_intercepted_when_disabled() {
        let config = config_with(&["exemple.onion"], false);
        let target = Target::new("exemple.onion", 443);
        assert_eq!(host_to_intercept(&config, &target), None);
    }

    #[test]
    fn only_listed_tls_hosts_are_intercepted() {
        let config = config_with(&["exemple.onion", ".forum.i2p"], true);

        // Hôte listé, port TLS : intercepté.
        assert_eq!(
            host_to_intercept(&config, &Target::new("exemple.onion", 443)),
            Some("exemple.onion".to_string())
        );
        // Suffixe listé.
        assert_eq!(
            host_to_intercept(&config, &Target::new("a.forum.i2p", 443)),
            Some("a.forum.i2p".to_string())
        );
        // Bon hôte, mais port non-TLS : le journal en clair suffit.
        assert_eq!(
            host_to_intercept(&config, &Target::new("exemple.onion", 80)),
            None
        );
        // Hôte non listé.
        assert_eq!(
            host_to_intercept(&config, &Target::new("autre.onion", 443)),
            None
        );
        // IP brute : jamais interceptée.
        assert_eq!(
            host_to_intercept(&config, &Target::new("10.0.0.1", 443)),
            None
        );
    }
}
