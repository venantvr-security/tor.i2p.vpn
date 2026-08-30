//! Modèle de configuration persistée.
//!
//! Le fichier entier est facultatif : chaque section et chaque champ possède une
//! valeur par défaut, si bien qu'un déploiement neuf démarre avec une répartition
//! Tor / I2P / sortie directe cohérente sans la moindre édition manuelle.
//! L'interface web lit et écrit exactement cette structure.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// Distingue les fichiers temporaires de deux enregistrements concurrents.
static SAVE_TICKET: AtomicU64 = AtomicU64::new(0);

/// Emplacement par défaut sur disque, surchargeable via `TIV_CONFIG`.
pub const DEFAULT_CONFIG_PATH: &str = "/data/config.toml";

pub fn config_path() -> PathBuf {
    std::env::var_os("TIV_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub server: ServerConfig,
    pub proxy: ProxyConfig,
    pub backends: Vec<Backend>,
    pub routing: RoutingConfig,
    pub tor_control: TorControlConfig,
    pub health: HealthConfig,
    pub catalogue: CatalogueConfig,
    pub mitm: MitmConfig,
    #[serde(skip_serializing_if = "AuthConfig::is_empty")]
    pub auth: AuthConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            proxy: ProxyConfig::default(),
            backends: Backend::defaults(),
            routing: RoutingConfig::default(),
            tor_control: TorControlConfig::default(),
            health: HealthConfig::default(),
            catalogue: CatalogueConfig::default(),
            mitm: MitmConfig::default(),
            auth: AuthConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Sections
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Adresse d'écoute de l'interface d'administration et de son API.
    pub admin_bind: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            admin_bind: "0.0.0.0:8090".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    /// Écoute SOCKS5, `null` pour la désactiver.
    pub socks5_bind: Option<String>,
    /// Écoute HTTP (CONNECT + URI absolue), `null` pour la désactiver.
    pub http_bind: Option<String>,
    /// Plafond strict de connexions relayées simultanées.
    pub max_connections: usize,
    /// Délai maximum accordé à la poignée de main et à la connexion amont.
    pub connect_timeout_ms: u64,
    /// Ferme un tunnel resté ce nombre de secondes sans le moindre octet.
    pub idle_timeout_s: u64,
    /// Impose une authentification sur les deux écoutes proxy : RFC 1929 côté
    /// SOCKS5, `Proxy-Authorization: Basic` côté HTTP.
    pub credentials: Option<ProxyCredentials>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            socks5_bind: Some("0.0.0.0:1080".to_string()),
            http_bind: Some("0.0.0.0:8118".to_string()),
            max_connections: 512,
            connect_timeout_ms: 20_000,
            idle_timeout_s: 300,
            credentials: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyCredentials {
    pub username: String,
    pub password: String,
}

/// Une sortie de trafic. Son `id` est référencé par les règles de routage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Backend {
    pub id: String,
    pub label: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Ce backend ne sait router que des noms, jamais une IP brute — c'est le
    /// cas de Tor et d'I2P, qui résolvent dans leur propre tunnel. Sert de base
    /// au refus des IP brutes, plutôt qu'une liste d'identifiants en dur.
    #[serde(default)]
    pub names_only: bool,
    #[serde(flatten)]
    pub kind: BackendKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BackendKind {
    /// Relaie via un proxy SOCKS5 amont (Tor, SOCKS d'i2pd, etc.).
    Socks5 {
        address: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<String>,
    },
    /// Relaie via un proxy HTTP amont en CONNECT (proxy HTTP d'i2pd).
    HttpConnect { address: String },
    /// Ouvre la connexion directement depuis cette machine, sans intermédiaire.
    ///
    /// Un VPN monté sur l'hôte — OpenVPN, WireGuard — est transparent pour la
    /// passerelle : il déplace la route par défaut du système, donc ce chemin
    /// l'emprunte sans que rien ne soit à configurer ici. C'est précisément
    /// pour cette raison que les sondes de santé existent : elles sont le seul
    /// moyen de constater que ce tunnel invisible est bien monté.
    Direct,
    /// Refus systématique. Utile comme route par défaut tant qu'un tunnel est
    /// tombé : on préfère bloquer plutôt que fuiter.
    Block,
}

impl Backend {
    pub fn defaults() -> Vec<Self> {
        vec![
            Backend {
                id: "tor".into(),
                label: "Tor".into(),
                enabled: true,
                names_only: true,
                kind: BackendKind::Socks5 {
                    address: "127.0.0.1:9050".into(),
                    username: None,
                    password: None,
                },
            },
            Backend {
                id: "i2p".into(),
                label: "I2P".into(),
                enabled: true,
                names_only: true,
                kind: BackendKind::Socks5 {
                    address: "127.0.0.1:4447".into(),
                    username: None,
                    password: None,
                },
            },
            Backend {
                id: "direct".into(),
                label: "Sortie directe".into(),
                enabled: true,
                names_only: false,
                kind: BackendKind::Direct,
            },
        ]
    }

    pub fn kind_name(&self) -> &'static str {
        match self.kind {
            BackendKind::Socks5 { .. } => "socks5",
            BackendKind::HttpConnect { .. } => "http_connect",
            BackendKind::Direct => "direct",
            BackendKind::Block => "block",
        }
    }

    /// Point de terminaison amont, lorsque le backend en possède un.
    pub fn upstream_address(&self) -> Option<&str> {
        match &self.kind {
            BackendKind::Socks5 { address, .. } | BackendKind::HttpConnect { address } => {
                Some(address.as_str())
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RoutingConfig {
    /// Backend utilisé lorsqu'aucune règle ne correspond.
    pub default_backend: String,
    /// Évaluées de haut en bas, la première correspondance l'emporte.
    pub rules: Vec<Rule>,
    /// Refuse de relayer vers une destination loopback / RFC 1918 / lien-local.
    pub block_private_ranges: bool,
    /// Refuse une destination donnée en IP brute sur les backends qui ne
    /// comprennent que des noms (services cachés Tor et I2P), plutôt que de la
    /// laisser fuiter silencieusement ailleurs.
    pub block_bare_ip_on_hidden: bool,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            default_backend: "direct".to_string(),
            rules: vec![
                Rule::suffix("onion", ".onion", "tor"),
                Rule::suffix("i2p", ".i2p", "i2p"),
            ],
            block_private_ranges: true,
            block_bare_ip_on_hidden: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    /// Nature de la comparaison appliquée au motif.
    #[serde(default)]
    pub match_type: MatchType,
    pub pattern: String,
    pub backend: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl Rule {
    pub fn suffix(id: &str, pattern: &str, backend: &str) -> Self {
        Self {
            id: id.to_string(),
            match_type: MatchType::Suffix,
            pattern: pattern.to_string(),
            backend: backend.to_string(),
            enabled: true,
            note: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MatchType {
    /// L'hôte se termine par le motif (`.onion`), sans distinction de casse.
    #[default]
    Suffix,
    /// L'hôte est exactement égal au motif.
    Exact,
    /// Motif à la mode shell avec `*` (`*.duckduckgo.com`).
    Wildcard,
    /// IP de destination contenue dans le CIDR (`10.0.0.0/8`).
    Cidr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TorControlConfig {
    pub enabled: bool,
    pub address: String,
    pub auth: TorAuth,
    /// Utilisé lorsque `auth = "password"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Utilisé lorsque `auth = "cookie"`.
    pub cookie_path: String,
    /// Délai minimum entre deux signaux NEWNYM, que Tor limite lui aussi.
    pub newnym_cooldown_s: u64,
}

impl Default for TorControlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            address: "127.0.0.1:9051".to_string(),
            auth: TorAuth::Cookie,
            password: None,
            cookie_path: "/var/run/tor/control.authcookie".to_string(),
            newnym_cooldown_s: 10,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TorAuth {
    #[default]
    Cookie,
    Password,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HealthConfig {
    pub enabled: bool,
    pub interval_s: u64,
    pub timeout_s: u64,
    /// Point d'API JSON indiquant si la requête est bien sortie par Tor.
    pub tor_check_url: String,
    /// Point d'API (texte ou JSON) renvoyant l'IP publique, interrogé backend
    /// par backend.
    pub ip_check_url: String,
    /// Site I2P servant à prouver que le tunnel est monté.
    pub i2p_check_url: String,
    /// Adresse publique que la sortie directe ne devrait jamais exhiber.
    ///
    /// C'est celle du lien nu, relevée sans aucun tunnel. Si la sortie directe
    /// se met à déboucher dessus alors qu'un tunnel est censé être monté sur
    /// l'hôte, ce tunnel est tombé — et rien d'autre ne le signalera, puisqu'il
    /// est transparent pour la passerelle. Laissée vide, la vérification ne
    /// s'applique pas.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unexpected_exit_ip: Option<String>,
    /// Nombre de points d'historique conservés.
    pub history_len: usize,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_s: 120,
            timeout_s: 25,
            tor_check_url: "https://check.torproject.org/api/ip".to_string(),
            ip_check_url: "https://api.ipify.org?format=json".to_string(),
            i2p_check_url: "http://stats.i2p/".to_string(),
            unexpected_exit_ip: None,
            history_len: 120,
        }
    }
}

/// Journal des destinations traversées.
///
/// Désactivé par défaut : sur une passerelle dont le rôle est de protéger le
/// trafic, écrire sur disque la liste des services visités est un choix
/// délibéré, pas un réglage anodin. Le fichier vit à côté de `config.toml`,
/// sous le nom `catalogue.jsonl`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CatalogueConfig {
    pub enabled: bool,
    /// Relève aussi le titre des pages servies en clair. Le code HTTP, lui, est
    /// relevé dès que la réponse n'est pas chiffrée.
    pub capture_titles: bool,
    /// Plafond de lignes conservées. Au-delà, la plus ancienne sort.
    pub max_entries: usize,
}

impl Default for CatalogueConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            capture_titles: true,
            max_entries: 500,
        }
    }
}

/// Interception TLS (« man-in-the-middle ») des seuls hôtes désignés.
///
/// Désactivée par défaut, et à part du reste : elle inverse la promesse de la
/// passerelle — protéger le trafic — pour la retourner en trafic déchiffré. Elle
/// ne s'applique qu'à une liste blanche explicite d'hôtes, jamais à tout le
/// trafic. La CA locale et sa clé vivent dans le volume, hors configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MitmConfig {
    pub enabled: bool,
    /// Hôtes à intercepter. Chaque entrée vaut :
    ///   * un nom exact (`forum.onion`), casse ignorée ;
    ///   * un suffixe si elle commence par un point (`.exemple.i2p`) ;
    ///   * un joker de sous-domaines si elle commence par `*.` (`*.exemple.com`).
    pub hosts: Vec<String>,
}

impl MitmConfig {
    /// Un hôte donné tombe-t-il dans la liste blanche d'interception ?
    pub fn intercepts(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.hosts.iter().any(|entry| {
            let entry = entry.trim().to_ascii_lowercase();
            if let Some(suffixe) = entry.strip_prefix("*.") {
                // `*.exemple.com` couvre les sous-domaines, pas le domaine nu.
                host.ends_with(&format!(".{suffixe}"))
            } else if let Some(suffixe) = entry.strip_prefix('.') {
                host == suffixe || host.ends_with(&format!(".{suffixe}"))
            } else {
                host == entry
            }
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    /// Empreinte Argon2id au format PHC. `None` bascule l'interface en mode
    /// première initialisation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<String>,
    /// Clé HMAC des cookies de session, générée au premier démarrage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_secret: Option<String>,
    pub session_ttl_h: u64,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            password_hash: None,
            session_secret: None,
            session_ttl_h: 24,
        }
    }
}

impl AuthConfig {
    fn is_empty(&self) -> bool {
        self.password_hash.is_none() && self.session_secret.is_none()
    }

    pub fn ttl_hours(&self) -> u64 {
        if self.session_ttl_h == 0 {
            24
        } else {
            self.session_ttl_h
        }
    }
}

fn yes() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Chargement / enregistrement / validation
// ---------------------------------------------------------------------------

impl Config {
    /// Lit la configuration, en la créant avec les valeurs par défaut si absente.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if !path.exists() {
            let cfg = Config::default();
            cfg.save(path).with_context(|| {
                format!(
                    "création de la configuration par défaut dans {}",
                    path.display()
                )
            })?;
            return Ok(cfg);
        }
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("lecture de {}", path.display()))?;
        let cfg: Config =
            toml::from_str(&raw).with_context(|| format!("analyse de {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("création de {}", dir.display()))?;
        }
        let body = toml::to_string_pretty(self).context("sérialisation de la configuration")?;
        // Passage par un fichier temporaire : un arrêt brutal ne peut jamais
        // laisser une configuration tronquée derrière lui. Le nom du temporaire
        // est unique, sans quoi deux enregistrements concurrents — deux sessions
        // d'administration, par exemple — se voleraient leur fichier et l'un des
        // deux échouerait au renommage.
        let ticket = SAVE_TICKET.fetch_add(1, AtomicOrdering::Relaxed);
        let tmp = path.with_extension(format!("toml.{}.{}.tmp", std::process::id(), ticket));
        std::fs::write(&tmp, body).with_context(|| format!("écriture de {}", tmp.display()))?;
        if let Err(err) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(err).with_context(|| format!("remplacement de {}", path.display()));
        }
        Ok(())
    }

    /// Rejette, avant application, toute configuration qui casserait le routage.
    pub fn validate(&self) -> Result<()> {
        if self.backends.is_empty() {
            bail!("au moins un backend est nécessaire");
        }
        let mut ids = BTreeSet::new();
        for backend in &self.backends {
            if backend.id.trim().is_empty() {
                bail!("l'identifiant d'un backend ne peut pas être vide");
            }
            if !ids.insert(backend.id.as_str()) {
                bail!("identifiant de backend `{}` en double", backend.id);
            }
            if let Some(address) = backend.upstream_address() {
                if !address.contains(':') {
                    bail!(
                        "backend `{}` : `{}` doit être au format hôte:port",
                        backend.id,
                        address
                    );
                }
            }
        }
        if !ids.contains(self.routing.default_backend.as_str()) {
            bail!(
                "le backend par défaut `{}` n'existe pas",
                self.routing.default_backend
            );
        }

        let mut rule_ids = BTreeSet::new();
        for rule in &self.routing.rules {
            if !rule_ids.insert(rule.id.as_str()) {
                bail!("identifiant de règle `{}` en double", rule.id);
            }
            if rule.pattern.trim().is_empty() {
                bail!("la règle `{}` a un motif vide", rule.id);
            }
            if !ids.contains(rule.backend.as_str()) {
                bail!(
                    "la règle `{}` vise le backend inconnu `{}`",
                    rule.id,
                    rule.backend
                );
            }
            if rule.match_type == MatchType::Cidr {
                crate::routing::parse_cidr(&rule.pattern).with_context(|| {
                    format!(
                        "la règle `{}` a un CIDR invalide `{}`",
                        rule.id, rule.pattern
                    )
                })?;
            }
        }

        for bind in [
            Some(&self.server.admin_bind),
            self.proxy.socks5_bind.as_ref(),
            self.proxy.http_bind.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if !bind.contains(':') {
                bail!("`{}` n'est pas une adresse d'écoute valide", bind);
            }
        }
        if self.proxy.max_connections == 0 {
            bail!("max_connections doit être strictement positif");
        }
        let bornes = crate::catalogue::MIN_ENTRIES..=crate::catalogue::MAX_ENTRIES;
        if !bornes.contains(&self.catalogue.max_entries) {
            bail!(
                "le plafond du journal doit être compris entre {} et {} lignes",
                crate::catalogue::MIN_ENTRIES,
                crate::catalogue::MAX_ENTRIES
            );
        }
        for host in &self.mitm.hosts {
            if host.trim().is_empty() {
                bail!("un hôte d'interception ne peut pas être vide");
            }
            if host.contains('/') || host.contains(':') {
                bail!(
                    "l'hôte d'interception `{}` doit être un nom seul, sans schéma ni port",
                    host
                );
            }
        }
        Ok(())
    }

    pub fn backend(&self, id: &str) -> Option<&Backend> {
        self.backends.iter().find(|b| b.id == id)
    }

    /// Copie de la configuration dont tous les secrets sont masqués, pour l'API.
    pub fn redacted(&self) -> Self {
        let mut clone = self.clone();
        clone.auth.password_hash = clone.auth.password_hash.as_ref().map(|_| "***".to_string());
        clone.auth.session_secret = None;
        if clone.tor_control.password.is_some() {
            clone.tor_control.password = Some("***".to_string());
        }
        if let Some(creds) = clone.proxy.credentials.as_mut() {
            creds.password = "***".to_string();
        }
        for backend in &mut clone.backends {
            if let BackendKind::Socks5 { password, .. } = &mut backend.kind {
                if password.is_some() {
                    *password = Some("***".to_string());
                }
            }
        }
        clone
    }

    /// Réinjecte les secrets que l'interface a renvoyés sous forme de `***`.
    pub fn unredact_from(&mut self, previous: &Config) {
        if self.auth.password_hash.as_deref() == Some("***") || self.auth.password_hash.is_none() {
            self.auth.password_hash = previous.auth.password_hash.clone();
        }
        self.auth.session_secret = previous.auth.session_secret.clone();
        if self.tor_control.password.as_deref() == Some("***") {
            self.tor_control.password = previous.tor_control.password.clone();
        }
        if let (Some(new), Some(old)) = (
            self.proxy.credentials.as_mut(),
            previous.proxy.credentials.as_ref(),
        ) {
            if new.password == "***" {
                new.password = old.password.clone();
            }
        }
        for backend in &mut self.backends {
            let Some(old) = previous.backend(&backend.id) else {
                continue;
            };
            let BackendKind::Socks5 {
                password: old_password,
                ..
            } = &old.kind
            else {
                continue;
            };
            if let BackendKind::Socks5 { password, .. } = &mut backend.kind {
                if password.as_deref() == Some("***") {
                    *password = old_password.clone();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid_and_round_trip() {
        let cfg = Config::default();
        cfg.validate().unwrap();
        let text = toml::to_string_pretty(&cfg).unwrap();
        let parsed: Config = toml::from_str(&text).unwrap();
        parsed.validate().unwrap();
        assert_eq!(parsed.backends.len(), 3);
        assert_eq!(parsed.routing.rules.len(), 2);
    }

    #[test]
    fn empty_document_yields_defaults() {
        let cfg: Config = toml::from_str("").unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.routing.default_backend, "direct");
    }

    #[test]
    fn rule_towards_unknown_backend_is_rejected() {
        let mut cfg = Config::default();
        cfg.routing.rules.push(Rule::suffix("bad", ".test", "nope"));
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn concurrent_saves_do_not_clobber_each_other() {
        let dir = std::env::temp_dir().join(format!("tiv-save-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");

        // Deux sessions d'administration qui enregistrent en même temps ne
        // doivent pas se disputer le même fichier temporaire.
        std::thread::scope(|scope| {
            for index in 0..8 {
                let path = path.clone();
                scope.spawn(move || {
                    let mut cfg = Config::default();
                    cfg.proxy.max_connections = 100 + index;
                    cfg.save(&path).expect("l'enregistrement doit aboutir");
                });
            }
        });

        let reloaded = Config::load_or_create(&path).unwrap();
        assert!((100..108).contains(&reloaded.proxy.max_connections));
        // Aucun fichier temporaire ne doit subsister.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temporaires oubliés : {leftovers:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn secrets_survive_a_redacted_round_trip() {
        let mut cfg = Config::default();
        cfg.tor_control.password = Some("hunter2".into());
        cfg.auth.password_hash = Some("$argon2id$stub".into());
        let mut edited = cfg.redacted();
        edited.routing.default_backend = "tor".into();
        edited.unredact_from(&cfg);
        assert_eq!(edited.tor_control.password.as_deref(), Some("hunter2"));
        assert_eq!(edited.auth.password_hash.as_deref(), Some("$argon2id$stub"));
        assert_eq!(edited.routing.default_backend, "tor");
    }
}
