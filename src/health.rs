//! Sondes de sortie périodiques.
//!
//! Chaque sonde sort par un backend donné et rapporte ce que le monde extérieur
//! a vu. C'est le seul moyen fiable de s'apercevoir que Tor n'est en réalité pas
//! emprunté — ou qu'un tunnel monté sur l'hôte, invisible pour la passerelle,
//! vient de tomber sans prévenir personne.

use std::collections::VecDeque;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use reqwest::Client;
use serde::Serialize;

use crate::config::{Backend, BackendKind, Config, HealthConfig};
use crate::metrics::now_ms;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeKind {
    /// IP publique telle que vue à travers le backend.
    ExitIp,
    /// Confirmation par `check.torproject.org` que la sortie est bien Tor.
    TorConfirmation,
    /// Joignabilité d'un site I2P de référence.
    I2pReachability,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeResult {
    pub backend: String,
    pub kind: ProbeKind,
    pub ok: bool,
    pub latency_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthReport {
    pub at: u64,
    pub duration_ms: u64,
    pub probes: Vec<ProbeResult>,
    pub findings: Vec<Finding>,
}

/// Point d'historique compact, un par campagne de sondes terminée.
#[derive(Debug, Clone, Serialize)]
pub struct HistoryPoint {
    pub at: u64,
    pub ok: usize,
    pub failed: usize,
    pub worst: Severity,
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthState {
    pub enabled: bool,
    pub running: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last: Option<HealthReport>,
    pub history: Vec<HistoryPoint>,
}

#[derive(Default)]
pub struct HealthRegistry {
    inner: RwLock<Inner>,
}

#[derive(Default)]
struct Inner {
    running: bool,
    last: Option<HealthReport>,
    history: VecDeque<HistoryPoint>,
}

impl HealthRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn state(&self, enabled: bool) -> HealthState {
        let guard = self.inner.read().expect("health lock");
        HealthState {
            enabled,
            running: guard.running,
            last: guard.last.clone(),
            history: guard.history.iter().cloned().collect(),
        }
    }

    fn mark_running(&self, running: bool) {
        self.inner.write().expect("health lock").running = running;
    }

    fn store(&self, report: HealthReport, history_len: usize) {
        let point = HistoryPoint {
            at: report.at,
            ok: report.probes.iter().filter(|p| p.ok).count(),
            failed: report.probes.iter().filter(|p| !p.ok).count(),
            worst: report
                .findings
                .iter()
                .map(|f| f.severity)
                .max_by_key(|s| match s {
                    Severity::Info => 0,
                    Severity::Warning => 1,
                    Severity::Critical => 2,
                })
                .unwrap_or(Severity::Info),
        };
        let mut guard = self.inner.write().expect("health lock");
        if guard.history.len() >= history_len.max(1) {
            guard.history.pop_front();
        }
        guard.history.push_back(point);
        guard.last = Some(report);
    }
}

/// Exécute chaque sonde une fois, puis analyse les résultats.
pub async fn run_probes(registry: &HealthRegistry, config: &Config) -> HealthReport {
    registry.mark_running(true);
    let started = Instant::now();
    let health = &config.health;

    let mut tasks = Vec::new();
    for backend in config.backends.iter().filter(|b| b.enabled) {
        if matches!(backend.kind, BackendKind::Block) {
            continue;
        }
        tasks.push(probe_exit_ip(backend.clone(), health.clone()));
    }

    let mut probes: Vec<ProbeResult> = futures_util::future::join_all(tasks).await;

    if let Some(tor) = config.backend("tor").filter(|b| b.enabled) {
        probes.push(probe_tor(tor.clone(), health.clone()).await);
    }
    if let Some(i2p) = config.backend("i2p").filter(|b| b.enabled) {
        probes.push(probe_i2p(i2p.clone(), health.clone()).await);
    }

    let findings = analyse(&probes, config);
    let report = HealthReport {
        at: now_ms(),
        duration_ms: started.elapsed().as_millis() as u64,
        probes,
        findings,
    };
    registry.store(report.clone(), health.history_len);
    registry.mark_running(false);
    report
}

/// Transforme les résultats bruts des sondes en constats exploitables.
fn analyse(probes: &[ProbeResult], config: &Config) -> Vec<Finding> {
    let mut findings = Vec::new();
    let exit_ip = |backend: &str| {
        probes
            .iter()
            .find(|p| p.kind == ProbeKind::ExitIp && p.backend == backend && p.ok)
            .and_then(|p| p.value.clone())
    };

    for probe in probes.iter().filter(|p| !p.ok) {
        findings.push(Finding {
            severity: Severity::Warning,
            message: format!(
                "sonde « {} » en échec sur `{}` : {}",
                match probe.kind {
                    ProbeKind::ExitIp => "IP de sortie",
                    ProbeKind::TorConfirmation => "confirmation Tor",
                    ProbeKind::I2pReachability => "joignabilité I2P",
                },
                probe.backend,
                probe.error.as_deref().unwrap_or("erreur inconnue")
            ),
        });
    }

    if let Some(tor_probe) = probes.iter().find(|p| p.kind == ProbeKind::TorConfirmation) {
        if tor_probe.ok && tor_probe.value.as_deref() == Some("false") {
            findings.push(Finding {
                severity: Severity::Critical,
                message: "le trafic envoyé au backend Tor n'est pas sorti par le réseau Tor".into(),
            });
        }
    }

    // Un tunnel monté sur l'hôte est transparent pour la passerelle : il ne
    // prévient pas quand il tombe. Comparer l'adresse de sortie directe à celle
    // du lien nu est le seul moyen de s'en rendre compte.
    let default_ip = exit_ip(&config.routing.default_backend);
    if let (Some(current), Some(bare)) = (&default_ip, &config.health.unexpected_exit_ip) {
        if current == bare {
            findings.push(Finding {
                severity: Severity::Critical,
                message: format!(
                    "la sortie directe débouche sur {current}, l'adresse du lien nu : \
                     le tunnel attendu sur l'hôte n'est plus là"
                ),
            });
        }
    }

    // Un backend anonymisant ne doit jamais partager son adresse de sortie avec
    // le chemin direct. La comparaison porte sur la propriété `names_only`, pas
    // sur un identifiant en dur : renommer « tor » ne doit pas la désactiver.
    if let Some(default_exit) = &default_ip {
        for backend in config.backends.iter().filter(|b| b.names_only && b.enabled) {
            if exit_ip(&backend.id).as_ref() == Some(default_exit) {
                findings.push(Finding {
                    severity: Severity::Critical,
                    message: format!(
                        "le backend « {} » et la sortie directe débouchent tous deux sur \
                         {default_exit} : le trafic n'est pas anonymisé",
                        backend.label
                    ),
                });
            }
        }
    }

    if findings.is_empty() {
        findings.push(Finding {
            severity: Severity::Info,
            message: "toutes les sondes sont passées".into(),
        });
    }
    findings
}

async fn probe_exit_ip(backend: Backend, health: HealthConfig) -> ProbeResult {
    let started = Instant::now();
    let result = async {
        let client = client_for(&backend, &health)?;
        let body = client
            .get(&health.ip_check_url)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        Ok::<_, anyhow::Error>(extract_ip(&body))
    }
    .await;

    match result {
        Ok(Some(ip)) => ProbeResult {
            backend: backend.id,
            kind: ProbeKind::ExitIp,
            ok: true,
            latency_ms: started.elapsed().as_millis() as u64,
            value: Some(ip),
            error: None,
        },
        Ok(None) => ProbeResult {
            backend: backend.id,
            kind: ProbeKind::ExitIp,
            ok: false,
            latency_ms: started.elapsed().as_millis() as u64,
            value: None,
            error: Some("la réponse ne contenait aucune adresse IP".into()),
        },
        Err(err) => ProbeResult {
            backend: backend.id,
            kind: ProbeKind::ExitIp,
            ok: false,
            latency_ms: started.elapsed().as_millis() as u64,
            value: None,
            error: Some(short_error(&err)),
        },
    }
}

async fn probe_tor(backend: Backend, health: HealthConfig) -> ProbeResult {
    let started = Instant::now();
    let result = async {
        let client = client_for(&backend, &health)?;
        let body: serde_json::Value = client
            .get(&health.tor_check_url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok::<_, anyhow::Error>(body.get("IsTor").and_then(|v| v.as_bool()))
    }
    .await;

    match result {
        Ok(Some(is_tor)) => ProbeResult {
            backend: backend.id,
            kind: ProbeKind::TorConfirmation,
            ok: true,
            latency_ms: started.elapsed().as_millis() as u64,
            value: Some(is_tor.to_string()),
            error: None,
        },
        Ok(None) => ProbeResult {
            backend: backend.id,
            kind: ProbeKind::TorConfirmation,
            ok: false,
            latency_ms: started.elapsed().as_millis() as u64,
            value: None,
            error: Some("le service de vérification n'a pas renvoyé `IsTor`".into()),
        },
        Err(err) => ProbeResult {
            backend: backend.id,
            kind: ProbeKind::TorConfirmation,
            ok: false,
            latency_ms: started.elapsed().as_millis() as u64,
            value: None,
            error: Some(short_error(&err)),
        },
    }
}

async fn probe_i2p(backend: Backend, health: HealthConfig) -> ProbeResult {
    let started = Instant::now();
    let result = async {
        let client = client_for(&backend, &health)?;
        let status = client.get(&health.i2p_check_url).send().await?.status();
        Ok::<_, anyhow::Error>(status)
    }
    .await;

    match result {
        Ok(status) => ProbeResult {
            backend: backend.id,
            kind: ProbeKind::I2pReachability,
            ok: status.is_success() || status.is_redirection(),
            latency_ms: started.elapsed().as_millis() as u64,
            value: Some(status.as_u16().to_string()),
            error: (!status.is_success() && !status.is_redirection())
                .then(|| format!("HTTP {status}")),
        },
        Err(err) => ProbeResult {
            backend: backend.id,
            kind: ProbeKind::I2pReachability,
            ok: false,
            latency_ms: started.elapsed().as_millis() as u64,
            value: None,
            error: Some(short_error(&err)),
        },
    }
}

/// Construit un client HTTP dont la sortie correspond au backend visé.
fn client_for(backend: &Backend, health: &HealthConfig) -> anyhow::Result<Client> {
    // reqwest panique s'il construit un client sans fournisseur cryptographique.
    crate::install_crypto_provider();
    let timeout = Duration::from_secs(health.timeout_s.max(1));
    let builder = Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout)
        .user_agent("tiv-gateway/health")
        // On n'hérite jamais d'un proxy ambiant : la sonde mentirait.
        .no_proxy();

    let builder = match &backend.kind {
        BackendKind::Direct | BackendKind::Block => builder,
        BackendKind::Socks5 { address, .. } => {
            // socks5h laisse la résolution de nom du côté du proxy, exactement
            // comme le fait le plan de données.
            builder.proxy(reqwest::Proxy::all(format!("socks5h://{address}"))?)
        }
        BackendKind::HttpConnect { address } => {
            builder.proxy(reqwest::Proxy::all(format!("http://{address}"))?)
        }
    };
    Ok(builder.build()?)
}

/// Extrait une IP d'une réponse en texte brut ou en JSON.
fn extract_ip(body: &str) -> Option<String> {
    let trimmed = body.trim();
    if trimmed.parse::<std::net::IpAddr>().is_ok() {
        return Some(trimmed.to_string());
    }
    let value: serde_json::Value = serde_json::from_str(trimmed).ok()?;
    for key in ["ip", "IP", "origin", "query", "YourFuckingIPAddress"] {
        if let Some(found) = value.get(key).and_then(|v| v.as_str()) {
            let candidate = found.split(',').next().unwrap_or(found).trim();
            if candidate.parse::<std::net::IpAddr>().is_ok() {
                return Some(candidate.to_string());
            }
        }
    }
    None
}

/// Rend une erreur de sonde en français, courte et exploitable.
///
/// Les erreurs de reqwest sont longues, en anglais, et détaillent une pile
/// d'appels sans intérêt pour l'exploitant : on les traduit en une phrase quand
/// on reconnaît le cas, et on se rabat sur le message brut sinon.
///
/// La coupure se fait sur une frontière de caractère : un message contenant un
/// accent ou une URL non ASCII ferait paniquer un découpage par octets, et le
/// profil de production compile avec `panic = "abort"`.
fn short_error(err: &anyhow::Error) -> String {
    if let Some(cause) = err.downcast_ref::<reqwest::Error>() {
        if cause.is_timeout() {
            return "délai dépassé : le backend n'a pas répondu à temps".to_string();
        }
        if cause.is_connect() {
            return "connexion impossible : le proxy amont est-il démarré ?".to_string();
        }
        if let Some(status) = cause.status() {
            return format!("le service de vérification a répondu {status}");
        }
        if cause.is_decode() {
            return "réponse illisible du service de vérification".to_string();
        }
        if cause.is_request() {
            return "requête refusée avant même de sortir".to_string();
        }
    }

    let text = format!("{err}");
    let text = text.split(": http").next().unwrap_or(&text).to_string();
    const LIMIT: usize = 180;
    match text.char_indices().nth(LIMIT) {
        Some((cut, _)) => format!("{}…", &text[..cut]),
        None => text,
    }
}

/// Boucle de fond qui déclenche les sondes à l'intervalle configuré.
pub async fn health_loop(state: std::sync::Arc<crate::state::AppState>) {
    loop {
        let config = state.config();
        let interval = Duration::from_secs(config.health.interval_s.max(15));
        if config.health.enabled {
            run_probes(&state.health, &config).await;
        }
        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_is_extracted_from_json_or_plain_text() {
        assert_eq!(extract_ip("  203.0.113.7 \n"), Some("203.0.113.7".into()));
        assert_eq!(
            extract_ip(r#"{"ip":"198.51.100.4"}"#),
            Some("198.51.100.4".into())
        );
        assert_eq!(
            extract_ip(r#"{"origin":"198.51.100.4, 10.0.0.1"}"#),
            Some("198.51.100.4".into())
        );
        assert_eq!(extract_ip("<html>nope</html>"), None);
    }

    fn probe(backend: &str, kind: ProbeKind, value: &str) -> ProbeResult {
        ProbeResult {
            backend: backend.into(),
            kind,
            ok: true,
            latency_ms: 10,
            value: Some(value.into()),
            error: None,
        }
    }

    #[test]
    fn an_identical_exit_ip_on_tor_and_clearnet_is_critical() {
        let mut config = Config::default();
        config.health.unexpected_exit_ip = Some("192.0.2.1".into());
        let probes = vec![
            probe("direct", ProbeKind::ExitIp, "203.0.113.9"),
            probe("tor", ProbeKind::ExitIp, "203.0.113.9"),
        ];
        let findings = analyse(&probes, &config);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical
                    && f.message.contains("n'est pas anonymisé"))
        );
    }

    #[test]
    fn a_direct_exit_matching_the_bare_link_is_critical() {
        let mut config = Config::default();
        config.health.unexpected_exit_ip = Some("192.0.2.1".into());
        let probes = vec![probe("direct", ProbeKind::ExitIp, "192.0.2.1")];
        let findings = analyse(&probes, &config);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical
            && f.message
                .contains("le tunnel attendu sur l'hôte n'est plus là")));
    }

    #[test]
    fn tor_reporting_is_tor_false_is_critical() {
        let config = Config::default();
        let probes = vec![probe("tor", ProbeKind::TorConfirmation, "false")];
        let findings = analyse(&probes, &config);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn a_clean_run_reports_a_single_info_finding() {
        let mut config = Config::default();
        config.health.unexpected_exit_ip = Some("192.0.2.1".into());
        let probes = vec![
            probe("direct", ProbeKind::ExitIp, "203.0.113.9"),
            probe("tor", ProbeKind::ExitIp, "198.51.100.2"),
            probe("tor", ProbeKind::TorConfirmation, "true"),
        ];
        let findings = analyse(&probes, &config);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[tokio::test]
    async fn a_probe_failure_is_reported_in_french() {
        // Une adresse amont fermée : reqwest renvoie une erreur anglaise que
        // l'interface ne doit jamais afficher telle quelle.
        crate::install_crypto_provider();
        let client = Client::builder()
            .timeout(Duration::from_secs(2))
            .no_proxy()
            .build()
            .unwrap();
        let err = client
            .get("http://127.0.0.1:1/")
            .send()
            .await
            .map_err(anyhow::Error::from)
            .unwrap_err();
        let message = short_error(&err);
        assert!(
            message.contains("connexion impossible") || message.contains("délai dépassé"),
            "message inattendu : {message}"
        );
    }

    #[test]
    fn a_long_accented_error_is_truncated_on_a_character_boundary() {
        // Un découpage par octets couperait au milieu d'un « é » et paniquerait,
        // ce qui abattrait tout le processus en profil de production.
        let long = "é".repeat(400);
        let shortened = short_error(&anyhow::anyhow!("{long}"));
        assert!(shortened.ends_with('…'));
        assert_eq!(shortened.chars().count(), 181);
    }

    #[test]
    fn history_is_capped() {
        let registry = HealthRegistry::new();
        for _ in 0..10 {
            registry.store(
                HealthReport {
                    at: 1,
                    duration_ms: 1,
                    probes: Vec::new(),
                    findings: Vec::new(),
                },
                3,
            );
        }
        assert_eq!(registry.state(true).history.len(), 3);
    }
}
