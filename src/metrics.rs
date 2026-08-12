//! Télémétrie en mémoire du plan de données.
//!
//! Tout est sans verrou sur le chemin chaud (des compteurs atomiques par
//! backend) ; les structures protégées par mutex ne sont touchées qu'une fois
//! par connexion ou une fois par tick d'échantillonnage.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// Nombre d'enregistrements de connexion conservés pour le journal live.
const RECENT_CAPACITY: usize = 250;
/// Nombre d'échantillons de débit conservés (soit ~10 minutes à `SAMPLE_PERIOD_S`).
const SERIES_CAPACITY: usize = 300;
/// Période d'échantillonnage de la série de débit, en secondes.
pub const SAMPLE_PERIOD_S: u64 = 2;

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

#[derive(Debug, Default)]
pub struct BackendCounters {
    pub connections_total: AtomicU64,
    pub connections_active: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    pub errors: AtomicU64,
    pub denied: AtomicU64,
    connect_latency_sum_ms: AtomicU64,
    connect_latency_count: AtomicU64,
    connect_latency_max_ms: AtomicU64,
}

impl BackendCounters {
    fn observe_connect(&self, latency_ms: u64) {
        self.connect_latency_sum_ms
            .fetch_add(latency_ms, Ordering::Relaxed);
        self.connect_latency_count.fetch_add(1, Ordering::Relaxed);
        self.connect_latency_max_ms
            .fetch_max(latency_ms, Ordering::Relaxed);
    }

    fn snapshot(&self, id: &str) -> BackendSnapshot {
        let count = self.connect_latency_count.load(Ordering::Relaxed);
        let sum = self.connect_latency_sum_ms.load(Ordering::Relaxed);
        BackendSnapshot {
            id: id.to_string(),
            connections_total: self.connections_total.load(Ordering::Relaxed),
            connections_active: self.connections_active.load(Ordering::Relaxed),
            bytes_up: self.bytes_up.load(Ordering::Relaxed),
            bytes_down: self.bytes_down.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            denied: self.denied.load(Ordering::Relaxed),
            avg_connect_ms: if count == 0 { 0 } else { sum / count },
            max_connect_ms: self.connect_latency_max_ms.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BackendSnapshot {
    pub id: String,
    pub connections_total: u64,
    pub connections_active: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub errors: u64,
    pub denied: u64,
    pub avg_connect_ms: u64,
    pub max_connect_ms: u64,
}

/// Une connexion cliente, terminée ou en cours, telle qu'affichée dans le
/// journal live.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionRecord {
    pub id: u64,
    pub started_ms: u64,
    pub client: String,
    pub target: String,
    pub protocol: &'static str,
    pub backend: Option<String>,
    pub rule: Option<String>,
    pub status: ConnectionStatus,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStatus {
    Active,
    Closed,
    Denied,
    Failed,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Sample {
    pub t: u64,
    pub up_bps: u64,
    pub down_bps: u64,
    pub active: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricsSnapshot {
    pub uptime_s: u64,
    pub totals: BackendSnapshot,
    pub backends: Vec<BackendSnapshot>,
    pub series: Vec<Sample>,
    pub recent: Vec<ConnectionRecord>,
    pub rejected_no_capacity: u64,
}

pub struct Metrics {
    started_ms: u64,
    next_conn_id: AtomicU64,
    rejected_no_capacity: AtomicU64,
    backends: RwLock<HashMap<String, Arc<BackendCounters>>>,
    recent: Mutex<VecDeque<ConnectionRecord>>,
    series: Mutex<VecDeque<Sample>>,
    last_totals: Mutex<(u64, u64)>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        Metrics {
            started_ms: now_ms(),
            next_conn_id: AtomicU64::new(1),
            rejected_no_capacity: AtomicU64::new(0),
            backends: RwLock::new(HashMap::new()),
            recent: Mutex::new(VecDeque::with_capacity(RECENT_CAPACITY)),
            series: Mutex::new(VecDeque::with_capacity(SERIES_CAPACITY)),
            last_totals: Mutex::new((0, 0)),
        }
    }

    pub fn next_id(&self) -> u64 {
        self.next_conn_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn note_capacity_rejection(&self) {
        self.rejected_no_capacity.fetch_add(1, Ordering::Relaxed);
    }

    /// Compteurs du backend `backend_id`, créés à la première utilisation.
    pub fn backend(&self, backend_id: &str) -> Arc<BackendCounters> {
        if let Some(found) = self
            .backends
            .read()
            .expect("metrics lock")
            .get(backend_id)
            .cloned()
        {
            return found;
        }
        let mut guard = self.backends.write().expect("metrics lock");
        guard
            .entry(backend_id.to_string())
            .or_insert_with(|| Arc::new(BackendCounters::default()))
            .clone()
    }

    pub fn observe_connect(&self, backend_id: &str, latency_ms: u64) {
        self.backend(backend_id).observe_connect(latency_ms);
    }

    /// Insère un enregistrement dans le journal live, ou le remplace si son
    /// identifiant y figure déjà.
    pub fn record(&self, record: ConnectionRecord) {
        let mut guard = self.recent.lock().expect("recent lock");
        if let Some(existing) = guard.iter_mut().find(|r| r.id == record.id) {
            *existing = record;
            return;
        }
        if guard.len() == RECENT_CAPACITY {
            guard.pop_back();
        }
        guard.push_front(record);
    }

    /// Appelée toutes les `SAMPLE_PERIOD_S` secondes pour ajouter un point de
    /// débit à la série.
    pub fn sample(&self) {
        let (up, down, active) = self.aggregate();
        let mut last = self.last_totals.lock().expect("totals lock");
        let delta_up = up.saturating_sub(last.0);
        let delta_down = down.saturating_sub(last.1);
        *last = (up, down);
        drop(last);

        let mut series = self.series.lock().expect("series lock");
        if series.len() == SERIES_CAPACITY {
            series.pop_front();
        }
        series.push_back(Sample {
            t: now_ms(),
            up_bps: delta_up / SAMPLE_PERIOD_S,
            down_bps: delta_down / SAMPLE_PERIOD_S,
            active,
        });
    }

    fn aggregate(&self) -> (u64, u64, u64) {
        let guard = self.backends.read().expect("metrics lock");
        guard.values().fold((0, 0, 0), |acc, counters| {
            (
                acc.0 + counters.bytes_up.load(Ordering::Relaxed),
                acc.1 + counters.bytes_down.load(Ordering::Relaxed),
                acc.2 + counters.connections_active.load(Ordering::Relaxed),
            )
        })
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        let backends: Vec<BackendSnapshot> = {
            let guard = self.backends.read().expect("metrics lock");
            let mut list: Vec<_> = guard
                .iter()
                .map(|(id, counters)| counters.snapshot(id))
                .collect();
            list.sort_by(|a, b| a.id.cmp(&b.id));
            list
        };

        let totals = backends.iter().fold(
            BackendSnapshot {
                id: "total".to_string(),
                connections_total: 0,
                connections_active: 0,
                bytes_up: 0,
                bytes_down: 0,
                errors: 0,
                denied: 0,
                avg_connect_ms: 0,
                max_connect_ms: 0,
            },
            |mut acc, b| {
                acc.connections_total += b.connections_total;
                acc.connections_active += b.connections_active;
                acc.bytes_up += b.bytes_up;
                acc.bytes_down += b.bytes_down;
                acc.errors += b.errors;
                acc.denied += b.denied;
                acc.max_connect_ms = acc.max_connect_ms.max(b.max_connect_ms);
                acc
            },
        );

        MetricsSnapshot {
            uptime_s: (now_ms().saturating_sub(self.started_ms)) / 1000,
            totals,
            backends,
            series: self
                .series
                .lock()
                .expect("series lock")
                .iter()
                .copied()
                .collect(),
            recent: self
                .recent
                .lock()
                .expect("recent lock")
                .iter()
                .cloned()
                .collect(),
            rejected_no_capacity: self.rejected_no_capacity.load(Ordering::Relaxed),
        }
    }

    /// Exposition au format texte Prometheus, pratique si l'on dispose déjà
    /// d'une instance Grafana.
    pub fn prometheus(&self) -> String {
        let snapshot = self.snapshot();
        let mut out = String::new();
        out.push_str(
            "# HELP tiv_uptime_seconds Durée de fonctionnement de la passerelle.\n\
             # TYPE tiv_uptime_seconds gauge\n",
        );
        out.push_str(&format!("tiv_uptime_seconds {}\n", snapshot.uptime_s));
        // L'exposition Prometheus est de l'UTF-8 : les libellés sont accentués
        // comme partout ailleurs dans le projet.
        for metric in [
            ("tiv_connections_total", "counter", "Connexions routées."),
            ("tiv_connections_active", "gauge", "Connexions en cours."),
            (
                "tiv_bytes_up_total",
                "counter",
                "Octets du client vers l'amont.",
            ),
            (
                "tiv_bytes_down_total",
                "counter",
                "Octets de l'amont vers le client.",
            ),
            ("tiv_errors_total", "counter", "Échecs de connexion amont."),
            (
                "tiv_denied_total",
                "counter",
                "Connexions refusées par la politique de routage.",
            ),
        ] {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} {kind}\n",
                name = metric.0,
                kind = metric.1,
                help = metric.2
            ));
            for backend in &snapshot.backends {
                let value = match metric.0 {
                    "tiv_connections_total" => backend.connections_total,
                    "tiv_connections_active" => backend.connections_active,
                    "tiv_bytes_up_total" => backend.bytes_up,
                    "tiv_bytes_down_total" => backend.bytes_down,
                    "tiv_errors_total" => backend.errors,
                    _ => backend.denied,
                };
                out.push_str(&format!(
                    "{}{{backend=\"{}\"}} {}\n",
                    metric.0, backend.id, value
                ));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_aggregate_per_backend() {
        let metrics = Metrics::new();
        let tor = metrics.backend("tor");
        tor.connections_total.fetch_add(3, Ordering::Relaxed);
        tor.bytes_up.fetch_add(1_000, Ordering::Relaxed);
        metrics
            .backend("vpn")
            .bytes_down
            .fetch_add(500, Ordering::Relaxed);
        metrics.observe_connect("tor", 120);
        metrics.observe_connect("tor", 80);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.totals.connections_total, 3);
        assert_eq!(snapshot.totals.bytes_up, 1_000);
        assert_eq!(snapshot.totals.bytes_down, 500);
        let tor_snapshot = snapshot.backends.iter().find(|b| b.id == "tor").unwrap();
        assert_eq!(tor_snapshot.avg_connect_ms, 100);
        assert_eq!(tor_snapshot.max_connect_ms, 120);
    }

    #[test]
    fn sampling_reports_a_rate_not_a_total() {
        let metrics = Metrics::new();
        metrics.sample();
        metrics
            .backend("tor")
            .bytes_down
            .fetch_add(2_000 * SAMPLE_PERIOD_S, Ordering::Relaxed);
        metrics.sample();
        let series = metrics.snapshot().series;
        assert_eq!(series.len(), 2);
        assert_eq!(series[1].down_bps, 2_000);
    }

    #[test]
    fn records_are_replaced_by_id_and_capped() {
        let metrics = Metrics::new();
        let make = |id: u64, status: ConnectionStatus| ConnectionRecord {
            id,
            started_ms: 0,
            client: "127.0.0.1:1".into(),
            target: "example.com:443".into(),
            protocol: "socks5",
            backend: Some("vpn".into()),
            rule: None,
            status,
            bytes_up: 0,
            bytes_down: 0,
            duration_ms: 0,
            detail: None,
        };
        metrics.record(make(1, ConnectionStatus::Active));
        metrics.record(make(1, ConnectionStatus::Closed));
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.recent.len(), 1);
        assert_eq!(snapshot.recent[0].status, ConnectionStatus::Closed);

        for id in 2..(RECENT_CAPACITY as u64 + 50) {
            metrics.record(make(id, ConnectionStatus::Closed));
        }
        assert_eq!(metrics.snapshot().recent.len(), RECENT_CAPACITY);
    }

    #[test]
    fn prometheus_output_is_labelled_per_backend() {
        let metrics = Metrics::new();
        metrics
            .backend("tor")
            .connections_total
            .fetch_add(7, Ordering::Relaxed);
        let text = metrics.prometheus();
        assert!(text.contains("tiv_connections_total{backend=\"tor\"} 7"));
    }
}
