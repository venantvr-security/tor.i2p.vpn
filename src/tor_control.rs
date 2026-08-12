//! Client du ControlPort de Tor.
//!
//! Tor tourne sur la machine hôte : chaque commande ouvre donc une connexion
//! éphémère vers le port de contrôle, s'authentifie, réalise un unique échange
//! puis raccroche. La passerelle reste ainsi sans état vis-à-vis des
//! redémarrages de Tor.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::config::{TorAuth, TorControlConfig};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Serialize)]
pub struct TorStatus {
    pub reachable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_read: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_written: Option<u64>,
    pub circuits: Vec<Circuit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl TorStatus {
    fn unreachable(error: impl Into<String>) -> Self {
        TorStatus {
            reachable: false,
            version: None,
            bootstrap: None,
            bytes_read: None,
            bytes_written: None,
            circuits: Vec::new(),
            error: Some(error.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Circuit {
    pub id: String,
    pub status: String,
    pub path: Vec<Relay>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_flags: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_created: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Relay {
    pub fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,
}

/// Fait respecter la limite de fréquence des NEWNYM d'une requête à l'autre.
pub struct TorControl {
    last_newnym: Mutex<Option<Instant>>,
}

impl Default for TorControl {
    fn default() -> Self {
        Self::new()
    }
}

impl TorControl {
    pub fn new() -> Self {
        TorControl {
            last_newnym: Mutex::new(None),
        }
    }

    /// Collecte la version, la phase d'amorçage, les compteurs de trafic et les
    /// circuits.
    pub async fn status(&self, config: &TorControlConfig) -> TorStatus {
        if !config.enabled {
            return TorStatus::unreachable(
                "le contrôle de Tor est désactivé dans la configuration",
            );
        }
        match self.collect(config).await {
            Ok(status) => status,
            Err(err) => TorStatus::unreachable(format!("{err:#}")),
        }
    }

    async fn collect(&self, config: &TorControlConfig) -> Result<TorStatus> {
        let mut session = Session::connect(config).await?;
        let version = session.get_info_value("version").await.ok();
        let bootstrap = session.get_info_value("status/bootstrap-phase").await.ok();
        let bytes_read = session
            .get_info_value("traffic/read")
            .await
            .ok()
            .and_then(|v| v.parse().ok());
        let bytes_written = session
            .get_info_value("traffic/written")
            .await
            .ok()
            .and_then(|v| v.parse().ok());
        let circuits = session
            .get_info_lines("circuit-status")
            .await
            .map(|lines| lines.iter().filter_map(|l| parse_circuit(l)).collect())
            .unwrap_or_default();
        let _ = session.quit().await;

        Ok(TorStatus {
            reachable: true,
            version,
            bootstrap,
            bytes_read,
            bytes_written,
            circuits,
            error: None,
        })
    }

    /// Demande à Tor un nouveau jeu de circuits.
    pub async fn new_identity(&self, config: &TorControlConfig) -> Result<()> {
        if !config.enabled {
            bail!("le contrôle de Tor est désactivé dans la configuration");
        }
        let cooldown = Duration::from_secs(config.newnym_cooldown_s);
        {
            let guard = self.last_newnym.lock().expect("newnym lock");
            if let Some(last) = *guard {
                let elapsed = last.elapsed();
                if elapsed < cooldown {
                    bail!(
                        "NEWNYM est limité en fréquence, réessayez dans {} s",
                        (cooldown - elapsed).as_secs() + 1
                    );
                }
            }
        }

        let mut session = Session::connect(config).await?;
        session.command("SIGNAL NEWNYM").await?;
        let _ = session.quit().await;
        *self.last_newnym.lock().expect("newnym lock") = Some(Instant::now());
        Ok(())
    }

    /// Ferme un circuit désigné par son identifiant.
    pub async fn close_circuit(&self, config: &TorControlConfig, circuit_id: &str) -> Result<()> {
        if !config.enabled {
            bail!("le contrôle de Tor est désactivé dans la configuration");
        }
        if !circuit_id.chars().all(|c| c.is_ascii_alphanumeric()) {
            bail!("identifiant de circuit invalide");
        }
        let mut session = Session::connect(config).await?;
        session
            .command(&format!("CLOSECIRCUIT {circuit_id}"))
            .await?;
        let _ = session.quit().await;
        Ok(())
    }
}

struct Session {
    stream: BufReader<TcpStream>,
}

impl Session {
    async fn connect(config: &TorControlConfig) -> Result<Self> {
        let stream =
            tokio::time::timeout(COMMAND_TIMEOUT, TcpStream::connect(config.address.as_str()))
                .await
                .map_err(|_| anyhow!("délai dépassé lors de la connexion à {}", config.address))?
                .with_context(|| format!("connexion au port de contrôle Tor {}", config.address))?;

        let mut session = Session {
            stream: BufReader::new(stream),
        };
        session.authenticate(config).await?;
        Ok(session)
    }

    async fn authenticate(&mut self, config: &TorControlConfig) -> Result<()> {
        let command = match config.auth {
            TorAuth::None => "AUTHENTICATE".to_string(),
            TorAuth::Password => {
                let password = config.password.as_deref().ok_or_else(|| {
                    anyhow!("authentification par mot de passe choisie, mais aucun n'est défini")
                })?;
                format!("AUTHENTICATE \"{}\"", escape(password))
            }
            TorAuth::Cookie => {
                let cookie = std::fs::read(&config.cookie_path).with_context(|| {
                    format!(
                        "lecture du cookie d'authentification Tor dans {} \
                         (à monter en lecture seule dans le conteneur)",
                        config.cookie_path
                    )
                })?;
                format!("AUTHENTICATE {}", hex::encode(cookie))
            }
        };
        self.command(&command)
            .await
            .context("Tor a rejeté l'authentification")?;
        Ok(())
    }

    /// Envoie une commande et renvoie les lignes de réponse, en erreur si le
    /// code n'est pas 250.
    async fn command(&mut self, command: &str) -> Result<Vec<String>> {
        let exchange = async {
            self.stream
                .get_mut()
                .write_all(format!("{command}\r\n").as_bytes())
                .await?;
            self.read_reply().await
        };
        let (code, lines) = tokio::time::timeout(COMMAND_TIMEOUT, exchange)
            .await
            .map_err(|_| anyhow!("délai dépassé en attendant le port de contrôle Tor"))??;
        if code != 250 {
            bail!("Tor a répondu {} ({})", code, lines.join(" "));
        }
        Ok(lines)
    }

    async fn read_reply(&mut self) -> Result<(u16, Vec<String>)> {
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            let read = self.stream.read_line(&mut line).await?;
            if read == 0 {
                bail!("le port de contrôle Tor a fermé la connexion");
            }
            let line = line.trim_end_matches(['\r', '\n']).to_string();
            if line.len() < 4 {
                bail!("réponse de contrôle mal formée `{line}`");
            }
            let code: u16 = line[..3]
                .parse()
                .map_err(|_| anyhow!("code de réponse mal formé dans `{line}`"))?;
            let separator = line.as_bytes()[3];
            let payload = line[4..].to_string();
            match separator {
                // Dernière ligne de la réponse.
                b' ' => {
                    if !payload.is_empty() {
                        lines.push(payload);
                    }
                    return Ok((code, lines));
                }
                // Ligne intermédiaire : la réponse continue.
                b'-' => lines.push(payload),
                // Bloc de données multiligne, terminé par un point isolé.
                b'+' => {
                    lines.push(payload);
                    loop {
                        let mut data = String::new();
                        if self.stream.read_line(&mut data).await? == 0 {
                            bail!("bloc de données tronqué depuis le port de contrôle Tor");
                        }
                        let data = data.trim_end_matches(['\r', '\n']).to_string();
                        if data == "." {
                            break;
                        }
                        lines.push(data);
                    }
                }
                _ => bail!("séparateur inattendu dans `{line}`"),
            }
        }
    }

    /// `GETINFO clé` pour une clé à valeur unique.
    async fn get_info_value(&mut self, key: &str) -> Result<String> {
        let lines = self.command(&format!("GETINFO {key}")).await?;
        lines
            .iter()
            .find_map(|line| line.strip_prefix(&format!("{key}=")))
            .map(|value| value.trim().to_string())
            .ok_or_else(|| anyhow!("Tor n'a renvoyé aucune valeur pour {key}"))
    }

    /// `GETINFO clé` pour une clé dont la valeur est un bloc multiligne.
    async fn get_info_lines(&mut self, key: &str) -> Result<Vec<String>> {
        let lines = self.command(&format!("GETINFO {key}")).await?;
        let prefix = format!("{key}=");
        let mut out = Vec::new();
        let mut collecting = false;
        for line in lines {
            if let Some(rest) = line.strip_prefix(&prefix) {
                collecting = true;
                if !rest.trim().is_empty() {
                    out.push(rest.trim().to_string());
                }
            } else if collecting && line != "OK" {
                out.push(line);
            }
        }
        Ok(out)
    }

    async fn quit(&mut self) -> Result<()> {
        self.stream.get_mut().write_all(b"QUIT\r\n").await?;
        Ok(())
    }
}

/// Échappe une chaîne entre guillemets du port de contrôle : antislash et
/// guillemet, conformément à la grammaire du protocole.
fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Analyse une ligne de `circuit-status`.
///
/// Exemple : `5 BUILT $AAAA~alpha,$BBBB~beta PURPOSE=GENERAL TIME_CREATED=...`
pub fn parse_circuit(line: &str) -> Option<Circuit> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let mut parts = line.split_whitespace();
    let id = parts.next()?.to_string();
    if !id.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    let status = parts.next()?.to_string();

    let mut path = Vec::new();
    let mut purpose = None;
    let mut build_flags = None;
    let mut time_created = None;

    for token in parts {
        if let Some((key, value)) = token.split_once('=') {
            match key {
                "PURPOSE" => purpose = Some(value.to_string()),
                "BUILD_FLAGS" => build_flags = Some(value.to_string()),
                "TIME_CREATED" => time_created = Some(value.to_string()),
                _ => {}
            }
        } else if token.starts_with('$') && path.is_empty() {
            path = token.split(',').filter_map(parse_relay).collect();
        }
    }

    Some(Circuit {
        id,
        status,
        path,
        purpose,
        build_flags,
        time_created,
    })
}

fn parse_relay(token: &str) -> Option<Relay> {
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    let token = token.strip_prefix('$').unwrap_or(token);
    // `EMPREINTE~Surnom` quand le relais est vérifié, `=Surnom` sinon.
    let (fingerprint, nickname) = match token.split_once(['~', '=']) {
        Some((fp, nick)) => (fp.to_string(), Some(nick.to_string())),
        None => (token.to_string(), None),
    };
    Some(Relay {
        fingerprint,
        nickname,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_built_circuit_is_parsed_with_its_full_path() {
        let line = "5 BUILT $AAAA~alpha,$BBBB~beta,$CCCC~gamma \
                    BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL TIME_CREATED=2026-08-12T10:00:00.000000";
        let circuit = parse_circuit(line).unwrap();
        assert_eq!(circuit.id, "5");
        assert_eq!(circuit.status, "BUILT");
        assert_eq!(circuit.path.len(), 3);
        assert_eq!(circuit.path[0].fingerprint, "AAAA");
        assert_eq!(circuit.path[2].nickname.as_deref(), Some("gamma"));
        assert_eq!(circuit.purpose.as_deref(), Some("GENERAL"));
        assert_eq!(circuit.build_flags.as_deref(), Some("NEED_CAPACITY"));
    }

    #[test]
    fn a_launched_circuit_without_a_path_still_parses() {
        let circuit = parse_circuit("7 LAUNCHED PURPOSE=GENERAL").unwrap();
        assert_eq!(circuit.id, "7");
        assert_eq!(circuit.status, "LAUNCHED");
        assert!(circuit.path.is_empty());
    }

    #[test]
    fn junk_lines_are_ignored() {
        assert!(parse_circuit("").is_none());
        assert!(parse_circuit("OK").is_none());
        assert!(parse_circuit("not-a-circuit BUILT").is_none());
    }

    #[test]
    fn quoted_passwords_are_escaped() {
        assert_eq!(escape(r#"pa"ss\word"#), r#"pa\"ss\\word"#);
    }

    #[tokio::test]
    async fn newnym_is_rate_limited() {
        let control = TorControl::new();
        *control.last_newnym.lock().unwrap() = Some(Instant::now());
        let config = TorControlConfig {
            enabled: true,
            newnym_cooldown_s: 30,
            ..Default::default()
        };
        let err = control.new_identity(&config).await.unwrap_err();
        assert!(err.to_string().contains("limité en fréquence"));
    }

    #[tokio::test]
    async fn a_disabled_control_port_reports_cleanly() {
        let control = TorControl::new();
        let status = control.status(&TorControlConfig::default()).await;
        assert!(!status.reachable);
        assert!(status.error.unwrap().contains("désactivé"));
    }
}
