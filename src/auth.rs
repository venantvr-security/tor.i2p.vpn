//! Authentification de l'administration : empreintes Argon2id et jetons de
//! session signés en HMAC.
//!
//! La passerelle détient les clés du trafic de quelqu'un : l'interface n'est
//! donc jamais laissée ouverte. Au premier démarrage, elle refuse tout hormis
//! l'appel d'initialisation qui fixe le mot de passe administrateur.

use anyhow::{anyhow, bail, Result};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub const COOKIE_NAME: &str = "tiv_session";
/// Refuse les mots de passe administrateur trivialement devinables.
pub const MIN_PASSWORD_LEN: usize = 5;

pub fn hash_password(password: &str) -> Result<String> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        bail!("le mot de passe doit comporter au moins {MIN_PASSWORD_LEN} caractères");
    }
    let salt = SaltString::encode_b64(&random_bytes::<16>())
        .map_err(|err| anyhow!("échec de la génération du sel : {err}"))?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|err| anyhow!("échec du hachage : {err}"))
}

pub fn verify_password(hash: &str, password: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

/// 32 octets aléatoires en hexadécimal, servant de clé de signature des sessions.
pub fn generate_secret() -> String {
    hex::encode(random_bytes::<32>())
}

/// Émet un jeton de session valable `ttl_hours` heures.
pub fn issue_token(secret: &str, ttl_hours: u64, now_s: u64) -> Result<String> {
    let expires_at = now_s + ttl_hours.max(1) * 3600;
    let payload = format!("v1.{}.{}", expires_at, hex::encode(random_bytes::<8>()));
    let signature = sign(secret, &payload)?;
    Ok(format!("{payload}.{signature}"))
}

/// Vérifie la signature et l'expiration. Renvoie la durée de vie restante, en
/// secondes.
pub fn verify_token(secret: &str, token: &str, now_s: u64) -> Result<u64> {
    let (payload, signature) = token
        .rsplit_once('.')
        .ok_or_else(|| anyhow!("jeton de session mal formé"))?;
    let expected = sign(secret, payload)?;
    if !constant_time_eq(expected.as_bytes(), signature.as_bytes()) {
        bail!("signature de session invalide");
    }
    let mut parts = payload.split('.');
    if parts.next() != Some("v1") {
        bail!("version de jeton de session non prise en charge");
    }
    let expires_at: u64 = parts
        .next()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| anyhow!("date d'expiration de session mal formée"))?;
    if expires_at <= now_s {
        bail!("session expirée");
    }
    Ok(expires_at - now_s)
}

fn sign(secret: &str, payload: &str) -> Result<String> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| anyhow!("le secret de session est inutilisable"))?;
    mac.update(payload.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Extrait le jeton de session d'un en-tête `Cookie`.
pub fn token_from_cookie_header(header: &str) -> Option<&str> {
    header.split(';').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name.trim() == COOKIE_NAME).then(|| value.trim())
    })
}

/// Sérialise la valeur `Set-Cookie` d'une session.
pub fn cookie_value(token: &str, max_age_s: u64) -> String {
    format!("{COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age_s}")
}

pub fn clear_cookie_value() -> String {
    format!("{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
}

/// Amortisseur de force brute pour le point d'entrée de connexion.
///
/// L'interface d'administration est le plus souvent exposée sur un LAN
/// domestique, c'est-à-dire précisément là où un équipement compromis
/// essaierait des mots de passe en boucle.
pub struct LoginGuard {
    attempts: std::sync::Mutex<std::collections::HashMap<String, Attempt>>,
}

struct Attempt {
    failures: u32,
    locked_until: Option<std::time::Instant>,
}

impl Default for LoginGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl LoginGuard {
    /// Nombre d'échecs tolérés avant le premier verrouillage.
    const FREE_ATTEMPTS: u32 = 5;
    const MAX_LOCKOUT_S: u64 = 900;
    /// Nombre maximum de sources suivies simultanément.
    const MAX_TRACKED: usize = 4096;

    pub fn new() -> Self {
        LoginGuard {
            attempts: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Secondes restantes avant que `key` puisse réessayer, ou `None` si elle
    /// est déjà autorisée.
    pub fn locked_for(&self, key: &str) -> Option<u64> {
        let guard = self.attempts.lock().expect("login guard lock");
        let attempt = guard.get(key)?;
        let until = attempt.locked_until?;
        let now = std::time::Instant::now();
        (until > now).then(|| (until - now).as_secs() + 1)
    }

    pub fn record_failure(&self, key: &str) {
        let mut guard = self.attempts.lock().expect("login guard lock");

        // Sans purge, une source qui fait tourner son adresse ferait grossir
        // cette table indéfiniment. On oublie les entrées dont le verrou est
        // expiré depuis longtemps avant d'en ajouter une nouvelle.
        if guard.len() >= Self::MAX_TRACKED && !guard.contains_key(key) {
            let now = std::time::Instant::now();
            guard.retain(|_, attempt| match attempt.locked_until {
                Some(until) => until > now,
                None => false,
            });
            // Toutes les entrées sont encore verrouillées : on refuse d'en
            // suivre davantage plutôt que de consommer de la mémoire sans fin.
            if guard.len() >= Self::MAX_TRACKED {
                return;
            }
        }

        let attempt = guard.entry(key.to_string()).or_insert(Attempt {
            failures: 0,
            locked_until: None,
        });
        attempt.failures += 1;
        if attempt.failures > Self::FREE_ATTEMPTS {
            // 2 s, 4 s, 8 s… puis plafonné : une faute de frappe honnête ne
            // coûte pratiquement rien.
            let over = attempt.failures - Self::FREE_ATTEMPTS;
            let delay = 2u64.saturating_pow(over.min(10)).min(Self::MAX_LOCKOUT_S);
            attempt.locked_until =
                Some(std::time::Instant::now() + std::time::Duration::from_secs(delay));
        }
    }

    pub fn record_success(&self, key: &str) {
        self.attempts.lock().expect("login guard lock").remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_login_guard_locks_out_after_repeated_failures() {
        let guard = LoginGuard::new();
        for _ in 0..LoginGuard::FREE_ATTEMPTS {
            guard.record_failure("10.0.0.5");
        }
        assert!(guard.locked_for("10.0.0.5").is_none());

        guard.record_failure("10.0.0.5");
        assert!(guard.locked_for("10.0.0.5").is_some());
        // Les autres clients ne sont pas affectés.
        assert!(guard.locked_for("10.0.0.6").is_none());

        guard.record_success("10.0.0.5");
        assert!(guard.locked_for("10.0.0.5").is_none());
    }

    #[test]
    fn the_login_guard_does_not_grow_without_bound() {
        let guard = LoginGuard::new();
        // Une source qui fait tourner son adresse ne doit pas pouvoir faire
        // gonfler la table indéfiniment.
        for index in 0..(LoginGuard::MAX_TRACKED + 500) {
            guard.record_failure(&format!("10.0.{}.{}", index / 256, index % 256));
        }
        let tracked = guard.attempts.lock().unwrap().len();
        assert!(
            tracked <= LoginGuard::MAX_TRACKED,
            "{tracked} entrées suivies"
        );
    }

    #[test]
    fn a_password_round_trips_through_argon2() {
        let hash = hash_password("correct horse battery").unwrap();
        assert!(hash.starts_with("$argon2"));
        assert!(verify_password(&hash, "correct horse battery"));
        assert!(!verify_password(&hash, "wrong horse battery"));
        assert!(!verify_password("not-a-hash", "correct horse battery"));
    }

    #[test]
    fn short_passwords_are_refused() {
        // Quatre caracteres : sous la borne, refuse.
        assert!(hash_password("abcd").is_err());
        // Cinq caracteres : la nouvelle borne minimale, accepte.
        assert!(hash_password("abcde").is_ok());
    }

    #[test]
    fn a_token_verifies_until_it_expires() {
        let secret = generate_secret();
        let token = issue_token(&secret, 1, 1_000).unwrap();
        assert_eq!(verify_token(&secret, &token, 1_000).unwrap(), 3_600);
        assert!(verify_token(&secret, &token, 1_000 + 3_601).is_err());
    }

    #[test]
    fn a_token_signed_with_another_secret_is_rejected() {
        let token = issue_token(&generate_secret(), 1, 0).unwrap();
        assert!(verify_token(&generate_secret(), &token, 0).is_err());
    }

    #[test]
    fn a_tampered_expiry_is_rejected() {
        let secret = generate_secret();
        let token = issue_token(&secret, 1, 1_000).unwrap();
        let mut parts: Vec<&str> = token.split('.').collect();
        parts[1] = "99999999999";
        let forged = parts.join(".");
        assert!(verify_token(&secret, &forged, 1_000).is_err());
    }

    #[test]
    fn two_tokens_issued_together_still_differ() {
        let secret = generate_secret();
        let a = issue_token(&secret, 1, 42).unwrap();
        let b = issue_token(&secret, 1, 42).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn the_session_cookie_is_found_among_others() {
        assert_eq!(
            token_from_cookie_header("theme=dark; tiv_session=abc.def; other=1"),
            Some("abc.def")
        );
        assert_eq!(token_from_cookie_header("theme=dark"), None);
    }

    #[test]
    fn the_cookie_is_hardened() {
        let cookie = cookie_value("tok", 3600);
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Max-Age=3600"));
    }
}
