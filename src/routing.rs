//! Routage par destination : choisit le backend qui portera la connexion.
//!
//! Les règles sont évaluées de haut en bas, la première correspondance
//! l'emporte. Avec les valeurs par défaut livrées, cela signifie que `*.onion`
//! part vers Tor, `*.i2p` vers I2P, et que tout le reste retombe sur le backend
//! par défaut, c'est-à-dire le chemin VPN.
//!
//! ```mermaid
//! flowchart LR
//!     C[Client SOCKS5 / HTTP] --> R{Suffixe du nom}
//!     R -- ".onion" --> T[Backend tor<br/>SOCKS5 127.0.0.1:9050]
//!     R -- ".i2p" --> I[Backend i2p<br/>SOCKS5 127.0.0.1:4447]
//!     R -- "sinon" --> V[Backend vpn<br/>sortie directe]
//!     R -- "IP privée" --> X[Refus]
//! ```

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{anyhow, bail, Result};

use crate::config::{Backend, BackendKind, Config, MatchType, Rule};

/// Destination demandée par le client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: Host,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    Name(String),
    Ip(IpAddr),
}

impl Target {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        let host: String = host.into();
        // Un nom pleinement qualifié peut légalement se terminer par un point.
        // Sans cette normalisation, `exemple.onion.` échapperait à la règle du
        // suffixe `.onion`, retomberait sur le backend par défaut et serait
        // résolu localement : une fuite DNS caractérisée.
        let host = host.strip_suffix('.').unwrap_or(&host).to_string();
        match host.parse::<IpAddr>() {
            Ok(ip) => Target {
                host: Host::Ip(ip),
                port,
            },
            Err(_) => Target {
                host: Host::Name(host),
                port,
            },
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Host::Name(name) => write!(f, "{}:{}", name, self.port),
            Host::Ip(IpAddr::V6(ip)) => write!(f, "[{}]:{}", ip, self.port),
            Host::Ip(IpAddr::V4(ip)) => write!(f, "{}:{}", ip, self.port),
        }
    }
}

/// Résultat de l'évaluation du jeu de règles.
#[derive(Debug, Clone)]
pub struct Decision {
    pub backend_id: String,
    pub matched_rule: Option<String>,
    pub verdict: Verdict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    /// Refus prononcé avant tout contact amont ; porte le motif lisible.
    Deny(DenyReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    /// Le backend retenu est un backend de type `block`.
    BlockedByPolicy,
    /// Le backend retenu existe mais il est désactivé.
    BackendDisabled,
    /// Le routage désigne un backend qui n'existe plus.
    UnknownBackend,
    /// La destination est une adresse loopback, privée ou lien-local.
    PrivateAddress,
    /// Une IP brute a été demandée sur un backend réservé aux services cachés.
    BareIpOnHiddenBackend,
}

impl DenyReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            DenyReason::BlockedByPolicy => "bloqué par la politique de routage",
            DenyReason::BackendDisabled => "backend désactivé",
            DenyReason::UnknownBackend => "backend inconnu",
            DenyReason::PrivateAddress => "adresse privée bloquée",
            DenyReason::BareIpOnHiddenBackend => "IP brute non routable sur ce backend",
        }
    }
}

/// Photographie immuable de la table de routage, reconstruite à chaque
/// changement de configuration.
pub struct Router {
    rules: Vec<CompiledRule>,
    default_backend: String,
    block_private_ranges: bool,
    block_bare_ip_on_hidden: bool,
}

struct CompiledRule {
    id: String,
    backend: String,
    matcher: Matcher,
}

enum Matcher {
    Suffix(String),
    Exact(String),
    Wildcard(Vec<String>),
    Cidr(IpAddr, u8),
}

impl Router {
    pub fn from_config(config: &Config) -> Self {
        let rules = config
            .routing
            .rules
            .iter()
            .filter(|rule| rule.enabled)
            .filter_map(|rule| CompiledRule::compile(rule).ok())
            .collect();
        Router {
            rules,
            default_backend: config.routing.default_backend.clone(),
            block_private_ranges: config.routing.block_private_ranges,
            block_bare_ip_on_hidden: config.routing.block_bare_ip_on_hidden,
        }
    }

    /// Choisit un backend pour `target` et décide si la connexion peut aboutir.
    pub fn route(&self, target: &Target, backends: &[Backend]) -> Decision {
        let (backend_id, matched_rule) = self
            .rules
            .iter()
            .find(|rule| rule.matches(target))
            .map(|rule| (rule.backend.clone(), Some(rule.id.clone())))
            .unwrap_or_else(|| (self.default_backend.clone(), None));

        let verdict = self.verdict(target, &backend_id, backends);
        Decision {
            backend_id,
            matched_rule,
            verdict,
        }
    }

    fn verdict(&self, target: &Target, backend_id: &str, backends: &[Backend]) -> Verdict {
        let Some(backend) = backends.iter().find(|b| b.id == backend_id) else {
            return Verdict::Deny(DenyReason::UnknownBackend);
        };
        if !backend.enabled {
            return Verdict::Deny(DenyReason::BackendDisabled);
        }
        if matches!(backend.kind, BackendKind::Block) {
            return Verdict::Deny(DenyReason::BlockedByPolicy);
        }
        // Une destination privée n'a de sens que sur le chemin local, et même
        // là elle offre un pivot facile vers le LAN : on la refuse d'emblée.
        if self.block_private_ranges {
            if let Host::Ip(ip) = &target.host {
                if is_private(ip) {
                    return Verdict::Deny(DenyReason::PrivateAddress);
                }
            }
        }
        // Tor et I2P résolvent les noms à l'intérieur du tunnel ; leur passer
        // une IP brute échoue, ou pire, ressort par un chemin inattendu. Le
        // garde-fou suit la propriété déclarée du backend, jamais son
        // identifiant : renommer « tor » ne doit pas désarmer la protection en
        // silence.
        if self.block_bare_ip_on_hidden && backend.names_only && matches!(target.host, Host::Ip(_))
        {
            return Verdict::Deny(DenyReason::BareIpOnHiddenBackend);
        }
        Verdict::Allow
    }
}

impl CompiledRule {
    fn compile(rule: &Rule) -> Result<Self> {
        let matcher = match rule.match_type {
            MatchType::Suffix => Matcher::Suffix(rule.pattern.to_ascii_lowercase()),
            MatchType::Exact => Matcher::Exact(rule.pattern.to_ascii_lowercase()),
            MatchType::Wildcard => Matcher::Wildcard(
                rule.pattern
                    .to_ascii_lowercase()
                    .split('*')
                    .map(str::to_string)
                    .collect(),
            ),
            MatchType::Cidr => {
                let (ip, prefix) = parse_cidr(&rule.pattern)?;
                Matcher::Cidr(ip, prefix)
            }
        };
        Ok(CompiledRule {
            id: rule.id.clone(),
            backend: rule.backend.clone(),
            matcher,
        })
    }

    fn matches(&self, target: &Target) -> bool {
        match (&self.matcher, &target.host) {
            (Matcher::Suffix(suffix), Host::Name(name)) => {
                name.to_ascii_lowercase().ends_with(suffix.as_str())
            }
            (Matcher::Exact(expected), Host::Name(name)) => name.to_ascii_lowercase() == *expected,
            (Matcher::Wildcard(parts), Host::Name(name)) => {
                glob_matches(parts, &name.to_ascii_lowercase())
            }
            (Matcher::Cidr(net, prefix), Host::Ip(ip)) => ip_in_cidr(ip, net, *prefix),
            _ => false,
        }
    }
}

/// Compare `value` à un motif déjà découpé sur les `*`.
fn glob_matches(parts: &[String], value: &str) -> bool {
    if parts.len() == 1 {
        return parts[0] == value;
    }
    let mut rest = value;
    // Les fragments de tête et de queue sont ancrés ; ceux du milieu flottent.
    let (first, middle) = parts.split_first().expect("non-empty");
    if !rest.starts_with(first.as_str()) {
        return false;
    }
    rest = &rest[first.len()..];
    let (last, middle) = middle.split_last().expect("at least two parts");
    for fragment in middle {
        if fragment.is_empty() {
            continue;
        }
        match rest.find(fragment.as_str()) {
            Some(idx) => rest = &rest[idx + fragment.len()..],
            None => return false,
        }
    }
    rest.len() >= last.len() && rest.ends_with(last.as_str())
}

/// Analyse `10.0.0.0/8` ou `fd00::/8` en une adresse et une longueur de préfixe.
pub fn parse_cidr(pattern: &str) -> Result<(IpAddr, u8)> {
    let (addr, prefix) = pattern
        .split_once('/')
        .ok_or_else(|| anyhow!("`/préfixe` manquant"))?;
    let ip: IpAddr = addr
        .trim()
        .parse()
        .map_err(|_| anyhow!("`{}` n'est pas une adresse IP", addr))?;
    let prefix: u8 = prefix
        .trim()
        .parse()
        .map_err(|_| anyhow!("`{}` n'est pas une longueur de préfixe", prefix))?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        bail!(
            "le préfixe /{} est hors bornes pour cette famille d'adresses",
            prefix
        );
    }
    Ok((ip, prefix))
}

fn ip_in_cidr(ip: &IpAddr, net: &IpAddr, prefix: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => bits_match(&ip.octets(), &net.octets(), prefix),
        (IpAddr::V6(ip), IpAddr::V6(net)) => bits_match(&ip.octets(), &net.octets(), prefix),
        _ => false,
    }
}

fn bits_match(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let full = (prefix / 8) as usize;
    if a[..full] != b[..full] {
        return false;
    }
    let remainder = prefix % 8;
    if remainder == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - remainder);
    a[full] & mask == b[full] & mask
}

/// Adresses qui ne doivent jamais être joignables à travers la passerelle.
pub fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.octets()[0] == 0
                // 100.64.0.0/10, NAT de niveau opérateur
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
                // 198.18.0.0/15, plage de tests de performance
                || (v4.octets()[0] == 198 && (18..20).contains(&v4.octets()[1]))
                || v4.octets()[0] >= 224
                || *v4 == Ipv4Addr::UNSPECIFIED
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || *v6 == Ipv6Addr::UNSPECIFIED
                // fc00::/7, adresses locales uniques
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // fe80::/10, lien-local
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // ff00::/8, multicast
                || (v6.segments()[0] & 0xff00) == 0xff00
                // ::ffff:0:0/96, IPv4 encapsulée, revérifiée en tant qu'IPv4
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| is_private(&IpAddr::V4(v4)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn router() -> (Router, Vec<Backend>) {
        let cfg = Config::default();
        (Router::from_config(&cfg), cfg.backends.clone())
    }

    #[test]
    fn onion_goes_to_tor_and_i2p_goes_to_i2p() {
        let (router, backends) = router();
        let onion = Target::new(
            "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
            443,
        );
        let decision = router.route(&onion, &backends);
        assert_eq!(decision.backend_id, "tor");
        assert_eq!(decision.verdict, Verdict::Allow);

        let i2p = Target::new("stats.i2p", 80);
        assert_eq!(router.route(&i2p, &backends).backend_id, "i2p");
    }

    #[test]
    fn clearnet_falls_through_to_the_default_backend() {
        let (router, backends) = router();
        let decision = router.route(&Target::new("example.com", 443), &backends);
        assert_eq!(decision.backend_id, "vpn");
        assert!(decision.matched_rule.is_none());
        assert_eq!(decision.verdict, Verdict::Allow);
    }

    #[test]
    fn matching_ignores_case() {
        let (router, backends) = router();
        assert_eq!(
            router
                .route(&Target::new("EXAMPLE.ONION", 443), &backends)
                .backend_id,
            "tor"
        );
    }

    #[test]
    fn a_trailing_dot_still_reaches_the_onion_rule() {
        let (router, backends) = router();
        // Un point final est légal dans un nom pleinement qualifié ; sans
        // normalisation, cette destination fuirait en clair.
        let decision = router.route(&Target::new("exemple.onion.", 443), &backends);
        assert_eq!(decision.backend_id, "tor");
        assert_eq!(decision.matched_rule.as_deref(), Some("onion"));
        assert_eq!(
            router
                .route(&Target::new("stats.i2p.", 80), &backends)
                .backend_id,
            "i2p"
        );
    }

    #[test]
    fn the_bare_ip_guard_follows_the_backend_property_not_its_id() {
        let mut cfg = Config::default();
        // Le backend Tor est renommé : la protection doit suivre la propriété
        // déclarée, pas l'identifiant.
        cfg.backends[0].id = "reseau-cache".into();
        cfg.routing.rules[0].backend = "reseau-cache".into();
        cfg.routing.rules.push(Rule {
            id: "ip-directe".into(),
            match_type: MatchType::Cidr,
            pattern: "1.1.1.0/24".into(),
            backend: "reseau-cache".into(),
            enabled: true,
            note: None,
        });
        let router = Router::from_config(&cfg);
        assert_eq!(
            router
                .route(&Target::new("1.1.1.1", 443), &cfg.backends)
                .verdict,
            Verdict::Deny(DenyReason::BareIpOnHiddenBackend)
        );

        // À l'inverse, un backend qui accepte les IP n'est pas entravé.
        assert_eq!(
            router
                .route(&Target::new("1.0.0.1", 443), &cfg.backends)
                .verdict,
            Verdict::Allow
        );
    }

    #[test]
    fn a_hostname_merely_containing_onion_is_not_tor() {
        let (router, backends) = router();
        assert_eq!(
            router
                .route(&Target::new("onion.example.com", 443), &backends)
                .backend_id,
            "vpn"
        );
    }

    #[test]
    fn private_destinations_are_refused() {
        let (router, backends) = router();
        let decision = router.route(&Target::new("192.168.1.10", 80), &backends);
        assert_eq!(decision.verdict, Verdict::Deny(DenyReason::PrivateAddress));
    }

    #[test]
    fn bare_ip_is_refused_on_hidden_backends() {
        #[allow(clippy::field_reassign_with_default)]
        let mut cfg = Config::default();
        cfg.routing.rules.push(Rule {
            id: "ip-to-tor".into(),
            match_type: MatchType::Cidr,
            pattern: "1.1.1.0/24".into(),
            backend: "tor".into(),
            enabled: true,
            note: None,
        });
        let router = Router::from_config(&cfg);
        let decision = router.route(&Target::new("1.1.1.1", 443), &cfg.backends);
        assert_eq!(decision.backend_id, "tor");
        assert_eq!(
            decision.verdict,
            Verdict::Deny(DenyReason::BareIpOnHiddenBackend)
        );
    }

    #[test]
    fn disabled_rules_are_skipped() {
        let mut cfg = Config::default();
        cfg.routing.rules[0].enabled = false;
        let router = Router::from_config(&cfg);
        assert_eq!(
            router
                .route(&Target::new("x.onion", 80), &cfg.backends)
                .backend_id,
            "vpn"
        );
    }

    #[test]
    fn wildcard_rules_match_subdomains() {
        let mut cfg = Config::default();
        cfg.routing.rules.insert(
            0,
            Rule {
                id: "ddg".into(),
                match_type: MatchType::Wildcard,
                pattern: "*.duckduckgo.com".into(),
                backend: "tor".into(),
                enabled: true,
                note: None,
            },
        );
        let router = Router::from_config(&cfg);
        assert_eq!(
            router
                .route(&Target::new("html.duckduckgo.com", 443), &cfg.backends)
                .backend_id,
            "tor"
        );
        assert_eq!(
            router
                .route(&Target::new("duckduckgo.com.evil.net", 443), &cfg.backends)
                .backend_id,
            "vpn"
        );
    }

    #[test]
    fn cidr_rules_match_inside_the_prefix_only() {
        let (net, prefix) = parse_cidr("10.0.0.0/8").unwrap();
        assert!(ip_in_cidr(&"10.4.3.2".parse().unwrap(), &net, prefix));
        assert!(!ip_in_cidr(&"11.0.0.1".parse().unwrap(), &net, prefix));

        let (net, prefix) = parse_cidr("192.168.4.0/22").unwrap();
        assert!(ip_in_cidr(&"192.168.7.255".parse().unwrap(), &net, prefix));
        assert!(!ip_in_cidr(&"192.168.8.1".parse().unwrap(), &net, prefix));
    }

    #[test]
    fn private_ranges_cover_v4_and_v6() {
        for addr in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.0.1",
            "169.254.1.1",
            "100.100.0.1",
        ] {
            assert!(
                is_private(&addr.parse().unwrap()),
                "{addr} should be private"
            );
        }
        for addr in ["1.1.1.1", "8.8.8.8", "2606:4700::1111"] {
            assert!(
                !is_private(&addr.parse().unwrap()),
                "{addr} should be public"
            );
        }
        assert!(is_private(&"::1".parse().unwrap()));
        assert!(is_private(&"fd00::1".parse().unwrap()));
        assert!(is_private(&"::ffff:192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn target_display_brackets_ipv6() {
        assert_eq!(
            Target::new("2606:4700::1111", 443).to_string(),
            "[2606:4700::1111]:443"
        );
        assert_eq!(Target::new("example.com", 80).to_string(), "example.com:80");
    }
}
