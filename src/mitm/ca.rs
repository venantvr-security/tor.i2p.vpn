//! Autorité de certification locale de l'interception.
//!
//! Une seule CA, générée sur la passerelle et persistée à côté de la
//! configuration. Sa clé privée est le secret le plus sensible du produit :
//! quiconque l'obtient peut usurper n'importe quel site vis-à-vis des clients
//! qui l'ont installée. Elle ne quitte donc jamais le volume de données, et
//! seul le certificat public est proposé au téléchargement.
//!
//! ```mermaid
//! flowchart TD
//!     G[Génération unique] --> K[(ca-key.pem<br/>clé privée, 0600)]
//!     G --> C[(ca-cert.pem<br/>certificat public)]
//!     C -->|téléchargement| Nav[Navigateur / système<br/>racine de confiance]
//!     K --> F[Certificat feuille par hôte<br/>signé à la volée, mis en cache]
//! ```
//!
//! Les certificats feuilles sont forgés à la demande, un par nom d'hôte, puis
//! gardés en cache : reforger à chaque poignée de main coûterait cher sur un
//! Raspberry Pi.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use sha2::{Digest, Sha256};

/// Nom de la clé privée de la CA, déposée à côté de `config.toml`.
const CA_KEY_FILE: &str = "mitm-ca-key.pem";
/// Nom du certificat public de la CA.
const CA_CERT_FILE: &str = "mitm-ca-cert.pem";

/// Sujet de la CA, volontairement explicite dans l'interface d'un navigateur :
/// un utilisateur qui inspecte ses racines de confiance doit comprendre d'un
/// coup d'œil ce que c'est et d'où ça vient.
const CA_COMMON_NAME: &str = "Passerelle Tor/I2P — interception locale";
const CA_ORG: &str = "tiv-gateway";

/// La CA vivante : de quoi forger et signer des feuilles, plus le certificat
/// public tel qu'il a été persisté (pour le téléchargement et l'empreinte).
pub struct LocalCa {
    /// Émetteur reconstruit à chaque chargement à partir de la clé persistée.
    /// Son propre DER n'est jamais transmis : on ne présente au client que la
    /// feuille, qu'il valide contre la CA qu'il a installée.
    issuer: Certificate,
    key: KeyPair,
    /// Certificat public canonique, celui du fichier, servi au téléchargement.
    cert_pem: String,
    fingerprint: String,
    /// Configurations TLS serveur déjà bâties, une par nom d'hôte.
    leaves: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl LocalCa {
    /// Charge la CA du disque, ou la crée si elle n'existe pas encore.
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        let key_path = dir.join(CA_KEY_FILE);
        let cert_path = dir.join(CA_CERT_FILE);

        if key_path.exists() && cert_path.exists() {
            let key_pem = std::fs::read_to_string(&key_path)
                .with_context(|| format!("lecture de {}", key_path.display()))?;
            let cert_pem = std::fs::read_to_string(&cert_path)
                .with_context(|| format!("lecture de {}", cert_path.display()))?;
            let key = KeyPair::from_pem(&key_pem).context("clé de CA illisible")?;
            // L'émetteur est reconstruit par le même chemin de code : même sujet,
            // même clé, donc même identifiant de clé. Les feuilles qu'il signe
            // chaînent vers le certificat déjà installé côté client. Le certificat
            // canonique reste celui du fichier, pour la stabilité de l'empreinte.
            let issuer = ca_params()?.self_signed(&key)?;
            let fingerprint = fingerprint_of(&cert_pem)?;
            return Ok(Self::assemble(issuer, key, cert_pem, fingerprint));
        }

        // Sinon, création : la clé d'abord (0600), puis le certificat public.
        Self::generate(dir)
    }

    /// (Re)génère la CA, en écrasant l'ancienne. Toute racine déjà installée
    /// côté client cesse alors d'être reconnue : c'est une rupture assumée.
    pub fn generate(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir).with_context(|| format!("création de {}", dir.display()))?;
        let key = KeyPair::generate().context("génération de la clé de CA")?;
        let issuer = ca_params()?.self_signed(&key)?;
        let cert_pem = issuer.pem();
        let key_pem = key.serialize_pem();

        let key_path = dir.join(CA_KEY_FILE);
        write_private(&key_path, &key_pem)
            .with_context(|| format!("écriture de {}", key_path.display()))?;
        let cert_path = dir.join(CA_CERT_FILE);
        std::fs::write(&cert_path, &cert_pem)
            .with_context(|| format!("écriture de {}", cert_path.display()))?;

        let fingerprint = fingerprint_of(&cert_pem)?;
        Ok(Self::assemble(issuer, key, cert_pem, fingerprint))
    }

    fn assemble(issuer: Certificate, key: KeyPair, cert_pem: String, fingerprint: String) -> Self {
        LocalCa {
            issuer,
            key,
            cert_pem,
            fingerprint,
            leaves: Mutex::new(HashMap::new()),
        }
    }

    /// Certificat public de la CA, au format PEM, pour le téléchargement.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Empreinte SHA-256 du certificat public, en hexadécimal deux-points.
    ///
    /// C'est ce que l'utilisateur compare à ce qu'affiche son navigateur après
    /// installation : la seule preuve que la racine installée est bien la nôtre.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Renvoie une configuration TLS serveur pour `host`, forgée puis mise en
    /// cache. Le certificat feuille couvre exactement ce nom.
    pub fn server_config_for(&self, host: &str) -> Result<Arc<ServerConfig>> {
        let key = host.to_ascii_lowercase();
        if let Some(config) = self.leaves.lock().unwrap().get(&key).cloned() {
            return Ok(config);
        }
        let config = Arc::new(self.forge_leaf(&key)?);
        self.leaves.lock().unwrap().insert(key, Arc::clone(&config));
        Ok(config)
    }

    /// Forge un certificat feuille pour `host`, signé par la CA, et le monte
    /// dans une configuration TLS serveur qui ne négocie que HTTP/1.1.
    fn forge_leaf(&self, host: &str) -> Result<ServerConfig> {
        let mut params = CertificateParams::new(vec![host.to_string()])
            .context("paramètres du certificat feuille")?;
        params
            .distinguished_name
            .push(DnType::CommonName, host.to_string());
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];

        let leaf_key = KeyPair::generate().context("génération de la clé feuille")?;
        let leaf = params
            .signed_by(&leaf_key, &self.issuer, &self.key)
            .context("signature du certificat feuille par la CA")?;

        let cert_der = CertificateDer::from(leaf.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        // On ne présente que la feuille : le client a installé la CA comme racine
        // de confiance, il n'a pas besoin qu'on la lui renvoie dans la chaîne.
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .context("montage de la configuration TLS serveur")?;
        // On force HTTP/1.1 : c'est le protocole que le pont sait analyser. Ne
        // pas annoncer h2 pousse les clients à retomber dessus d'eux-mêmes.
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(config)
    }
}

/// Paramètres canoniques de la CA, source unique de son sujet.
fn ca_params() -> Result<CertificateParams> {
    let mut params = CertificateParams::new(Vec::new()).context("paramètres de la CA")?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, CA_COMMON_NAME);
    dn.push(DnType::OrganizationName, CA_ORG);
    params.distinguished_name = dn;
    Ok(params)
}

/// Empreinte SHA-256 du corps DER d'un certificat PEM.
fn fingerprint_of(cert_pem: &str) -> Result<String> {
    let der = pem_to_der(cert_pem).context("décodage du certificat de la CA")?;
    let digest = Sha256::digest(&der);
    let hex = digest
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    Ok(hex)
}

/// Extrait le corps DER d'un bloc PEM `CERTIFICATE`.
fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .concat();
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .context("base64 du certificat")
}

/// Écrit un fichier de secret avec des droits restreints là où c'est possible.
fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(contents.as_bytes())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_dir(nom: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tiv-ca-{}-{nom}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_ca_is_created_then_reloaded_with_a_stable_fingerprint() {
        let dir = temp_dir("reload");
        let created = LocalCa::load_or_create(&dir).unwrap();
        let fp1 = created.fingerprint().to_string();
        let pem1 = created.cert_pem().to_string();
        assert!(pem1.contains("BEGIN CERTIFICATE"));
        assert_eq!(fp1.matches(':').count(), 31, "32 octets => 31 séparateurs");

        // Rechargée du disque, l'empreinte et le PEM public ne bougent pas.
        let reloaded = LocalCa::load_or_create(&dir).unwrap();
        assert_eq!(reloaded.fingerprint(), fp1);
        assert_eq!(reloaded.cert_pem(), pem1);
    }

    #[test]
    fn regeneration_changes_the_fingerprint() {
        let dir = temp_dir("regen");
        let before = LocalCa::load_or_create(&dir)
            .unwrap()
            .fingerprint()
            .to_string();
        let after = LocalCa::generate(&dir).unwrap().fingerprint().to_string();
        assert_ne!(before, after);
    }

    #[test]
    fn a_leaf_config_is_forged_and_cached_per_host() {
        let dir = temp_dir("leaf");
        let ca = LocalCa::load_or_create(&dir).unwrap();
        let a = ca.server_config_for("exemple.onion").unwrap();
        let a_again = ca.server_config_for("Exemple.Onion").unwrap();
        // Même hôte (casse ignorée) => même configuration en cache.
        assert!(Arc::ptr_eq(&a, &a_again));
        let b = ca.server_config_for("autre.i2p").unwrap();
        assert!(!Arc::ptr_eq(&a, &b));
        assert_eq!(a.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[cfg(unix)]
    #[test]
    fn the_private_key_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("perms");
        LocalCa::load_or_create(&dir).unwrap();
        let mode = std::fs::metadata(dir.join(CA_KEY_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "la clé de CA doit rester privée");
    }
}
