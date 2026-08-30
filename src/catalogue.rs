//! Journal des destinations traversées : une URL, son code HTTP, son titre.
//!
//! Volontairement pas de base SQL. Quelques milliers de lignes tiennent sans
//! peine dans un fichier en ajout seul doublé d'un index en mémoire ; SQLite ne
//! se justifierait qu'avec plusieurs écrivains concurrents ou des requêtes
//! complexes, et son amalgame C alourdirait la compilation croisée pour rien.
//!
//! Le journal est borné et se comporte en file : au-delà du plafond, la plus
//! ancienne ligne sort. Une URL revue remonte en tête au lieu d'être dupliquée,
//! si bien que le plafond compte des destinations distinctes, pas des visites.
//!
//! ```mermaid
//! flowchart LR
//!     V[Tunnel ouvert] --> U[visit: URL + horodatage]
//!     U --> F[(Journal FIFO borné)]
//!     D[Flux descendant] --> S{En clair ?}
//!     S -- "TLS / CONNECT" --> N[Rien à apprendre]
//!     S -- "HTTP/1.x" --> C[Code de statut]
//!     C --> T{text/html<br/>non compressé ?}
//!     T -- oui --> E[Titre de la page]
//!     T -- non --> N
//!     C --> F
//!     E --> F
//! ```
//!
//! **Ce journal est une trace de navigation.** Il est donc désactivé par
//! défaut : sur une passerelle dont le rôle est de protéger le trafic, écrire
//! sur disque la liste des services visités est un choix, pas un réglage anodin.

use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::metrics::now_ms;

/// Bornes du plafond de lignes, pour qu'un réglage aberrant ne fasse ni
/// disparaître le journal ni gonfler la mémoire.
pub const MIN_ENTRIES: usize = 10;
pub const MAX_ENTRIES: usize = 20_000;

/// Longueur maximale d'une URL retenue, pour ne pas stocker n'importe quoi.
const MAX_URL_LEN: usize = 512;
/// Longueur maximale d'un titre retenu.
const MAX_TITLE_LEN: usize = 300;

/// Une ligne du journal, telle qu'elle est écrite sur disque.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub url: String,
    /// Code de statut HTTP, absent lorsque le trafic était chiffré.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub titre: Option<String>,
    /// Dernier passage, en millisecondes depuis l'époque Unix.
    #[serde(default)]
    pub vu: u64,
}

impl Entry {
    /// Famille de réseau déduite du suffixe, pour classer l'affichage.
    ///
    /// La déduction porte sur le nom, pas sur le backend effectivement emprunté :
    /// une règle qui enverrait un domaine clearnet dans Tor resterait affichée
    /// « standard ». C'est le prix d'un journal à quatre colonnes plutôt qu'à
    /// cinq, et c'est bien la nature de la destination qui intéresse ici.
    pub fn reseau(&self) -> &'static str {
        famille(&self.url)
    }
}

/// Classe une URL par la nature de sa destination.
pub fn famille(url: &str) -> &'static str {
    let sans_scheme = url.split_once("://").map(|(_, reste)| reste).unwrap_or(url);
    let autorite = sans_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(sans_scheme);
    // Un `:` sans port derrière laisse l'autorité intacte ; une IPv6 entre
    // crochets ressort découpée n'importe comment, mais elle ne portera jamais
    // l'un de ces deux suffixes et retombera donc sur « standard ».
    let hote = autorite
        .rsplit_once(':')
        .map(|(hote, _)| hote)
        .unwrap_or(autorite)
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if hote.ends_with(".onion") {
        "tor"
    } else if hote.ends_with(".i2p") {
        "i2p"
    } else {
        "standard"
    }
}

pub struct Catalogue {
    path: PathBuf,
    /// Plafond de lignes, ajustable à chaud depuis l'interface.
    max_entries: AtomicUsize,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    records: HashMap<String, Record>,
    /// Rang d'ancienneté vers URL : la clé la plus basse est la plus ancienne,
    /// donc la première à sortir quand le plafond est atteint.
    order: BTreeMap<u64, String>,
    next_seq: u64,
    /// Lignes présentes dans le fichier, pour décider d'un compactage.
    lines: usize,
}

#[derive(Clone)]
struct Record {
    seq: u64,
    code: Option<u16>,
    titre: Option<String>,
    vu: u64,
}

impl Inner {
    /// Note un passage : nouvelle entrée, ou remontée en tête de la file.
    fn visit(&mut self, url: String, vu: u64) {
        if let Some(record) = self.records.get_mut(&url) {
            let ancien = record.seq;
            record.seq = self.next_seq;
            record.vu = vu;
            self.order.remove(&ancien);
        } else {
            self.records.insert(
                url.clone(),
                Record {
                    seq: self.next_seq,
                    code: None,
                    titre: None,
                    vu,
                },
            );
        }
        self.order.insert(self.next_seq, url);
        self.next_seq += 1;
    }

    /// Complète une entrée déjà connue. Renvoie `true` s'il y a du neuf.
    fn observe(&mut self, url: &str, code: Option<u16>, titre: Option<String>) -> bool {
        let Some(record) = self.records.get_mut(url) else {
            return false;
        };
        let mut change = false;
        if code.is_some() && record.code != code {
            record.code = code;
            change = true;
        }
        if titre.is_some() && record.titre != titre {
            record.titre = titre;
            change = true;
        }
        change
    }

    /// Ramène la file sous son plafond. Renvoie `true` si quelque chose est sorti.
    fn evict(&mut self, max: usize) -> bool {
        let mut sorti = false;
        while self.records.len() > max {
            let Some((&seq, url)) = self.order.iter().next() else {
                break;
            };
            let url = url.clone();
            self.order.remove(&seq);
            self.records.remove(&url);
            sorti = true;
        }
        sorti
    }

    fn entry(&self, url: &str) -> Option<Entry> {
        let record = self.records.get(url)?;
        Some(Entry {
            url: url.to_string(),
            code: record.code,
            titre: record.titre.clone(),
            vu: record.vu,
        })
    }

    /// Toutes les entrées, de la plus ancienne à la plus récente.
    fn snapshot(&self) -> Vec<Entry> {
        self.order
            .values()
            .filter_map(|url| self.entry(url))
            .collect()
    }
}

impl Catalogue {
    /// Charge le journal depuis son fichier, en ignorant les lignes illisibles.
    ///
    /// Le plafond est réappliqué à la relecture : un fichier qui contiendrait
    /// encore des lignes évincées avant un compactage ne les ressuscite pas.
    pub fn load(path: &Path, max_entries: usize) -> Self {
        let max = clamp_entries(max_entries);
        let mut inner = Inner::default();
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                for line in contents.lines().filter(|l| !l.trim().is_empty()) {
                    inner.lines += 1;
                    match serde_json::from_str::<Entry>(line) {
                        // La dernière ligne portant une URL l'emporte : c'est
                        // ainsi qu'un titre découvert plus tard écrase l'absence
                        // de titre notée à l'ouverture du tunnel.
                        Ok(entry) => {
                            let Entry {
                                url,
                                code,
                                titre,
                                vu,
                            } = entry;
                            inner.visit(url.clone(), vu);
                            inner.observe(&url, code, titre);
                        }
                        Err(err) => debug!(%err, "ligne de journal ignorée"),
                    }
                }
                inner.evict(max);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => warn!(%err, path = %path.display(), "journal illisible"),
        }
        Catalogue {
            path: path.to_path_buf(),
            max_entries: AtomicUsize::new(max),
            inner: Mutex::new(inner),
        }
    }

    pub fn max_entries(&self) -> usize {
        self.max_entries.load(Ordering::Relaxed)
    }

    /// Ajuste le plafond à chaud et rogne immédiatement le surplus.
    pub fn set_max_entries(&self, max_entries: usize) {
        let max = clamp_entries(max_entries);
        if self.max_entries.swap(max, Ordering::Relaxed) == max {
            return;
        }
        let mut guard = self.lock();
        if guard.evict(max) {
            let snapshot = guard.snapshot();
            drop(guard);
            self.persist(Written::Whole(snapshot));
        }
    }

    /// Note l'ouverture d'un tunnel vers `url`.
    pub fn visit(&self, url: &str) {
        let url = truncate(url, MAX_URL_LEN);
        if url.is_empty() {
            return;
        }
        let max = self.max_entries();
        let mut guard = self.lock();
        guard.visit(url.clone(), now_ms());
        let evince = guard.evict(max);
        let written = self.plan(&mut guard, &url, evince);
        drop(guard);
        self.persist(written);
    }

    /// Enrichit une entrée d'un code de statut ou d'un titre découverts en route.
    pub fn observe(&self, url: &str, code: Option<u16>, titre: Option<String>) {
        let url = truncate(url, MAX_URL_LEN);
        let titre = titre
            .map(|t| truncate(&t, MAX_TITLE_LEN))
            .filter(|t| !t.is_empty());
        if code.is_none() && titre.is_none() {
            return;
        }
        let mut guard = self.lock();
        if !guard.observe(&url, code, titre) {
            return;
        }
        let written = self.plan(&mut guard, &url, false);
        drop(guard);
        self.persist(written);
    }

    /// Décide entre l'ajout d'une ligne et une réécriture complète.
    ///
    /// Une éviction impose la réécriture : sans elle le fichier grossirait de
    /// destinations que le journal ne montre plus.
    fn plan(&self, guard: &mut Inner, url: &str, evince: bool) -> Written {
        let compacter = evince || guard.lines > guard.records.len() * 2 + 64;
        if compacter {
            let snapshot = guard.snapshot();
            guard.lines = snapshot.len();
            Written::Whole(snapshot)
        } else {
            guard.lines += 1;
            match guard.entry(url) {
                Some(entry) => Written::One(entry),
                None => Written::Nothing,
            }
        }
    }

    fn persist(&self, written: Written) {
        let outcome = match written {
            Written::Nothing => Ok(()),
            Written::One(entry) => self.append(&entry),
            Written::Whole(entries) => self.rewrite(&entries),
        };
        if let Err(err) = outcome {
            warn!(%err, "journal non enregistré");
        }
    }

    fn append(&self, entry: &Entry) -> Result<()> {
        self.ensure_dir();
        let mut line = serde_json::to_string(entry).context("sérialisation d'une entrée")?;
        line.push('\n');
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("ouverture de {}", self.path.display()))?;
        file.write_all(line.as_bytes())
            .with_context(|| format!("écriture dans {}", self.path.display()))
    }

    /// Réécrit le fichier à partir de l'index, via un temporaire renommé.
    fn rewrite(&self, entries: &[Entry]) -> Result<()> {
        self.ensure_dir();
        let mut body = String::new();
        for entry in entries {
            body.push_str(&serde_json::to_string(entry).context("sérialisation")?);
            body.push('\n');
        }
        let tmp = self
            .path
            .with_extension(format!("jsonl.{}.tmp", std::process::id()));
        std::fs::write(&tmp, body).with_context(|| format!("écriture de {}", tmp.display()))?;
        if let Err(err) = std::fs::rename(&tmp, &self.path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(err).with_context(|| format!("remplacement de {}", self.path.display()));
        }
        Ok(())
    }

    fn ensure_dir(&self) {
        if let Some(dir) = self.path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
    }

    /// Toutes les entrées, de la plus récente à la plus ancienne.
    pub fn entries(&self) -> Vec<Entry> {
        let mut entries = self.lock().snapshot();
        entries.reverse();
        entries
    }

    /// Vide le journal, fichier compris.
    pub fn purge(&self) -> Result<()> {
        {
            let mut guard = self.lock();
            *guard = Inner::default();
        }
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err).with_context(|| format!("suppression de {}", self.path.display())),
        }
    }

    /// Un verrou empoisonné ne doit pas faire tomber le plan de données : le
    /// journal est un agrément, jamais une raison de couper un tunnel.
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|err| err.into_inner())
    }
}

/// Ce qu'il reste à écrire sur disque, une fois le verrou relâché.
enum Written {
    Nothing,
    One(Entry),
    Whole(Vec<Entry>),
}

pub fn clamp_entries(value: usize) -> usize {
    value.clamp(MIN_ENTRIES, MAX_ENTRIES)
}

/// Tronque sur une frontière de caractère, jamais au milieu d'un octet UTF-8.
fn truncate(value: &str, limit: usize) -> String {
    let value = value.trim();
    match value.char_indices().nth(limit) {
        Some((cut, _)) => value[..cut].to_string(),
        None => value.to_string(),
    }
}

/// Forme l'URL retenue pour une destination.
///
/// Le proxy HTTP connaît l'URL complète ; en SOCKS5 on ne dispose que de l'hôte
/// et du port, d'où une origine reconstruite.
pub fn url_for(host: &str, port: u16, full_url: Option<&str>) -> String {
    if let Some(url) = full_url {
        return strip_userinfo(url);
    }
    match port {
        80 => format!("http://{host}/"),
        443 => format!("https://{host}/"),
        other => format!("{host}:{other}"),
    }
}

/// Retire le `utilisateur:motdepasse@` d'une URL.
///
/// Un identifiant glissé dans l'autorité n'a rien à faire dans un fichier
/// conservé sur disque : on l'écarte au seul endroit par lequel toutes les URL
/// entrent dans le journal.
fn strip_userinfo(url: &str) -> String {
    let Some((scheme, reste)) = url.split_once("://") else {
        return url.to_string();
    };
    let coupe = reste.find(['/', '?', '#']).unwrap_or(reste.len());
    let (autorite, chemin) = reste.split_at(coupe);
    match autorite.rsplit_once('@') {
        Some((_, hote)) => format!("{scheme}://{hote}{chemin}"),
        None => url.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Observation du flux descendant
// ---------------------------------------------------------------------------

/// Taille maximale examinée dans une réponse avant d'abandonner.
const SNIFF_LIMIT: usize = 64 * 1024;

/// Ce qu'une réponse a livré : un code de statut, puis éventuellement un titre.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Found {
    pub code: Option<u16>,
    pub titre: Option<String>,
}

/// Lit le début d'une réponse HTTP en clair pour en tirer le code et le titre.
///
/// L'analyse s'arrête immédiatement si les premiers octets ne sont pas ceux
/// d'une réponse HTTP : du TLS n'est jamais inspecté au-delà de sa première
/// poignée de main. Une réponse compressée est abandonnée telle quelle, faute
/// de la décompresser, mais son code de statut a déjà été relevé.
pub struct ResponseSniffer {
    buffer: Vec<u8>,
    fini: bool,
    code_emis: bool,
    veut_titre: bool,
}

impl ResponseSniffer {
    pub fn new(veut_titre: bool) -> Self {
        ResponseSniffer {
            buffer: Vec::new(),
            fini: false,
            code_emis: false,
            veut_titre,
        }
    }

    /// Consomme un morceau de réponse et signale ce qu'il aura appris.
    pub fn feed(&mut self, chunk: &[u8]) -> Option<Found> {
        if self.fini {
            return None;
        }
        self.buffer.extend_from_slice(chunk);

        // Premier verdict : est-ce seulement du HTTP en clair ?
        if self.buffer.len() < 8 {
            return None;
        }
        if !self.buffer.starts_with(b"HTTP/1.") {
            self.abandon();
            return None;
        }

        let texte = String::from_utf8_lossy(&self.buffer);
        let mut trouve = Found::default();

        if !self.code_emis {
            let Some(ligne) = texte.split("\r\n").next().filter(|l| l.len() < texte.len()) else {
                // La ligne de statut n'est pas encore complète.
                return None;
            };
            trouve.code = parse_status(ligne);
            self.code_emis = true;
            // Sans titre à chercher, il n'y a plus rien à apprendre de ce flux.
            if !self.veut_titre {
                self.abandon();
                return Some(trouve);
            }
        }

        // Une réponse compressée ne livrera pas son titre sans décompression,
        // que l'on ne fait pas : inutile de continuer à l'accumuler. Idem pour
        // un corps qui n'est pas du HTML.
        //
        // Le verdict attend la ligne vide qui clôt les en-têtes : jugé sur un
        // bloc tronqué, un `Content-Type: text/` coupé en plein milieu se
        // lirait comme « pas du HTML » et ferait tout abandonner à tort.
        if let Some((entete, _)) = texte.split_once("\r\n\r\n") {
            let bas = entete.to_ascii_lowercase();
            let compresse =
                bas.contains("content-encoding:") && !bas.contains("content-encoding: identity");
            let pas_html = bas.contains("content-type:") && !bas.contains("text/html");
            if compresse || pas_html {
                self.abandon();
                return trouve.into_option();
            }
        }

        if let Some(titre) = extract_title(&texte) {
            trouve.titre = Some(titre);
            self.abandon();
            return trouve.into_option();
        }
        if self.buffer.len() >= SNIFF_LIMIT {
            self.abandon();
        }
        trouve.into_option()
    }

    fn abandon(&mut self) {
        self.fini = true;
        self.buffer = Vec::new();
    }

    pub fn actif(&self) -> bool {
        !self.fini
    }
}

impl Found {
    fn into_option(self) -> Option<Found> {
        (self.code.is_some() || self.titre.is_some()).then_some(self)
    }
}

/// Extrait le code d'une ligne de statut `HTTP/1.1 200 OK`.
fn parse_status(ligne: &str) -> Option<u16> {
    ligne
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .filter(|code| (100..=599).contains(code))
}

/// Extrait le contenu de la première balise `<title>`.
pub fn extract_title(texte: &str) -> Option<String> {
    let bas = texte.to_ascii_lowercase();
    let ouverture = bas.find("<title")?;
    // La balise peut porter des attributs : on saute jusqu'au `>`.
    let debut = ouverture + bas[ouverture..].find('>')? + 1;
    let fin = debut + bas[debut..].find("</title")?;
    let brut = &texte[debut..fin];

    let titre = decode_entities(brut);
    let titre = titre.split_whitespace().collect::<Vec<_>>().join(" ");
    (!titre.is_empty()).then(|| truncate(&titre, MAX_TITLE_LEN))
}

/// Décode les quelques entités HTML qui apparaissent réellement dans un titre.
fn decode_entities(value: &str) -> String {
    value
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&nbsp;", " ")
}

/// Branche le renifleur sur le flux descendant d'un tunnel donné.
pub struct ResponseWatch {
    catalogue: Arc<Catalogue>,
    url: String,
    sniffer: ResponseSniffer,
}

impl ResponseWatch {
    pub fn new(catalogue: Arc<Catalogue>, url: String, capture_titles: bool) -> Self {
        ResponseWatch {
            catalogue,
            url,
            sniffer: ResponseSniffer::new(capture_titles),
        }
    }

    pub fn actif(&self) -> bool {
        self.sniffer.actif()
    }

    pub fn observe(&mut self, chunk: &[u8]) {
        if let Some(found) = self.sniffer.feed(chunk) {
            self.catalogue.observe(&self.url, found.code, found.titre);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(nom: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tiv-cat-{}-{nom}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("catalogue.jsonl");
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn an_entry_survives_a_reload() {
        let path = temp_path("reload");

        let catalogue = Catalogue::load(&path, 100);
        catalogue.visit("http://exemple.onion/");
        catalogue.observe("http://exemple.onion/", Some(200), Some("Exemple".into()));

        let relu = Catalogue::load(&path, 100);
        let entries = relu.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].url, "http://exemple.onion/");
        assert_eq!(entries[0].code, Some(200));
        assert_eq!(entries[0].titre.as_deref(), Some("Exemple"));
        assert!(entries[0].vu > 0);
    }

    #[test]
    fn a_known_url_is_enriched_rather_than_duplicated() {
        let path = temp_path("dedup");
        let catalogue = Catalogue::load(&path, 100);

        catalogue.visit("http://a.onion/");
        catalogue.observe("http://a.onion/", Some(200), Some("A".into()));
        catalogue.visit("http://a.onion/");
        // Une nouvelle visite n'efface ni le code ni le titre déjà connus.
        assert_eq!(catalogue.entries().len(), 1);
        assert_eq!(catalogue.entries()[0].titre.as_deref(), Some("A"));
        assert_eq!(catalogue.entries()[0].code, Some(200));
    }

    #[test]
    fn the_oldest_line_leaves_first_when_the_ceiling_is_reached() {
        let path = temp_path("fifo");
        let catalogue = Catalogue::load(&path, MIN_ENTRIES);
        for i in 0..(MIN_ENTRIES + 5) {
            catalogue.visit(&format!("http://s{i}.onion/"));
        }
        assert_eq!(catalogue.entries().len(), MIN_ENTRIES);

        let urls: Vec<String> = catalogue.entries().into_iter().map(|e| e.url).collect();
        // La plus récente d'abord, et les cinq premières sont sorties.
        assert_eq!(urls[0], format!("http://s{}.onion/", MIN_ENTRIES + 4));
        assert!(!urls.contains(&"http://s0.onion/".to_string()));

        // Le fichier ne doit pas ressusciter les évincées à la relecture.
        assert_eq!(
            Catalogue::load(&path, MIN_ENTRIES).entries().len(),
            MIN_ENTRIES
        );
    }

    #[test]
    fn revisiting_a_url_saves_it_from_eviction() {
        let path = temp_path("remontee");
        let catalogue = Catalogue::load(&path, MIN_ENTRIES);
        catalogue.visit("http://vieux.onion/");
        for i in 0..(MIN_ENTRIES - 1) {
            catalogue.visit(&format!("http://s{i}.onion/"));
        }
        // Revue juste avant le débordement, elle remonte en tête de file.
        catalogue.visit("http://vieux.onion/");
        for i in 0..5 {
            catalogue.visit(&format!("http://neuf{i}.onion/"));
        }
        let urls: Vec<String> = catalogue.entries().into_iter().map(|e| e.url).collect();
        assert!(urls.contains(&"http://vieux.onion/".to_string()));
        assert!(!urls.contains(&"http://s0.onion/".to_string()));
    }

    #[test]
    fn lowering_the_ceiling_trims_the_journal_at_once() {
        let path = temp_path("plafond-chaud");
        let catalogue = Catalogue::load(&path, 100);
        for i in 0..40 {
            catalogue.visit(&format!("http://s{i}.onion/"));
        }
        catalogue.set_max_entries(MIN_ENTRIES);
        assert_eq!(catalogue.entries().len(), MIN_ENTRIES);
        assert_eq!(
            Catalogue::load(&path, MIN_ENTRIES).entries().len(),
            MIN_ENTRIES
        );
        // Un plafond aberrant est ramené dans les bornes.
        catalogue.set_max_entries(0);
        assert_eq!(catalogue.max_entries(), MIN_ENTRIES);
    }

    #[test]
    fn purging_empties_the_file_too() {
        let path = temp_path("purge");
        let catalogue = Catalogue::load(&path, 100);
        catalogue.visit("http://a.onion/");
        catalogue.purge().unwrap();
        assert!(catalogue.entries().is_empty());
        assert!(!path.exists());
        assert!(Catalogue::load(&path, 100).entries().is_empty());
    }

    #[test]
    fn the_file_is_compacted_instead_of_growing_forever() {
        let path = temp_path("compactage");
        let catalogue = Catalogue::load(&path, 100);
        for _ in 0..500 {
            catalogue.visit("http://boucle.onion/");
        }
        let lines = std::fs::read_to_string(&path).unwrap().lines().count();
        assert!(lines < 200, "{lines} lignes pour une seule destination");
    }

    #[test]
    fn urls_are_rebuilt_from_host_and_port_when_unknown() {
        assert_eq!(url_for("a.onion", 80, None), "http://a.onion/");
        assert_eq!(url_for("a.onion", 443, None), "https://a.onion/");
        assert_eq!(url_for("a.onion", 8080, None), "a.onion:8080");
        assert_eq!(
            url_for("a.onion", 80, Some("http://a.onion/page?x=1")),
            "http://a.onion/page?x=1"
        );
    }

    #[test]
    fn credentials_never_reach_the_journal() {
        assert_eq!(
            url_for("a.onion", 80, Some("http://pi:secret@a.onion/page")),
            "http://a.onion/page"
        );
        assert_eq!(
            url_for("a.onion", 80, Some("http://a.onion/@ailleurs")),
            "http://a.onion/@ailleurs"
        );
    }

    #[test]
    fn destinations_are_classified_by_suffix() {
        assert_eq!(famille("http://exemple.onion/page"), "tor");
        assert_eq!(famille("https://stats.i2p"), "i2p");
        assert_eq!(famille("exemple.onion:8080"), "tor");
        assert_eq!(famille("https://example.com/onion"), "standard");
        assert_eq!(famille("https://onion.example.com/"), "standard");
    }

    #[test]
    fn a_title_is_extracted_and_normalised() {
        assert_eq!(
            extract_title("<html><head><title>  Mon  site\n\tcaché </title>").as_deref(),
            Some("Mon site caché")
        );
        assert_eq!(
            extract_title("<TITLE lang=\"fr\">Caf&eacute; &amp; Th&#39;</TITLE>").as_deref(),
            Some("Caf&eacute; & Th'")
        );
        assert_eq!(extract_title("<html>sans titre</html>"), None);
        assert_eq!(extract_title("<title></title>"), None);
    }

    #[test]
    fn the_sniffer_reports_the_status_code_then_the_title() {
        let mut sniffer = ResponseSniffer::new(true);
        assert_eq!(
            sniffer.feed(b"HTTP/1.1 404 Not Found\r\nContent-Type: text/"),
            Some(Found {
                code: Some(404),
                titre: None
            })
        );
        assert_eq!(sniffer.feed(b"html\r\n\r\n<html><head><ti"), None);
        assert_eq!(
            sniffer.feed(b"tle>Service cach\xc3\xa9</title>"),
            Some(Found {
                code: None,
                titre: Some("Service caché".into())
            })
        );
        assert!(!sniffer.actif());
    }

    #[test]
    fn the_status_code_is_still_read_without_title_capture() {
        let mut sniffer = ResponseSniffer::new(false);
        assert_eq!(
            sniffer.feed(b"HTTP/1.0 301 Moved Permanently\r\nLocation: /ailleurs\r\n\r\n"),
            Some(Found {
                code: Some(301),
                titre: None
            })
        );
        // Sans titre à chercher, l'analyse s'arrête aussitôt le code relevé.
        assert!(!sniffer.actif());
    }

    #[test]
    fn the_sniffer_never_inspects_encrypted_traffic() {
        // Début d'une poignée de main TLS : ce n'est pas du HTTP en clair.
        let mut sniffer = ResponseSniffer::new(true);
        assert_eq!(
            sniffer.feed(&[0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01]),
            None
        );
        assert!(
            !sniffer.actif(),
            "l'analyse doit s'arrêter dès le premier verdict"
        );
    }

    #[test]
    fn a_compressed_or_non_html_response_still_yields_its_code() {
        let mut sniffer = ResponseSniffer::new(true);
        let found = sniffer
            .feed(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Type: text/html\r\n\r\n")
            .unwrap();
        assert_eq!(found.code, Some(200));
        assert_eq!(found.titre, None);
        assert!(!sniffer.actif());

        let mut sniffer = ResponseSniffer::new(true);
        let found = sniffer
            .feed(b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n")
            .unwrap();
        assert_eq!(found.code, Some(200));
        assert!(!sniffer.actif());
    }

    #[test]
    fn the_sniffer_gives_up_on_an_endless_body() {
        let mut sniffer = ResponseSniffer::new(true);
        sniffer.feed(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n");
        assert!(sniffer.actif());
        sniffer.feed(&vec![b'x'; SNIFF_LIMIT + 1]);
        assert!(!sniffer.actif(), "au-delà de la limite, on abandonne");
    }

    #[test]
    fn a_watch_files_what_it_learns_into_the_journal() {
        let path = temp_path("watch");
        let catalogue = Arc::new(Catalogue::load(&path, 100));
        catalogue.visit("http://a.onion/");

        let mut watch = ResponseWatch::new(Arc::clone(&catalogue), "http://a.onion/".into(), true);
        watch.observe(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<title>Ici</title>");
        assert!(!watch.actif());

        let entry = &catalogue.entries()[0];
        assert_eq!(entry.code, Some(200));
        assert_eq!(entry.titre.as_deref(), Some("Ici"));
    }
}
