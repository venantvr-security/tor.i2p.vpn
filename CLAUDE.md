# Conventions du dépôt

Passerelle proxy vers Tor et I2P écrite en Rust, avec une interface web Vue 3,
destinée à tourner en conteneur Docker sous CasaOS sur un Raspberry Pi.

Il n'existe pas de « backend VPN » : un VPN monté sur l'hôte est transparent
pour la passerelle, puisqu'il déplace la route par défaut du système. Ce sont
les sondes de santé, et non le routage, qui vérifient qu'il tient.

## Langue

- **Tous les commentaires sont en français, accents compris.** Cela vaut pour
  les commentaires de ligne, les commentaires de documentation `///` et `//!`,
  les blocs `<!-- -->` et les commentaires JavaScript et CSS.
- **Tout le texte destiné à un humain est en français accentué** : libellés de
  l'interface, messages d'erreur d'API, journaux, messages `bail!` et
  `#[error("…")]`, libellés `# HELP` de l'exposition Prometheus.
- **Les identifiants de code restent en anglais** : noms de types, de fonctions,
  de variables, de champs sérialisés, de routes d'API et de fichiers. Un
  identifiant technique qui apparaît dans un fichier TOML ou dans une URL reste
  en ASCII (`rule-3`, `backend-2`), jamais un mot français non accentué.
- Les noms de tests sont des phrases anglaises décrivant le comportement vérifié.

## Diagrammes

- **Les diagrammes sont écrits en mermaid**, jamais en ASCII art ni en image
  binaire. Ils vont dans un bloc ```mermaid``` du README, ou dans un bloc
  ```mermaid``` d'un commentaire de documentation `//!` en tête de module.
- Un diagramme sert à montrer un mécanisme réel : le routage par suffixe, la
  séquence d'établissement d'une connexion, les couches du déploiement. Pas de
  diagramme purement décoratif.

## Rust

- Édition 2021. `cargo clippy --all-targets` doit rester silencieux.
- Chaque module commence par un `//!` qui explique son rôle et, quand c'est
  utile, la décision de conception qui le structure.
- Les commentaires expliquent le *pourquoi* — la contrainte, le risque de fuite,
  la raison d'un garde-fou — pas ce que le code dit déjà.
- Les tests unitaires vivent dans un `mod tests` en fin de fichier. Chaque
  comportement de sécurité (refus d'IP privée, IP brute sur Tor, limitation des
  tentatives de connexion) est couvert par un test.
- Le plan de données ne doit jamais bloquer : la configuration est lue derrière
  un `ArcSwap`, les compteurs sont atomiques.

## Interface web

- Vue 3 en `<script setup>`, JavaScript sans TypeScript, sans gestionnaire
  d'état externe. Le build doit rester rapide sur ARM.
- Les couleurs passent exclusivement par les jetons CSS de `styles.css`. Le
  thème sombre est défini deux fois — sous `prefers-color-scheme` et sous
  `[data-theme="dark"]` — pour que le choix explicite l'emporte.
- Les graphiques sont du SVG écrit à la main, sans bibliothèque : un Raspberry
  Pi sert ces fichiers. La palette catégorielle est attribuée dans un ordre fixe
  et jamais recyclée ; une couleur suit toujours une entité, jamais son rang.
- Toute identité portée par une couleur est doublée d'une étiquette texte.

## Sécurité

- L'interface d'administration n'est jamais accessible sans mot de passe : au
  premier démarrage elle n'expose que l'écran d'initialisation.
- Les secrets ne sortent jamais de l'API : `Config::redacted` les remplace par
  `***`, et `unredact_from` les réinjecte à l'enregistrement.
- Toute comparaison de secret se fait en temps constant.
- En cas de doute sur une destination, on refuse : bloquer vaut mieux que
  laisser fuiter.
