/** Formatage des grandeurs affichées dans l'interface. */

const UNITS = ['o', 'Ko', 'Mo', 'Go', 'To']

/** Taille en octets, en base 1024. */
export function bytes(value) {
  if (!Number.isFinite(value) || value <= 0) return '0 o'
  let index = 0
  let scaled = value
  while (scaled >= 1024 && index < UNITS.length - 1) {
    scaled /= 1024
    index += 1
  }
  const digits = scaled < 10 && index > 0 ? 1 : 0
  return `${scaled.toFixed(digits)} ${UNITS[index]}`
}

/** Débit exprimé en octets par seconde. */
export function rate(value) {
  return `${bytes(value)}/s`
}

/** Durée en secondes, rendue sous forme compacte. */
export function duration(seconds) {
  if (!Number.isFinite(seconds) || seconds < 0) return '—'
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  if (days > 0) return `${days} j ${hours} h`
  if (hours > 0) return `${hours} h ${minutes} min`
  if (minutes > 0) return `${minutes} min ${Math.floor(seconds % 60)} s`
  return `${Math.floor(seconds)} s`
}

/** Durée en millisecondes. */
export function millis(value) {
  if (!Number.isFinite(value)) return '—'
  if (value < 1000) return `${Math.round(value)} ms`
  return `${(value / 1000).toFixed(1)} s`
}

/** Horodatage epoch en millisecondes, rendu en heure locale. */
export function clock(ms) {
  if (!ms) return '—'
  return new Date(ms).toLocaleTimeString('fr-FR', { hour12: false })
}

/** Horodatage complet, date et heure. */
export function stamp(ms) {
  if (!ms) return '—'
  return new Date(ms).toLocaleString('fr-FR', { hour12: false })
}

/** Nombre entier avec séparateurs de milliers. */
export function count(value) {
  return new Intl.NumberFormat('fr-FR').format(value ?? 0)
}

/**
 * Couleur d'un backend, attribuée dans l'ordre fixe des emplacements de la
 * palette catégorielle. Au-delà du huitième backend, on retombe sur une teinte
 * neutre plutôt que de recycler une couleur déjà employée.
 */
export function backendColor(index) {
  return index >= 0 && index < 8 ? `var(--series-${index + 1})` : 'var(--text-muted)'
}

/** Libellés des états de connexion. */
export const STATUS_LABELS = {
  active: 'en cours',
  closed: 'terminée',
  denied: 'refusée',
  failed: 'échec',
}

/** Libellés des types de backend. */
export const KIND_LABELS = {
  socks5: 'SOCKS5 amont',
  http_connect: 'HTTP CONNECT amont',
  direct: 'sortie directe',
  block: 'blocage',
}

/** Libellés des types de correspondance des règles. */
export const MATCH_LABELS = {
  suffix: 'suffixe',
  exact: 'exact',
  wildcard: 'joker',
  cidr: 'CIDR',
}
