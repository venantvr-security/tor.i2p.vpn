/**
 * État partagé entre les vues : session, notifications et flux de métriques.
 *
 * Le flux SSE est ouvert une seule fois et compté par référence, de sorte que
 * plusieurs vues peuvent s'y abonner sans multiplier les connexions.
 */

import { reactive, readonly, ref } from 'vue'
import { api, ApiError } from './api.js'

export const session = reactive({
  authenticated: false,
  setupRequired: false,
  checked: false,
})

export async function refreshSession() {
  try {
    const info = await api.session()
    session.authenticated = info.authenticated
    session.setupRequired = info.setup_required
  } catch {
    // Passerelle injoignable : on garde l'utilisateur sur l'écran de connexion
    // plutôt que de prétendre qu'il est authentifié.
    session.authenticated = false
  } finally {
    session.checked = true
  }
}

export function markSignedIn() {
  session.authenticated = true
  session.setupRequired = false
  session.checked = true
}

export function markSignedOut() {
  session.authenticated = false
  stopMetricsStream(true)
}

// --- Notifications --------------------------------------------------------

const toastList = ref([])
let nextToastId = 1

export const toasts = readonly(toastList)

export function notify(message, kind = 'ok', ttl = 4500) {
  const id = nextToastId++
  toastList.value = [...toastList.value, { id, message, kind }]
  setTimeout(() => {
    toastList.value = toastList.value.filter((toast) => toast.id !== id)
  }, ttl)
}

/** Signale une erreur d'API, en déconnectant si la session a expiré. */
export function notifyError(error) {
  if (error instanceof ApiError && error.unauthorized) {
    markSignedOut()
    notify('session expirée, reconnectez-vous', 'error')
    return
  }
  notify(error?.message ?? 'erreur inattendue', 'error')
}

// --- Flux de métriques ----------------------------------------------------

export const live = reactive({
  connected: false,
  snapshot: null,
})

let source = null
let subscribers = 0

/** Ouvre le flux SSE si nécessaire et incrémente le compteur d'abonnés. */
export function startMetricsStream() {
  subscribers += 1
  if (source) return

  // Une première lecture immédiate évite un tableau de bord vide pendant la
  // période d'échantillonnage.
  api
    .metrics()
    .then((snapshot) => {
      live.snapshot = snapshot
    })
    .catch(() => {})

  source = new EventSource('/api/stream')
  source.addEventListener('open', () => {
    live.connected = true
  })
  source.addEventListener('metrics', (event) => {
    try {
      live.snapshot = JSON.parse(event.data)
      live.connected = true
    } catch {
      // Trame illisible : on garde la précédente plutôt que de vider l'affichage.
    }
  })
  source.addEventListener('error', () => {
    live.connected = false
  })
}

/** Décrémente le compteur d'abonnés et ferme le flux quand il tombe à zéro. */
export function stopMetricsStream(force = false) {
  subscribers = force ? 0 : Math.max(0, subscribers - 1)
  if (subscribers === 0 && source) {
    source.close()
    source = null
    live.connected = false
  }
}
