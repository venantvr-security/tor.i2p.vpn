/**
 * Client de l'API d'administration.
 *
 * Toutes les requêtes portent le cookie de session ; un 401 rejette une erreur
 * marquée `unauthorized`, que le routeur transforme en redirection vers l'écran
 * de connexion.
 */

export class ApiError extends Error {
  constructor(message, status, payload) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.payload = payload ?? {}
  }

  get unauthorized() {
    return this.status === 401
  }
}

async function request(method, path, body) {
  let response
  try {
    response = await fetch(path, {
      method,
      credentials: 'same-origin',
      headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    })
  } catch (cause) {
    throw new ApiError('la passerelle est injoignable', 0, { cause: String(cause) })
  }

  const text = await response.text()
  let payload = null
  if (text) {
    try {
      payload = JSON.parse(text)
    } catch {
      payload = { raw: text }
    }
  }

  if (!response.ok) {
    const message = payload?.error ?? `erreur HTTP ${response.status}`
    throw new ApiError(message, response.status, payload)
  }
  return payload
}

export const api = {
  session: () => request('GET', '/api/session'),
  login: (password) => request('POST', '/api/login', { password }),
  setup: (password) => request('POST', '/api/setup', { password }),
  logout: () => request('POST', '/api/logout'),

  status: () => request('GET', '/api/status'),
  metrics: () => request('GET', '/api/metrics'),

  getConfig: () => request('GET', '/api/config'),
  putConfig: (config) => request('PUT', '/api/config', config),
  validateConfig: (config) => request('POST', '/api/config/validate', config),
  changePassword: (current, next) => request('PUT', '/api/password', { current, new: next }),

  health: () => request('GET', '/api/health'),
  runHealth: () => request('POST', '/api/health/run'),

  tor: () => request('GET', '/api/tor'),
  torNewnym: () => request('POST', '/api/tor/newnym'),
  torCloseCircuit: (id) => request('POST', `/api/tor/circuits/${encodeURIComponent(id)}/close`),

  catalogue: () => request('GET', '/api/catalogue'),
  purgeCatalogue: () => request('DELETE', '/api/catalogue'),

  testRoute: (host, port) => request('POST', '/api/routing/test', { host, port }),

  mitm: () => request('GET', '/api/mitm'),
  regenerateCa: () => request('POST', '/api/mitm/ca/regenerate'),
  // Lien direct : le certificat se télécharge, il ne transite pas par fetch.
  caUrl: '/api/mitm/ca.pem',
}
