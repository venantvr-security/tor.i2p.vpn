<script setup>
/** Configuration des backends et des écoutes proxy. */

import { computed, onMounted } from 'vue'
import { backendColor, KIND_LABELS } from '../format.js'
import { makeId, useConfig } from '../useConfig.js'

const { config, loading, saving, error, dirty, load, save, reset } = useConfig()

onMounted(load)

const backends = computed(() => config.value?.backends ?? [])

/** Règles qui pointent vers un backend, pour prévenir avant suppression. */
function dependents(id) {
  const rules = config.value?.routing?.rules ?? []
  return rules.filter((rule) => rule.backend === id).map((rule) => rule.id)
}

function isDefault(id) {
  return config.value?.routing?.default_backend === id
}

function addBackend() {
  const ids = backends.value.map((backend) => backend.id)
  const id = makeId('backend', ids)
  config.value.backends.push({
    id,
    label: id,
    enabled: true,
    names_only: false,
    kind: 'socks5',
    address: '127.0.0.1:9050',
  })
}

function removeBackend(index) {
  config.value.backends.splice(index, 1)
}

/**
 * Le type est aplati dans le JSON (champ `kind` plus les champs propres au
 * type) : changer de type impose donc d'ajuster les champs qui l'accompagnent.
 */
function onKindChange(backend) {
  if (backend.kind === 'socks5' || backend.kind === 'http_connect') {
    if (!backend.address) backend.address = '127.0.0.1:9050'
  } else {
    delete backend.address
    delete backend.username
    delete backend.password
  }
  if (backend.kind !== 'socks5') {
    delete backend.username
    delete backend.password
  }
}

const hasCredentials = computed({
  get: () => Boolean(config.value?.proxy?.credentials),
  set: (value) => {
    config.value.proxy.credentials = value ? { username: '', password: '' } : null
  },
})

/**
 * Une adresse d'écoute vidée doit devenir `null`, pas la chaîne vide : c'est
 * `null` qui désactive l'écoute côté passerelle, tandis qu'une chaîne vide est
 * rejetée comme adresse invalide.
 */
function bindField(key) {
  return computed({
    get: () => config.value.proxy[key] ?? '',
    set: (value) => {
      const trimmed = value.trim()
      config.value.proxy[key] = trimmed === '' ? null : trimmed
    },
  })
}

const socks5Bind = bindField('socks5_bind')
const httpBind = bindField('http_bind')
</script>

<template>
  <div class="page-head">
    <div>
      <h1>Backends</h1>
      <p>
        Tor et I2P tournent sur la machine hôte ; la passerelle ne fait que leur
        transmettre le trafic. Les adresses ci-dessous sont celles de leurs proxys.
      </p>
    </div>
  </div>

  <p v-if="loading" class="muted">Chargement…</p>

  <template v-else-if="config">
    <div v-if="error" class="banner error">{{ error }}</div>

    <div class="card">
      <h2>Sorties</h2>
      <p class="hint">
        Un backend <em>sortie directe</em> emprunte la route par défaut de la
        machine, donc le VPN lorsque celui-ci est monté. Un backend
        <em>blocage</em> refuse tout : c'est la bonne valeur par défaut si vous
        préférez couper plutôt que fuiter.
      </p>

      <div class="backends">
        <article v-for="(backend, index) in backends" :key="index" class="backend">
          <header>
            <span class="swatch" :style="{ background: backendColor(index) }" />
            <input v-model="backend.label" type="text" class="label-input" />
            <span v-if="isDefault(backend.id)" class="pill">par défaut</span>
          </header>

          <div class="fields">
            <label class="field">
              Identifiant
              <input v-model="backend.id" type="text" class="mono" />
            </label>

            <label class="field">
              Type
              <select v-model="backend.kind" @change="onKindChange(backend)">
                <option v-for="(label, value) in KIND_LABELS" :key="value" :value="value">
                  {{ label }}
                </option>
              </select>
            </label>

            <label class="check names-only">
              <input v-model="backend.names_only" type="checkbox" />
              Ne route que des noms, jamais une IP brute
            </label>

            <label v-if="backend.kind === 'socks5' || backend.kind === 'http_connect'" class="field">
              Adresse amont
              <input v-model="backend.address" type="text" class="mono" placeholder="hôte:port" />
            </label>

            <label v-if="backend.kind === 'socks5'" class="field">
              Identifiant amont (facultatif)
              <input v-model="backend.username" type="text" />
            </label>

            <label v-if="backend.kind === 'socks5'" class="field">
              Mot de passe amont
              <input v-model="backend.password" type="password" />
            </label>
          </div>

          <footer>
            <label class="check">
              <input v-model="backend.enabled" type="checkbox" />
              Activé
            </label>
            <span v-if="dependents(backend.id).length" class="muted">
              utilisé par : {{ dependents(backend.id).join(', ') }}
            </span>
            <button
              class="tiny danger"
              :disabled="isDefault(backend.id)"
              :title="
                isDefault(backend.id)
                  ? 'Choisissez un autre backend par défaut avant de supprimer celui-ci'
                  : ''
              "
              @click="removeBackend(index)"
            >
              Supprimer
            </button>
          </footer>
        </article>
      </div>

      <div class="actions">
        <button @click="addBackend">Ajouter un backend</button>
      </div>
    </div>

    <div class="card">
      <h2>Écoutes proxy</h2>
      <p class="hint">
        Modifier une adresse d'écoute exige un redémarrage du conteneur ; tout le
        reste est appliqué à chaud. Laissez un champ vide pour désactiver l'écoute
        correspondante.
      </p>
      <div class="grid cols-2">
        <label class="field">
          SOCKS5
          <input v-model="socks5Bind" type="text" class="mono" placeholder="désactivée" />
        </label>
        <label class="field">
          HTTP
          <input v-model="httpBind" type="text" class="mono" placeholder="désactivée" />
        </label>
        <label class="field">
          Connexions simultanées maximum
          <input v-model.number="config.proxy.max_connections" type="number" min="1" max="65535" />
        </label>
        <label class="field">
          Délai de connexion amont (ms)
          <input v-model.number="config.proxy.connect_timeout_ms" type="number" min="500" step="500" />
        </label>
        <label class="field">
          Fermeture sur inactivité (s)
          <input v-model.number="config.proxy.idle_timeout_s" type="number" min="5" step="5" />
        </label>
      </div>

      <label class="check spaced">
        <input v-model="hasCredentials" type="checkbox" />
        Exiger une authentification des clients du proxy
      </label>

      <div v-if="config.proxy.credentials" class="grid cols-2 spaced">
        <label class="field">
          Identifiant
          <input v-model="config.proxy.credentials.username" type="text" />
        </label>
        <label class="field">
          Mot de passe
          <input v-model="config.proxy.credentials.password" type="password" />
        </label>
      </div>
    </div>

    <div class="actions sticky">
      <button class="primary" :disabled="!dirty || saving" @click="save">
        {{ saving ? 'Enregistrement…' : 'Enregistrer' }}
      </button>
      <button :disabled="!dirty || saving" @click="reset">Annuler les modifications</button>
      <span v-if="dirty" class="muted">Modifications non enregistrées.</span>
    </div>
  </template>
</template>

<style scoped>
.backends {
  display: grid;
  gap: 12px;
  grid-template-columns: repeat(auto-fit, minmax(310px, 1fr));
}

.backend {
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 12px;
  background: var(--surface-raised);
}

.backend header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 10px;
}

.label-input {
  font-weight: 600;
  border: 1px solid transparent;
  background: transparent;
  padding: 3px 5px;
}

.label-input:hover,
.label-input:focus {
  border-color: var(--border-strong);
  background: var(--surface);
}

.fields {
  display: grid;
  gap: 9px;
}

.names-only {
  font-size: 13px;
  margin-top: 2px;
}

.backend footer {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px;
  margin-top: 12px;
  padding-top: 10px;
  border-top: 1px solid var(--grid);
  font-size: 12.5px;
}

.backend footer button {
  margin-left: auto;
}

.spaced {
  margin-top: 14px;
}

.actions.sticky {
  position: sticky;
  bottom: 0;
  background: var(--plane);
  padding: 12px 0;
  border-top: 1px solid var(--border);
  margin-top: 18px;
}
</style>
