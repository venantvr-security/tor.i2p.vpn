<script setup>
/** Édition des règles de routage, avec simulateur de destination. */

import { computed, onMounted, ref } from 'vue'
import { api } from '../api.js'
import { backendColor, MATCH_LABELS } from '../format.js'
import { notifyError } from '../store.js'
import { makeId, useConfig } from '../useConfig.js'

const { config, loading, saving, error, dirty, load, save, reset } = useConfig()

onMounted(load)

const backends = computed(() => config.value?.backends ?? [])
const rules = computed(() => config.value?.routing?.rules ?? [])

const colorFor = (id) => {
  const index = backends.value.findIndex((backend) => backend.id === id)
  return backendColor(index)
}

function addRule() {
  const ids = rules.value.map((rule) => rule.id)
  config.value.routing.rules.push({
    // Les identifiants restent en ASCII : ils voyagent dans le TOML et dans les
    // URL de l'API. Seuls les libellés affichés sont en français.
    id: makeId('rule', ids),
    match_type: 'suffix',
    pattern: '',
    backend: config.value.routing.default_backend,
    enabled: true,
    note: null,
  })
}

function removeRule(index) {
  config.value.routing.rules.splice(index, 1)
}

/** Déplace une règle : l'ordre définit la priorité, la première l'emporte. */
function move(index, delta) {
  const target = index + delta
  if (target < 0 || target >= rules.value.length) return
  const list = config.value.routing.rules
  ;[list[index], list[target]] = [list[target], list[index]]
}

// --- Simulateur -----------------------------------------------------------

const probeHost = ref('')
const probePort = ref(443)
const probeResult = ref(null)
const probing = ref(false)

async function probe() {
  if (!probeHost.value.trim()) return
  probing.value = true
  probeResult.value = null
  try {
    probeResult.value = await api.testRoute(probeHost.value.trim(), Number(probePort.value) || 443)
  } catch (err) {
    notifyError(err)
  } finally {
    probing.value = false
  }
}
</script>

<template>
  <div class="page-head">
    <div>
      <h1>Routage</h1>
      <p>
        Les règles sont évaluées de haut en bas et la première correspondance
        l'emporte. Ce qui ne correspond à rien part vers le backend par défaut.
      </p>
    </div>
  </div>

  <p v-if="loading" class="muted">Chargement…</p>

  <template v-else-if="config">
    <div v-if="error" class="banner error">{{ error }}</div>

    <div class="card">
      <h2>Règles</h2>
      <p class="hint">
        Le suffixe <code>.onion</code> couvre tous les services cachés Tor, le
        suffixe <code>.i2p</code> tous les sites I2P. Un joker accepte
        <code>*</code>, par exemple <code>*.duckduckgo.com</code>.
      </p>

      <div class="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Ordre</th>
              <th>Identifiant</th>
              <th>Type</th>
              <th>Motif</th>
              <th>Backend</th>
              <th>Active</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(rule, index) in rules" :key="index">
              <td class="order">
                <button
                  class="tiny"
                  :disabled="index === 0"
                  title="Monter"
                  @click="move(index, -1)"
                >
                  ↑
                </button>
                <button
                  class="tiny"
                  :disabled="index === rules.length - 1"
                  title="Descendre"
                  @click="move(index, 1)"
                >
                  ↓
                </button>
              </td>
              <td><input v-model="rule.id" type="text" class="narrow" /></td>
              <td>
                <select v-model="rule.match_type">
                  <option v-for="(label, value) in MATCH_LABELS" :key="value" :value="value">
                    {{ label }}
                  </option>
                </select>
              </td>
              <td><input v-model="rule.pattern" type="text" class="mono wide" /></td>
              <td>
                <span class="cell-label">
                  <span class="swatch" :style="{ background: colorFor(rule.backend) }" />
                  <select v-model="rule.backend">
                    <option v-for="backend in backends" :key="backend.id" :value="backend.id">
                      {{ backend.label }}
                    </option>
                  </select>
                </span>
              </td>
              <td><input v-model="rule.enabled" type="checkbox" /></td>
              <td>
                <button class="tiny danger" @click="removeRule(index)">Supprimer</button>
              </td>
            </tr>
            <tr v-if="!rules.length">
              <td colspan="7" class="muted">
                Aucune règle : tout le trafic emprunte le backend par défaut.
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="actions">
        <button @click="addRule">Ajouter une règle</button>
      </div>
    </div>

    <div class="card">
      <h2>Politique générale</h2>
      <div class="grid cols-2">
        <label class="field">
          Backend par défaut
          <select v-model="config.routing.default_backend">
            <option v-for="backend in backends" :key="backend.id" :value="backend.id">
              {{ backend.label }}
            </option>
          </select>
        </label>
        <div class="switches">
          <label class="check">
            <input v-model="config.routing.block_private_ranges" type="checkbox" />
            Bloquer les destinations privées (loopback, RFC 1918, lien-local)
          </label>
          <label class="check">
            <input v-model="config.routing.block_bare_ip_on_hidden" type="checkbox" />
            Refuser les IP brutes sur les backends Tor et I2P
          </label>
        </div>
      </div>
      <p class="hint spaced">
        Ces deux garde-fous empêchent qu'un client du réseau local n'utilise la
        passerelle pour atteindre le LAN, et qu'une IP brute confiée à Tor ou I2P
        ne ressorte par un chemin inattendu.
      </p>
    </div>

    <div class="card">
      <h2>Tester une destination</h2>
      <p class="hint">
        Simule le routage sans ouvrir la moindre connexion : la règle affichée est
        celle qui s'appliquerait avec la configuration actuellement en service.
      </p>
      <form class="probe" @submit.prevent="probe">
        <label class="field grow">
          Nom d'hôte
          <input v-model="probeHost" type="text" placeholder="exemple.onion" class="mono" />
        </label>
        <label class="field port">
          Port
          <input v-model="probePort" type="number" min="1" max="65535" />
        </label>
        <button class="primary" type="submit" :disabled="probing || !probeHost">Tester</button>
      </form>

      <div v-if="probeResult" class="probe-result" :class="{ denied: !probeResult.allowed }">
        <span class="swatch" :style="{ background: colorFor(probeResult.backend) }" />
        <span class="mono">{{ probeResult.target }}</span>
        <span>→</span>
        <strong>{{ probeResult.backend_label ?? probeResult.backend }}</strong>
        <span class="muted">
          règle : {{ probeResult.rule ?? 'aucune, backend par défaut' }}
        </span>
        <span v-if="!probeResult.allowed" class="refusal">refusé — {{ probeResult.reason }}</span>
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
.order {
  display: flex;
  gap: 3px;
  padding-top: 10px;
}

.narrow {
  min-width: 8ch;
}

.wide {
  min-width: 20ch;
}

td select,
td input[type='text'] {
  padding: 4px 7px;
  font-size: 13px;
}

.cell-label {
  display: inline-flex;
  align-items: center;
  gap: 7px;
}

.switches {
  display: flex;
  flex-direction: column;
  gap: 9px;
  justify-content: center;
}

.hint.spaced {
  margin-top: 14px;
  margin-bottom: 0;
}

.probe {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  align-items: flex-end;
}

.probe .grow {
  flex: 1 1 240px;
}

.probe .port {
  width: 110px;
}

.probe-result {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 9px;
  margin-top: 14px;
  padding: 9px 11px;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  font-size: 13.5px;
}

.probe-result.denied {
  border-color: var(--warning);
}

.refusal {
  color: var(--critical);
  font-weight: 600;
}

.actions.sticky {
  position: sticky;
  bottom: 0;
  background: var(--plane);
  padding: 12px 0;
  border-top: 1px solid var(--border);
  margin-top: 18px;
}

code {
  font-family: var(--mono);
  font-size: 12.5px;
  background: var(--wash);
  padding: 1px 4px;
  border-radius: 3px;
}
</style>
