<script setup>
/** Supervision du réseau Tor via le ControlPort, et réglages associés. */

import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { api } from '../api.js'
import { bytes } from '../format.js'
import { notify, notifyError } from '../store.js'
import { useConfig } from '../useConfig.js'

const { config, loading, saving, error, dirty, load, save, reset } = useConfig()

const tor = ref(null)
const refreshing = ref(false)
const acting = ref(false)
let timer = null

onMounted(async () => {
  await load()
  await refresh()
  // Les circuits changent lentement : une actualisation toutes les 15 secondes
  // suffit et évite de solliciter le ControlPort en permanence.
  timer = setInterval(refresh, 15000)
})

onBeforeUnmount(() => clearInterval(timer))

async function refresh() {
  refreshing.value = true
  try {
    tor.value = await api.tor()
  } catch (err) {
    notifyError(err)
  } finally {
    refreshing.value = false
  }
}

async function newIdentity() {
  acting.value = true
  try {
    await api.torNewnym()
    notify('Nouvelle identité demandée à Tor.')
    await refresh()
  } catch (err) {
    notifyError(err)
  } finally {
    acting.value = false
  }
}

async function closeCircuit(id) {
  acting.value = true
  try {
    await api.torCloseCircuit(id)
    notify(`Circuit ${id} fermé.`)
    await refresh()
  } catch (err) {
    notifyError(err)
  } finally {
    acting.value = false
  }
}

/** Les circuits construits d'abord : ce sont ceux qui portent du trafic. */
const circuits = computed(() => {
  const list = [...(tor.value?.circuits ?? [])]
  return list.sort((a, b) => {
    if (a.status === b.status) return Number(a.id) - Number(b.id)
    return a.status === 'BUILT' ? -1 : 1
  })
})

const built = computed(() => circuits.value.filter((circuit) => circuit.status === 'BUILT').length)
</script>

<template>
  <div class="page-head">
    <div>
      <h1>Tor</h1>
      <p>
        État du démon Tor de la machine hôte, lu via son port de contrôle. Sans
        port de contrôle, le routage vers <code>.onion</code> fonctionne toujours,
        mais cette page reste vide.
      </p>
    </div>
    <button :disabled="refreshing" @click="refresh">
      {{ refreshing ? 'Actualisation…' : 'Actualiser' }}
    </button>
  </div>

  <div v-if="tor && !tor.reachable" class="banner error">
    Port de contrôle injoignable — {{ tor.error }}
  </div>

  <div v-if="tor?.reachable" class="card">
    <h2>État du démon</h2>
    <div class="grid cols-4 facts">
      <div>
        <span class="fact-label">Version</span>
        <span class="fact-value mono">{{ tor.version ?? '—' }}</span>
      </div>
      <div>
        <span class="fact-label">Amorçage</span>
        <span class="fact-value">{{ tor.bootstrap ?? '—' }}</span>
      </div>
      <div>
        <span class="fact-label">Reçu</span>
        <span class="fact-value">{{ bytes(tor.bytes_read ?? 0) }}</span>
      </div>
      <div>
        <span class="fact-label">Émis</span>
        <span class="fact-value">{{ bytes(tor.bytes_written ?? 0) }}</span>
      </div>
    </div>

    <div class="actions">
      <button class="primary" :disabled="acting" @click="newIdentity">
        Nouvelle identité (NEWNYM)
      </button>
      <span class="muted">
        Renouvelle les circuits pour les connexions à venir ; celles déjà ouvertes
        conservent le leur.
      </span>
    </div>
  </div>

  <div v-if="tor?.reachable" class="card">
    <h2>Circuits</h2>
    <p class="hint">
      {{ circuits.length }} circuit(s), dont {{ built }} construit(s). Le chemin se
      lit de l'entrée vers la sortie.
    </p>
    <div class="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Id</th>
            <th>État</th>
            <th>Chemin</th>
            <th>Usage</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="circuit in circuits" :key="circuit.id">
            <td class="mono">{{ circuit.id }}</td>
            <td>
              <span class="cell-label">
                <span
                  class="swatch"
                  :style="{
                    background: circuit.status === 'BUILT' ? 'var(--good)' : 'var(--warning)',
                  }"
                />
                {{ circuit.status }}
              </span>
            </td>
            <td>
              <span v-if="circuit.path.length" class="path">
                <span v-for="(relay, index) in circuit.path" :key="relay.fingerprint" class="relay">
                  <span v-if="index > 0" class="arrow">→</span>
                  <span :title="relay.fingerprint">{{ relay.nickname ?? relay.fingerprint }}</span>
                </span>
              </span>
              <span v-else class="muted">chemin non encore établi</span>
            </td>
            <td class="muted">{{ circuit.purpose ?? '—' }}</td>
            <td>
              <button class="tiny danger" :disabled="acting" @click="closeCircuit(circuit.id)">
                Fermer
              </button>
            </td>
          </tr>
          <tr v-if="!circuits.length">
            <td colspan="5" class="muted">Aucun circuit ouvert.</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

  <p v-if="loading" class="muted">Chargement de la configuration…</p>

  <template v-else-if="config">
    <div v-if="error" class="banner error">{{ error }}</div>

    <div class="card">
      <h2>Accès au port de contrôle</h2>
      <p class="hint">
        Tor n'ouvre son port de contrôle que si <code>ControlPort 9051</code> figure
        dans son <code>torrc</code>. En authentification par cookie, le fichier doit
        être monté en lecture seule dans le conteneur.
      </p>

      <label class="check">
        <input v-model="config.tor_control.enabled" type="checkbox" />
        Activer le contrôle de Tor
      </label>

      <div class="grid cols-2 spaced">
        <label class="field">
          Adresse
          <input v-model="config.tor_control.address" type="text" class="mono" />
        </label>
        <label class="field">
          Authentification
          <select v-model="config.tor_control.auth">
            <option value="cookie">cookie</option>
            <option value="password">mot de passe</option>
            <option value="none">aucune</option>
          </select>
        </label>
        <label v-if="config.tor_control.auth === 'cookie'" class="field">
          Chemin du cookie
          <input v-model="config.tor_control.cookie_path" type="text" class="mono" />
        </label>
        <label v-if="config.tor_control.auth === 'password'" class="field">
          Mot de passe du ControlPort
          <input v-model="config.tor_control.password" type="password" />
        </label>
        <label class="field">
          Délai minimum entre deux NEWNYM (s)
          <input v-model.number="config.tor_control.newnym_cooldown_s" type="number" min="0" />
        </label>
      </div>
    </div>

    <div class="actions sticky">
      <button class="primary" :disabled="!dirty || saving" @click="save">
        {{ saving ? 'Enregistrement…' : 'Enregistrer' }}
      </button>
      <button :disabled="!dirty || saving" @click="reset">Annuler les modifications</button>
    </div>
  </template>
</template>

<style scoped>
.facts {
  margin-bottom: 4px;
}

.facts > div {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.fact-label {
  font-size: 12px;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.fact-value {
  font-size: 15px;
}

.cell-label {
  display: inline-flex;
  align-items: center;
  gap: 7px;
}

.path {
  display: inline-flex;
  flex-wrap: wrap;
  gap: 5px;
  font-size: 13px;
}

.relay {
  display: inline-flex;
  gap: 5px;
  align-items: center;
}

.arrow {
  color: var(--text-muted);
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

code {
  font-family: var(--mono);
  font-size: 12.5px;
  background: var(--wash);
  padding: 1px 4px;
  border-radius: 3px;
}
</style>
