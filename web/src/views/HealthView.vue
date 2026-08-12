<script setup>
/** Sondes de sortie : IP publique par backend, confirmation Tor, fuites. */

import { computed, onMounted, ref } from 'vue'
import { api } from '../api.js'
import { millis, stamp } from '../format.js'
import { notify, notifyError } from '../store.js'
import { useConfig } from '../useConfig.js'

const { config, loading, saving, error, dirty, load, save, reset } = useConfig()

const health = ref(null)
const running = ref(false)

onMounted(async () => {
  await load()
  await refresh()
})

async function refresh() {
  try {
    health.value = await api.health()
  } catch (err) {
    notifyError(err)
  }
}

async function runNow() {
  running.value = true
  try {
    const report = await api.runHealth()
    health.value = { ...(health.value ?? {}), last: report }
    notify('Campagne de sondes terminée.')
    await refresh()
  } catch (err) {
    notifyError(err)
  } finally {
    running.value = false
  }
}

const report = computed(() => health.value?.last ?? null)
const history = computed(() => health.value?.history ?? [])

const PROBE_LABELS = {
  exit_ip: 'IP de sortie',
  tor_confirmation: 'Confirmation Tor',
  i2p_reachability: 'Joignabilité I2P',
}

const SEVERITY = {
  info: { label: 'information', color: 'var(--good)' },
  warning: { label: 'avertissement', color: 'var(--warning)' },
  critical: { label: 'critique', color: 'var(--critical)' },
}

/** Pire sévérité du dernier rapport, affichée en tête de page. */
const worst = computed(() => {
  const order = { info: 0, warning: 1, critical: 2 }
  return (report.value?.findings ?? []).reduce(
    (acc, finding) => (order[finding.severity] > order[acc] ? finding.severity : acc),
    'info',
  )
})
</script>

<template>
  <div class="page-head">
    <div>
      <h1>Santé</h1>
      <p>
        Chaque sonde sort par un backend donné et rapporte ce que le monde
        extérieur a vu. C'est le seul moyen fiable de détecter un VPN tombé ou un
        trafic qui ne passe pas réellement par Tor.
      </p>
    </div>
    <button class="primary" :disabled="running" @click="runNow">
      {{ running ? 'Sondage en cours…' : 'Sonder maintenant' }}
    </button>
  </div>

  <div v-if="report" class="card">
    <h2>
      Dernier rapport
      <span class="pill">
        <span class="swatch" :style="{ background: SEVERITY[worst].color }" />
        {{ SEVERITY[worst].label }}
      </span>
    </h2>
    <p class="hint">
      {{ stamp(report.at) }} · campagne exécutée en {{ millis(report.duration_ms) }}
    </p>

    <ul class="findings">
      <li v-for="(finding, index) in report.findings" :key="index">
        <span class="swatch" :style="{ background: SEVERITY[finding.severity].color }" />
        <span class="finding-severity">{{ SEVERITY[finding.severity].label }}</span>
        <span>{{ finding.message }}</span>
      </li>
    </ul>

    <div class="table-scroll spaced">
      <table>
        <thead>
          <tr>
            <th>Sonde</th>
            <th>Backend</th>
            <th>Résultat</th>
            <th>Valeur</th>
            <th class="num">Latence</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(probe, index) in report.probes" :key="index">
            <td>{{ PROBE_LABELS[probe.kind] ?? probe.kind }}</td>
            <td class="mono">{{ probe.backend }}</td>
            <td>
              <span class="cell-label">
                <span
                  class="swatch"
                  :style="{ background: probe.ok ? 'var(--good)' : 'var(--critical)' }"
                />
                {{ probe.ok ? 'réussie' : 'échouée' }}
              </span>
            </td>
            <td class="mono">{{ probe.value ?? probe.error ?? '—' }}</td>
            <td class="num">{{ millis(probe.latency_ms) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

  <div v-else-if="!loading" class="card">
    <h2>Aucun rapport</h2>
    <p class="hint">
      Aucune campagne n'a encore été exécutée. Lancez-en une, ou activez les sondes
      périodiques ci-dessous.
    </p>
  </div>

  <div v-if="history.length" class="card">
    <h2>Historique</h2>
    <p class="hint">
      Une barre par campagne, la plus ancienne à gauche. Passez la souris pour
      connaître le détail.
    </p>
    <div class="history">
      <span
        v-for="(point, index) in history"
        :key="index"
        class="bar"
        :style="{ background: SEVERITY[point.worst].color }"
        :title="`${stamp(point.at)} — ${point.ok} réussie(s), ${point.failed} échouée(s), ${SEVERITY[point.worst].label}`"
      />
    </div>
  </div>

  <p v-if="loading" class="muted">Chargement de la configuration…</p>

  <template v-else-if="config">
    <div v-if="error" class="banner error">{{ error }}</div>

    <div class="card">
      <h2>Réglages des sondes</h2>
      <label class="check">
        <input v-model="config.health.enabled" type="checkbox" />
        Sonder périodiquement
      </label>

      <div class="grid cols-2 spaced">
        <label class="field">
          Intervalle (s)
          <input v-model.number="config.health.interval_s" type="number" min="15" step="15" />
        </label>
        <label class="field">
          Délai maximum par sonde (s)
          <input v-model.number="config.health.timeout_s" type="number" min="1" />
        </label>
        <label class="field">
          Service d'IP publique
          <input v-model="config.health.ip_check_url" type="url" class="mono" />
        </label>
        <label class="field">
          Service de vérification Tor
          <input v-model="config.health.tor_check_url" type="url" class="mono" />
        </label>
        <label class="field">
          Site I2P témoin
          <input v-model="config.health.i2p_check_url" type="url" class="mono" />
        </label>
        <label class="field">
          Points d'historique conservés
          <input v-model.number="config.health.history_len" type="number" min="1" max="1000" />
        </label>
      </div>

      <label class="check spaced">
        <input v-model="config.health.expect_vpn_exit" type="checkbox" />
        Alerter si le trafic clearnet ne passe pas par le VPN
      </label>

      <label class="field spaced narrow">
        IP publique de référence du FAI
        <input v-model="config.health.isp_ip_hint" type="text" class="mono" placeholder="203.0.113.7" />
      </label>
      <p class="hint spaced">
        Renseignez ici l'adresse publique observée <em>sans</em> VPN. La sonde la
        compare à l'IP de sortie du chemin clearnet : si les deux coïncident, le VPN
        est tombé ou il est contourné.
      </p>
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
.card > h2 {
  display: flex;
  align-items: center;
  gap: 10px;
}

.findings {
  list-style: none;
  margin: 0 0 4px;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 7px;
}

.findings li {
  display: flex;
  align-items: baseline;
  gap: 9px;
  font-size: 13.5px;
}

.finding-severity {
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--text-secondary);
  flex: none;
  min-width: 11ch;
}

.cell-label {
  display: inline-flex;
  align-items: center;
  gap: 7px;
}

.history {
  display: flex;
  gap: 2px;
  align-items: flex-end;
  height: 34px;
}

.bar {
  flex: 1 1 auto;
  min-width: 3px;
  max-width: 14px;
  height: 100%;
  border-radius: 2px 2px 0 0;
}

.spaced {
  margin-top: 14px;
}

.narrow {
  max-width: 280px;
}

.hint.spaced {
  margin-bottom: 0;
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
