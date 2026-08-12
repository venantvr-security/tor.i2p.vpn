<script setup>
/** Tableau de bord : débit temps réel, répartition par backend, journal live. */

import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import StatTile from '../components/StatTile.vue'
import ThroughputChart from '../components/ThroughputChart.vue'
import { api } from '../api.js'
import {
  backendColor,
  bytes,
  clock,
  count,
  duration,
  millis,
  rate,
  STATUS_LABELS,
} from '../format.js'
import { live, notifyError, startMetricsStream, stopMetricsStream } from '../store.js'

const status = ref(null)

onMounted(async () => {
  startMetricsStream()
  try {
    status.value = await api.status()
  } catch (error) {
    notifyError(error)
  }
})

onBeforeUnmount(() => stopMetricsStream())

const snapshot = computed(() => live.snapshot)
const series = computed(() => snapshot.value?.series ?? [])
const totals = computed(() => snapshot.value?.totals ?? null)

/** Dernier échantillon, source des débits instantanés affichés en tuiles. */
const latest = computed(() => series.value[series.value.length - 1] ?? null)

/**
 * Backends décorés de leur couleur, dans l'ordre de la configuration : la
 * teinte suit l'entité et ne change pas quand un backend cesse d'émettre.
 */
const backends = computed(() => {
  const configured = status.value?.backends ?? []
  const measured = snapshot.value?.backends ?? []
  return configured.map((backend, index) => {
    const stats = measured.find((entry) => entry.id === backend.id)
    return {
      ...backend,
      color: backendColor(index),
      connections_total: stats?.connections_total ?? 0,
      connections_active: stats?.connections_active ?? 0,
      bytes_up: stats?.bytes_up ?? 0,
      bytes_down: stats?.bytes_down ?? 0,
      errors: stats?.errors ?? 0,
      denied: stats?.denied ?? 0,
      avg_connect_ms: stats?.avg_connect_ms ?? 0,
    }
  })
})

const colorById = computed(() =>
  Object.fromEntries(backends.value.map((backend) => [backend.id, backend.color])),
)

const recent = computed(() => (snapshot.value?.recent ?? []).slice(0, 40))

function statusColor(state) {
  if (state === 'denied') return 'var(--warning)'
  if (state === 'failed') return 'var(--critical)'
  if (state === 'active') return 'var(--good)'
  return 'var(--text-muted)'
}
</script>

<template>
  <div class="page-head">
    <div>
      <h1>Tableau de bord</h1>
      <p>
        Trafic relayé en temps réel. Les compteurs repartent de zéro à chaque
        redémarrage de la passerelle.
      </p>
    </div>
    <div v-if="status" class="pill">
      version {{ status.version }} · en service depuis {{ duration(status.uptime_s) }}
    </div>
  </div>

  <div class="grid cols-4">
    <StatTile
      label="Descendant"
      :value="rate(latest?.down_bps ?? 0)"
      :sub="`${bytes(totals?.bytes_down ?? 0)} au total`"
      accent="var(--series-1)"
    />
    <StatTile
      label="Montant"
      :value="rate(latest?.up_bps ?? 0)"
      :sub="`${bytes(totals?.bytes_up ?? 0)} au total`"
      accent="var(--series-2)"
    />
    <StatTile
      label="Connexions actives"
      :value="count(snapshot?.active_connections ?? 0)"
      :sub="`plafond ${count(snapshot?.max_connections ?? 0)}`"
    />
    <StatTile
      label="Connexions routées"
      :value="count(totals?.connections_total ?? 0)"
      :sub="`${count(totals?.denied ?? 0)} refusées · ${count(totals?.errors ?? 0)} en échec`"
    />
  </div>

  <div class="card chart-card">
    <ThroughputChart :samples="series" />
  </div>

  <div class="card">
    <h2>Répartition par backend</h2>
    <p class="hint">
      Chaque backend garde sa couleur dans toute l'interface, y compris lorsqu'il
      cesse d'émettre.
    </p>
    <div class="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Backend</th>
            <th class="num">Actives</th>
            <th class="num">Total</th>
            <th class="num">Descendant</th>
            <th class="num">Montant</th>
            <th class="num">Connexion moy.</th>
            <th class="num">Refus</th>
            <th class="num">Échecs</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="backend in backends" :key="backend.id">
            <td>
              <span class="cell-label">
                <span class="swatch" :style="{ background: backend.color }" />
                {{ backend.label }}
                <span v-if="!backend.enabled" class="muted">(désactivé)</span>
              </span>
            </td>
            <td class="num">{{ count(backend.connections_active) }}</td>
            <td class="num">{{ count(backend.connections_total) }}</td>
            <td class="num">{{ bytes(backend.bytes_down) }}</td>
            <td class="num">{{ bytes(backend.bytes_up) }}</td>
            <td class="num">{{ backend.avg_connect_ms ? millis(backend.avg_connect_ms) : '—' }}</td>
            <td class="num">{{ count(backend.denied) }}</td>
            <td class="num">{{ count(backend.errors) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

  <div class="card">
    <h2>Connexions récentes</h2>
    <p class="hint">
      Les {{ recent.length }} dernières connexions vues par la passerelle, la plus
      récente en tête.
    </p>
    <div class="table-scroll log">
      <table>
        <thead>
          <tr>
            <th>Heure</th>
            <th>Client</th>
            <th>Destination</th>
            <th>Prot.</th>
            <th>Backend</th>
            <th>Règle</th>
            <th>État</th>
            <th class="num">Volume</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="entry in recent" :key="entry.id">
            <td class="mono">{{ clock(entry.started_ms) }}</td>
            <td class="mono">{{ entry.client }}</td>
            <td class="mono target">{{ entry.target }}</td>
            <td>{{ entry.protocol }}</td>
            <td>
              <span v-if="entry.backend" class="cell-label">
                <span
                  class="swatch"
                  :style="{ background: colorById[entry.backend] ?? 'var(--text-muted)' }"
                />
                {{ entry.backend }}
              </span>
              <span v-else class="muted">—</span>
            </td>
            <td class="muted">{{ entry.rule ?? 'défaut' }}</td>
            <td>
              <span class="cell-label" :title="entry.detail ?? ''">
                <span class="swatch" :style="{ background: statusColor(entry.status) }" />
                {{ STATUS_LABELS[entry.status] ?? entry.status }}
              </span>
            </td>
            <td class="num">
              {{ bytes((entry.bytes_up ?? 0) + (entry.bytes_down ?? 0)) }}
            </td>
          </tr>
          <tr v-if="!recent.length">
            <td colspan="8" class="muted">Aucune connexion enregistrée pour l'instant.</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<style scoped>
.chart-card {
  margin-top: 16px;
}

/* Le journal défile sur lui-même : quarante lignes ne doivent pas repousser
   le reste de la page hors de l'écran. */
.log {
  max-height: 420px;
  overflow-y: auto;
}

.log thead th {
  position: sticky;
  top: 0;
  background: var(--surface);
  z-index: 1;
}

.cell-label {
  display: inline-flex;
  align-items: center;
  gap: 7px;
}

.target {
  max-width: 28ch;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  display: inline-block;
  vertical-align: middle;
}
</style>
