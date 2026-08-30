<script setup>
/**
 * Journal des destinations : URL traversées, code HTTP et titre quand le
 * trafic était en clair.
 *
 * La page assume ce qu'elle est — une trace de navigation — et le dit : elle
 * annonce ce qui est enregistré, ce qui ne peut pas l'être, et laisse le
 * plafond de lignes à portée de main.
 */

import { computed, onMounted, ref } from 'vue'
import { api } from '../api.js'
import { count, stamp } from '../format.js'
import { notify, notifyError } from '../store.js'
import { useConfig } from '../useConfig.js'

const { config, loading, saving, error, dirty, load, save, reset } = useConfig()

const journal = ref(null)
const refreshing = ref(false)
const purging = ref(false)
const filtre = ref('tous')
const recherche = ref('')

/**
 * Chaque famille garde sa couleur quel que soit son rang dans la liste : une
 * teinte suit une entité, jamais sa position. Le libellé texte double toujours
 * la couleur.
 */
const RESEAUX = {
  tor: { label: 'Tor', color: 'var(--series-7)' },
  i2p: { label: 'I2P', color: 'var(--series-3)' },
  standard: { label: 'Standard', color: 'var(--series-1)' },
}

const ONGLETS = [
  { id: 'tous', label: 'Tout' },
  { id: 'tor', label: 'Tor' },
  { id: 'i2p', label: 'I2P' },
  { id: 'standard', label: 'Standard' },
]

onMounted(async () => {
  await load()
  await refresh()
})

async function refresh() {
  refreshing.value = true
  try {
    journal.value = await api.catalogue()
  } catch (err) {
    notifyError(err)
  } finally {
    refreshing.value = false
  }
}

async function purge() {
  purging.value = true
  try {
    await api.purgeCatalogue()
    notify('Journal effacé.')
    await refresh()
  } catch (err) {
    notifyError(err)
  } finally {
    purging.value = false
  }
}

/**
 * Enregistre puis relit : abaisser le plafond rogne le journal côté passerelle,
 * et la page doit montrer ce qu'il en reste, pas ce qu'il en restait.
 */
async function enregistrer() {
  if (await save()) await refresh()
}

const entries = computed(() => journal.value?.entries ?? [])

/** Compte par famille, affiché sur les onglets. */
const totaux = computed(() => {
  const total = { tous: entries.value.length, tor: 0, i2p: 0, standard: 0 }
  for (const entry of entries.value) total[entry.reseau] += 1
  return total
})

const visibles = computed(() => {
  const terme = recherche.value.trim().toLowerCase()
  return entries.value.filter((entry) => {
    if (filtre.value !== 'tous' && entry.reseau !== filtre.value) return false
    if (!terme) return true
    return (
      entry.url.toLowerCase().includes(terme) ||
      (entry.titre ?? '').toLowerCase().includes(terme)
    )
  })
})

/** Couleur d'un code HTTP : la famille du code, pas sa valeur exacte. */
function codeColor(code) {
  if (!code) return 'var(--text-muted)'
  if (code < 300) return 'var(--good)'
  if (code < 400) return 'var(--series-1)'
  if (code < 500) return 'var(--warning)'
  return 'var(--critical)'
}

const remplissage = computed(() => {
  const plafond = journal.value?.max_entries ?? 0
  if (!plafond) return 0
  return Math.min(100, Math.round((entries.value.length / plafond) * 100))
})
</script>

<template>
  <div class="page-head">
    <div>
      <h1>Journal</h1>
      <p>
        Les destinations traversées, Tor, I2P et trafic standard confondus. Le
        journal se comporte en file : au-delà du plafond, la plus ancienne ligne
        sort. Une destination revue remonte en tête au lieu d'être dupliquée.
      </p>
    </div>
    <div class="head-actions">
      <button :disabled="refreshing" @click="refresh">
        {{ refreshing ? 'Lecture…' : 'Rafraîchir' }}
      </button>
      <button class="danger" :disabled="purging || !entries.length" @click="purge">
        {{ purging ? 'Effacement…' : 'Effacer' }}
      </button>
    </div>
  </div>

  <div v-if="journal && !journal.enabled" class="banner">
    Le journal est désactivé : rien n'est écrit sur disque. Activez-le ci-dessous
    si vous voulez conserver la trace des destinations.
  </div>

  <div class="card">
    <h2>
      Destinations
      <span class="pill">{{ count(entries.length) }} / {{ count(journal?.max_entries ?? 0) }}</span>
    </h2>
    <div class="gauge" :title="`${remplissage} % du plafond`">
      <span :style="{ width: `${remplissage}%` }" />
    </div>

    <div class="filtres">
      <div class="onglets">
        <button
          v-for="onglet in ONGLETS"
          :key="onglet.id"
          :class="{ actif: filtre === onglet.id }"
          @click="filtre = onglet.id"
        >
          <span
            v-if="onglet.id !== 'tous'"
            class="swatch"
            :style="{ background: RESEAUX[onglet.id].color }"
          />
          {{ onglet.label }}
          <span class="tally">{{ count(totaux[onglet.id]) }}</span>
        </button>
      </div>
      <input v-model="recherche" type="search" placeholder="Filtrer une URL ou un titre" />
    </div>

    <div v-if="visibles.length" class="table-scroll tall">
      <table>
        <thead>
          <tr>
            <th>Réseau</th>
            <th>URL</th>
            <th>Titre</th>
            <th class="code">Code</th>
            <th>Dernier passage</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="entry in visibles" :key="entry.url">
            <td>
              <span class="cell-label">
                <span class="swatch" :style="{ background: RESEAUX[entry.reseau].color }" />
                {{ RESEAUX[entry.reseau].label }}
              </span>
            </td>
            <td class="mono url">{{ entry.url }}</td>
            <td>{{ entry.titre ?? '—' }}</td>
            <td class="code">
              <span class="cell-label">
                <span class="swatch" :style="{ background: codeColor(entry.code) }" />
                {{ entry.code ?? '—' }}
              </span>
            </td>
            <td class="mono">{{ stamp(entry.vu) }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <p v-else class="muted">
      {{ entries.length ? 'Aucune ligne ne correspond au filtre.' : 'Le journal est vide.' }}
    </p>
  </div>

  <p v-if="loading" class="muted">Chargement de la configuration…</p>

  <template v-else-if="config">
    <div v-if="error" class="banner error">{{ error }}</div>

    <div class="card">
      <h2>Réglages du journal</h2>
      <label class="check">
        <input v-model="config.catalogue.enabled" type="checkbox" />
        Journaliser les destinations
      </label>
      <label class="check">
        <input
          v-model="config.catalogue.capture_titles"
          type="checkbox"
          :disabled="!config.catalogue.enabled"
        />
        Relever aussi le titre des pages servies en clair
      </label>

      <label class="field spaced narrow">
        Lignes conservées (file)
        <input
          v-model.number="config.catalogue.max_entries"
          type="number"
          :min="journal?.min_allowed ?? 10"
          :max="journal?.max_allowed ?? 20000"
          step="10"
        />
      </label>
      <p class="hint">
        Entre {{ count(journal?.min_allowed ?? 10) }} et
        {{ count(journal?.max_allowed ?? 20000) }} destinations distinctes.
        Abaisser ce nombre rogne le journal immédiatement.
      </p>

      <p class="hint spaced">
        <strong>Ce qui est toujours consigné</strong> : l'URL et l'heure du
        dernier passage. En SOCKS5, la poignée de main ne transporte pas de
        chemin : l'URL se réduit alors à l'origine.
      </p>
      <p class="hint">
        <strong>Ce qui l'est parfois</strong> : le code HTTP, dès que la réponse
        n'est pas chiffrée, et le titre, en plus des mêmes conditions, seulement
        si la page est en <span class="mono">text/html</span> non compressé et
        que sa balise tombe dans les 64 premiers kilo-octets. En HTTPS, ni l'un
        ni l'autre : le tunnel est opaque, et la passerelle ne le déchiffre pas.
      </p>
      <p class="hint">
        <strong>Ce que cela implique</strong> : ce fichier est une trace de
        navigation, déposée à côté de la configuration. Sur une passerelle dont
        le rôle est de protéger le trafic, c'est un choix, pas un réglage anodin.
      </p>
    </div>

    <div class="actions sticky">
      <button class="primary" :disabled="!dirty || saving" @click="enregistrer">
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

.head-actions {
  display: flex;
  gap: 8px;
}

.gauge {
  height: 4px;
  border-radius: 2px;
  background: var(--wash);
  overflow: hidden;
  margin-bottom: 14px;
}

.gauge span {
  display: block;
  height: 100%;
  background: var(--series-1);
}

.filtres {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 12px;
}

.onglets {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.onglets button {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  font-size: 13px;
  padding: 5px 11px;
}

.onglets button.actif {
  border-color: var(--text-primary);
  color: var(--text-primary);
}

.tally {
  font-variant-numeric: tabular-nums;
  color: var(--text-muted);
  font-size: 12px;
}

.filtres input[type='search'] {
  flex: 1 1 200px;
  max-width: 320px;
}

.cell-label {
  display: inline-flex;
  align-items: center;
  gap: 7px;
}

/* Volontairement pas `.num` : cette règle globale supprime la marge droite
   pour une colonne de fin de tableau, et le code HTTP en a une derrière lui. */
.code {
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}

.url {
  max-width: 46ch;
  overflow-wrap: anywhere;
}

/* Le journal peut compter des milliers de lignes : il défile dans son propre
   cadre plutôt que d'étirer la page. */
.table-scroll.tall {
  max-height: 460px;
  overflow-y: auto;
}

.table-scroll.tall thead th {
  position: sticky;
  top: 0;
  background: var(--surface);
  z-index: 1;
}

.spaced {
  margin-top: 14px;
}

.narrow {
  max-width: 220px;
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
