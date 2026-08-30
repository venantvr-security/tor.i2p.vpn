<script setup>
/**
 * Interception TLS : un mode à part, désactivé par défaut, qui déchiffre le
 * trafic des seuls hôtes explicitement inscrits.
 *
 * La page assume ce qu'elle propose : elle le dit franchement, met la CA et son
 * empreinte à portée de main, et n'active rien sans un geste délibéré.
 */

import { computed, onMounted, ref } from 'vue'
import { api } from '../api.js'
import { count } from '../format.js'
import { notify, notifyError } from '../store.js'
import { useConfig } from '../useConfig.js'

const { config, loading, saving, error, dirty, load, save, reset } = useConfig()

const status = ref(null)
const regenerating = ref(false)
const nouvelHote = ref('')

onMounted(async () => {
  await load()
  await refresh()
})

async function refresh() {
  try {
    status.value = await api.mitm()
  } catch (err) {
    notifyError(err)
  }
}

const mitm = computed(() => config.value?.mitm ?? null)

/** Empreinte de la CA, découpée pour rester lisible sur une ligne étroite. */
const empreinte = computed(() => status.value?.ca_fingerprint ?? '—')

function ajouterHote() {
  const hote = nouvelHote.value.trim().toLowerCase()
  if (!hote) return
  if (!mitm.value.hosts.includes(hote)) mitm.value.hosts.push(hote)
  nouvelHote.value = ''
}

function retirerHote(index) {
  mitm.value.hosts.splice(index, 1)
}

async function regenerer() {
  const ok = window.confirm(
    'Régénérer la CA invalide immédiatement toute racine déjà installée sur vos ' +
      'appareils : ils ne feront plus confiance aux certificats forgés tant que la ' +
      'nouvelle CA n’aura pas été réinstallée. Continuer ?',
  )
  if (!ok) return
  regenerating.value = true
  try {
    const { fingerprint } = await api.regenerateCa()
    notify('Nouvelle CA générée. Réinstallez-la sur vos appareils.', 'ok', 9000)
    if (status.value) status.value.ca_fingerprint = fingerprint
    await refresh()
  } catch (err) {
    notifyError(err)
  } finally {
    regenerating.value = false
  }
}

/** Reflète le libellé d'une entrée selon sa forme de correspondance. */
function forme(entree) {
  if (entree.startsWith('*.')) return 'sous-domaines'
  if (entree.startsWith('.')) return 'suffixe'
  return 'exact'
}
</script>

<template>
  <div class="page-head">
    <div>
      <h1>Interception</h1>
      <p>
        Pour les seuls hôtes que vous inscrivez ici, la passerelle termine le TLS
        avec un certificat forgé localement, rouvre un tunnel chiffré vers la vraie
        destination, et journalise le HTTP en clair qui circule entre les deux —
        URL complètes, codes, titres. Partout ailleurs, le trafic reste opaque.
      </p>
    </div>
    <div class="pill" :class="{ live: status?.enabled }">
      <span
        class="swatch"
        :style="{ background: status?.enabled ? 'var(--critical)' : 'var(--text-muted)' }"
      />
      {{ status?.enabled ? 'interception active' : 'interception inactive' }}
    </div>
  </div>

  <div class="banner warn">
    <strong>Ce mode déchiffre le trafic.</strong>
    Il inverse le rôle habituel de la passerelle. À n'utiliser que sur des appareils
    que vous contrôlez : chacun doit faire confiance à la CA ci-dessous, et
    l'épinglage de certificat (HSTS, applications mobiles) fera échouer certaines
    connexions. La clé de la CA est le secret le plus sensible de la passerelle —
    elle ne quitte jamais le volume de données.
  </div>

  <p v-if="loading" class="muted">Chargement…</p>

  <template v-else-if="config">
    <div v-if="error" class="banner error">{{ error }}</div>

    <div class="card">
      <h2>Autorité de certification</h2>
      <p class="hint">
        Installez ce certificat comme racine de confiance sur chaque appareil dont
        vous voulez intercepter le trafic. Après installation, comparez l'empreinte
        affichée par le système à celle-ci — elles doivent être identiques.
      </p>

      <label class="field">
        Empreinte SHA-256
        <span class="mono empreinte"><span class="cell-scroll">{{ empreinte }}</span></span>
      </label>

      <div class="actions">
        <a class="button primary" :href="api.caUrl" download>Télécharger la CA (.pem)</a>
        <button class="danger" :disabled="regenerating" @click="regenerer">
          {{ regenerating ? 'Régénération…' : 'Régénérer la CA' }}
        </button>
      </div>

      <details class="aide">
        <summary>Comment l'installer</summary>
        <ul>
          <li>
            <strong>Firefox</strong> gère son propre magasin :
            <span class="mono">Paramètres → Vie privée → Certificats → Autorités →
            Importer</span>, puis cochez « confiance pour les sites web ».
          </li>
          <li>
            <strong>Système (Debian/Ubuntu)</strong> : déposez le fichier dans
            <span class="mono">/usr/local/share/ca-certificates/</span> (extension
            <span class="mono">.crt</span>) puis
            <span class="mono">sudo update-ca-certificates</span>.
          </li>
          <li>
            <strong>Android / iOS</strong> : installez le profil, puis activez la
            confiance pleine dans les réglages de sécurité.
          </li>
        </ul>
      </details>
    </div>

    <div class="card">
      <h2>Activation</h2>
      <label class="check">
        <input v-model="mitm.enabled" type="checkbox" />
        Intercepter les hôtes listés ci-dessous
      </label>
      <p class="hint spaced">
        Tant que cette case est décochée, aucune connexion n'est déchiffrée, même si
        des hôtes figurent dans la liste. L'interception ne vise que le port 443 : le
        trafic déjà en clair est couvert par le <RouterLink to="/journal">Journal</RouterLink>.
      </p>
    </div>

    <div class="card">
      <h2>
        Hôtes interceptés
        <span class="pill">{{ count(mitm.hosts.length) }}</span>
      </h2>
      <p class="hint">
        Un nom exact (<span class="mono">forum.onion</span>), un suffixe s'il commence
        par un point (<span class="mono">.exemple.i2p</span>), ou un joker de
        sous-domaines avec <span class="mono">*.</span>
        (<span class="mono">*.exemple.com</span>).
      </p>

      <form class="ajout" @submit.prevent="ajouterHote">
        <input
          v-model="nouvelHote"
          type="text"
          class="mono"
          placeholder="forum.onion"
          autocapitalize="none"
          spellcheck="false"
        />
        <button type="submit" :disabled="!nouvelHote.trim()">Ajouter</button>
      </form>

      <ul v-if="mitm.hosts.length" class="hotes">
        <li v-for="(hote, index) in mitm.hosts" :key="index">
          <span class="mono hote"><span class="cell-scroll">{{ hote }}</span></span>
          <span class="pill forme">{{ forme(hote) }}</span>
          <button class="tiny danger" @click="retirerHote(index)">Retirer</button>
        </li>
      </ul>
      <p v-else class="muted">
        Aucun hôte : rien n'est intercepté, l'interception fût-elle activée.
      </p>
    </div>

    <div class="card">
      <h2>
        Ce que l'interception a vu
        <button class="tiny" @click="refresh">Rafraîchir</button>
      </h2>
      <div class="grid cols-2 chiffres">
        <div>
          <span class="fact-label">Connexions interceptées</span>
          <span class="fact-value">{{ count(status?.connections ?? 0) }}</span>
        </div>
        <div>
          <span class="fact-label">Requêtes lues</span>
          <span class="fact-value">{{ count(status?.requests ?? 0) }}</span>
        </div>
      </div>

      <p class="hint spaced">
        Empreinte du certificat présenté par chaque hôte amont. Un changement
        inattendu sur un service surveillé mérite un regard : saisie, clone de
        phishing, interception tierce.
      </p>
      <div v-if="status?.certificates?.length" class="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Hôte</th>
              <th>Empreinte du certificat vu</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="cert in status.certificates" :key="cert.host">
              <td class="mono"><span class="cell-scroll hote">{{ cert.host }}</span></td>
              <td class="mono"><span class="cell-scroll">{{ cert.fingerprint }}</span></td>
            </tr>
          </tbody>
        </table>
      </div>
      <p v-else class="muted">Aucun certificat vu pour l'instant.</p>
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
.card > h2 {
  display: flex;
  align-items: center;
  gap: 10px;
}

/* Un bandeau d'avertissement franc, distinct de l'erreur et du succès. */
.banner.warn {
  border-color: var(--serious);
  color: var(--text-primary);
  background: var(--wash);
}

.banner.warn strong {
  color: var(--serious);
}

.pill.live {
  border-color: var(--critical);
}

.empreinte {
  font-size: 12.5px;
  background: var(--wash);
  border-radius: var(--radius-sm);
  padding: 6px 9px;
}

.aide {
  margin-top: 14px;
  font-size: 13.5px;
}

.aide summary {
  cursor: pointer;
  color: var(--text-secondary);
}

.aide ul {
  margin: 10px 0 0;
  padding-left: 18px;
  display: flex;
  flex-direction: column;
  gap: 8px;
  color: var(--text-secondary);
}

.ajout {
  display: flex;
  gap: 8px;
  margin-bottom: 12px;
}

.ajout input {
  flex: 1 1 auto;
}

.ajout button {
  flex: none;
}

.hotes {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.hotes li {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 6px 0;
  border-bottom: 1px solid var(--grid);
}

.hote {
  flex: 1 1 auto;
  min-width: 0;
  max-width: 42ch;
}

.forme {
  flex: none;
  font-size: 12px;
  color: var(--text-muted);
}

.chiffres > div {
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
  font-size: 21px;
  font-variant-numeric: tabular-nums;
}

.spaced {
  margin-top: 14px;
}

/* Un lien stylé en bouton, pour le téléchargement de la CA. */
a.button {
  display: inline-flex;
  align-items: center;
  text-decoration: none;
  font-size: 14px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border-strong);
  padding: 7px 13px;
}

a.button.primary {
  background: var(--series-1);
  border-color: var(--series-1);
  color: #ffffff;
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
