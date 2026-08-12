<script setup>
/** Réglages de l'interface d'administration et du compte. */

import { onMounted, ref } from 'vue'
import { api } from '../api.js'
import { notify, notifyError } from '../store.js'
import { useConfig } from '../useConfig.js'

const { config, loading, saving, error, dirty, load, save, reset } = useConfig()

const current = ref('')
const next = ref('')
const confirmation = ref('')
const changing = ref(false)
const passwordError = ref('')

onMounted(load)

async function changePassword() {
  passwordError.value = ''
  if (next.value !== confirmation.value) {
    passwordError.value = 'les deux mots de passe ne correspondent pas'
    return
  }
  changing.value = true
  try {
    await api.changePassword(current.value, next.value)
    notify('Mot de passe modifié. Les autres sessions ont été déconnectées.')
    current.value = ''
    next.value = ''
    confirmation.value = ''
  } catch (err) {
    passwordError.value = err.message
    if (err.unauthorized === false) notifyError(err)
  } finally {
    changing.value = false
  }
}
</script>

<template>
  <div class="page-head">
    <div>
      <h1>Réglages</h1>
      <p>Compte administrateur, écoute de l'interface web et export des métriques.</p>
    </div>
  </div>

  <div class="card">
    <h2>Mot de passe administrateur</h2>
    <p class="hint">
      Changer le mot de passe fait aussi tourner la clé de signature des sessions :
      toutes les autres sessions ouvertes sont invalidées.
    </p>

    <div v-if="passwordError" class="banner error">{{ passwordError }}</div>

    <form class="grid cols-2" @submit.prevent="changePassword">
      <label class="field">
        Mot de passe actuel
        <input v-model="current" type="password" autocomplete="current-password" required />
      </label>
      <label class="field">
        Nouveau mot de passe
        <input v-model="next" type="password" autocomplete="new-password" required />
      </label>
      <label class="field">
        Confirmation
        <input v-model="confirmation" type="password" autocomplete="new-password" required />
      </label>
      <div class="submit">
        <button class="primary" type="submit" :disabled="changing || !current || !next">
          {{ changing ? 'Modification…' : 'Modifier le mot de passe' }}
        </button>
      </div>
    </form>
  </div>

  <p v-if="loading" class="muted">Chargement…</p>

  <template v-else-if="config">
    <div v-if="error" class="banner error">{{ error }}</div>

    <div class="card">
      <h2>Interface d'administration</h2>
      <p class="hint">
        L'adresse d'écoute ne peut pas changer à chaud : après enregistrement,
        redémarrez le conteneur.
      </p>
      <div class="grid cols-2">
        <label class="field">
          Adresse d'écoute
          <input v-model="config.server.admin_bind" type="text" class="mono" />
        </label>
        <label class="field">
          Durée de validité d'une session (h)
          <input v-model.number="config.auth.session_ttl_h" type="number" min="1" max="720" />
        </label>
      </div>
    </div>

    <div class="card">
      <h2>Métriques</h2>
      <p class="hint">
        Les compteurs sont exposés au format texte Prometheus sur
        <code>/api/metrics/prometheus</code>. Ce point d'entrée exige la session
        d'administration : configurez votre collecteur avec le cookie, ou placez-le
        derrière un reverse proxy qui l'ajoute.
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
.submit {
  display: flex;
  align-items: flex-end;
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
