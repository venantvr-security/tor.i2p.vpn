<script setup>
/** Écran de connexion, qui sert aussi à la première initialisation. */

import { onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api } from '../api.js'
import { markSignedIn, refreshSession, session } from '../store.js'

const route = useRoute()
const router = useRouter()

const password = ref('')
const confirmation = ref('')
const busy = ref(false)
const error = ref('')

onMounted(refreshSession)

async function submit() {
  error.value = ''
  if (session.setupRequired && password.value !== confirmation.value) {
    error.value = 'les deux mots de passe ne correspondent pas'
    return
  }
  busy.value = true
  try {
    if (session.setupRequired) {
      await api.setup(password.value)
    } else {
      await api.login(password.value)
    }
    markSignedIn()
    router.push(route.query.suite ?? { name: 'dashboard' })
  } catch (err) {
    error.value = err.message
  } finally {
    busy.value = false
    password.value = ''
    confirmation.value = ''
  }
}
</script>

<template>
  <div class="centered">
    <form class="card login-card" @submit.prevent="submit">
      <h2>{{ session.setupRequired ? 'Première configuration' : 'Connexion' }}</h2>
      <p class="hint">
        <template v-if="session.setupRequired">
          Choisissez le mot de passe administrateur de la passerelle. Il protège la
          configuration du routage ainsi que le contrôle de Tor : douze caractères
          minimum sont recommandés.
        </template>
        <template v-else>
          Cette interface pilote le routage de votre trafic. Authentifiez-vous pour
          continuer.
        </template>
      </p>

      <div v-if="error" class="banner error">{{ error }}</div>

      <label class="field">
        Mot de passe
        <input
          v-model="password"
          type="password"
          autocomplete="current-password"
          required
          autofocus
        />
      </label>

      <label v-if="session.setupRequired" class="field confirm">
        Confirmation
        <input v-model="confirmation" type="password" autocomplete="new-password" required />
      </label>

      <div class="actions">
        <button class="primary" type="submit" :disabled="busy || !password">
          {{ session.setupRequired ? 'Créer le mot de passe' : 'Se connecter' }}
        </button>
      </div>
    </form>
  </div>
</template>

<style scoped>
.confirm {
  margin-top: 12px;
}
</style>
