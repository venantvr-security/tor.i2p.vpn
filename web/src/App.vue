<script setup>
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api } from './api.js'
import { live, markSignedOut, notifyError, session, toasts } from './store.js'

const route = useRoute()
const router = useRouter()

const chrome = computed(() => session.authenticated && !route.meta.public)

const links = [
  { to: '/tableau-de-bord', label: 'Tableau de bord' },
  { to: '/routage', label: 'Routage' },
  { to: '/backends', label: 'Backends' },
  { to: '/tor', label: 'Tor' },
  { to: '/journal', label: 'Journal' },
  { to: '/interception', label: 'Interception' },
  { to: '/sante', label: 'Santé' },
  { to: '/reglages', label: 'Réglages' },
]

async function signOut() {
  try {
    await api.logout()
  } catch (error) {
    notifyError(error)
  }
  markSignedOut()
  router.push({ name: 'login' })
}
</script>

<template>
  <div v-if="chrome" class="shell">
    <aside class="sidebar">
      <div class="brand">
        <strong>Passerelle</strong>
        <span>Tor · I2P</span>
      </div>

      <nav class="nav">
        <RouterLink v-for="link in links" :key="link.to" :to="link.to">
          {{ link.label }}
        </RouterLink>
      </nav>

      <div class="sidebar-foot">
        <p class="stream-state">
          <span class="swatch" :style="{ background: live.connected ? 'var(--good)' : 'var(--text-muted)' }" />
          {{ live.connected ? 'flux temps réel actif' : 'flux temps réel arrêté' }}
        </p>
        <button class="tiny" @click="signOut">Se déconnecter</button>
      </div>
    </aside>

    <main class="main">
      <RouterView />
    </main>
  </div>

  <RouterView v-else />

  <div class="toasts" role="status" aria-live="polite">
    <div v-for="toast in toasts" :key="toast.id" class="toast" :class="toast.kind">
      {{ toast.message }}
    </div>
  </div>
</template>

<style scoped>
.sidebar-foot {
  margin-top: auto;
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding: 0 8px;
}

.stream-state {
  display: flex;
  align-items: center;
  gap: 7px;
  margin: 0;
  font-size: 12px;
  color: var(--text-muted);
}

@media (max-width: 860px) {
  .sidebar-foot {
    margin-top: 4px;
    flex-direction: row;
    align-items: center;
    justify-content: space-between;
  }
}
</style>
