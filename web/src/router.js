/** Routage de la SPA, avec garde d'authentification. */

import { createRouter, createWebHistory } from 'vue-router'
import { refreshSession, session } from './store.js'

const routes = [
  { path: '/', redirect: '/tableau-de-bord' },
  {
    path: '/tableau-de-bord',
    name: 'dashboard',
    component: () => import('./views/DashboardView.vue'),
    meta: { title: 'Tableau de bord' },
  },
  {
    path: '/routage',
    name: 'routing',
    component: () => import('./views/RoutingView.vue'),
    meta: { title: 'Routage' },
  },
  {
    path: '/backends',
    name: 'backends',
    component: () => import('./views/BackendsView.vue'),
    meta: { title: 'Backends' },
  },
  {
    path: '/tor',
    name: 'tor',
    component: () => import('./views/TorView.vue'),
    meta: { title: 'Tor' },
  },
  {
    path: '/sante',
    name: 'health',
    component: () => import('./views/HealthView.vue'),
    meta: { title: 'Santé' },
  },
  {
    path: '/reglages',
    name: 'settings',
    component: () => import('./views/SettingsView.vue'),
    meta: { title: 'Réglages' },
  },
  {
    path: '/connexion',
    name: 'login',
    component: () => import('./views/LoginView.vue'),
    meta: { public: true, title: 'Connexion' },
  },
  { path: '/:pathMatch(.*)*', redirect: '/tableau-de-bord' },
]

export const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach(async (to) => {
  if (!session.checked) {
    await refreshSession()
  }
  if (to.meta.public) {
    // Une session déjà ouverte n'a rien à faire sur l'écran de connexion.
    return session.authenticated ? { name: 'dashboard' } : true
  }
  return session.authenticated ? true : { name: 'login', query: { suite: to.fullPath } }
})

router.afterEach((to) => {
  document.title = to.meta.title
    ? `${to.meta.title} — Passerelle Tor / I2P`
    : 'Passerelle Tor / I2P'
})
