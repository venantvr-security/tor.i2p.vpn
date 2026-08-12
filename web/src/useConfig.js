/**
 * Chargement et enregistrement de la configuration.
 *
 * Chaque vue de configuration travaille sur sa propre copie profonde : tant que
 * l'enregistrement n'a pas eu lieu, la passerelle continue de tourner avec la
 * configuration précédente.
 */

import { computed, ref } from 'vue'
import { api } from './api.js'
import { notify, notifyError } from './store.js'

export function useConfig() {
  const config = ref(null)
  const original = ref('')
  const loading = ref(true)
  const saving = ref(false)
  const error = ref('')

  const dirty = computed(
    () => config.value !== null && JSON.stringify(config.value) !== original.value,
  )

  async function load() {
    loading.value = true
    error.value = ''
    try {
      const loaded = await api.getConfig()
      config.value = loaded
      original.value = JSON.stringify(loaded)
    } catch (err) {
      error.value = err.message
      notifyError(err)
    } finally {
      loading.value = false
    }
  }

  async function save() {
    if (!config.value) return false
    saving.value = true
    error.value = ''
    try {
      const result = await api.putConfig(config.value)
      original.value = JSON.stringify(config.value)
      if (result.restart_required?.length) {
        notify(
          `Enregistré. Redémarrez le conteneur pour appliquer : ${result.restart_required.join(', ')}.`,
          'ok',
          9000,
        )
      } else {
        notify('Configuration enregistrée et appliquée à chaud.')
      }
      return true
    } catch (err) {
      error.value = err.message
      notifyError(err)
      return false
    } finally {
      saving.value = false
    }
  }

  function reset() {
    if (original.value) config.value = JSON.parse(original.value)
  }

  return { config, loading, saving, error, dirty, load, save, reset }
}

/** Identifiant court et stable pour une règle nouvellement créée. */
export function makeId(prefix, existing) {
  const taken = new Set(existing)
  let index = existing.length + 1
  let candidate = `${prefix}-${index}`
  while (taken.has(candidate)) {
    index += 1
    candidate = `${prefix}-${index}`
  }
  return candidate
}
