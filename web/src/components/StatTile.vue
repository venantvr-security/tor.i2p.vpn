<script setup>
/** Tuile de statistique : une grandeur unique, sans graphique. */
defineProps({
  label: { type: String, required: true },
  value: { type: [String, Number], required: true },
  sub: { type: String, default: '' },
  accent: { type: String, default: '' },
})
</script>

<template>
  <div class="tile">
    <div class="tile-label">
      <span v-if="accent" class="swatch" :style="{ background: accent }" />
      {{ label }}
    </div>
    <div class="tile-value">{{ value }}</div>
    <div v-if="sub" class="tile-sub">{{ sub }}</div>
  </div>
</template>

<style scoped>
.tile {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 13px 15px;
}

.tile-label {
  display: flex;
  align-items: center;
  gap: 7px;
  font-size: 12px;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.tile-value {
  font-size: 25px;
  line-height: 1.2;
  letter-spacing: -0.02em;
  margin-top: 5px;
}

.tile-sub {
  font-size: 12.5px;
  color: var(--text-muted);
  margin-top: 2px;
}
</style>
