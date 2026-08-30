<script setup>
/**
 * Débit relayé au fil du temps, en aires empilées côte à côte.
 *
 * Deux séries seulement — descendant et montant — donc une légende est présente
 * et la dernière valeur de chaque série est étiquetée directement : l'identité
 * ne repose jamais sur la seule couleur. Le SVG est dessiné en pixels réels
 * plutôt qu'étiré via `preserveAspectRatio`, afin que les traits gardent leur
 * épaisseur quelle que soit la largeur du conteneur.
 */

import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { clock, rate } from '../format.js'

const props = defineProps({
  samples: { type: Array, default: () => [] },
  height: { type: Number, default: 190 },
})

/// Écart vertical minimal entre deux étiquettes directes avant décalage.
const LABEL_GAP = 13

const wrapper = ref(null)
const width = ref(720)
const hoverIndex = ref(null)
let observer = null

// La marge gauche doit loger une graduation complète du type « 1.9 Mo/s », et
// la marge droite l'étiquette directe de fin de série. Sur écran étroit, les
// deux se resserrent pour laisser la place au tracé lui-même.
const PADDING = computed(() =>
  width.value < 520
    ? { top: 16, right: 58, bottom: 22, left: 52 }
    : { top: 16, right: 74, bottom: 22, left: 70 },
)

onMounted(() => {
  if (!wrapper.value) return
  observer = new ResizeObserver((entries) => {
    const measured = entries[0]?.contentRect?.width
    if (measured) width.value = Math.max(260, measured)
  })
  observer.observe(wrapper.value)
})

onBeforeUnmount(() => observer?.disconnect())

const series = [
  { key: 'down_bps', label: 'Descendant', color: 'var(--series-1)' },
  { key: 'up_bps', label: 'Montant', color: 'var(--series-2)' },
]

const points = computed(() => props.samples ?? [])
const hasData = computed(() => points.value.length >= 2)

const plot = computed(() => ({
  width: Math.max(10, width.value - PADDING.value.left - PADDING.value.right),
  height: Math.max(10, props.height - PADDING.value.top - PADDING.value.bottom),
}))

/** Borne haute de l'axe, arrondie pour donner des graduations lisibles. */
const maxValue = computed(() => {
  const peak = points.value.reduce(
    (acc, sample) => Math.max(acc, sample.down_bps ?? 0, sample.up_bps ?? 0),
    0,
  )
  if (peak <= 0) return 1024
  const magnitude = 10 ** Math.floor(Math.log10(peak))
  return Math.ceil(peak / magnitude) * magnitude
})

function x(index) {
  const span = Math.max(1, points.value.length - 1)
  return PADDING.value.left + (index / span) * plot.value.width
}

function y(value) {
  const ratio = Math.min(1, (value ?? 0) / maxValue.value)
  return PADDING.value.top + plot.value.height - ratio * plot.value.height
}

function linePath(key) {
  return points.value
    .map((sample, index) => `${index === 0 ? 'M' : 'L'}${x(index).toFixed(1)},${y(sample[key]).toFixed(1)}`)
    .join(' ')
}

function areaPath(key) {
  if (!hasData.value) return ''
  const base = PADDING.value.top + plot.value.height
  const last = points.value.length - 1
  return `${linePath(key)} L${x(last).toFixed(1)},${base} L${x(0).toFixed(1)},${base} Z`
}

const ticks = computed(() => [0, 0.5, 1].map((ratio) => ({
  value: maxValue.value * ratio,
  y: PADDING.value.top + plot.value.height - ratio * plot.value.height,
})))

const lastSample = computed(() => points.value[points.value.length - 1] ?? null)

/**
 * Étiquettes directes de fin de série, écartées quand les deux valeurs se
 * confondent — c'est le cas courant à débit nul, où elles se superposeraient.
 */
const endLabels = computed(() => {
  const sample = lastSample.value
  if (!sample) return []
  const placed = series.map((entry) => ({
    key: entry.key,
    color: entry.color,
    value: sample[entry.key] ?? 0,
    y: y(sample[entry.key]),
  }))
  const [first, second] = placed
  if (Math.abs(first.y - second.y) < LABEL_GAP) {
    // La série la plus haute monte, l'autre descend, d'une demi-hauteur chacune.
    const higher = first.y <= second.y ? first : second
    const lower = higher === first ? second : first
    higher.y -= LABEL_GAP / 2
    lower.y += LABEL_GAP / 2
  }
  return placed
})

/** Point survolé, ou dernier point quand la souris est ailleurs. */
const focused = computed(() => {
  if (hoverIndex.value === null) return null
  return points.value[hoverIndex.value] ?? null
})

function onMove(event) {
  if (!hasData.value) return
  const rect = event.currentTarget.getBoundingClientRect()
  const offset = event.clientX - rect.left - PADDING.value.left
  const span = Math.max(1, points.value.length - 1)
  const index = Math.round((offset / plot.value.width) * span)
  hoverIndex.value = Math.min(points.value.length - 1, Math.max(0, index))
}

function onLeave() {
  hoverIndex.value = null
}

/** Position du panneau de survol, replié à gauche près du bord droit. */
const tooltipStyle = computed(() => {
  if (hoverIndex.value === null) return { display: 'none' }
  const anchor = x(hoverIndex.value)
  const flip = anchor > width.value * 0.6
  return {
    left: `${flip ? anchor - 12 : anchor + 12}px`,
    transform: flip ? 'translateX(-100%)' : 'none',
    top: `${PADDING.value.top}px`,
  }
})
</script>

<template>
  <figure ref="wrapper" class="chart">
    <figcaption class="chart-head">
      <span class="chart-title">Débit relayé</span>
      <span class="legend">
        <span v-for="entry in series" :key="entry.key" class="legend-item">
          <span class="swatch" :style="{ background: entry.color }" />
          {{ entry.label }}
        </span>
      </span>
    </figcaption>

    <div class="chart-body">
      <svg
        :width="width"
        :height="height"
        role="img"
        :aria-label="`Débit relayé sur les ${points.length} derniers points de mesure`"
        @mousemove="onMove"
        @mouseleave="onLeave"
      >
        <!-- Graduations horizontales, volontairement en retrait. -->
        <g>
          <line
            v-for="tick in ticks"
            :key="tick.y"
            :x1="PADDING.left"
            :x2="width - PADDING.right"
            :y1="tick.y"
            :y2="tick.y"
            stroke="var(--grid)"
            stroke-width="1"
          />
          <text
            v-for="tick in ticks"
            :key="`label-${tick.y}`"
            :x="PADDING.left - 8"
            :y="tick.y + 4"
            text-anchor="end"
            class="tick"
          >
            {{ rate(tick.value) }}
          </text>
        </g>

        <template v-if="hasData">
          <path
            v-for="entry in series"
            :key="`area-${entry.key}`"
            :d="areaPath(entry.key)"
            :fill="entry.color"
            fill-opacity="0.12"
          />
          <path
            v-for="entry in series"
            :key="`line-${entry.key}`"
            :d="linePath(entry.key)"
            fill="none"
            :stroke="entry.color"
            stroke-width="2"
            stroke-linejoin="round"
            stroke-linecap="round"
          />

          <!-- Étiquetage direct de la dernière valeur de chaque série. -->
          <g>
            <text
              v-for="label in endLabels"
              :key="`tag-${label.key}`"
              :x="width - PADDING.right + 8"
              :y="label.y + 4"
              class="tag"
              :fill="label.color"
            >
              {{ rate(label.value) }}
            </text>
          </g>

          <!-- Réticule de survol et marqueurs. -->
          <g v-if="hoverIndex !== null && focused">
            <line
              :x1="x(hoverIndex)"
              :x2="x(hoverIndex)"
              :y1="PADDING.top"
              :y2="PADDING.top + plot.height"
              stroke="var(--axis)"
              stroke-width="1"
              stroke-dasharray="3 3"
            />
            <circle
              v-for="entry in series"
              :key="`dot-${entry.key}`"
              :cx="x(hoverIndex)"
              :cy="y(focused[entry.key])"
              r="4.5"
              :fill="entry.color"
              stroke="var(--surface)"
              stroke-width="2"
            />
          </g>
        </template>

        <line
          :x1="PADDING.left"
          :x2="width - PADDING.right"
          :y1="PADDING.top + plot.height"
          :y2="PADDING.top + plot.height"
          stroke="var(--axis)"
          stroke-width="1"
        />

        <text v-if="hasData" :x="PADDING.left" :y="height - 6" class="tick">
          {{ clock(points[0].t) }}
        </text>
        <text
          v-if="hasData"
          :x="width - PADDING.right"
          :y="height - 6"
          text-anchor="end"
          class="tick"
        >
          {{ clock(points[points.length - 1].t) }}
        </text>
      </svg>

      <div v-if="hoverIndex !== null && focused" class="tooltip" :style="tooltipStyle">
        <div class="tooltip-time">{{ clock(focused.t) }}</div>
        <div v-for="entry in series" :key="`tip-${entry.key}`" class="tooltip-row">
          <span class="swatch" :style="{ background: entry.color }" />
          <span>{{ entry.label }}</span>
          <strong>{{ rate(focused[entry.key]) }}</strong>
        </div>
        <div class="tooltip-row">
          <span class="swatch" style="background: transparent" />
          <span>Connexions</span>
          <strong>{{ focused.active }}</strong>
        </div>
      </div>

      <p v-if="!hasData" class="empty">
        En attente de mesures : le premier point apparaît après quelques secondes.
      </p>
    </div>
  </figure>
</template>

<style scoped>
.chart {
  margin: 0;
}

.chart-head {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  justify-content: space-between;
  gap: 10px;
  margin-bottom: 6px;
}

.chart-title {
  font-size: 15px;
  font-weight: 600;
  letter-spacing: -0.01em;
}

.legend {
  display: flex;
  gap: 14px;
}

.legend-item {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 12.5px;
  color: var(--text-secondary);
}

.chart-body {
  position: relative;
  overflow-x: auto;
}

.tick {
  font-size: 11px;
  fill: var(--text-muted);
  font-variant-numeric: tabular-nums;
}

.tag {
  font-size: 11.5px;
  font-variant-numeric: tabular-nums;
  font-weight: 600;
}

.tooltip {
  position: absolute;
  background: var(--surface-raised);
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-sm);
  padding: 7px 9px;
  font-size: 12.5px;
  pointer-events: none;
  box-shadow: 0 6px 18px rgba(0, 0, 0, 0.16);
  min-width: 150px;
}

.tooltip-time {
  color: var(--text-muted);
  font-variant-numeric: tabular-nums;
  margin-bottom: 4px;
}

.tooltip-row {
  display: grid;
  grid-template-columns: 10px 1fr auto;
  align-items: center;
  gap: 7px;
  color: var(--text-secondary);
}

.tooltip-row strong {
  color: var(--text-primary);
  font-variant-numeric: tabular-nums;
}

.empty {
  position: absolute;
  inset: 0;
  display: grid;
  place-items: center;
  margin: 0;
  color: var(--text-muted);
  font-size: 13px;
  text-align: center;
  padding: 0 20px;
}
</style>
