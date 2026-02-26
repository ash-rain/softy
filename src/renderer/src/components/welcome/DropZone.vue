<script setup lang="ts">
import { ref } from 'vue'

defineProps<{ loading: boolean }>()
const emit = defineEmits<{
  file: [path: string]
  clickOpen: []
}>()

const isDragging = ref(false)
const dragDepth  = ref(0)

function onDragEnter(e: DragEvent) {
  e.preventDefault()
  dragDepth.value++
  isDragging.value = true
}

function onDragLeave(e: DragEvent) {
  e.preventDefault()
  dragDepth.value--
  if (dragDepth.value === 0) isDragging.value = false
}

function onDragOver(e: DragEvent) { e.preventDefault() }

function onDrop(e: DragEvent) {
  e.preventDefault()
  isDragging.value = false
  dragDepth.value  = 0
  const files = e.dataTransfer?.files
  if (files && files.length > 0) {
    // Electron provides real file path via path property on File objects
    const file = files[0] as File & { path?: string }
    const path = file.path || (file as unknown as { webkitRelativePath?: string }).webkitRelativePath || file.name
    emit('file', path)
  }
}
</script>

<template>
  <div
    class="drop-zone"
    :class="{ dragging: isDragging, loading }"
    @dragenter="onDragEnter"
    @dragleave="onDragLeave"
    @dragover="onDragOver"
    @drop="onDrop"
    @click="!loading && emit('clickOpen')"
  >
    <!-- Scan line animation when dragging -->
    <div v-if="isDragging" class="scan-line" />

    <!-- Loading spinner -->
    <div v-if="loading" class="zone-inner">
      <div class="spinner" />
      <p class="zone-label">Analyzing…</p>
      <p class="zone-sub">Reading binary metadata</p>
    </div>

    <!-- Default state -->
    <div v-else class="zone-inner">
      <div class="drop-icon" :class="{ pulse: isDragging }">
        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
          <polyline points="17 8 12 3 7 8"/>
          <line x1="12" y1="3" x2="12" y2="15"/>
        </svg>
      </div>
      <p class="zone-label">
        <span v-if="isDragging" style="color: var(--color-accent)">Drop to analyze</span>
        <span v-else>Drop a binary here</span>
      </p>
      <p class="zone-sub">or <span class="link">click to browse</span></p>
    </div>
  </div>
</template>

<style scoped>
.drop-zone {
  width: 100%; max-width: 480px;
  height: 180px;
  display: flex; align-items: center; justify-content: center;
  background: var(--color-bg-surface);
  border: 1.5px dashed var(--color-bg-border);
  border-radius: 14px;
  cursor: pointer;
  transition: border-color 0.2s, background 0.2s, transform 0.15s, box-shadow 0.2s;
  position: relative; overflow: hidden;
}

.drop-zone:hover {
  border-color: var(--color-text-muted);
  background: var(--color-bg-elevated);
}

.drop-zone.dragging {
  border-color: var(--color-accent);
  border-style: solid;
  background: rgba(0, 212, 255, 0.04);
  transform: scale(1.01);
  box-shadow: 0 0 0 1px var(--color-accent), 0 0 32px rgba(0,212,255,0.12);
}

.drop-zone.loading {
  cursor: wait;
  pointer-events: none;
  border-style: solid;
  border-color: rgba(0,212,255,0.3);
}

/* Scan line */
.scan-line {
  position: absolute; left: 0; right: 0; height: 1px;
  background: linear-gradient(90deg, transparent, var(--color-accent), transparent);
  animation: scan 1.5s ease infinite;
  pointer-events: none;
}

.zone-inner {
  display: flex; flex-direction: column; align-items: center; gap: 8px;
}

.drop-icon {
  color: var(--color-text-muted);
  transition: color 0.2s, transform 0.2s;
}
.drop-zone:hover .drop-icon { color: var(--color-accent); }
.drop-zone.dragging .drop-icon { color: var(--color-accent); transform: translateY(-4px); }
.drop-icon.pulse { animation: fade-in 0.3s ease; }

.zone-label {
  font-size: 15px; font-weight: 500;
  color: var(--color-text-primary);
}

.zone-sub {
  font-size: 13px; color: var(--color-text-muted);
}

.link { color: var(--color-accent); text-decoration: underline; text-underline-offset: 2px; }

.spinner {
  width: 28px; height: 28px;
  border: 2px solid var(--color-bg-border);
  border-top-color: var(--color-accent);
  border-radius: 50%;
  animation: spin 0.7s linear infinite;
}
</style>
