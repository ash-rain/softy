<script setup lang="ts">
import { computed } from 'vue'
import { useBinaryStore } from '@/stores/binary.store'
import { useUIStore } from '@/stores/ui.store'

const binary = useBinaryStore()
const ui     = useUIStore()

const info = computed(() => {
  const m = binary.meta
  if (!m) return null
  return `${m.arch} · ${m.format} · ${m.bits}-bit · ${m.os}`
})

const functionCount = computed(() => {
  const done  = binary.functionList.length
  const total = binary.totalFunctions
  if (!binary.isDecompiling && done === 0) return null
  return binary.isDecompiling ? `${done} / ${total} functions` : `${done} functions`
})

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1048576).toFixed(2)} MB`
}
</script>

<template>
  <footer class="status-bar">
    <div class="status-left">
      <span v-if="info" class="status-item mono">{{ info }}</span>
      <span v-if="binary.meta" class="status-item mono muted">{{ formatSize(binary.meta.fileSize) }}</span>
      <span v-if="binary.meta?.compiler" class="status-item mono muted">{{ binary.meta.compiler }}</span>
    </div>
    <div class="status-center">
      <span v-if="ui.statusMessage" class="status-item">{{ ui.statusMessage }}</span>
    </div>
    <div class="status-right">
      <span v-if="functionCount" class="status-item mono">
        <span v-if="binary.isDecompiling" class="spin-dot" />
        {{ functionCount }}
      </span>
      <span class="status-item mono muted">{{ binary.decompileBackend }}</span>
    </div>
  </footer>
</template>

<style scoped>
.status-bar {
  height: 26px; display: flex; align-items: center;
  padding: 0 12px; background: var(--color-bg-base);
  border-top: 1px solid var(--color-bg-border); flex-shrink: 0; gap: 16px;
}
.status-left, .status-right { display: flex; align-items: center; gap: 12px; }
.status-center { flex: 1; text-align: center; }
.status-item { font-size: 11px; color: var(--color-text-secondary); }
.status-item.mono  { font-family: var(--font-family-code); }
.status-item.muted { color: var(--color-text-muted); }
.spin-dot {
  display: inline-block; width: 6px; height: 6px; border-radius: 50%;
  border: 1px solid var(--color-accent); border-top-color: transparent;
  animation: spin 0.8s linear infinite; margin-right: 4px; vertical-align: middle;
}
</style>
