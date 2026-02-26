<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useBinaryStore } from '@/stores/binary.store'

const binary  = useBinaryStore()
const loading = ref(false)
const search  = ref('')

onMounted(async () => {
  if (binary.strings.length === 0 && binary.relPath) {
    loading.value = true
    try {
      const res = await window.softy.binary.getStrings(binary.relPath)
      binary.strings = res.strings
    } catch { /* ignore */ }
    loading.value = false
  }
})

const filtered = computed(() => {
  const q = search.value.toLowerCase()
  if (!q) return binary.strings.slice(0, 500)
  return binary.strings.filter((s) => s.value.toLowerCase().includes(q)).slice(0, 500)
})
</script>

<template>
  <div class="strings-panel">
    <div class="search-wrap">
      <input v-model="search" class="search" placeholder="Filter strings…" />
    </div>
    <div v-if="loading" class="loading">Loading strings…</div>
    <div v-else class="strings-list">
      <div v-for="s in filtered" :key="s.offset" class="string-item">
        <span class="str-offset mono">{{ '0x' + s.offset.toString(16).padStart(8, '0') }}</span>
        <span class="str-value selectable">{{ s.value }}</span>
      </div>
      <div v-if="binary.strings.length > 500" class="more-hint">Showing 500 of {{ binary.strings.length }}</div>
    </div>
  </div>
</template>

<style scoped>
.strings-panel { display: flex; flex-direction: column; height: 100%; }
.search-wrap { padding: 8px; flex-shrink: 0; border-bottom: 1px solid var(--color-bg-border); }
.search {
  width: 100%; padding: 6px 10px;
  background: var(--color-bg-elevated); border: 1px solid var(--color-bg-border);
  border-radius: 6px; color: var(--color-text-primary); font-size: 12px; outline: none;
}
.search::placeholder { color: var(--color-text-muted); }
.strings-list { flex: 1; overflow-y: auto; }
.loading { padding: 24px; text-align: center; font-size: 12px; color: var(--color-text-muted); }
.string-item { display: flex; gap: 10px; padding: 4px 10px; border-bottom: 1px solid var(--color-bg-border); }
.string-item:hover { background: var(--color-bg-surface); }
.str-offset { font-size: 10px; color: var(--color-text-muted); flex-shrink: 0; }
.str-value { font-size: 11px; font-family: var(--font-family-code); color: var(--color-text-code); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.more-hint { padding: 8px 10px; font-size: 11px; color: var(--color-text-muted); }
.mono { font-family: var(--font-family-code); }
</style>
