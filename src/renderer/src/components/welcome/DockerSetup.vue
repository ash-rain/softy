<script setup lang="ts">
import { ref } from 'vue'
import { useUIStore } from '@/stores/ui.store'

const ui      = useUIStore()
const loading = ref(false)
const err     = ref<string | null>(null)

async function startDocker() {
  loading.value = true
  err.value     = null
  ui.setDockerStatus('starting')
  const result = await window.softy.docker.start()
  if (result.ok) {
    ui.setDockerStatus('running')
  } else {
    err.value = result.error ?? 'Failed to start Docker container'
    ui.setDockerStatus('stopped')
  }
  loading.value = false
}
</script>

<template>
  <div class="docker-notice">
    <div class="notice-icon">⬡</div>
    <div class="notice-body">
      <p class="notice-title">Docker container not running</p>
      <p class="notice-sub">The analysis tools run in Docker. Make sure Docker Desktop is running, then start the container.</p>
      <p v-if="err" class="notice-err">{{ err }}</p>
    </div>
    <button class="start-btn" :disabled="loading" @click="startDocker">
      <span v-if="loading" class="btn-spinner" />
      <span v-else>Start Container</span>
    </button>
  </div>
</template>

<style scoped>
.docker-notice {
  display: flex; align-items: flex-start; gap: 14px;
  padding: 16px 20px;
  background: rgba(255,170,0,0.06);
  border: 1px solid rgba(255,170,0,0.2);
  border-radius: 10px;
  max-width: 480px; width: 100%;
}
.notice-icon { font-size: 20px; color: var(--color-warn); flex-shrink: 0; margin-top: 2px; }
.notice-body { flex: 1; }
.notice-title { font-size: 13px; font-weight: 600; color: var(--color-warn); margin-bottom: 4px; }
.notice-sub   { font-size: 12px; color: var(--color-text-secondary); line-height: 1.5; }
.notice-err   { font-size: 11px; color: var(--color-error); margin-top: 6px; font-family: var(--font-family-code); }
.start-btn {
  flex-shrink: 0; padding: 8px 14px;
  background: rgba(255,170,0,0.1); border: 1px solid rgba(255,170,0,0.3);
  color: var(--color-warn); border-radius: 6px;
  font-size: 12px; font-weight: 600; cursor: pointer;
  transition: background 0.15s;
  display: flex; align-items: center; gap: 6px;
}
.start-btn:hover:not(:disabled)  { background: rgba(255,170,0,0.18); }
.start-btn:disabled { opacity: 0.6; cursor: not-allowed; }
.btn-spinner {
  width: 12px; height: 12px; border-radius: 50%;
  border: 1.5px solid rgba(255,170,0,0.3); border-top-color: var(--color-warn);
  animation: spin 0.7s linear infinite;
}
</style>
