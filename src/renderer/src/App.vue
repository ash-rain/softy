<script setup lang="ts">
import { onMounted } from 'vue'
import { useUIStore } from '@/stores/ui.store'
import TitleBar from '@/components/layout/TitleBar.vue'

const ui = useUIStore()

onMounted(async () => {
  // Check Docker on startup
  ui.setDockerStatus('unknown')
  const status = await window.softy.docker.status()
  ui.setDockerStatus(status.running ? 'running' : 'stopped')
})
</script>

<template>
  <div class="app-root">
    <TitleBar />
    <div class="app-content">
      <RouterView />
    </div>
  </div>
</template>

<style scoped>
.app-root {
  display: flex;
  flex-direction: column;
  height: 100vh;
  background: var(--color-bg-void);
  overflow: hidden;
}
.app-content {
  flex: 1;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}
</style>
