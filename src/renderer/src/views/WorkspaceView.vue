<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import { useBinaryStore } from '@/stores/binary.store'
import { useUIStore } from '@/stores/ui.store'
import AppShell from '@/components/layout/AppShell.vue'

const binary = useBinaryStore()
const ui     = useUIStore()
let removeListener: (() => void) | null = null

onMounted(async () => {
  if (!binary.projectId || !binary.relPath) return

  // Start decompilation
  binary.isDecompiling = true
  ui.setStatus(`Decompiling with ${binary.decompileBackend}…`)

  try {
    await window.softy.decompile.start(binary.relPath, binary.projectId, binary.decompileBackend)
  } catch (err) {
    const msg = (err as Error).message ?? 'Failed to start decompilation'
    binary.isDecompiling = false
    binary.decompileError = msg
    ui.setStatus('')
    return
  }

  // Listen for streamed function events
  removeListener = window.softy.decompile.onEvent((ev) => {
    if (ev.type === 'function') {
      binary.addFunction(ev as unknown as Parameters<typeof binary.addFunction>[0])
      binary.decompileProgress = binary.functionList.length
    } else if (ev.type === 'progress') {
      ui.setStatus(`Decompiling ${ev.message as string}…`)
    } else if (ev.type === 'complete') {
      binary.isDecompiling = false
      binary.totalFunctions = binary.functionList.length
      ui.setStatus(`Decompiled ${binary.totalFunctions} functions`)
      setTimeout(() => ui.setStatus(''), 3000)
    } else if (ev.type === 'error') {
      binary.isDecompiling = false
      binary.decompileError = ev.message as string
      ui.setStatus('')
    }
  })

  // Load resources in background
  window.softy.binary.listResources(binary.relPath).then((res) => {
    binary.resources = res.resources
  }).catch(() => {})
})

onUnmounted(() => {
  removeListener?.()
})
</script>

<template>
  <AppShell />
</template>
