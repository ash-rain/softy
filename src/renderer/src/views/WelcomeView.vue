<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useBinaryStore } from '@/stores/binary.store'
import { useUIStore } from '@/stores/ui.store'
import DropZone from '@/components/welcome/DropZone.vue'
import DockerSetup from '@/components/welcome/DockerSetup.vue'

const router = useRouter()
const binary = useBinaryStore()
const ui     = useUIStore()

const loading = ref(false)
const error   = ref<string | null>(null)

async function openFile(path: string) {
  if (loading.value) return
  loading.value = true
  error.value   = null
  ui.setStatus('Analyzing binary…')

  try {
    const result = await window.softy.binary.analyze(path)
    binary.openBinary(result)
    router.push('/workspace')
  } catch (err: unknown) {
    error.value = (err as Error).message
  } finally {
    loading.value = false
    ui.setStatus('')
  }
}

async function openDialog() {
  const path = await window.softy.binary.openDialog()
  if (path) await openFile(path)
}
</script>

<template>
  <div class="welcome">
    <!-- Background grid -->
    <div class="grid-bg" aria-hidden="true" />
    <div class="hero-glow" aria-hidden="true" />

    <div class="welcome-content">
      <!-- Logo + tagline -->
      <div class="hero-brand animate-fade-up">
        <div class="hero-logo">◈</div>
        <h1 class="hero-title">Softy</h1>
        <p class="hero-tag">Every binary hides a story.</p>
      </div>

      <!-- Drop zone -->
      <DropZone
        :loading="loading"
        @file="openFile"
        @click-open="openDialog"
        class="animate-fade-up"
        style="animation-delay: 0.1s"
      />

      <!-- Error -->
      <div v-if="error" class="error-msg animate-fade-up">
        <span class="error-icon">⚠</span> {{ error }}
      </div>

      <!-- Docker not running notice -->
      <DockerSetup v-if="ui.dockerStatus === 'stopped'" class="animate-fade-up" style="animation-delay:0.2s" />

      <!-- Supported formats hint -->
      <div class="formats-hint animate-fade-up" style="animation-delay: 0.2s">
        <span class="fmt">.exe</span>
        <span class="fmt">.dll</span>
        <span class="fmt">ELF</span>
        <span class="fmt">Mach-O</span>
        <span class="fmt">.wasm</span>
        <span class="fmt">.dex</span>
        <span class="fmt">.class</span>
        <span class="fmt muted">+ more</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.welcome {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  position: relative;
  overflow: hidden;
  background: var(--color-bg-void);
}

.grid-bg {
  position: absolute; inset: 0; pointer-events: none;
  background-image:
    linear-gradient(rgba(0,212,255,0.025) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0,212,255,0.025) 1px, transparent 1px);
  background-size: 48px 48px;
  mask-image: radial-gradient(ellipse 70% 60% at 50% 40%, black 20%, transparent 100%);
}

.hero-glow {
  position: absolute; top: -100px; left: 50%; transform: translateX(-50%);
  width: 700px; height: 500px; pointer-events: none;
  background: radial-gradient(ellipse, rgba(0,212,255,0.06), transparent 70%);
}

.welcome-content {
  display: flex; flex-direction: column; align-items: center; gap: 32px;
  position: relative; z-index: 1;
  width: 100%; max-width: 640px;
  padding: 40px 24px;
}

.hero-brand {
  display: flex; flex-direction: column; align-items: center; gap: 10px;
  text-align: center;
}

.hero-logo {
  font-size: 40px; line-height: 1;
  background: linear-gradient(135deg, var(--color-accent), var(--color-ai));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}

.hero-title {
  font-size: 28px; font-weight: 700;
  letter-spacing: -0.03em;
  color: var(--color-text-primary);
}

.hero-tag {
  font-size: 15px; color: var(--color-text-secondary);
}

.error-msg {
  display: flex; align-items: center; gap: 8px;
  padding: 10px 16px;
  background: rgba(255,68,68,0.08);
  border: 1px solid rgba(255,68,68,0.2);
  border-radius: 8px;
  font-size: 13px; color: var(--color-error);
  max-width: 480px;
}
.error-icon { font-size: 14px; }

.formats-hint {
  display: flex; gap: 8px; flex-wrap: wrap; justify-content: center;
}
.fmt {
  font-family: var(--font-family-code); font-size: 11px;
  color: var(--color-text-muted);
  background: var(--color-bg-surface);
  border: 1px solid var(--color-bg-border);
  border-radius: 4px; padding: 3px 8px;
}
.fmt.muted { opacity: 0.5; }
</style>
