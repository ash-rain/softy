<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useBinaryStore } from '@/stores/binary.store'
import { useUIStore } from '@/stores/ui.store'

const route  = useRoute()
const router = useRouter()
const binary = useBinaryStore()
const ui     = useUIStore()

const isMaximized = ref(false)
const isMac = navigator.platform.toLowerCase().includes('mac')

const dockerStatusLabel = computed(() => {
  const map: Record<string, string> = {
    running: 'Docker', stopped: 'Docker offline', starting: 'Starting…', unknown: '…',
  }
  return map[ui.dockerStatus] ?? '…'
})

async function checkMaximized() {
  isMaximized.value = await window.softy.window.isMaximized()
}

onMounted(() => { checkMaximized() })

function minimize()  { window.softy.window.minimize() }
function maximize()  { window.softy.window.maximize(); checkMaximized() }
function closeWin()  { window.softy.window.close() }
function goHome()    { router.push('/') }
function goSettings(){ router.push('/settings') }
</script>

<template>
  <header class="titlebar drag-region">
    <div class="traffic-light-spacer" v-if="isMac" />

    <div class="brand no-drag" @click="goHome">
      <div class="logo-mark">◈</div>
      <span class="app-name">Softy</span>
      <span v-if="binary.projectName" class="separator">·</span>
      <span v-if="binary.projectName" class="project-name">{{ binary.projectName }}</span>
    </div>

    <div class="center-nav no-drag" v-if="route.name === 'workspace'">
      <button class="nav-btn" :class="{ active: !ui.splitDisasm }" @click="ui.splitDisasm = false">Code</button>
      <button class="nav-btn" :class="{ active: ui.splitDisasm }"  @click="ui.splitDisasm = true">Split</button>
    </div>

    <div class="spacer" />

    <div class="docker-status no-drag" :class="ui.dockerStatus">
      <span class="status-dot" />
      <span class="status-label">{{ dockerStatusLabel }}</span>
    </div>

    <button class="icon-btn no-drag" @click="goSettings" title="Settings">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="12" r="3"/>
        <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
      </svg>
    </button>

    <div class="win-controls no-drag" v-if="!isMac">
      <button class="win-btn" @click="minimize">─</button>
      <button class="win-btn" @click="maximize">{{ isMaximized ? '❐' : '□' }}</button>
      <button class="win-btn close" @click="closeWin">✕</button>
    </div>
  </header>
</template>

<style scoped>
.titlebar {
  height: 40px; display: flex; align-items: center; gap: 0;
  padding: 0 12px; background: var(--color-bg-base);
  border-bottom: 1px solid var(--color-bg-border);
  flex-shrink: 0; position: relative; z-index: 100;
}
.traffic-light-spacer { width: 68px; flex-shrink: 0; }
.brand { display: flex; align-items: center; gap: 8px; cursor: pointer; padding: 4px 8px; border-radius: 6px; transition: background 0.15s; }
.brand:hover { background: var(--color-bg-surface); }
.logo-mark {
  font-size: 16px; line-height: 1;
  background: linear-gradient(135deg, var(--color-accent), var(--color-ai));
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
}
.app-name   { font-size: 13px; font-weight: 600; color: var(--color-text-primary); letter-spacing: -0.01em; }
.separator  { color: var(--color-text-muted); font-size: 13px; }
.project-name { font-size: 13px; color: var(--color-text-secondary); font-family: var(--font-family-code); max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.center-nav { display: flex; gap: 2px; margin: 0 16px; }
.nav-btn {
  padding: 4px 12px; font-size: 12px; font-weight: 500;
  color: var(--color-text-muted); background: transparent; border: none;
  border-radius: 4px; cursor: pointer; transition: background 0.15s, color 0.15s;
}
.nav-btn:hover, .nav-btn.active { background: var(--color-bg-surface); color: var(--color-text-primary); }
.spacer { flex: 1; }
.docker-status {
  display: flex; align-items: center; gap: 5px; padding: 3px 10px;
  border-radius: 100px; font-size: 11px; font-weight: 500;
  margin-right: 8px; border: 1px solid transparent;
}
.docker-status.running  { color: var(--color-ok);    border-color: rgba(0,255,157,0.2);  background: rgba(0,255,157,0.06);  }
.docker-status.stopped  { color: var(--color-error); border-color: rgba(255,68,68,0.2);  background: rgba(255,68,68,0.06);  }
.docker-status.starting { color: var(--color-warn);  border-color: rgba(255,170,0,0.2);  background: rgba(255,170,0,0.06);  }
.docker-status.unknown  { color: var(--color-text-muted); border-color: var(--color-bg-border); }
.status-dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.docker-status.running .status-dot { animation: pulse-glow 2s ease infinite; }
.status-label { text-transform: capitalize; }
.icon-btn {
  width: 28px; height: 28px; display: flex; align-items: center; justify-content: center;
  background: transparent; border: none; color: var(--color-text-muted);
  border-radius: 6px; cursor: pointer; transition: background 0.15s, color 0.15s;
}
.icon-btn:hover { background: var(--color-bg-surface); color: var(--color-text-primary); }
.win-controls { display: flex; margin-left: 4px; }
.win-btn {
  width: 32px; height: 32px; background: transparent; border: none;
  color: var(--color-text-muted); font-size: 12px;
  cursor: pointer; border-radius: 4px; transition: background 0.15s, color 0.15s;
}
.win-btn:hover       { background: var(--color-bg-surface); color: var(--color-text-primary); }
.win-btn.close:hover { background: rgba(255,68,68,0.15); color: var(--color-error); }
</style>
