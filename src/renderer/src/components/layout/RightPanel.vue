<script setup lang="ts">
import { computed } from 'vue'
import { useUIStore } from '@/stores/ui.store'
import MetaPanel    from '@/components/panels/MetaPanel.vue'
import AIPanel      from '@/components/panels/AIPanel.vue'
import StringsPanel from '@/components/panels/StringsPanel.vue'

const ui = useUIStore()

const activePanel = computed(() => {
  const map: Record<string, unknown> = {
    meta:      MetaPanel,
    ai:        AIPanel,
    strings:   StringsPanel,
    resources: MetaPanel,
  }
  return map[ui.rightPanelTab] ?? MetaPanel
})
</script>

<template>
  <div class="right-panel">
    <div class="tab-strip">
      <button class="tab-btn" :class="{ active: ui.rightPanelTab === 'meta' }"      @click="ui.setRightPanelTab('meta')">Meta</button>
      <button class="tab-btn" :class="{ active: ui.rightPanelTab === 'ai' }"        @click="ui.setRightPanelTab('ai')">AI</button>
      <button class="tab-btn" :class="{ active: ui.rightPanelTab === 'strings' }"   @click="ui.setRightPanelTab('strings')">Strings</button>
      <button class="tab-btn" :class="{ active: ui.rightPanelTab === 'resources' }" @click="ui.setRightPanelTab('resources')">Resources</button>
    </div>
    <div class="panel-body">
      <KeepAlive>
        <component :is="activePanel" :key="ui.rightPanelTab" />
      </KeepAlive>
    </div>
  </div>
</template>

<style scoped>
.right-panel { display: flex; flex-direction: column; height: 100%; background: var(--color-bg-base); }
.tab-strip { display: flex; border-bottom: 1px solid var(--color-bg-border); flex-shrink: 0; }
.tab-btn {
  flex: 1; padding: 10px 0; font-size: 11px; font-weight: 500;
  color: var(--color-text-muted); background: none; border: none;
  cursor: pointer; border-bottom: 2px solid transparent; transition: color 0.15s, border-color 0.15s;
}
.tab-btn.active { color: var(--color-accent); border-bottom-color: var(--color-accent); }
.panel-body { flex: 1; overflow-y: auto; }
</style>
