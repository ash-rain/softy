<script setup lang="ts">
import { ref, computed, defineComponent, h } from 'vue'
import { useBinaryStore } from '@/stores/binary.store'
import { useUIStore } from '@/stores/ui.store'

const binary = useBinaryStore()
const ui     = useUIStore()
const search = ref('')

const filteredFunctions = computed(() => {
  const q = search.value.toLowerCase().trim()
  if (!q) return binary.functionList
  return binary.functionList.filter((fn) =>
    fn.name.toLowerCase().includes(q) || fn.address.toLowerCase().includes(q)
  )
})

function formatBytes(b: number) {
  if (b < 1024) return `${b}B`
  if (b < 1048576) return `${(b / 1024).toFixed(0)}KB`
  return `${(b / 1048576).toFixed(1)}MB`
}

// Recursive resource tree node (inline component)
const ResourceTreeNode = defineComponent({
  name: 'ResourceTreeNode',
  props: { node: { type: Object, required: true } },
  setup(props) {
    const open = ref(false)
    return () => h('div', { class: 'rtree-node' }, [
      h('div', {
        class: 'rtree-row',
        onClick: () => {
          if (props.node.children?.length > 0) open.value = !open.value
          else ui.setRightPanelTab('resources')
        },
      }, [
        props.node.children?.length > 0
          ? h('span', { class: 'rtree-arrow' }, open.value ? '▾' : '▸')
          : h('span', { class: 'rtree-leaf' }, '·'),
        h('span', { class: 'rtree-name' }, props.node.name),
        props.node.size > 0
          ? h('span', { class: 'rtree-size' }, formatBytes(props.node.size))
          : null,
      ]),
      open.value && props.node.children?.length > 0
        ? h('div', { class: 'rtree-children' },
            props.node.children.map((c: { id: string }) =>
              h(ResourceTreeNode, { node: c, key: c.id })
            )
          )
        : null,
    ])
  },
})
</script>

<template>
  <div class="sidebar">
    <div class="tab-strip">
      <button class="tab-btn" :class="{ active: ui.sidebarTab === 'functions' }" @click="ui.sidebarTab = 'functions'">Functions</button>
      <button class="tab-btn" :class="{ active: ui.sidebarTab === 'resources' }" @click="ui.sidebarTab = 'resources'">Resources</button>
    </div>

    <template v-if="ui.sidebarTab === 'functions'">
      <div class="search-wrap">
        <input v-model="search" class="search" placeholder="Search functions…" spellcheck="false" />
      </div>
      <div v-if="binary.isDecompiling && filteredFunctions.length === 0" class="empty-state">
        <div class="loading-dots"><span /><span /><span /></div>
        <p class="empty-label">Decompiling…</p>
      </div>
      <div v-else class="fn-list">
        <div
          v-for="fn in filteredFunctions"
          :key="fn.address"
          class="fn-item"
          :class="{ active: binary.activeFunction?.address === fn.address }"
          :title="fn.signature"
          @click="binary.setActiveFunction(fn.address)"
        >
          <span class="fn-name">{{ fn.name }}</span>
          <span class="fn-addr">{{ fn.address }}</span>
        </div>
        <div v-if="binary.isDecompiling" class="loading-more">
          <span class="spin-dot" /> Decompiling…
        </div>
      </div>
    </template>

    <template v-if="ui.sidebarTab === 'resources'">
      <div class="resource-list">
        <div v-if="binary.resources.length === 0" class="empty-state">
          <p class="empty-label">No resources found</p>
        </div>
        <ResourceTreeNode v-for="node in binary.resources" :key="node.id" :node="node" />
      </div>
    </template>
  </div>
</template>

<style scoped>
.sidebar { display: flex; flex-direction: column; height: 100%; background: var(--color-bg-base); }
.tab-strip { display: flex; border-bottom: 1px solid var(--color-bg-border); flex-shrink: 0; }
.tab-btn {
  flex: 1; padding: 10px 0; font-size: 12px; font-weight: 500;
  color: var(--color-text-muted); background: none; border: none;
  cursor: pointer; border-bottom: 2px solid transparent; transition: color 0.15s, border-color 0.15s;
}
.tab-btn.active { color: var(--color-accent); border-bottom-color: var(--color-accent); }
.search-wrap { padding: 8px; flex-shrink: 0; }
.search {
  width: 100%; padding: 7px 10px; background: var(--color-bg-elevated);
  border: 1px solid var(--color-bg-border); border-radius: 6px;
  color: var(--color-text-primary); font-size: 12px; outline: none; transition: border-color 0.15s;
}
.search:focus { border-color: var(--color-accent); }
.search::placeholder { color: var(--color-text-muted); }
.fn-list { flex: 1; overflow-y: auto; }
.fn-item {
  display: flex; justify-content: space-between; align-items: center;
  padding: 7px 12px; cursor: pointer; border-left: 2px solid transparent;
  transition: background 0.1s, border-color 0.1s;
}
.fn-item:hover  { background: var(--color-bg-surface); }
.fn-item.active { background: var(--color-bg-elevated); border-left-color: var(--color-accent); }
.fn-name {
  font-family: var(--font-family-code); font-size: 12px; color: var(--color-text-primary);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; min-width: 0;
}
.fn-addr {
  font-family: var(--font-family-code); font-size: 10px; color: var(--color-text-muted);
  flex-shrink: 0; margin-left: 8px;
}
.empty-state { display: flex; flex-direction: column; align-items: center; gap: 8px; padding: 40px 20px; }
.empty-label { font-size: 12px; color: var(--color-text-muted); }
.loading-dots { display: flex; gap: 4px; }
.loading-dots span {
  width: 5px; height: 5px; border-radius: 50%; background: var(--color-accent); opacity: 0.4;
  animation: fade-in 1.2s ease infinite;
}
.loading-dots span:nth-child(2) { animation-delay: 0.2s; }
.loading-dots span:nth-child(3) { animation-delay: 0.4s; }
.loading-more { display: flex; align-items: center; gap: 6px; padding: 8px 12px; font-size: 11px; color: var(--color-text-muted); }
.spin-dot {
  display: inline-block; width: 8px; height: 8px; border-radius: 50%;
  border: 1px solid var(--color-accent); border-top-color: transparent;
  animation: spin 0.7s linear infinite;
}
.resource-list { flex: 1; overflow-y: auto; padding: 4px 0; }
.rtree-node {}
.rtree-row {
  display: flex; align-items: center; gap: 6px; padding: 5px 10px;
  cursor: pointer; font-size: 12px; color: var(--color-text-secondary); transition: background 0.1s;
}
.rtree-row:hover { background: var(--color-bg-surface); color: var(--color-text-primary); }
.rtree-arrow, .rtree-leaf { font-size: 10px; color: var(--color-text-muted); width: 10px; flex-shrink: 0; }
.rtree-name { flex: 1; font-family: var(--font-family-code); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.rtree-size { font-size: 10px; color: var(--color-text-muted); flex-shrink: 0; }
.rtree-children { padding-left: 14px; }
</style>
