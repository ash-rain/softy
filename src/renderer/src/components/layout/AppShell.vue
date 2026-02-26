<script setup lang="ts">
import { ref, computed } from 'vue'
import { useUIStore } from '@/stores/ui.store'
import Sidebar from '@/components/layout/Sidebar.vue'
import RightPanel from '@/components/layout/RightPanel.vue'
import CodeEditor from '@/components/editor/CodeEditor.vue'
import StatusBar from '@/components/layout/StatusBar.vue'

const ui = useUIStore()

// Resize logic
const isResizingLeft  = ref(false)
const isResizingRight = ref(false)

function startResizeLeft(e: MouseEvent) {
  isResizingLeft.value = true
  const startX = e.clientX
  const startW = ui.sidebarWidth
  const onMove = (ev: MouseEvent) => {
    const delta = ev.clientX - startX
    ui.sidebarWidth = Math.max(200, Math.min(480, startW + delta))
  }
  const onUp = () => {
    isResizingLeft.value = false
    window.removeEventListener('mousemove', onMove)
    window.removeEventListener('mouseup', onUp)
  }
  window.addEventListener('mousemove', onMove)
  window.addEventListener('mouseup', onUp)
}

function startResizeRight(e: MouseEvent) {
  isResizingRight.value = true
  const startX = e.clientX
  const startW = ui.rightPanelWidth
  const onMove = (ev: MouseEvent) => {
    const delta = startX - ev.clientX
    ui.rightPanelWidth = Math.max(280, Math.min(560, startW + delta))
  }
  const onUp = () => {
    isResizingRight.value = false
    window.removeEventListener('mousemove', onMove)
    window.removeEventListener('mouseup', onUp)
  }
  window.addEventListener('mousemove', onMove)
  window.addEventListener('mouseup', onUp)
}
</script>

<template>
  <div class="shell">
    <!-- Main 3-column layout -->
    <div class="workspace" :class="{ 'is-resizing': isResizingLeft || isResizingRight }">
      <!-- Left sidebar -->
      <div
        v-if="ui.sidebarOpen"
        class="sidebar-col"
        :style="{ width: ui.sidebarWidth + 'px' }"
      >
        <Sidebar />
      </div>

      <!-- Left resize handle -->
      <div
        v-if="ui.sidebarOpen"
        class="resize-handle"
        @mousedown.prevent="startResizeLeft"
      />

      <!-- Editor area -->
      <div class="editor-col">
        <CodeEditor />
      </div>

      <!-- Right resize handle -->
      <div
        v-if="ui.rightPanelOpen"
        class="resize-handle"
        @mousedown.prevent="startResizeRight"
      />

      <!-- Right panel -->
      <div
        v-if="ui.rightPanelOpen"
        class="right-col"
        :style="{ width: ui.rightPanelWidth + 'px' }"
      >
        <RightPanel />
      </div>
    </div>

    <StatusBar />
  </div>
</template>

<style scoped>
.shell {
  display: flex; flex-direction: column;
  flex: 1; overflow: hidden;
}

.workspace {
  display: flex; flex: 1; overflow: hidden;
}
.workspace.is-resizing { cursor: col-resize; user-select: none; }

.sidebar-col {
  flex-shrink: 0;
  border-right: 1px solid var(--color-bg-border);
  overflow: hidden;
  display: flex; flex-direction: column;
}

.editor-col {
  flex: 1; overflow: hidden;
  display: flex; flex-direction: column;
  min-width: 0;
}

.right-col {
  flex-shrink: 0;
  border-left: 1px solid var(--color-bg-border);
  overflow: hidden;
  display: flex; flex-direction: column;
}
</style>
