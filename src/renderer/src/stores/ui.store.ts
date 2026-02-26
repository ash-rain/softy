import { defineStore } from 'pinia'
import { ref } from 'vue'

export type RightPanelTab = 'meta' | 'ai' | 'resources' | 'strings'
export type SidebarTab    = 'functions' | 'resources'

export const useUIStore = defineStore('ui', () => {
  const sidebarWidth    = ref(280)
  const rightPanelWidth = ref(360)
  const sidebarOpen     = ref(true)
  const rightPanelOpen  = ref(true)
  const rightPanelTab   = ref<RightPanelTab>('meta')
  const sidebarTab      = ref<SidebarTab>('functions')
  const splitDisasm     = ref(false)   // show disasm pane alongside editor
  const dockerStatus    = ref<'unknown' | 'running' | 'stopped' | 'starting'>('unknown')
  const statusMessage   = ref('')

  function setDockerStatus(s: typeof dockerStatus.value) { dockerStatus.value = s }
  function setStatus(msg: string) { statusMessage.value = msg }
  function toggleSidebar() { sidebarOpen.value = !sidebarOpen.value }
  function toggleRightPanel() { rightPanelOpen.value = !rightPanelOpen.value }
  function setRightPanelTab(tab: RightPanelTab) {
    rightPanelTab.value = tab
    rightPanelOpen.value = true
  }

  return {
    sidebarWidth, rightPanelWidth, sidebarOpen, rightPanelOpen,
    rightPanelTab, sidebarTab, splitDisasm, dockerStatus, statusMessage,
    setDockerStatus, setStatus, toggleSidebar, toggleRightPanel, setRightPanelTab,
  }
})
