import { describe, it, expect, beforeEach } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useUIStore } from '../ui.store'

describe('ui.store', () => {
  beforeEach(() => { setActivePinia(createPinia()) })

  it('has correct default values', () => {
    const ui = useUIStore()
    expect(ui.sidebarOpen).toBe(true)
    expect(ui.rightPanelOpen).toBe(true)
    expect(ui.sidebarWidth).toBe(280)
    expect(ui.rightPanelWidth).toBe(360)
    expect(ui.rightPanelTab).toBe('meta')
    expect(ui.sidebarTab).toBe('functions')
    expect(ui.splitDisasm).toBe(false)
    expect(ui.dockerStatus).toBe('unknown')
    expect(ui.statusMessage).toBe('')
  })

  it('toggleSidebar flips sidebarOpen', () => {
    const ui = useUIStore()
    expect(ui.sidebarOpen).toBe(true)
    ui.toggleSidebar()
    expect(ui.sidebarOpen).toBe(false)
    ui.toggleSidebar()
    expect(ui.sidebarOpen).toBe(true)
  })

  it('toggleRightPanel flips rightPanelOpen', () => {
    const ui = useUIStore()
    ui.toggleRightPanel()
    expect(ui.rightPanelOpen).toBe(false)
    ui.toggleRightPanel()
    expect(ui.rightPanelOpen).toBe(true)
  })

  it('setRightPanelTab sets tab and opens panel', () => {
    const ui = useUIStore()
    ui.rightPanelOpen = false
    ui.setRightPanelTab('ai')
    expect(ui.rightPanelTab).toBe('ai')
    expect(ui.rightPanelOpen).toBe(true)
  })

  it('setRightPanelTab accepts all valid tab values', () => {
    const ui = useUIStore()
    for (const tab of ['meta', 'ai', 'resources', 'strings'] as const) {
      ui.setRightPanelTab(tab)
      expect(ui.rightPanelTab).toBe(tab)
    }
  })

  it('setDockerStatus updates dockerStatus', () => {
    const ui = useUIStore()
    ui.setDockerStatus('running')
    expect(ui.dockerStatus).toBe('running')
    ui.setDockerStatus('stopped')
    expect(ui.dockerStatus).toBe('stopped')
    ui.setDockerStatus('starting')
    expect(ui.dockerStatus).toBe('starting')
  })

  it('setStatus updates statusMessage', () => {
    const ui = useUIStore()
    ui.setStatus('Decompiling…')
    expect(ui.statusMessage).toBe('Decompiling…')
    ui.setStatus('')
    expect(ui.statusMessage).toBe('')
  })

  it('sidebarTab can be changed directly', () => {
    const ui = useUIStore()
    ui.sidebarTab = 'resources'
    expect(ui.sidebarTab).toBe('resources')
  })
})
