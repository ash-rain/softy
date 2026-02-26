import { contextBridge, ipcRenderer } from 'electron'
import { electronAPI } from '@electron-toolkit/preload'

const softyAPI = {
  // ── Window controls ────────────────────────────────────────────────────────
  window: {
    minimize:    ()           => ipcRenderer.send('window:minimize'),
    maximize:    ()           => ipcRenderer.send('window:maximize'),
    close:       ()           => ipcRenderer.send('window:close'),
    isMaximized: ()           => ipcRenderer.invoke('window:isMaximized'),
  },

  // ── Binary / Docker ────────────────────────────────────────────────────────
  binary: {
    openDialog:    ()                           => ipcRenderer.invoke('binary:open-dialog'),
    analyze:       (localPath: string)          => ipcRenderer.invoke('binary:analyze', localPath),
    getStrings:    (relPath: string, min?: number) => ipcRenderer.invoke('binary:get-strings', relPath, min),
    listResources: (relPath: string)            => ipcRenderer.invoke('binary:list-resources', relPath),
  },

  docker: {
    status: ()  => ipcRenderer.invoke('docker:status'),
    start:  ()  => ipcRenderer.invoke('docker:start'),
  },

  // ── Decompiler ─────────────────────────────────────────────────────────────
  decompile: {
    start: (relPath: string, projectId: string, backend?: string) =>
      ipcRenderer.invoke('decompile:start', relPath, projectId, backend),
    onEvent: (cb: (event: Record<string, unknown>) => void) => {
      const handler = (_: Electron.IpcRendererEvent, data: Record<string, unknown>) => cb(data)
      ipcRenderer.on('decompile:event', handler)
      return () => ipcRenderer.removeListener('decompile:event', handler)
    },
  },

  // ── Compiler ───────────────────────────────────────────────────────────────
  compile: {
    code:     (req: unknown) => ipcRenderer.invoke('compile:code', req),
    assemble: (req: unknown) => ipcRenderer.invoke('compile:assemble', req),
    patch:    (req: unknown) => ipcRenderer.invoke('compile:patch', req),
  },

  // ── AI ─────────────────────────────────────────────────────────────────────
  ai: {
    providers:    ()           => ipcRenderer.invoke('ai:providers'),
    ollamaModels: ()           => ipcRenderer.invoke('ai:ollama-models'),
    rename: (payload: unknown) => ipcRenderer.invoke('ai:rename', payload),
    chat: (payload: unknown)   => ipcRenderer.send('ai:chat', payload),
    onEvent: (cb: (event: Record<string, unknown>) => void) => {
      const handler = (_: Electron.IpcRendererEvent, data: Record<string, unknown>) => cb(data)
      ipcRenderer.on('ai:event', handler)
      return () => ipcRenderer.removeListener('ai:event', handler)
    },
  },
}

if (process.contextIsolated) {
  contextBridge.exposeInMainWorld('electron', electronAPI)
  contextBridge.exposeInMainWorld('softy', softyAPI)
} else {
  // @ts-ignore
  window.electron = electronAPI
  // @ts-ignore
  window.softy = softyAPI
}

export type SoftyAPI = typeof softyAPI
