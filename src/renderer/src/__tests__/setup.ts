import { vi } from 'vitest'

// Mock window.softy (Electron contextBridge IPC) for all tests
const mockSofty = {
  binary: {
    open:    vi.fn(),
    analyze: vi.fn(),
    copyToWork: vi.fn(),
  },
  decompile: {
    start:   vi.fn(),
    stop:    vi.fn(),
    getFunction: vi.fn(),
  },
  compile: {
    code:    vi.fn(),
    assemble: vi.fn(),
  },
  ai: {
    chat:    vi.fn(),
    rename:  vi.fn(),
  },
  docker: {
    status:  vi.fn(),
    start:   vi.fn(),
    stop:    vi.fn(),
  },
  resources: {
    list:    vi.fn(),
    getData: vi.fn(),
  },
  on:       vi.fn(),
  off:      vi.fn(),
}

Object.defineProperty(window, 'softy', {
  value: mockSofty,
  writable: true,
})

// Provide crypto.randomUUID in happy-dom if missing
if (!globalThis.crypto?.randomUUID) {
  let counter = 0
  Object.defineProperty(globalThis, 'crypto', {
    value: {
      ...globalThis.crypto,
      randomUUID: () => `test-uuid-${++counter}`,
    },
    writable: true,
  })
}
