import { describe, it, expect, beforeEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'

// localStorage must be mocked BEFORE the store module is imported, because
// the store calls load() at module evaluation time.
const storageMock = (() => {
  let store: Record<string, string> = {}
  return {
    getItem:    (k: string) => store[k] ?? null,
    setItem:    (k: string, v: string) => { store[k] = v },
    removeItem: (k: string) => { delete store[k] },
    clear:      () => { store = {} },
  }
})()
Object.defineProperty(globalThis, 'localStorage', { value: storageMock, writable: true })

describe('settings.store', () => {
  beforeEach(async () => {
    storageMock.clear()
    vi.resetModules()
    setActivePinia(createPinia())
  })

  it('loads default values when localStorage is empty', async () => {
    const { useSettingsStore } = await import('../settings.store')
    const settings = useSettingsStore()
    expect(settings.ai.provider).toBe('ollama')
    expect(settings.ai.ollamaModel).toBe('deepseek-r1:14b')
    expect(settings.ai.ollamaBaseUrl).toBe('http://localhost:11434')
    expect(settings.ai.openaiApiKey).toBe('')
    expect(settings.ai.openaiModel).toBe('gpt-4o')
    expect(settings.ai.anthropicModel).toBe('claude-opus-4-6')
    expect(settings.ai.openrouterModel).toBe('deepseek/deepseek-r1')
    expect(settings.ai.autoRename).toBe(false)
  })

  it('merges stored values over defaults', async () => {
    storageMock.setItem('softy:ai-settings', JSON.stringify({
      provider: 'openai',
      openaiApiKey: 'sk-test-key',
      openaiModel: 'gpt-4-turbo',
    }))
    const { useSettingsStore } = await import('../settings.store')
    const settings = useSettingsStore()
    expect(settings.ai.provider).toBe('openai')
    expect(settings.ai.openaiApiKey).toBe('sk-test-key')
    expect(settings.ai.openaiModel).toBe('gpt-4-turbo')
    // Defaults still present for unset keys
    expect(settings.ai.ollamaModel).toBe('deepseek-r1:14b')
  })

  it('falls back to defaults when localStorage contains invalid JSON', async () => {
    storageMock.setItem('softy:ai-settings', 'not valid json{{{')
    const { useSettingsStore } = await import('../settings.store')
    const settings = useSettingsStore()
    expect(settings.ai.provider).toBe('ollama')
  })

  it('persists changes to localStorage (debounced)', async () => {
    vi.useFakeTimers()
    const { useSettingsStore } = await import('../settings.store')
    const settings = useSettingsStore()

    settings.ai.provider = 'anthropic'
    settings.ai.anthropicApiKey = 'test-key'

    // Advance past the 300ms debounce
    await vi.advanceTimersByTimeAsync(400)

    const stored = JSON.parse(storageMock.getItem('softy:ai-settings') ?? '{}')
    expect(stored.provider).toBe('anthropic')
    expect(stored.anthropicApiKey).toBe('test-key')
    vi.useRealTimers()
  })

  it('debounces rapid writes (only one save for multiple quick changes)', async () => {
    vi.useFakeTimers()
    const setItemSpy = vi.spyOn(storageMock, 'setItem')
    const { useSettingsStore } = await import('../settings.store')
    const settings = useSettingsStore()

    // Make several rapid changes
    settings.ai.provider = 'openai'
    settings.ai.openaiApiKey = 'key1'
    settings.ai.openaiApiKey = 'key2'
    settings.ai.openaiApiKey = 'key3'

    // Before debounce fires, nothing saved yet
    expect(setItemSpy).not.toHaveBeenCalled()

    await vi.advanceTimersByTimeAsync(400)

    // Only one write after debounce
    expect(setItemSpy).toHaveBeenCalledTimes(1)
    const stored = JSON.parse(storageMock.getItem('softy:ai-settings') ?? '{}')
    expect(stored.openaiApiKey).toBe('key3')
    vi.useRealTimers()
  })

  it('ai object exposes all required fields', async () => {
    const { useSettingsStore } = await import('../settings.store')
    const settings = useSettingsStore()
    const keys = [
      'provider', 'ollamaModel', 'ollamaBaseUrl',
      'openaiApiKey', 'openaiModel',
      'anthropicApiKey', 'anthropicModel',
      'openrouterApiKey', 'openrouterModel',
      'autoRename',
    ]
    for (const key of keys) {
      expect(settings.ai).toHaveProperty(key)
    }
  })
})
