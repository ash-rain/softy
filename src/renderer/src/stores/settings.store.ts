import { defineStore } from 'pinia'
import { ref, watch } from 'vue'

export interface AISettings {
  provider: 'ollama' | 'openai' | 'anthropic' | 'openrouter'
  ollamaModel: string
  ollamaBaseUrl: string
  openaiApiKey: string
  openaiModel: string
  anthropicApiKey: string
  anthropicModel: string
  openrouterApiKey: string
  openrouterModel: string
  autoRename: boolean
}

const DEFAULTS: AISettings = {
  provider:         'ollama',
  ollamaModel:      'deepseek-r1:14b',
  ollamaBaseUrl:    'http://localhost:11434',
  openaiApiKey:     '',
  openaiModel:      'gpt-4o',
  anthropicApiKey:  '',
  anthropicModel:   'claude-opus-4-6',
  openrouterApiKey: '',
  openrouterModel:  'deepseek/deepseek-r1',
  autoRename:       false,
}

function load(): AISettings {
  try {
    const raw = localStorage.getItem('softy:ai-settings')
    return raw ? { ...DEFAULTS, ...JSON.parse(raw) } : { ...DEFAULTS }
  } catch { return { ...DEFAULTS } }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function debounce<T extends (...args: any[]) => void>(fn: T, ms: number): T {
  let timer: ReturnType<typeof setTimeout>
  return ((...args: Parameters<T>) => {
    clearTimeout(timer)
    timer = setTimeout(() => fn(...args), ms)
  }) as T
}

const persist = debounce((val: AISettings) => {
  try {
    localStorage.setItem('softy:ai-settings', JSON.stringify(val))
  } catch { /* storage full or unavailable */ }
}, 300)

export const useSettingsStore = defineStore('settings', () => {
  const ai = ref<AISettings>(load())

  watch(ai, persist, { deep: true })

  return { ai }
})
