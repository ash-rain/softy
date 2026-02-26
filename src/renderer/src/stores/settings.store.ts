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
  provider: 'ollama',
  ollamaModel: 'deepseek-r1:14b',
  ollamaBaseUrl: 'http://localhost:11434',
  openaiApiKey: '',
  openaiModel: 'gpt-4o',
  anthropicApiKey: '',
  anthropicModel: 'claude-3-5-sonnet-20241022',
  openrouterApiKey: '',
  openrouterModel: 'deepseek/deepseek-r1',
  autoRename: false,
}

function load(): AISettings {
  try {
    const raw = localStorage.getItem('softy:ai-settings')
    return raw ? { ...DEFAULTS, ...JSON.parse(raw) } : { ...DEFAULTS }
  } catch { return { ...DEFAULTS } }
}

export const useSettingsStore = defineStore('settings', () => {
  const ai = ref<AISettings>(load())

  watch(ai, (val) => {
    localStorage.setItem('softy:ai-settings', JSON.stringify(val))
  }, { deep: true })

  return { ai }
})
