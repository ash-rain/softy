import { defineStore } from 'pinia'
import { ref } from 'vue'

export interface ChatMessage {
  id: string
  role: 'user' | 'assistant' | 'system'
  content: string
  streaming?: boolean
  timestamp: number
}

export const useAIStore = defineStore('ai', () => {
  const messages      = ref<ChatMessage[]>([])
  const isStreaming   = ref(false)
  const activeSession = ref<string | null>(null)

  function addMessage(msg: Omit<ChatMessage, 'id' | 'timestamp'>) {
    const id = crypto.randomUUID()
    messages.value.push({ ...msg, id, timestamp: Date.now() })
    return id
  }

  function appendChunk(id: string, text: string) {
    const msg = messages.value.find((m) => m.id === id)
    if (msg) msg.content += text
  }

  function finalizeMessage(id: string) {
    const msg = messages.value.find((m) => m.id === id)
    if (msg) msg.streaming = false
    isStreaming.value = false
  }

  function clearHistory() {
    messages.value = []
  }

  return { messages, isStreaming, activeSession, addMessage, appendChunk, finalizeMessage, clearHistory }
})
