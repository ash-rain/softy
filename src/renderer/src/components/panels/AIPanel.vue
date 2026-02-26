<script setup lang="ts">
import { ref, nextTick, computed, onMounted, onUnmounted } from 'vue'
import { useAIStore } from '@/stores/ai.store'
import { useSettingsStore } from '@/stores/settings.store'
import { useBinaryStore } from '@/stores/binary.store'

const ai       = useAIStore()
const settings = useSettingsStore()
const binary   = useBinaryStore()

const input     = ref('')
const scrollEl  = ref<HTMLElement | null>(null)
const sessionId = ref(crypto.randomUUID())
const pendingId = ref<string | null>(null)
let removeListener: (() => void) | null = null

const providerLabel = computed(() => {
  const map: Record<string, string> = {
    ollama:     `Ollama · ${settings.ai.ollamaModel}`,
    openai:     `OpenAI · ${settings.ai.openaiModel}`,
    anthropic:  `Anthropic · ${settings.ai.anthropicModel}`,
    openrouter: `OpenRouter · ${settings.ai.openrouterModel}`,
  }
  return map[settings.ai.provider] ?? settings.ai.provider
})

function getApiKey() {
  const p = settings.ai.provider
  if (p === 'openai')     return settings.ai.openaiApiKey
  if (p === 'anthropic')  return settings.ai.anthropicApiKey
  if (p === 'openrouter') return settings.ai.openrouterApiKey
  return ''
}

function getModel() {
  const p = settings.ai.provider
  if (p === 'openai')     return settings.ai.openaiModel
  if (p === 'anthropic')  return settings.ai.anthropicModel
  if (p === 'openrouter') return settings.ai.openrouterModel
  return settings.ai.ollamaModel
}

function buildSystem() {
  const m = binary.meta
  if (!m) return 'You are an expert reverse engineer.'
  return `You are an expert reverse engineer analyzing a binary.
Format: ${m.format} ${m.arch} ${m.bits}-bit, OS: ${m.os}, Compiler: ${m.compiler ?? 'unknown'}.
Active function: ${binary.activeFunction?.name ?? 'none'} at ${binary.activeFunction?.address ?? 'N/A'}.
Be concise and technical. Format code in markdown code blocks.`
}

function scrollToBottom() {
  nextTick(() => { if (scrollEl.value) scrollEl.value.scrollTop = scrollEl.value.scrollHeight })
}

async function sendMessage() {
  const text = input.value.trim()
  if (!text || ai.isStreaming) return
  input.value = ''

  ai.addMessage({ role: 'user', content: text })
  ai.isStreaming = true
  const msgId = ai.addMessage({ role: 'assistant', content: '', streaming: true })
  pendingId.value = msgId

  const messages = [
    { role: 'system', content: buildSystem() },
    ...ai.messages
      .filter((m) => !m.streaming && m.role !== 'system')
      .slice(-20)
      .map((m) => ({ role: m.role, content: m.content })),
  ]

  window.softy.ai.chat({ provider: settings.ai.provider, model: getModel(), apiKey: getApiKey(), messages, sessionId: sessionId.value })
  await nextTick()
  scrollToBottom()
}

function handleKeydown(e: KeyboardEvent) {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage() }
}

function renderMarkdown(text: string): string {
  if (!text) return ''
  return text
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/```(\w*)\n?([\s\S]*?)```/g, '<pre class="code-block"><code>$2</code></pre>')
    .replace(/`([^`]+)`/g, '<code class="inline-code">$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\n/g, '<br>')
}

function quickPrompt(text: string) { input.value = text }

onMounted(() => {
  removeListener = window.softy.ai.onEvent((ev) => {
    if (ev.sessionId !== sessionId.value) return
    if (ev.type === 'chunk' && pendingId.value) {
      ai.appendChunk(pendingId.value, ev.text as string)
      scrollToBottom()
    } else if (ev.type === 'complete' || ev.type === 'error') {
      if (pendingId.value) ai.finalizeMessage(pendingId.value)
      pendingId.value = null
    }
  })
})

onUnmounted(() => { removeListener?.() })
</script>

<template>
  <div class="ai-panel">
    <div class="provider-bar">
      <span class="ai-dot" />
      <span class="provider-label">{{ providerLabel }}</span>
      <button class="clear-btn" @click="ai.clearHistory()" title="Clear history">✕</button>
    </div>

    <div class="messages" ref="scrollEl">
      <div v-if="ai.messages.length === 0" class="empty-ai">
        <div class="empty-icon">✦</div>
        <p>Ask anything about this binary.</p>
        <div class="empty-hints">
          <span @click="quickPrompt('What does the main function do?')">What does main do?</span>
          <span @click="quickPrompt('Find any security vulnerabilities')">Find vulnerabilities</span>
          <span @click="quickPrompt('Rename all variables to meaningful names')">Rename variables</span>
        </div>
      </div>

      <div
        v-for="msg in ai.messages.filter(m => m.role !== 'system')"
        :key="msg.id"
        class="message"
        :class="msg.role"
      >
        <div v-if="msg.role === 'assistant'" class="msg-header">
          <span class="ai-badge">✦ AI</span>
          <span v-if="msg.streaming" class="streaming-dot" />
        </div>
        <div class="msg-content selectable" v-html="renderMarkdown(msg.content)" />
      </div>
    </div>

    <div class="input-area">
      <textarea
        v-model="input"
        class="chat-input"
        placeholder="Ask about this binary…"
        rows="3"
        :disabled="ai.isStreaming"
        @keydown="handleKeydown"
      />
      <button class="send-btn" :disabled="!input.trim() || ai.isStreaming" @click="sendMessage">
        <span v-if="ai.isStreaming" class="send-spinner" />
        <span v-else>↑</span>
      </button>
    </div>
  </div>
</template>

<style scoped>
.ai-panel { display: flex; flex-direction: column; height: 100%; }
.provider-bar { display: flex; align-items: center; gap: 6px; padding: 8px 12px; border-bottom: 1px solid var(--color-bg-border); flex-shrink: 0; }
.ai-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--color-ai); animation: pulse-glow 2s ease infinite; }
.provider-label { flex: 1; font-size: 11px; color: var(--color-text-muted); font-family: var(--font-family-code); }
.clear-btn { background: none; border: none; color: var(--color-text-muted); cursor: pointer; font-size: 10px; padding: 2px 4px; border-radius: 3px; }
.clear-btn:hover { color: var(--color-error); background: rgba(255,68,68,0.08); }
.messages { flex: 1; overflow-y: auto; padding: 12px; display: flex; flex-direction: column; gap: 12px; }
.empty-ai { display: flex; flex-direction: column; align-items: center; gap: 8px; padding: 40px 16px; text-align: center; }
.empty-icon { font-size: 24px; color: var(--color-ai); }
.empty-ai p { font-size: 12px; color: var(--color-text-secondary); }
.empty-hints { display: flex; flex-direction: column; gap: 6px; margin-top: 8px; }
.empty-hints span { font-size: 11px; color: var(--color-accent); cursor: pointer; padding: 4px 10px; background: rgba(0,212,255,0.05); border: 1px solid rgba(0,212,255,0.15); border-radius: 6px; transition: background 0.15s; }
.empty-hints span:hover { background: rgba(0,212,255,0.1); }
.message { display: flex; flex-direction: column; gap: 4px; }
.message.user .msg-content { align-self: flex-end; max-width: 90%; padding: 8px 12px; border-radius: 8px; background: var(--color-bg-elevated); border: 1px solid var(--color-bg-border); font-size: 13px; color: var(--color-text-primary); }
.message.assistant .msg-content { padding: 8px 12px; border-radius: 8px; background: rgba(168,85,247,0.06); border: 1px solid rgba(168,85,247,0.15); font-size: 13px; color: var(--color-text-primary); line-height: 1.6; }
.msg-header { display: flex; align-items: center; gap: 8px; }
.streaming-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--color-ai); animation: pulse-glow 1s ease infinite; }
:deep(.code-block) { background: var(--color-bg-void); border: 1px solid var(--color-bg-border); border-radius: 6px; padding: 10px 12px; margin: 6px 0; font-family: var(--font-family-code); font-size: 11px; color: var(--color-text-code); overflow-x: auto; white-space: pre; }
:deep(.inline-code) { font-family: var(--font-family-code); font-size: 11px; background: var(--color-bg-void); border: 1px solid var(--color-bg-border); border-radius: 3px; padding: 1px 5px; color: var(--color-text-code); }
.input-area { display: flex; gap: 8px; align-items: flex-end; padding: 10px 12px; border-top: 1px solid var(--color-bg-border); flex-shrink: 0; }
.chat-input { flex: 1; padding: 8px 10px; background: var(--color-bg-elevated); border: 1px solid var(--color-bg-border); border-radius: 8px; color: var(--color-text-primary); font-size: 13px; font-family: var(--font-family-ui); resize: none; outline: none; line-height: 1.5; transition: border-color 0.15s; }
.chat-input:focus { border-color: var(--color-ai); }
.chat-input::placeholder { color: var(--color-text-muted); }
.chat-input:disabled { opacity: 0.6; }
.send-btn { width: 36px; height: 36px; flex-shrink: 0; background: var(--color-ai); border: none; border-radius: 8px; color: white; font-size: 16px; cursor: pointer; display: flex; align-items: center; justify-content: center; transition: opacity 0.15s, transform 0.1s; }
.send-btn:hover:not(:disabled) { opacity: 0.85; transform: translateY(-1px); }
.send-btn:disabled { background: var(--color-bg-border); cursor: not-allowed; }
.send-spinner { width: 14px; height: 14px; border-radius: 50%; border: 2px solid rgba(255,255,255,0.3); border-top-color: white; animation: spin 0.7s linear infinite; }
</style>
