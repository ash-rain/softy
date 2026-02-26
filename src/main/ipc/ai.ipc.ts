/**
 * AI IPC — streaming chat with Ollama (local) or hosted providers.
 * Provider selection and API keys managed via settings store.
 */

import { ipcMain, BrowserWindow } from 'electron'
import { DockerBridge } from '../bridge/docker'

const OLLAMA_BASE = 'http://localhost:11434'

export function registerAIIPC(_docker: DockerBridge): void {

  ipcMain.handle('ai:providers', async () => {
    // Check Ollama availability
    const ollamaOk = await fetch(`${OLLAMA_BASE}/api/tags`, { signal: AbortSignal.timeout(2000) })
      .then(() => true).catch(() => false)

    return [
      { id: 'ollama',     name: 'Ollama (Local)',  available: ollamaOk,  local: true  },
      { id: 'openai',     name: 'OpenAI',          available: true,      local: false },
      { id: 'anthropic',  name: 'Anthropic',       available: true,      local: false },
      { id: 'openrouter', name: 'OpenRouter',      available: true,      local: false },
    ]
  })

  ipcMain.handle('ai:ollama-models', async () => {
    try {
      const res = await fetch(`${OLLAMA_BASE}/api/tags`, { signal: AbortSignal.timeout(3000) })
      const data = await res.json() as { models: { name: string }[] }
      return data.models?.map((m) => m.name) ?? []
    } catch {
      return []
    }
  })

  // Streaming chat — sends chunks back via webContents.send
  // Non-streaming rename — returns suggested snake_case name or null
  ipcMain.handle('ai:rename', async (_, { provider, model, apiKey, code, currentName }: {
    provider: string; model: string; apiKey: string; code: string; currentName: string
  }) => {
    const prompt = [
      'You are a reverse engineering expert.',
      'Given this decompiled C function, suggest a concise snake_case name that describes what it does.',
      'Reply with ONLY the function name — no explanation, no parentheses, no extra text.',
      '',
      `Current name: ${currentName}`,
      '',
      '```c',
      code.slice(0, 3000),
      '```',
    ].join('\n')

    const messages = [{ role: 'user' as const, content: prompt }]
    let result = ''
    const onChunk = (t: string) => { result += t }

    try {
      if (provider === 'ollama') {
        await streamOllama(model, messages, onChunk)
      } else if (provider === 'openai') {
        await streamOpenAI(model, messages, apiKey, onChunk)
      } else if (provider === 'anthropic') {
        await streamAnthropic(model, messages, apiKey, onChunk)
      } else if (provider === 'openrouter') {
        await streamOpenAI(model, messages, apiKey, onChunk, 'https://openrouter.ai/api/v1')
      }
      // Extract first token, strip non-identifier chars
      const name = result.trim().split(/[\s\n(]/)[0].replace(/[^a-zA-Z0-9_]/g, '')
      return name || null
    } catch {
      return null
    }
  })

  ipcMain.on('ai:chat', async (event, { provider, model, apiKey, messages, sessionId }) => {
    const win = BrowserWindow.fromWebContents(event.sender)
    if (!win) return

    const send = (type: string, payload: Record<string, unknown>) => {
      if (!win.isDestroyed()) win.webContents.send('ai:event', { type, sessionId, ...payload })
    }

    try {
      if (provider === 'ollama') {
        await streamOllama(model, messages, (chunk) => send('chunk', { text: chunk }))
      } else if (provider === 'openai') {
        await streamOpenAI(model, messages, apiKey, (chunk) => send('chunk', { text: chunk }))
      } else if (provider === 'anthropic') {
        await streamAnthropic(model, messages, apiKey, (chunk) => send('chunk', { text: chunk }))
      } else if (provider === 'openrouter') {
        await streamOpenAI(model, messages, apiKey, (chunk) => send('chunk', { text: chunk }),
          'https://openrouter.ai/api/v1')
      }
      send('complete', {})
    } catch (err: unknown) {
      send('error', { message: (err as Error).message })
    }
  })
}

// ── Ollama streaming ──────────────────────────────────────────────────────────

async function streamOllama(
  model: string,
  messages: { role: string; content: string }[],
  onChunk: (text: string) => void,
): Promise<void> {
  const res = await fetch(`${OLLAMA_BASE}/api/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ model, messages, stream: true, options: { temperature: 0.1, num_ctx: 32768 } }),
  })
  if (!res.ok || !res.body) throw new Error(`Ollama error: ${res.status}`)

  const reader = res.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''

  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })
    const lines = buffer.split('\n')
    buffer = lines.pop() ?? ''
    for (const line of lines) {
      if (line.trim()) {
        try {
          const data = JSON.parse(line)
          if (data.message?.content) onChunk(data.message.content)
        } catch { /* skip */ }
      }
    }
  }
}

// ── OpenAI-compatible streaming (OpenAI + OpenRouter) ────────────────────────

async function streamOpenAI(
  model: string,
  messages: { role: string; content: string }[],
  apiKey: string,
  onChunk: (text: string) => void,
  baseUrl = 'https://api.openai.com/v1',
): Promise<void> {
  const res = await fetch(`${baseUrl}/chat/completions`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({ model, messages, stream: true, temperature: 0.1 }),
  })
  if (!res.ok || !res.body) {
    const err = await res.text()
    throw new Error(`OpenAI error ${res.status}: ${err}`)
  }

  const reader = res.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''

  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })
    const lines = buffer.split('\n')
    buffer = lines.pop() ?? ''
    for (const line of lines) {
      if (line.startsWith('data: ')) {
        const raw = line.slice(6).trim()
        if (raw === '[DONE]') return
        try {
          const data = JSON.parse(raw)
          const text = data.choices?.[0]?.delta?.content
          if (text) onChunk(text)
        } catch { /* skip */ }
      }
    }
  }
}

// ── Anthropic streaming ───────────────────────────────────────────────────────

async function streamAnthropic(
  model: string,
  messages: { role: string; content: string }[],
  apiKey: string,
  onChunk: (text: string) => void,
): Promise<void> {
  // Separate system message from conversation
  const systemMsg = messages.find((m) => m.role === 'system')
  const convMsgs  = messages.filter((m) => m.role !== 'system')

  const body: Record<string, unknown> = {
    model,
    max_tokens: 8192,
    stream: true,
    messages: convMsgs,
  }
  if (systemMsg) body.system = systemMsg.content

  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify(body),
  })
  if (!res.ok || !res.body) {
    const err = await res.text()
    throw new Error(`Anthropic error ${res.status}: ${err}`)
  }

  const reader = res.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''

  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })
    const lines = buffer.split('\n')
    buffer = lines.pop() ?? ''
    for (const line of lines) {
      if (line.startsWith('data: ')) {
        try {
          const data = JSON.parse(line.slice(6))
          if (data.type === 'content_block_delta' && data.delta?.text) {
            onChunk(data.delta.text)
          }
        } catch { /* skip */ }
      }
    }
  }
}
