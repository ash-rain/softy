import { describe, it, expect, beforeEach } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useAIStore } from '../ai.store'

describe('ai.store', () => {
  beforeEach(() => { setActivePinia(createPinia()) })

  it('has correct initial state', () => {
    const store = useAIStore()
    expect(store.messages).toHaveLength(0)
    expect(store.isStreaming).toBe(false)
    expect(store.activeSession).toBeNull()
  })

  describe('addMessage', () => {
    it('adds a message with id and timestamp', () => {
      const store = useAIStore()
      const id = store.addMessage({ role: 'user', content: 'hello', streaming: false })
      expect(id).toBeTruthy()
      expect(store.messages).toHaveLength(1)
      expect(store.messages[0].role).toBe('user')
      expect(store.messages[0].content).toBe('hello')
      expect(store.messages[0].id).toBe(id)
      expect(store.messages[0].timestamp).toBeGreaterThan(0)
    })

    it('assigns unique ids to different messages', () => {
      const store = useAIStore()
      const id1 = store.addMessage({ role: 'user', content: 'a' })
      const id2 = store.addMessage({ role: 'assistant', content: 'b' })
      expect(id1).not.toBe(id2)
    })

    it('adds multiple messages in order', () => {
      const store = useAIStore()
      store.addMessage({ role: 'user', content: 'question' })
      store.addMessage({ role: 'assistant', content: 'answer' })
      expect(store.messages[0].role).toBe('user')
      expect(store.messages[1].role).toBe('assistant')
    })

    it('returns the message id', () => {
      const store = useAIStore()
      const id = store.addMessage({ role: 'system', content: 'sys' })
      expect(typeof id).toBe('string')
      expect(id.length).toBeGreaterThan(0)
    })
  })

  describe('appendChunk', () => {
    it('appends text to existing message content', () => {
      const store = useAIStore()
      const id = store.addMessage({ role: 'assistant', content: 'Hello', streaming: true })
      store.appendChunk(id, ' world')
      expect(store.messages[0].content).toBe('Hello world')
    })

    it('appends multiple chunks cumulatively', () => {
      const store = useAIStore()
      const id = store.addMessage({ role: 'assistant', content: '' })
      store.appendChunk(id, 'foo')
      store.appendChunk(id, 'bar')
      store.appendChunk(id, 'baz')
      expect(store.messages[0].content).toBe('foobarbaz')
    })

    it('does nothing for unknown id', () => {
      const store = useAIStore()
      expect(() => store.appendChunk('nonexistent-id', 'text')).not.toThrow()
    })
  })

  describe('finalizeMessage', () => {
    it('sets streaming to false on the message and clears isStreaming', () => {
      const store = useAIStore()
      store.isStreaming = true
      const id = store.addMessage({ role: 'assistant', content: 'answer', streaming: true })
      store.finalizeMessage(id)
      expect(store.messages[0].streaming).toBe(false)
      expect(store.isStreaming).toBe(false)
    })

    it('does nothing for unknown id', () => {
      const store = useAIStore()
      store.isStreaming = true
      expect(() => store.finalizeMessage('unknown')).not.toThrow()
      // isStreaming still set to false because finalizeMessage always sets it
      expect(store.isStreaming).toBe(false)
    })
  })

  describe('clearHistory', () => {
    it('removes all messages', () => {
      const store = useAIStore()
      store.addMessage({ role: 'user', content: 'a' })
      store.addMessage({ role: 'assistant', content: 'b' })
      store.clearHistory()
      expect(store.messages).toHaveLength(0)
    })

    it('is idempotent on empty history', () => {
      const store = useAIStore()
      expect(() => store.clearHistory()).not.toThrow()
      expect(store.messages).toHaveLength(0)
    })
  })

  describe('streaming workflow', () => {
    it('supports full streaming message lifecycle', () => {
      const store = useAIStore()
      store.isStreaming = true
      const id = store.addMessage({ role: 'assistant', content: '', streaming: true })
      store.appendChunk(id, 'The answer ')
      store.appendChunk(id, 'is 42.')
      store.finalizeMessage(id)

      const msg = store.messages[0]
      expect(msg.content).toBe('The answer is 42.')
      expect(msg.streaming).toBe(false)
      expect(store.isStreaming).toBe(false)
    })
  })
})
