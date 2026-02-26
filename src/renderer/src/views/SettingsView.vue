<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useSettingsStore } from '@/stores/settings.store'

const router   = useRouter()
const settings = useSettingsStore()
const ollamaModels = ref<string[]>([])
const testingProvider = ref(false)
const testResult = ref<string | null>(null)

onMounted(async () => {
  ollamaModels.value = await window.softy.ai.ollamaModels()
})

async function testProvider() {
  testingProvider.value = true
  testResult.value = null
  // Simple connectivity test
  const providers = await window.softy.ai.providers()
  const current = providers.find((p: { id: string }) => p.id === settings.ai.provider)
  testResult.value = current?.available ? '✓ Connected' : '✗ Not reachable'
  testingProvider.value = false
}
</script>

<template>
  <div class="settings-view">
    <div class="settings-content">
      <div class="settings-header">
        <button class="back-btn" @click="router.back()">← Back</button>
        <h2 class="settings-title">Settings</h2>
      </div>

      <!-- AI Provider -->
      <section class="settings-section">
        <h3 class="section-title">AI Provider</h3>
        <div class="field">
          <label>Provider</label>
          <select v-model="settings.ai.provider" class="select">
            <option value="ollama">Ollama (Local)</option>
            <option value="openai">OpenAI</option>
            <option value="anthropic">Anthropic</option>
            <option value="openrouter">OpenRouter</option>
          </select>
        </div>

        <!-- Ollama config -->
        <template v-if="settings.ai.provider === 'ollama'">
          <div class="field">
            <label>Base URL</label>
            <input v-model="settings.ai.ollamaBaseUrl" class="input" placeholder="http://localhost:11434" />
          </div>
          <div class="field">
            <label>Model</label>
            <select v-if="ollamaModels.length > 0" v-model="settings.ai.ollamaModel" class="select">
              <option v-for="m in ollamaModels" :key="m" :value="m">{{ m }}</option>
            </select>
            <input v-else v-model="settings.ai.ollamaModel" class="input" placeholder="deepseek-r1:14b" />
          </div>
        </template>

        <!-- OpenAI -->
        <template v-if="settings.ai.provider === 'openai'">
          <div class="field">
            <label>API Key</label>
            <input v-model="settings.ai.openaiApiKey" type="password" class="input" placeholder="sk-…" />
          </div>
          <div class="field">
            <label>Model</label>
            <select v-model="settings.ai.openaiModel" class="select">
              <option value="gpt-4o">GPT-4o</option>
              <option value="gpt-4o-mini">GPT-4o mini</option>
            </select>
          </div>
        </template>

        <!-- Anthropic -->
        <template v-if="settings.ai.provider === 'anthropic'">
          <div class="field">
            <label>API Key</label>
            <input v-model="settings.ai.anthropicApiKey" type="password" class="input" placeholder="sk-ant-…" />
          </div>
          <div class="field">
            <label>Model</label>
            <select v-model="settings.ai.anthropicModel" class="select">
              <option value="claude-sonnet-4-6">claude-sonnet-4-6</option>
              <option value="claude-3-5-sonnet-20241022">Claude 3.5 Sonnet</option>
              <option value="claude-3-haiku-20240307">Claude 3 Haiku</option>
            </select>
          </div>
        </template>

        <!-- OpenRouter -->
        <template v-if="settings.ai.provider === 'openrouter'">
          <div class="field">
            <label>API Key</label>
            <input v-model="settings.ai.openrouterApiKey" type="password" class="input" placeholder="sk-or-…" />
          </div>
          <div class="field">
            <label>Model</label>
            <input v-model="settings.ai.openrouterModel" class="input" placeholder="deepseek/deepseek-r1" />
          </div>
        </template>

        <div class="field">
          <label>Auto-rename on decompile</label>
          <label class="toggle">
            <input type="checkbox" v-model="settings.ai.autoRename" />
            <span class="toggle-slider" />
          </label>
        </div>

        <button class="test-btn" :disabled="testingProvider" @click="testProvider">
          {{ testingProvider ? 'Testing…' : 'Test connection' }}
        </button>
        <span v-if="testResult" class="test-result" :class="{ ok: testResult.startsWith('✓') }">
          {{ testResult }}
        </span>
      </section>
    </div>
  </div>
</template>

<style scoped>
.settings-view {
  flex: 1; overflow-y: auto;
  background: var(--color-bg-void);
  display: flex; justify-content: center;
  padding: 40px 24px;
}
.settings-content { width: 100%; max-width: 520px; }
.settings-header { display: flex; align-items: center; gap: 16px; margin-bottom: 32px; }
.back-btn {
  font-size: 13px; color: var(--color-text-secondary); background: none; border: none;
  cursor: pointer; padding: 6px 0;
}
.back-btn:hover { color: var(--color-text-primary); }
.settings-title { font-size: 20px; font-weight: 600; color: var(--color-text-primary); }
.settings-section { background: var(--color-bg-surface); border: 1px solid var(--color-bg-border); border-radius: 12px; padding: 24px; margin-bottom: 24px; }
.section-title { font-size: 13px; font-weight: 600; color: var(--color-text-primary); margin-bottom: 20px; text-transform: uppercase; letter-spacing: 0.06em; }
.field { display: flex; align-items: center; justify-content: space-between; margin-bottom: 14px; gap: 12px; }
.field label:first-child { font-size: 13px; color: var(--color-text-secondary); min-width: 140px; }
.input, .select {
  flex: 1; padding: 7px 10px;
  background: var(--color-bg-elevated); border: 1px solid var(--color-bg-border);
  border-radius: 6px; color: var(--color-text-primary); font-size: 13px;
  font-family: var(--font-family-ui); outline: none;
  transition: border-color 0.15s;
}
.input:focus, .select:focus { border-color: var(--color-accent); }
.select { cursor: pointer; }
.test-btn {
  padding: 8px 16px; background: var(--color-bg-elevated); border: 1px solid var(--color-bg-border);
  color: var(--color-text-primary); border-radius: 6px; font-size: 13px; cursor: pointer;
  transition: border-color 0.15s;
}
.test-btn:hover { border-color: var(--color-accent); }
.test-result { margin-left: 12px; font-size: 13px; color: var(--color-error); }
.test-result.ok { color: var(--color-ok); }
.toggle { display: flex; align-items: center; cursor: pointer; }
.toggle input { display: none; }
.toggle-slider {
  width: 36px; height: 20px; background: var(--color-bg-border); border-radius: 10px;
  position: relative; transition: background 0.2s;
}
.toggle-slider::after {
  content: ''; position: absolute; top: 2px; left: 2px;
  width: 16px; height: 16px; border-radius: 50%;
  background: white; transition: transform 0.2s;
}
.toggle input:checked + .toggle-slider { background: var(--color-accent); }
.toggle input:checked + .toggle-slider::after { transform: translateX(16px); }
</style>
