<script setup lang="ts">
import { ref, watch, onMounted, onUnmounted, computed } from 'vue'
import { useBinaryStore } from '@/stores/binary.store'
import { useUIStore } from '@/stores/ui.store'
import { useSettingsStore } from '@/stores/settings.store'
import * as monaco from 'monaco-editor'

const binary   = useBinaryStore()
const ui       = useUIStore()
const settings = useSettingsStore()

const editorEl   = ref<HTMLElement | null>(null)
const disasmEl   = ref<HTMLElement | null>(null)
let editor: monaco.editor.IStandaloneCodeEditor | null = null
let disasmEditor: monaco.editor.IStandaloneCodeEditor | null = null

// Rename state
const isRenaming = ref(false)

function getAiModel() {
  const ai = settings.ai
  if (ai.provider === 'openai')     return ai.openaiModel
  if (ai.provider === 'anthropic')  return ai.anthropicModel
  if (ai.provider === 'openrouter') return ai.openrouterModel
  return ai.ollamaModel
}

function getAiKey() {
  const ai = settings.ai
  if (ai.provider === 'openai')     return ai.openaiApiKey
  if (ai.provider === 'anthropic')  return ai.anthropicApiKey
  if (ai.provider === 'openrouter') return ai.openrouterApiKey
  return ''
}

function isGenericName(name: string) {
  return /^(FUN_|sub_|func_|fcn\.|loc_|j_|thunk_|nullsub_)/i.test(name)
}

async function renameCurrentFunction() {
  const fn = binary.activeFunction
  if (!fn || isRenaming.value) return
  isRenaming.value = true
  try {
    const newName = await window.softy.ai.rename({
      provider:    settings.ai.provider,
      model:       getAiModel(),
      apiKey:      getAiKey(),
      code:        editor?.getValue() ?? fn.cCode,
      currentName: fn.name,
    })
    if (newName) binary.renameFunction(fn.address, newName)
  } catch { /* silent */ } finally {
    isRenaming.value = false
  }
}

// Compile output state
const isCompiling   = ref(false)
const compileResult = ref<null | { success: boolean; output: string; isText: boolean; errors: { message: string; line: number }[]; warnings: { message: string; line: number }[]; sizeBytes: number }>(null)
const showCompile   = ref(false)

// Auto-detect language from meta
const editorLanguage = computed(() => {
  const compiler = binary.meta?.compiler ?? ''
  if (compiler.toLowerCase().includes('clang') || compiler.toLowerCase().includes('gcc')) return 'c'
  if (compiler.toLowerCase().includes('rust')) return 'rust'
  return 'c'
})

monaco.editor.defineTheme('softy-dark', {
  base: 'vs-dark',
  inherit: true,
  rules: [
    { token: 'keyword',   foreground: '00d4ff', fontStyle: 'bold' },
    { token: 'type',      foreground: '00e5cc' },
    { token: 'function',  foreground: '66d9ff' },
    { token: 'string',    foreground: 'ffcc66' },
    { token: 'number',    foreground: 'ff9933' },
    { token: 'comment',   foreground: '3d5a78', fontStyle: 'italic' },
    { token: 'variable',  foreground: 'c9e8ff' },
    { token: 'delimiter', foreground: '7a9ab8' },
  ],
  colors: {
    'editor.background':                   '#090d12',
    'editor.foreground':                   '#e8f4fd',
    'editor.lineHighlightBackground':      '#0e1420',
    'editor.selectionBackground':          '#00d4ff26',
    'editorLineNumber.foreground':         '#3d5a78',
    'editorLineNumber.activeForeground':   '#7a9ab8',
    'editorCursor.foreground':             '#00d4ff',
    'editor.inactiveSelectionBackground':  '#00d4ff10',
    'editorGutter.background':             '#090d12',
    'editorWidget.background':             '#0f1520',
    'editorWidget.border':                 '#1e2d42',
    'input.background':                    '#161e2e',
    'input.foreground':                    '#e8f4fd',
    'input.border':                        '#1e2d42',
    'list.hoverBackground':                '#161e2e',
    'list.activeSelectionBackground':      '#00d4ff20',
    'scrollbarSlider.background':          '#1e2d4266',
    'scrollbarSlider.hoverBackground':     '#3d5a7866',
  },
})

function makeEditorOptions(readOnly = false): monaco.editor.IStandaloneEditorConstructionOptions {
  return {
    theme: 'softy-dark',
    language: editorLanguage.value,
    readOnly,
    fontSize: 13,
    fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
    fontLigatures: true,
    lineHeight: 22,
    minimap: { enabled: false },
    scrollBeyondLastLine: false,
    renderLineHighlight: 'line',
    cursorBlinking: 'smooth',
    smoothScrolling: true,
    automaticLayout: true,
    padding: { top: 16, bottom: 16 },
    overviewRulerBorder: false,
    scrollbar: { verticalScrollbarSize: 6, horizontalScrollbarSize: 6 },
    suggest: { showWords: false },
    quickSuggestions: { other: 'on', comments: 'off', strings: 'off' },
  }
}

onMounted(() => {
  if (!editorEl.value) return

  editor = monaco.editor.create(editorEl.value, {
    ...makeEditorOptions(false),
    value: '// Open a binary and select a function to view decompiled code.\n',
  })

  if (disasmEl.value) {
    disasmEditor = monaco.editor.create(disasmEl.value, {
      ...makeEditorOptions(true),
      language: 'plaintext',
      value: '',
    })
  }

  editor.onDidChangeModelContent(() => {
    if (binary.activeFunction) {
      binary.updateFunctionCode(binary.activeFunction.address, editor!.getValue())
    }
  })

  // Cmd/Ctrl+Shift+B to compile
  editor.addCommand(
    monaco.KeyMod.CtrlCmd | monaco.KeyMod.Shift | monaco.KeyCode.KeyB,
    () => compileCurrentFunction(),
  )
})

onUnmounted(() => {
  editor?.dispose()
  disasmEditor?.dispose()
})

watch(() => binary.activeFunction, (fn) => {
  if (!fn) return
  const code = fn.editedCode ?? fn.aiCode ?? fn.cCode
  if (editor && editor.getValue() !== code) {
    editor.setValue(code)
    editor.setScrollPosition({ scrollTop: 0 })
    // Update language based on meta
    const model = editor.getModel()
    if (model) monaco.editor.setModelLanguage(model, editorLanguage.value)
  }
  if (disasmEditor) {
    const disasmText = fn.disassembly
      .map((op) => `${op.addr.padEnd(16)}  ${op.mnem.padEnd(8)}  ${op.ops}`)
      .join('\n')
    disasmEditor.setValue(disasmText || '; No disassembly available')
  }
  // Auto-rename if enabled and function has a generic decompiler name
  if (settings.ai.autoRename && isGenericName(fn.name)) {
    renameCurrentFunction()
  }
})

watch(() => binary.isDecompiling, (val) => {
  if (val && !binary.activeFunction && !binary.decompileError) {
    editor?.setValue('// Decompiling — click a function in the sidebar to view its code.\n')
  }
})

// ── Patch binary ───────────────────────────────────────────────────────────
const isPatching = ref(false)
const patchError = ref<string | null>(null)

async function patchBinary() {
  const fn  = binary.activeFunction
  const res = compileResult.value
  if (!fn || !res?.success || res.isText || !res.output) return
  if (!binary.relPath) return

  isPatching.value = true
  patchError.value = null
  try {
    const result = await window.softy.compile.patch({
      filePath:        binary.relPath,
      functionAddress: fn.address,
      functionSize:    fn.size,
      objectBase64:    res.output,
    })
    // Download the patched binary
    const bytes = Uint8Array.from(atob((result as { data: string }).data), (c) => c.charCodeAt(0))
    const blob  = new Blob([bytes], { type: 'application/octet-stream' })
    const url   = URL.createObjectURL(blob)
    const a     = document.createElement('a')
    a.href      = url
    a.download  = (result as { filename: string }).filename || 'binary.patched'
    a.click()
    URL.revokeObjectURL(url)
  } catch (err) {
    patchError.value = (err as Error).message
  } finally {
    isPatching.value = false
  }
}

// ── Compile ────────────────────────────────────────────────────────────────
async function compileCurrentFunction() {
  const code = editor?.getValue()
  if (!code || !binary.meta) return
  isCompiling.value = true
  showCompile.value  = true
  compileResult.value = null
  try {
    const arch = binary.meta.arch.toLowerCase().replace('arm64', 'arm64').replace('x86', 'x86_64')
    const os   = binary.meta.os.toLowerCase().replace('macos', 'macos').replace('windows', 'windows')
    const res  = await window.softy.compile.code({
      sourceCode:   code,
      arch,
      os,
      optimize:     'O1',
      outputFormat: 'object',
    })
    compileResult.value = res
  } catch (err) {
    compileResult.value = {
      success: false, output: null, isText: false, errors: [{ message: String(err), line: 0 }],
      warnings: [], sizeBytes: 0,
    }
  } finally {
    isCompiling.value = false
  }
}

function downloadObject() {
  const res = compileResult.value
  if (!res?.output || res.isText) return
  const bytes = Uint8Array.from(atob(res.output), (c) => c.charCodeAt(0))
  const blob  = new Blob([bytes], { type: 'application/octet-stream' })
  const url   = URL.createObjectURL(blob)
  const a     = document.createElement('a')
  a.href      = url
  a.download  = `${binary.activeFunction?.name ?? 'function'}.o`
  a.click()
  URL.revokeObjectURL(url)
}
</script>

<template>
  <div class="editor-wrap">
    <!-- Error overlay -->
    <div v-if="binary.decompileError && !binary.activeFunction" class="editor-empty editor-error">
      <span class="editor-error-icon">⚠</span>
      <p class="editor-error-title">Decompilation failed</p>
      <p class="editor-error-msg">{{ binary.decompileError }}</p>
    </div>

    <!-- Empty overlay -->
    <div v-else-if="!binary.activeFunction && !binary.isDecompiling" class="editor-empty">
      <p>Select a function from the sidebar</p>
    </div>

    <!-- Function header -->
    <div v-if="binary.activeFunction" class="fn-header">
      <span class="fn-header-name mono">{{ binary.activeFunction.name }}</span>
      <span class="fn-header-sig mono muted">{{ binary.activeFunction.signature }}</span>
      <span class="fn-header-addr mono dim">{{ binary.activeFunction.address }}</span>
      <div class="header-spacer" />
      <span class="fn-size mono dim">{{ binary.activeFunction.size }} bytes</span>
      <button
        class="rename-btn"
        :class="{ renaming: isRenaming }"
        :disabled="isRenaming || !binary.activeFunction"
        title="AI Rename (ask AI to suggest a name)"
        @click="renameCurrentFunction"
      >
        <span v-if="isRenaming" class="compile-spinner" />
        <span v-else>✦ Rename</span>
      </button>
      <button
        class="compile-btn"
        :class="{ compiling: isCompiling }"
        :disabled="isCompiling || !binary.activeFunction"
        title="Compile (⌘⇧B)"
        @click="compileCurrentFunction"
      >
        <span v-if="isCompiling" class="compile-spinner" />
        <span v-else>▶ Compile</span>
      </button>
    </div>

    <!-- Editor + optional disasm split -->
    <div class="editor-body">
      <div ref="editorEl" class="monaco-container" />
      <template v-if="ui.splitDisasm">
        <div class="disasm-divider" />
        <div ref="disasmEl" class="monaco-container disasm" />
      </template>
    </div>

    <!-- Compile output drawer -->
    <Transition name="slide-up">
      <div v-if="showCompile && compileResult" class="compile-drawer">
        <div class="compile-drawer-header">
          <span class="compile-status" :class="compileResult.success ? 'ok' : 'err'">
            {{ compileResult.success ? '✓ Compiled' : '✗ Build failed' }}
          </span>
          <span v-if="compileResult.success" class="compile-size mono">
            {{ compileResult.sizeBytes.toLocaleString() }} bytes
          </span>
          <div class="drawer-spacer" />
          <button v-if="compileResult.success && !compileResult.isText"
                  class="dl-btn" @click="downloadObject">↓ Download .o</button>
          <button v-if="compileResult.success && !compileResult.isText && binary.relPath"
                  class="patch-btn" :class="{ patching: isPatching }" :disabled="isPatching"
                  @click="patchBinary" title="Replace this function's bytes in the original binary">
            <span v-if="isPatching" class="compile-spinner" />
            <span v-else>⚡ Patch Binary</span>
          </button>
          <button class="close-drawer" @click="showCompile = false; patchError = null">✕</button>
        </div>

        <!-- Errors -->
        <div v-if="compileResult.errors.length" class="diag-list">
          <div v-for="(e, i) in compileResult.errors" :key="i" class="diag-item err">
            <span class="diag-loc">L{{ e.line }}</span>
            <span class="diag-msg">{{ e.message }}</span>
          </div>
        </div>

        <!-- Warnings -->
        <div v-if="compileResult.warnings.length" class="diag-list">
          <div v-for="(w, i) in compileResult.warnings" :key="i" class="diag-item warn">
            <span class="diag-loc">L{{ w.line }}</span>
            <span class="diag-msg">{{ w.message }}</span>
          </div>
        </div>

        <!-- Patch error -->
        <div v-if="patchError" class="diag-list">
          <div class="diag-item err">
            <span class="diag-loc">patch</span>
            <span class="diag-msg">{{ patchError }}</span>
          </div>
        </div>

        <!-- Text output (asm/ir) -->
        <pre v-if="compileResult.isText && compileResult.output" class="text-output">{{ compileResult.output }}</pre>
      </div>
    </Transition>
  </div>
</template>

<style scoped>
.editor-wrap { display: flex; flex-direction: column; height: 100%; background: var(--color-bg-base); position: relative; }

.editor-empty { position: absolute; inset: 0; display: flex; align-items: center; justify-content: center; pointer-events: none; z-index: 1; }
.editor-empty p { font-size: 13px; color: var(--color-text-muted); }
.editor-error { flex-direction: column; gap: 8px; padding: 40px; }
.editor-error-icon  { font-size: 28px; color: var(--color-error, #ff4444); line-height: 1; }
.editor-error-title { font-size: 14px; font-weight: 600; color: var(--color-error, #ff4444); margin: 0; }
.editor-error-msg   { font-size: 12px; font-family: var(--font-family-code); color: var(--color-text-muted); background: rgba(255,68,68,0.06); border: 1px solid rgba(255,68,68,0.15); border-radius: 6px; padding: 8px 14px; max-width: 520px; word-break: break-word; text-align: center; line-height: 1.5; margin: 0; }

.fn-header { display: flex; align-items: center; gap: 12px; padding: 8px 16px; background: var(--color-bg-base); border-bottom: 1px solid var(--color-bg-border); flex-shrink: 0; overflow: hidden; }
.fn-header-name { font-size: 13px; color: var(--color-text-primary); font-weight: 500; flex-shrink: 0; }
.fn-header-sig  { font-size: 11px; color: var(--color-text-secondary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; min-width: 0; }
.fn-header-addr { font-size: 11px; color: var(--color-accent); opacity: 0.7; flex-shrink: 0; }
.fn-size        { font-size: 11px; color: var(--color-text-muted); flex-shrink: 0; }
.header-spacer  { flex: 1; }

.rename-btn {
  flex-shrink: 0; padding: 4px 10px; font-size: 11px; font-weight: 500;
  background: rgba(168,85,247,0.08); border: 1px solid rgba(168,85,247,0.2);
  color: var(--color-ai, #a855f7); border-radius: 5px; cursor: pointer;
  transition: background 0.15s, opacity 0.15s; display: flex; align-items: center; gap: 5px;
}
.rename-btn:hover:not(:disabled) { background: rgba(168,85,247,0.14); }
.rename-btn:disabled { opacity: 0.5; cursor: not-allowed; }
.rename-btn.renaming { border-color: rgba(168,85,247,0.1); }

.compile-btn {
  flex-shrink: 0; padding: 4px 10px; font-size: 11px; font-weight: 500;
  background: rgba(0,212,255,0.08); border: 1px solid rgba(0,212,255,0.2);
  color: var(--color-accent); border-radius: 5px; cursor: pointer;
  transition: background 0.15s, opacity 0.15s; display: flex; align-items: center; gap: 5px;
}
.compile-btn:hover:not(:disabled) { background: rgba(0,212,255,0.14); }
.compile-btn:disabled { opacity: 0.5; cursor: not-allowed; }
.compile-btn.compiling { border-color: rgba(0,212,255,0.1); }
.compile-spinner { width: 10px; height: 10px; border-radius: 50%; border: 1.5px solid rgba(0,212,255,0.3); border-top-color: var(--color-accent); animation: spin 0.7s linear infinite; }

.editor-body { display: flex; flex: 1; overflow: hidden; }
.monaco-container { flex: 1; min-width: 0; }
.monaco-container.disasm { flex: 0 0 45%; border-left: 1px solid var(--color-bg-border); }
.disasm-divider { width: 1px; background: var(--color-bg-border); flex-shrink: 0; }

.mono  { font-family: var(--font-family-code); }
.muted { color: var(--color-text-secondary) !important; }
.dim   { color: var(--color-text-muted) !important; }

/* Compile drawer */
.compile-drawer {
  flex-shrink: 0; max-height: 200px; overflow-y: auto;
  background: var(--color-bg-base); border-top: 1px solid var(--color-bg-border);
}
.compile-drawer-header {
  display: flex; align-items: center; gap: 10px; padding: 8px 14px;
  border-bottom: 1px solid var(--color-bg-border); flex-shrink: 0; position: sticky; top: 0;
  background: var(--color-bg-base); z-index: 1;
}
.compile-status { font-size: 12px; font-weight: 600; }
.compile-status.ok  { color: var(--color-ok, #00ff9d); }
.compile-status.err { color: var(--color-error, #ff4444); }
.compile-size { font-size: 11px; color: var(--color-text-muted); }
.drawer-spacer { flex: 1; }
.dl-btn { padding: 3px 9px; font-size: 11px; background: rgba(0,212,255,0.08); border: 1px solid rgba(0,212,255,0.2); color: var(--color-accent); border-radius: 4px; cursor: pointer; }
.dl-btn:hover { background: rgba(0,212,255,0.14); }
.patch-btn { padding: 3px 9px; font-size: 11px; background: rgba(168,85,247,0.08); border: 1px solid rgba(168,85,247,0.2); color: var(--color-ai, #a855f7); border-radius: 4px; cursor: pointer; display: flex; align-items: center; gap: 4px; transition: background 0.15s, opacity 0.15s; }
.patch-btn:hover:not(:disabled) { background: rgba(168,85,247,0.14); }
.patch-btn:disabled { opacity: 0.5; cursor: not-allowed; }
.close-drawer { background: none; border: none; color: var(--color-text-muted); cursor: pointer; font-size: 11px; padding: 2px 4px; border-radius: 3px; }
.close-drawer:hover { color: var(--color-error, #ff4444); }

.diag-list { padding: 4px 14px; }
.diag-item { display: flex; gap: 8px; align-items: baseline; padding: 2px 0; font-size: 11px; font-family: var(--font-family-code); }
.diag-item.err  .diag-loc { color: var(--color-error, #ff4444); }
.diag-item.warn .diag-loc { color: var(--color-warn, #ffaa00); }
.diag-loc { flex-shrink: 0; min-width: 32px; }
.diag-msg { color: var(--color-text-secondary); }

.text-output { margin: 0; padding: 10px 14px; font-family: var(--font-family-code); font-size: 11px; color: var(--color-text-code); white-space: pre; overflow-x: auto; }

.slide-up-enter-active, .slide-up-leave-active { transition: max-height 0.2s ease, opacity 0.2s ease; }
.slide-up-enter-from, .slide-up-leave-to { max-height: 0; opacity: 0; }
.slide-up-enter-to, .slide-up-leave-from { max-height: 200px; opacity: 1; }
</style>
