<script setup lang="ts">
import { ref, watch, onMounted, onUnmounted } from 'vue'
import { useBinaryStore } from '@/stores/binary.store'
import { useUIStore } from '@/stores/ui.store'
import * as monaco from 'monaco-editor'

const binary = useBinaryStore()
const ui     = useUIStore()

const editorEl  = ref<HTMLElement | null>(null)
const disasmEl  = ref<HTMLElement | null>(null)
let editor: monaco.editor.IStandaloneCodeEditor | null = null
let disasmEditor: monaco.editor.IStandaloneCodeEditor | null = null

// Register the softy-dark theme
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
    'editor.background':           '#090d12',
    'editor.foreground':           '#e8f4fd',
    'editor.lineHighlightBackground': '#0e1420',
    'editor.selectionBackground':  '#00d4ff26',
    'editorLineNumber.foreground': '#3d5a78',
    'editorLineNumber.activeForeground': '#7a9ab8',
    'editorCursor.foreground':     '#00d4ff',
    'editor.inactiveSelectionBackground': '#00d4ff10',
    'editorGutter.background':     '#090d12',
    'editorWidget.background':     '#0f1520',
    'editorWidget.border':         '#1e2d42',
    'input.background':            '#161e2e',
    'input.foreground':            '#e8f4fd',
    'input.border':                '#1e2d42',
    'list.hoverBackground':        '#161e2e',
    'list.activeSelectionBackground': '#00d4ff20',
    'scrollbarSlider.background':  '#1e2d4266',
    'scrollbarSlider.hoverBackground': '#3d5a7866',
  },
})

function makeEditorOptions(readOnly = false): monaco.editor.IStandaloneEditorConstructionOptions {
  return {
    theme: 'softy-dark',
    language: 'c',
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

  // Save edits back to store
  editor.onDidChangeModelContent(() => {
    if (binary.activeFunction) {
      const code = editor!.getValue()
      binary.updateFunctionCode(binary.activeFunction.address, code)
    }
  })
})

onUnmounted(() => {
  editor?.dispose()
  disasmEditor?.dispose()
})

// When active function changes, load its code
watch(() => binary.activeFunction, (fn) => {
  if (!fn) return
  const code = fn.editedCode ?? fn.aiCode ?? fn.cCode
  if (editor && editor.getValue() !== code) {
    editor.setValue(code)
    editor.setScrollPosition({ scrollTop: 0 })
  }
  if (disasmEditor) {
    const disasmText = fn.disassembly
      .map((op) => `${op.addr.padEnd(16)}  ${op.mnem.padEnd(8)}  ${op.ops}`)
      .join('\n')
    disasmEditor.setValue(disasmText || '; No disassembly available')
  }
})

// Placeholder when nothing selected
watch(() => binary.isDecompiling, (val) => {
  if (val && !binary.activeFunction) {
    editor?.setValue('// Decompiling — click a function in the sidebar to view its code.\n')
  }
})
</script>

<template>
  <div class="editor-wrap">
    <!-- Empty state overlay -->
    <div
      v-if="!binary.activeFunction && !binary.isDecompiling"
      class="editor-empty"
    >
      <p>Select a function from the sidebar</p>
    </div>

    <!-- Function header -->
    <div v-if="binary.activeFunction" class="fn-header">
      <span class="fn-header-name mono">{{ binary.activeFunction.name }}</span>
      <span class="fn-header-sig mono muted">{{ binary.activeFunction.signature }}</span>
      <span class="fn-header-addr mono dim">{{ binary.activeFunction.address }}</span>
      <div class="header-spacer" />
      <span class="fn-size mono dim">{{ binary.activeFunction.size }} bytes</span>
    </div>

    <!-- Editor area (code + optional disasm split) -->
    <div class="editor-body">
      <div ref="editorEl" class="monaco-container" />
      <template v-if="ui.splitDisasm">
        <div class="disasm-divider" />
        <div ref="disasmEl" class="monaco-container disasm" />
      </template>
    </div>
  </div>
</template>

<style scoped>
.editor-wrap {
  display: flex; flex-direction: column;
  height: 100%; background: var(--color-bg-base);
  position: relative;
}

.editor-empty {
  position: absolute; inset: 0;
  display: flex; align-items: center; justify-content: center;
  pointer-events: none; z-index: 1;
}
.editor-empty p { font-size: 13px; color: var(--color-text-muted); }

.fn-header {
  display: flex; align-items: center; gap: 12px;
  padding: 8px 16px;
  background: var(--color-bg-base);
  border-bottom: 1px solid var(--color-bg-border);
  flex-shrink: 0; overflow: hidden;
}
.fn-header-name { font-size: 13px; color: var(--color-text-primary); font-weight: 500; flex-shrink: 0; }
.fn-header-sig   { font-size: 11px; color: var(--color-text-secondary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; min-width: 0; }
.fn-header-addr  { font-size: 11px; color: var(--color-accent); opacity: 0.7; flex-shrink: 0; }
.fn-size         { font-size: 11px; color: var(--color-text-muted); flex-shrink: 0; }
.header-spacer   { flex: 1; }
.mono  { font-family: var(--font-family-code); }
.muted { color: var(--color-text-secondary) !important; }
.dim   { color: var(--color-text-muted) !important; }

.editor-body {
  display: flex; flex: 1; overflow: hidden;
}
.monaco-container { flex: 1; min-width: 0; }
.monaco-container.disasm { flex: 0 0 45%; border-left: 1px solid var(--color-bg-border); }
.disasm-divider { width: 1px; background: var(--color-bg-border); flex-shrink: 0; }
</style>
