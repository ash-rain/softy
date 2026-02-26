<script setup lang="ts">
import { computed } from 'vue'
import { useBinaryStore } from '@/stores/binary.store'

const binary = useBinaryStore()
const meta   = computed(() => binary.meta)

function formatSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1048576).toFixed(2)} MB`
}

function entropyClass(e: number) {
  if (e < 5) return 'entropy-low'
  if (e < 7) return 'entropy-medium'
  return 'entropy-high'
}

function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text).catch(() => {})
}
</script>

<template>
  <div class="meta-panel" v-if="meta">
    <section class="meta-section">
      <h3 class="section-title">Binary</h3>
      <div class="kv-list">
        <div class="kv"><span class="kv-key">Name</span><span class="kv-val">{{ binary.projectName }}</span></div>
        <div class="kv"><span class="kv-key">Format</span><span class="kv-val chip cyan">{{ meta.format }}</span></div>
        <div class="kv"><span class="kv-key">Architecture</span><span class="kv-val chip">{{ meta.arch }} {{ meta.bits }}-bit</span></div>
        <div class="kv"><span class="kv-key">OS Target</span><span class="kv-val">{{ meta.os }}</span></div>
        <div class="kv"><span class="kv-key">Endianness</span><span class="kv-val">{{ meta.endian }}</span></div>
        <div class="kv" v-if="meta.compiler"><span class="kv-key">Compiler</span><span class="kv-val">{{ meta.compiler }}</span></div>
        <div class="kv"><span class="kv-key">Size</span><span class="kv-val mono">{{ formatSize(meta.fileSize) }}</span></div>
        <div class="kv"><span class="kv-key">Entry Point</span><span class="kv-val mono">0x{{ meta.entryPoint.toString(16).toUpperCase() }}</span></div>
        <div class="kv"><span class="kv-key">Base Address</span><span class="kv-val mono">0x{{ meta.baseAddress.toString(16).toUpperCase() }}</span></div>
      </div>
      <div class="flags-row">
        <span v-if="meta.isPacked"  class="flag warn">⚠ Packed</span>
        <span v-if="meta.isSigned"  class="flag ok">✓ Signed</span>
        <span v-if="!meta.isSigned" class="flag muted">⊘ Unsigned</span>
      </div>
    </section>

    <section class="meta-section">
      <h3 class="section-title">Hashes</h3>
      <div class="hash-list">
        <div class="hash-item"><span class="hash-algo">MD5</span><span class="hash-val mono" @click="copyToClipboard(meta.hashes.md5)" title="Copy">{{ meta.hashes.md5 }}</span></div>
        <div class="hash-item"><span class="hash-algo">SHA-1</span><span class="hash-val mono" @click="copyToClipboard(meta.hashes.sha1)" title="Copy">{{ meta.hashes.sha1 }}</span></div>
        <div class="hash-item"><span class="hash-algo">SHA-256</span><span class="hash-val mono" @click="copyToClipboard(meta.hashes.sha256)" title="Copy">{{ meta.hashes.sha256 }}</span></div>
      </div>
    </section>

    <section class="meta-section" v-if="meta.sections.length">
      <h3 class="section-title">Sections</h3>
      <div class="sections-table">
        <div class="sections-header"><span>Name</span><span>Entropy</span><span>Size</span></div>
        <div v-for="sec in meta.sections" :key="sec.name" class="section-row">
          <span class="sec-name mono">{{ sec.name || '(unnamed)' }}</span>
          <div class="entropy-bar-wrap">
            <div class="entropy-bar" :class="entropyClass(sec.entropy)" :style="{ width: (sec.entropy / 8 * 100).toFixed(0) + '%' }" />
            <span class="entropy-val">{{ sec.entropy.toFixed(2) }}</span>
          </div>
          <span class="sec-size mono">{{ formatSize(sec.rawSize) }}</span>
        </div>
      </div>
    </section>

    <section class="meta-section" v-if="meta.imports.length">
      <h3 class="section-title">Imports ({{ meta.imports.length }})</h3>
      <div class="import-list">
        <div v-for="(imp, i) in meta.imports.slice(0, 80)" :key="i" class="import-item">
          <span class="imp-lib mono">{{ imp.library || '·' }}</span>
          <span class="imp-name mono">{{ imp.name }}</span>
        </div>
        <div v-if="meta.imports.length > 80" class="more-hint">+ {{ meta.imports.length - 80 }} more</div>
      </div>
    </section>
  </div>
  <div v-else class="meta-empty"><p>No binary loaded</p></div>
</template>

<style scoped>
.meta-panel { padding: 4px 0; }
.meta-empty { display: flex; align-items: center; justify-content: center; height: 200px; color: var(--color-text-muted); font-size: 13px; }
.meta-section { padding: 16px; border-bottom: 1px solid var(--color-bg-border); }
.section-title { font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; color: var(--color-text-muted); margin-bottom: 12px; }
.kv-list { display: flex; flex-direction: column; gap: 8px; }
.kv { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.kv-key { font-size: 12px; color: var(--color-text-muted); flex-shrink: 0; }
.kv-val { font-size: 12px; color: var(--color-text-primary); text-align: right; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.kv-val.mono { font-family: var(--font-family-code); font-size: 11px; color: var(--color-text-code); }
.chip { display: inline-block; padding: 1px 7px; background: var(--color-bg-elevated); border: 1px solid var(--color-bg-border); border-radius: 4px; font-family: var(--font-family-code); font-size: 11px; }
.chip.cyan { color: var(--color-accent); border-color: rgba(0,212,255,0.2); background: rgba(0,212,255,0.06); }
.flags-row { display: flex; gap: 8px; margin-top: 12px; flex-wrap: wrap; }
.flag { font-size: 11px; padding: 2px 8px; border-radius: 4px; font-weight: 500; }
.flag.warn  { color: var(--color-warn);  background: rgba(255,170,0,0.08);  border: 1px solid rgba(255,170,0,0.2);  }
.flag.ok    { color: var(--color-ok);    background: rgba(0,255,157,0.06);  border: 1px solid rgba(0,255,157,0.15); }
.flag.muted { color: var(--color-text-muted); background: var(--color-bg-elevated); border: 1px solid var(--color-bg-border); }
.hash-list { display: flex; flex-direction: column; gap: 6px; }
.hash-item { display: flex; align-items: center; gap: 8px; }
.hash-algo { font-size: 10px; font-weight: 600; color: var(--color-text-muted); text-transform: uppercase; min-width: 44px; }
.hash-val { font-size: 10px; color: var(--color-text-code); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; cursor: pointer; }
.hash-val:hover { color: var(--color-accent); }
.sections-table { display: flex; flex-direction: column; gap: 6px; }
.sections-header { display: grid; grid-template-columns: 80px 1fr 60px; gap: 8px; font-size: 10px; color: var(--color-text-muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 2px; }
.section-row { display: grid; grid-template-columns: 80px 1fr 60px; gap: 8px; align-items: center; }
.sec-name { font-size: 11px; color: var(--color-text-code); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.entropy-bar-wrap { display: flex; align-items: center; gap: 6px; }
.entropy-bar { height: 5px; border-radius: 2px; min-width: 2px; flex-shrink: 0; }
.entropy-val { font-size: 10px; color: var(--color-text-muted); flex-shrink: 0; }
.sec-size { font-size: 10px; color: var(--color-text-muted); text-align: right; }
.import-list { display: flex; flex-direction: column; gap: 3px; max-height: 200px; overflow-y: auto; }
.import-item { display: flex; gap: 8px; align-items: center; }
.imp-lib { font-size: 10px; color: var(--color-text-muted); min-width: 60px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.imp-name { font-size: 11px; color: var(--color-text-code); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.more-hint { font-size: 11px; color: var(--color-text-muted); padding: 4px 0; }
.mono { font-family: var(--font-family-code); }
</style>
