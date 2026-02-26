import { defineStore } from 'pinia'
import { ref, computed } from 'vue'

export interface SectionInfo {
  name: string; virtualAddress: number; virtualSize: number
  rawSize: number; entropy: number; flags: string
}

export interface BinaryMeta {
  format: string; arch: string; bits: number; endian: string; os: string
  compiler: string | null; entryPoint: number; baseAddress: number
  fileSize: number; hashes: { md5: string; sha1: string; sha256: string }
  sections: SectionInfo[]; imports: { library: string; name: string }[]
  exports: { name: string; address: number }[]
  isPacked: boolean; isSigned: boolean; characteristics: Record<string, string>
}

export interface DecompiledFunction {
  address: string; name: string; signature: string; size: number
  callers: string[]; callees: string[]
  cCode: string; editedCode?: string; aiCode?: string
  disassembly: { addr: string; mnem: string; ops: string }[]
  aiSummary?: string
}

export interface ResourceNode {
  id: string; name: string; type: string; path: string
  size: number; offset: number; canPreview: boolean; canEdit: boolean
  children: ResourceNode[]
}

export interface StringEntry {
  offset: number; value: string; encoding: string
}

export const useBinaryStore = defineStore('binary', () => {
  // ── Active project ──────────────────────────────────────────────────────
  const projectId    = ref<string | null>(null)
  const projectName  = ref<string>('')
  const localPath    = ref<string>('')
  const relPath      = ref<string>('')

  // ── Analysis state ──────────────────────────────────────────────────────
  const isAnalyzing  = ref(false)
  const meta         = ref<BinaryMeta | null>(null)
  const quickInfo    = ref<{ functions: unknown[]; imports: unknown[]; exports: unknown[] } | null>(null)

  // ── Decompilation state ─────────────────────────────────────────────────
  const isDecompiling     = ref(false)
  const decompileProgress = ref(0)
  const decompileBackend  = ref<'ghidra' | 'r2'>('ghidra')
  const decompileError    = ref<string | null>(null)
  const functions         = ref<Map<string, DecompiledFunction>>(new Map())
  const functionList      = computed(() => Array.from(functions.value.values()))
  const totalFunctions    = ref(0)

  // ── Resources ───────────────────────────────────────────────────────────
  const resources = ref<ResourceNode[]>([])
  const strings   = ref<StringEntry[]>([])

  // ── Active selection ────────────────────────────────────────────────────
  const activeFunction = ref<DecompiledFunction | null>(null)

  // ── Actions ─────────────────────────────────────────────────────────────

  function openBinary(result: {
    projectId: string; name: string; localPath: string; relPath: string
    meta: BinaryMeta; quick: { functions: unknown[]; imports: unknown[]; exports: unknown[] }
  }) {
    projectId.value    = result.projectId
    projectName.value  = result.name
    localPath.value    = result.localPath
    relPath.value      = result.relPath
    meta.value         = result.meta
    quickInfo.value    = result.quick
    functions.value    = new Map()
    totalFunctions.value = result.quick.functions.length
    activeFunction.value = null
    decompileProgress.value = 0
    decompileError.value = null
  }

  function addFunction(fn: DecompiledFunction) {
    functions.value.set(fn.address, fn)
  }

  function updateFunctionCode(address: string, code: string) {
    const fn = functions.value.get(address)
    if (fn) fn.editedCode = code
  }

  function setActiveFunction(address: string) {
    activeFunction.value = functions.value.get(address) ?? null
  }

  function renameFunction(address: string, name: string) {
    const fn = functions.value.get(address)
    if (fn) fn.name = name
  }

  function reset() {
    projectId.value = null; projectName.value = ''; localPath.value = ''
    relPath.value = ''; meta.value = null; quickInfo.value = null
    isDecompiling.value = false; isAnalyzing.value = false
    functions.value = new Map(); activeFunction.value = null
    resources.value = []; strings.value = []; decompileProgress.value = 0
    decompileError.value = null
  }

  return {
    projectId, projectName, localPath, relPath,
    isAnalyzing, meta, quickInfo,
    isDecompiling, decompileProgress, decompileBackend, decompileError,
    functions, functionList, totalFunctions, activeFunction,
    resources, strings,
    openBinary, addFunction, updateFunctionCode, setActiveFunction, renameFunction, reset,
  }
})
