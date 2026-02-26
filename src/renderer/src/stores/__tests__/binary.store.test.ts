import { describe, it, expect, beforeEach } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useBinaryStore, type BinaryMeta, type DecompiledFunction } from '../binary.store'

const makeMeta = (overrides: Partial<BinaryMeta> = {}): BinaryMeta => ({
  format: 'ELF64', arch: 'x86_64', bits: 64, endian: 'little', os: 'linux',
  compiler: 'gcc', entryPoint: 0x401000, baseAddress: 0x400000, fileSize: 8192,
  hashes: { md5: 'abc', sha1: 'def', sha256: 'ghi' },
  sections: [{ name: '.text', virtualAddress: 0x401000, virtualSize: 100, rawSize: 100, entropy: 4.5, flags: 'r-x' }],
  imports: [{ library: 'libc.so', name: 'printf' }],
  exports: [{ name: 'main', address: 0x401010 }],
  isPacked: false, isSigned: false, characteristics: {},
  ...overrides,
})

const makeFn = (overrides: Partial<DecompiledFunction> = {}): DecompiledFunction => ({
  address: '0x401010', name: 'main', signature: 'int main()', size: 42,
  callers: [], callees: ['printf'],
  cCode: 'int main() { return 0; }',
  disassembly: [{ addr: '0x401010', mnem: 'push', ops: 'rbp' }],
  ...overrides,
})

describe('binary.store', () => {
  beforeEach(() => { setActivePinia(createPinia()) })

  it('has correct initial state', () => {
    const store = useBinaryStore()
    expect(store.projectId).toBeNull()
    expect(store.projectName).toBe('')
    expect(store.meta).toBeNull()
    expect(store.isAnalyzing).toBe(false)
    expect(store.isDecompiling).toBe(false)
    expect(store.functionList).toHaveLength(0)
    expect(store.activeFunction).toBeNull()
    expect(store.resources).toHaveLength(0)
    expect(store.strings).toHaveLength(0)
    expect(store.decompileProgress).toBe(0)
    expect(store.decompileError).toBeNull()
  })

  describe('openBinary', () => {
    it('sets all project state from result', () => {
      const store = useBinaryStore()
      const meta  = makeMeta()
      store.openBinary({
        projectId: 'proj-1', name: 'hello', localPath: '/tmp/hello', relPath: 'hello',
        meta, quick: { functions: [1, 2, 3], imports: [], exports: [] },
      })
      expect(store.projectId).toBe('proj-1')
      expect(store.projectName).toBe('hello')
      expect(store.localPath).toBe('/tmp/hello')
      expect(store.relPath).toBe('hello')
      expect(store.meta).toEqual(meta)
      expect(store.totalFunctions).toBe(3)
    })

    it('clears previous functions and active selection', () => {
      const store = useBinaryStore()
      store.addFunction(makeFn())
      store.setActiveFunction('0x401010')
      expect(store.activeFunction).not.toBeNull()

      store.openBinary({
        projectId: 'proj-2', name: 'bye', localPath: '/tmp/bye', relPath: 'bye',
        meta: makeMeta(), quick: { functions: [], imports: [], exports: [] },
      })
      expect(store.functionList).toHaveLength(0)
      expect(store.activeFunction).toBeNull()
    })

    it('resets decompile progress and error', () => {
      const store = useBinaryStore()
      store.decompileProgress = 50
      store.decompileError    = 'some error'
      store.openBinary({
        projectId: 'p', name: 'n', localPath: 'l', relPath: 'r',
        meta: makeMeta(), quick: { functions: [], imports: [], exports: [] },
      })
      expect(store.decompileProgress).toBe(0)
      expect(store.decompileError).toBeNull()
    })
  })

  describe('addFunction / functionList', () => {
    it('addFunction inserts into the map and updates functionList', () => {
      const store = useBinaryStore()
      store.addFunction(makeFn({ address: '0x401010', name: 'main' }))
      store.addFunction(makeFn({ address: '0x401050', name: 'add' }))
      expect(store.functionList).toHaveLength(2)
    })

    it('addFunction overwrites existing entry for same address', () => {
      const store = useBinaryStore()
      store.addFunction(makeFn({ address: '0x401010', name: 'main' }))
      store.addFunction(makeFn({ address: '0x401010', name: 'renamed' }))
      expect(store.functionList).toHaveLength(1)
      expect(store.functionList[0].name).toBe('renamed')
    })

    it('functionList is reactive to Map changes', () => {
      const store = useBinaryStore()
      expect(store.functionList).toHaveLength(0)
      store.addFunction(makeFn())
      expect(store.functionList).toHaveLength(1)
    })
  })

  describe('setActiveFunction', () => {
    it('sets activeFunction for a known address', () => {
      const store = useBinaryStore()
      const fn    = makeFn({ address: '0x401010', name: 'main' })
      store.addFunction(fn)
      store.setActiveFunction('0x401010')
      expect(store.activeFunction?.name).toBe('main')
    })

    it('sets activeFunction to null for unknown address', () => {
      const store = useBinaryStore()
      store.setActiveFunction('0xdeadbeef')
      expect(store.activeFunction).toBeNull()
    })
  })

  describe('renameFunction', () => {
    it('updates the function name', () => {
      const store = useBinaryStore()
      store.addFunction(makeFn({ address: '0x401010', name: 'sub_401010' }))
      store.renameFunction('0x401010', 'decrypt_buffer')
      expect(store.functions.get('0x401010')?.name).toBe('decrypt_buffer')
    })

    it('updates activeFunction name when it is the renamed function', () => {
      const store = useBinaryStore()
      store.addFunction(makeFn({ address: '0x401010', name: 'FUN_401010' }))
      store.setActiveFunction('0x401010')
      store.renameFunction('0x401010', 'parse_header')
      expect(store.activeFunction?.name).toBe('parse_header')
    })

    it('does nothing for unknown address', () => {
      const store = useBinaryStore()
      expect(() => store.renameFunction('0xdeadbeef', 'foo')).not.toThrow()
    })
  })

  describe('updateFunctionCode', () => {
    it('sets editedCode on the function', () => {
      const store = useBinaryStore()
      store.addFunction(makeFn({ address: '0x401010' }))
      store.updateFunctionCode('0x401010', 'int main() { return 1; }')
      expect(store.functions.get('0x401010')?.editedCode).toBe('int main() { return 1; }')
    })

    it('does nothing for unknown address', () => {
      const store = useBinaryStore()
      // Should not throw
      expect(() => store.updateFunctionCode('0xdeadbeef', 'code')).not.toThrow()
    })
  })

  describe('reset', () => {
    it('clears all state back to defaults', () => {
      const store = useBinaryStore()
      store.openBinary({
        projectId: 'p', name: 'n', localPath: 'l', relPath: 'r',
        meta: makeMeta(), quick: { functions: [1], imports: [], exports: [] },
      })
      store.addFunction(makeFn())
      store.isDecompiling = true

      store.reset()

      expect(store.projectId).toBeNull()
      expect(store.projectName).toBe('')
      expect(store.meta).toBeNull()
      expect(store.isDecompiling).toBe(false)
      expect(store.isAnalyzing).toBe(false)
      expect(store.functionList).toHaveLength(0)
      expect(store.activeFunction).toBeNull()
      expect(store.resources).toHaveLength(0)
      expect(store.strings).toHaveLength(0)
      expect(store.decompileProgress).toBe(0)
      expect(store.decompileError).toBeNull()
    })
  })
})
