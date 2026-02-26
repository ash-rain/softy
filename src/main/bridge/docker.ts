/**
 * DockerBridge — manages the softy-tools Docker container lifecycle
 * and provides a typed HTTP client to the container's FastAPI server.
 *
 * All binary file operations happen through a shared volume:
 *   HOST: ~/.softy/work/{projectId}/  ↔  CONTAINER: /work/{projectId}/
 */

import { app } from 'electron'
import { spawn } from 'child_process'
import { join } from 'path'
import { mkdirSync, copyFileSync } from 'fs'

const BASE_URL  = 'http://127.0.0.1:7800'
const COMPOSE   = join(__dirname, '../../../../docker/docker-compose.yml')

export class DockerBridge {
  private _workDir: string
  private _running = false

  constructor() {
    this._workDir = join(app.getPath('home'), '.softy', 'work')
    mkdirSync(this._workDir, { recursive: true })
    mkdirSync(join(app.getPath('home'), '.softy', 'ghidra-projects'), { recursive: true })
  }

  get workDir() { return this._workDir }
  get isRunning() { return this._running }

  // ── Container lifecycle ───────────────────────────────────────────────────

  async ensureRunning(): Promise<void> {
    if (await this.isHealthy()) {
      this._running = true
      return
    }
    await this.start()
  }

  async start(): Promise<void> {
    return new Promise((resolve, reject) => {
      const proc = spawn('docker', ['compose', '-f', COMPOSE, 'up', '-d', '--build'], {
        env: { ...process.env, HOME: app.getPath('home') },
        stdio: 'pipe',
      })
      proc.on('close', async (code) => {
        if (code !== 0) {
          reject(new Error(`docker compose up exited with code ${code}`))
          return
        }
        // Wait for health check
        let attempts = 0
        while (attempts < 30) {
          await sleep(1000)
          if (await this.isHealthy()) {
            this._running = true
            resolve()
            return
          }
          attempts++
        }
        reject(new Error('Container started but health check failed after 30s'))
      })
      proc.on('error', reject)
    })
  }

  async stop(): Promise<void> {
    return new Promise((resolve) => {
      const proc = spawn('docker', ['compose', '-f', COMPOSE, 'down'], {
        env: { ...process.env, HOME: app.getPath('home') },
        stdio: 'ignore',
      })
      proc.on('close', () => {
        this._running = false
        resolve()
      })
      proc.on('error', () => resolve())
    })
  }

  async isHealthy(): Promise<boolean> {
    try {
      const res = await fetch(`${BASE_URL}/health`, { signal: AbortSignal.timeout(2000) })
      return res.ok
    } catch {
      return false
    }
  }

  // ── File staging ──────────────────────────────────────────────────────────

  /**
   * Stage a local binary into the work volume.
   * Returns the relative path (container-relative) to use in API calls.
   */
  stageFile(localPath: string, projectId: string): string {
    const projectDir = join(this._workDir, projectId)
    mkdirSync(projectDir, { recursive: true })
    const fileName = 'binary'
    const dest = join(projectDir, fileName)
    copyFileSync(localPath, dest)
    return `${projectId}/${fileName}`
  }

  projectDir(projectId: string): string {
    return join(this._workDir, projectId)
  }

  // ── API methods ───────────────────────────────────────────────────────────

  async analyze(relPath: string): Promise<AnalyzeResponse> {
    return this._post('/api/analyze', { filePath: relPath })
  }

  async getStrings(relPath: string, minLen = 6): Promise<StringsResponse> {
    return this._get(`/api/analyze/strings?filePath=${encodeURIComponent(relPath)}&minLen=${minLen}`)
  }

  async startDecompile(relPath: string, projectId: string, backend = 'ghidra'): Promise<{ streamId: string; backend: string }> {
    return this._post('/api/decompile/start', { filePath: relPath, projectId, backend })
  }

  /** Returns an AsyncGenerator streaming DecompiledFunction objects via SSE */
  async *streamDecompile(streamId: string): AsyncGenerator<SSEEvent> {
    const res = await fetch(`${BASE_URL}/api/decompile/stream/${streamId}`, {
      headers: { Accept: 'text/event-stream' },
    })
    if (!res.ok || !res.body) throw new Error(`SSE failed: ${res.status}`)

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
          if (raw) {
            try { yield JSON.parse(raw) } catch { /* skip */ }
          }
        }
      }
    }
  }

  async quickAnalysis(relPath: string): Promise<QuickAnalysisResponse> {
    return this._post('/api/decompile/quick', { filePath: relPath })
  }

  async compile(req: CompileRequest): Promise<CompileResponse> {
    return this._post('/api/compile', req)
  }

  async assemble(req: AssembleRequest): Promise<AssembleResponse> {
    return this._post('/api/compile/assemble', req)
  }

  async listResources(relPath: string): Promise<{ resources: ResourceNode[] }> {
    return this._get(`/api/resources/list?filePath=${encodeURIComponent(relPath)}`)
  }

  /** Patch a function's bytes in the binary. Returns the patched binary as a Buffer. */
  async patchBinary(req: PatchBinaryRequest): Promise<Buffer> {
    const res = await fetch(`${BASE_URL}/api/patch/function`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req),
      signal: AbortSignal.timeout(30_000),
    })
    if (!res.ok) {
      const err = await res.text()
      throw new Error(`Patch error ${res.status}: ${err}`)
    }
    const ab = await res.arrayBuffer()
    return Buffer.from(ab)
  }

  // ── HTTP helpers ──────────────────────────────────────────────────────────

  private async _post<T>(path: string, body: unknown, timeoutMs = 90_000): Promise<T> {
    const res = await fetch(`${BASE_URL}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    })
    if (!res.ok) {
      const err = await res.text()
      throw new Error(`${path} → ${res.status}: ${err}`)
    }
    return res.json()
  }

  private async _get<T>(path: string, timeoutMs = 30_000): Promise<T> {
    const res = await fetch(`${BASE_URL}${path}`, {
      signal: AbortSignal.timeout(timeoutMs),
    })
    if (!res.ok) throw new Error(`GET ${path} → ${res.status}`)
    return res.json()
  }
}

function sleep(ms: number) { return new Promise((r) => setTimeout(r, ms)) }

// ── Types ──────────────────────────────────────────────────────────────────

export interface AnalyzeResponse {
  format: string
  arch: string
  bits: number
  endian: string
  os: string
  compiler: string | null
  entryPoint: number
  baseAddress: number
  fileSize: number
  hashes: { md5: string; sha1: string; sha256: string }
  sections: SectionInfo[]
  imports: ImportEntry[]
  exports: ExportEntry[]
  isPacked: boolean
  isSigned: boolean
  characteristics: Record<string, string>
}

export interface SectionInfo {
  name: string
  virtualAddress: number
  virtualSize: number
  rawSize: number
  entropy: number
  flags: string
}

export interface ImportEntry {
  library: string
  name: string
  address?: number
}

export interface ExportEntry {
  name: string
  address: number
  ordinal?: number
}

export interface DecompiledFunction {
  type: 'function'
  address: string
  name: string
  signature: string
  size: number
  callers: string[]
  callees: string[]
  cCode: string
  disassembly: DisasmOp[]
}

export interface DisasmOp {
  addr: string
  mnem: string
  ops: string
}

export interface SSEEvent {
  type: 'function' | 'progress' | 'complete' | 'error'
  [key: string]: unknown
}

export interface QuickAnalysisResponse {
  functions: unknown[]
  imports: unknown[]
  exports: unknown[]
  sections: unknown[]
  info: unknown
}

export interface StringsResponse {
  strings: { offset: number; value: string; encoding: string }[]
  total: number
}

export interface CompileRequest {
  sourceCode: string
  arch?: string
  os?: string
  optimize?: string
  outputFormat?: string
}

export interface CompileResponse {
  success: boolean
  output: string | null
  outputFormat: string
  errors: DiagnosticItem[]
  warnings: DiagnosticItem[]
  sizeBytes: number
}

export interface DiagnosticItem {
  file: string
  line: number
  col: number
  message: string
  raw: string
}

export interface AssembleRequest {
  assembly: string
  arch?: string
  syntax?: string
}

export interface AssembleResponse {
  success: boolean
  output: string | null
  errors: { message: string }[]
}

export interface PatchBinaryRequest {
  filePath:        string  // relative path to the binary in work dir
  functionAddress: string  // hex string e.g. "0x401010"
  functionSize:    number  // original function size in bytes
  objectBase64:    string  // base64-encoded compiled .o file
}

export interface ResourceNode {
  id: string
  name: string
  type: string
  path: string
  size: number
  offset: number
  canPreview: boolean
  canEdit: boolean
  children: ResourceNode[]
}
