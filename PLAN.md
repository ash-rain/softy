# Softy — Implementation Plan

**Stack**: Electron 33 · Node.js 22 · Vue 3 · TypeScript · Vite 6 · Tailwind CSS v4 · Monaco Editor · Pinia · Electron Forge
**AI**: Ollama (local) · OpenAI · Anthropic · OpenRouter
**Tools**: Ghidra 11.3 (headless) · Radare2/r2pipe · RetDec · LLVM/Clang · Keystone Assembler
**Database**: SQLite (better-sqlite3)

---

## Table of Contents

1. [Project Vision](#1-project-vision)
2. [Architecture](#2-architecture)
3. [Repository Structure](#3-repository-structure)
4. [Technology Decisions](#4-technology-decisions)
5. [UI Design System](#5-ui-design-system)
6. [IPC Contract](#6-ipc-contract)
7. [Decompilation Pipeline](#7-decompilation-pipeline)
8. [Compiler Pipeline](#8-compiler-pipeline)
9. [AI Integration](#9-ai-integration)
10. [Resources Browser](#10-resources-browser)
11. [Binary Meta Panel](#11-binary-meta-panel)
12. [VS Code Integration](#12-vs-code-integration)
13. [Data Model & Storage](#13-data-model--storage)
14. [Implementation Phases](#14-implementation-phases)
15. [External Tool Dependencies](#15-external-tool-dependencies)
16. [Testing Strategy](#16-testing-strategy)
17. [Packaging & Distribution](#17-packaging--distribution)
18. [Future Roadmap](#18-future-roadmap)

---

## 1. Project Vision

Softy collapses the distance between a compiled binary and human understanding. The thesis is simple: **any binary should be readable, any readable code should be recompilable, and AI should do the hard cognitive work in between**.

The product is a desktop application — local-first, private by default, cross-platform — that wraps the best open-source analysis toolchain (Ghidra, r2, RetDec, LLVM) in an interface worthy of the task. The AI layer is not bolted on; it is the differentiating feature that makes the output of those tools actually useful.

### Design Principles (Steve Jobs Mode)
1. **One thing at a time** — The binary is the document. Open it, work on it, close it. No project overhead until you need it.
2. **Invisible complexity** — Ghidra, LLVM, Ollama are infrastructure. The user should never see them.
3. **Progressive disclosure** — Start with the overview. Drill into functions. Drill into instructions. Each level reveals more, never overwhelms.
4. **No dead pixels** — Every element earns its place. If a feature isn't visible, it shouldn't exist.
5. **Fast or it's broken** — Streaming decompilation, instant AI responses, sub-100ms UI transitions. Slow tools are unusable tools.

---

## 2. Architecture

### Process Model

```
┌──────────────────────────────────────────────────────────────┐
│  Electron Main Process (Node.js)                             │
│                                                              │
│  ┌─────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │ IPC Router  │  │  Tool Manager   │  │  Project Store  │  │
│  │             │  │                 │  │  (SQLite)       │  │
│  │ ipcMain     │  │ Ghidra          │  │                 │  │
│  │ handlers    │  │ r2pipe          │  │ Projects        │  │
│  │             │  │ RetDec          │  │ Sessions        │  │
│  │             │  │ LLVM            │  │ AI history      │  │
│  │             │  │ Keystone        │  │                 │  │
│  └──────┬──────┘  └─────────────────┘  └─────────────────┘  │
│         │                                                    │
│  ┌──────▼──────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │  AI Manager │  │Resource Extractor│  │  File Analyzer  │  │
│  │             │  │                 │  │                 │  │
│  │ Ollama      │  │ PE resources    │  │ Format detect   │  │
│  │ OpenAI      │  │ ELF sections    │  │ Arch detect     │  │
│  │ Anthropic   │  │ Mach-O segments │  │ Entropy         │  │
│  │ OpenRouter  │  │                 │  │ Hashing         │  │
│  └─────────────┘  └─────────────────┘  └─────────────────┘  │
└──────────────────────────────────────────────────────────────┘
                              │ IPC (contextBridge)
┌─────────────────────────────▼────────────────────────────────┐
│  Renderer Process (Vue 3 + Vite)                             │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  App Shell                                              │ │
│  │  ┌──────────┐ ┌────────────────────────┐ ┌──────────┐  │ │
│  │  │ Sidebar  │ │    Editor Area         │ │  Right   │  │ │
│  │  │          │ │                        │ │  Panel   │  │ │
│  │  │ Function │ │  Monaco Editor         │ │          │  │ │
│  │  │ Tree     │ │  (decompiled code)     │ │  AI Chat │  │ │
│  │  │          │ │                        │ │  or      │  │ │
│  │  │ Resource │ │  + split disassembly   │ │  Meta    │  │ │
│  │  │ Browser  │ │                        │ │  Info    │  │ │
│  │  │          │ │                        │ │          │  │ │
│  │  │ Symbol   │ └────────────────────────┘ └──────────┘  │ │
│  │  │ Table    │                                          │ │
│  │  └──────────┘                                          │ │
│  └─────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

### Data Flow — Decompilation

```
Binary File
    │
    ▼
[File Analyzer] → format, arch, OS, compiler hint
    │
    ▼
[Decompiler Controller]
    │
    ├─── Ghidra headless (preferred, best quality)
    ├─── Radare2 r2pipe (fast, fallback / parallel overview)
    └─── RetDec (fallback for Ghidra failure)
    │
    ▼
[Raw Decompile Output]  ← C pseudocode + disassembly JSON
    │
    ▼
[AI Enhancement Layer] (optional, configurable)
    │  ├── Rename variables/functions
    │  ├── Recover types
    │  └── Add inline comments
    ▼
[Project Store] → SQLite
    │
    ▼
[IPC → Renderer]  ← streamed function-by-function
    │
    ▼
[Monaco Editor] + [Function Tree] + [Disassembly Pane]
```

---

## 3. Repository Structure

```
softy/
├── electron/                     # Main process (Node.js)
│   ├── main.ts                   # Electron app entry, window creation
│   ├── preload.ts                # contextBridge API exposure
│   ├── ipc/                      # IPC handler modules
│   │   ├── index.ts              # Register all handlers
│   │   ├── decompiler.ipc.ts     # Decompilation IPC
│   │   ├── compiler.ipc.ts       # Compilation IPC
│   │   ├── ai.ipc.ts             # AI streaming IPC
│   │   ├── resources.ipc.ts      # Resource browser IPC
│   │   ├── meta.ipc.ts           # Binary metadata IPC
│   │   ├── vscode.ipc.ts         # VS Code integration IPC
│   │   └── project.ipc.ts        # Project persistence IPC
│   ├── tools/                    # External tool wrappers
│   │   ├── ghidra.ts             # Ghidra headless runner + script output parser
│   │   ├── r2.ts                 # Radare2 r2pipe wrapper
│   │   ├── retdec.ts             # RetDec CLI wrapper
│   │   ├── llvm.ts               # Clang/LLVM compile wrapper
│   │   ├── keystone.ts           # Keystone assembler (node-keystone)
│   │   ├── file-analyzer.ts      # Format/arch/compiler detection
│   │   ├── resource-extractor.ts # PE/ELF/Mach-O resource extraction
│   │   └── tool-manager.ts       # Tool availability detection, download
│   ├── ai/                       # AI provider abstraction
│   │   ├── ai-manager.ts         # Provider switcher, streaming
│   │   ├── providers/
│   │   │   ├── ollama.ts         # Ollama HTTP client
│   │   │   ├── openai.ts         # OpenAI SDK wrapper
│   │   │   ├── anthropic.ts      # Anthropic SDK wrapper
│   │   │   └── openrouter.ts     # OpenRouter (OpenAI-compat) wrapper
│   │   └── prompts/
│   │       ├── rename.ts         # Variable/function rename prompts
│   │       ├── explain.ts        # Function explanation prompts
│   │       ├── vulnerability.ts  # Security analysis prompts
│   │       ├── type-recovery.ts  # Type/struct recovery prompts
│   │       └── context.ts        # Context assembly (chunking strategy)
│   ├── db/
│   │   ├── database.ts           # better-sqlite3 initialization
│   │   ├── schema.ts             # Table definitions
│   │   └── repositories/
│   │       ├── project.repo.ts
│   │       ├── function.repo.ts
│   │       └── ai-session.repo.ts
│   └── utils/
│       ├── temp-dir.ts           # Managed temp directories
│       ├── process-runner.ts     # Child process helper with streaming
│       └── entropy.ts            # Shannon entropy calculation
│
├── src/                          # Renderer process (Vue 3)
│   ├── main.ts                   # Vue app entry
│   ├── App.vue                   # Root component, layout
│   ├── router/
│   │   └── index.ts              # Vue Router (Welcome → Workspace)
│   ├── stores/                   # Pinia stores
│   │   ├── binary.store.ts       # Active binary, functions, analysis state
│   │   ├── editor.store.ts       # Editor state, cursor, splits
│   │   ├── ai.store.ts           # AI config, conversation history
│   │   ├── resources.store.ts    # Resources tree data
│   │   └── settings.store.ts     # User preferences
│   ├── views/
│   │   ├── WelcomeView.vue       # Drop zone, recent files
│   │   ├── WorkspaceView.vue     # Main analysis workspace
│   │   └── SettingsView.vue      # AI config, tools, appearance
│   ├── components/
│   │   ├── layout/
│   │   │   ├── AppShell.vue      # Main layout shell (sidebar + editor + panel)
│   │   │   ├── TitleBar.vue      # Custom titlebar (frameless window)
│   │   │   └── StatusBar.vue     # Bottom status: arch, progress, AI status
│   │   ├── welcome/
│   │   │   ├── DropZone.vue      # Drag-and-drop binary intake
│   │   │   └── RecentFiles.vue   # Recent project list
│   │   ├── sidebar/
│   │   │   ├── Sidebar.vue       # Collapsible left sidebar
│   │   │   ├── FunctionTree.vue  # Hierarchical function navigator
│   │   │   ├── ResourceBrowser.vue  # Resource tree view
│   │   │   └── SymbolTable.vue   # Import/export symbol list
│   │   ├── editor/
│   │   │   ├── CodeEditor.vue    # Monaco wrapper (decompiled C)
│   │   │   ├── DisasmPane.vue    # Annotated disassembly split
│   │   │   ├── DiffViewer.vue    # Before/after binary diff
│   │   │   └── EditorTabs.vue    # Open functions as tabs
│   │   ├── panels/
│   │   │   ├── RightPanel.vue    # Switching panel container
│   │   │   ├── AIPanel.vue       # AI chat, streaming, history
│   │   │   ├── MetaPanel.vue     # Binary metadata display
│   │   │   ├── EntropyChart.vue  # Section entropy visualization
│   │   │   └── ResourcePreview.vue  # Preview selected resource
│   │   ├── resources/
│   │   │   ├── ResourceEditor.vue   # Edit resource values
│   │   │   ├── ImagePreview.vue     # Inline image renderer
│   │   │   ├── StringsTable.vue     # Strings with search/edit
│   │   │   ├── ManifestEditor.vue   # XML manifest editor
│   │   │   └── VersionInfoEditor.vue # PE version info editor
│   │   └── ui/                   # Primitive design system components
│   │       ├── GlassCard.vue
│   │       ├── SoftyButton.vue
│   │       ├── SoftyInput.vue
│   │       ├── ProgressRing.vue
│   │       ├── AnalysisProgress.vue
│   │       ├── Badge.vue
│   │       ├── Tooltip.vue
│   │       ├── ContextMenu.vue
│   │       └── Modal.vue
│   ├── composables/
│   │   ├── useIPC.ts             # Typed IPC bridge
│   │   ├── useMonaco.ts          # Monaco initialization, theming
│   │   ├── useAI.ts              # AI streaming composable
│   │   ├── useDragDrop.ts        # File drag/drop handling
│   │   └── useKeyboard.ts        # Global keyboard shortcuts
│   └── assets/
│       ├── fonts/                # JetBrains Mono, Inter
│       └── icons/                # App icons, format icons
│
├── scripts/
│   └── ghidra/
│       ├── DecompileAll.java     # Ghidra headless script: decompile all functions
│       ├── ExportDisasm.java     # Export disassembly as JSON
│       └── ExtractResources.java # Extract embedded resources
│
├── vscode-extension/             # Softy VS Code extension
│   ├── src/
│   │   ├── extension.ts          # Extension entry
│   │   ├── softyLanguage.ts      # Syntax highlight for Ghidra pseudocode
│   │   ├── compileBack.ts        # "Compile back" command
│   │   └── fileWatcher.ts        # Watch for changes, sync to Softy
│   └── package.json
│
├── electron.vite.config.ts       # electron-vite config (main + preload + renderer)
├── package.json
├── tsconfig.json
├── tailwind.config.ts
└── forge.config.ts               # Electron Forge packaging
```

---

## 4. Technology Decisions

### Electron vs. Tauri
Electron is chosen because:
- Ghidra requires spawning a JVM process — Node.js `child_process` is battle-tested for this
- `better-sqlite3` provides synchronous SQLite with excellent performance
- `r2pipe` has a Node.js binding that works through stdin/stdout
- The node ecosystem has `file-type`, binary parsing libs (`pe-library`, `macho-parser`, `elfinfo`) that are mature

### Vue 3 vs. React
Vue 3 with `<script setup>` and Pinia gives cleaner reactivity for data-heavy UIs (function lists with thousands of entries, streaming AI text) with less boilerplate. The Composition API maps naturally to the "composable per IPC domain" pattern we use.

### electron-vite
`electron-vite` (not plain Vite) handles the three separate build targets (main, preload, renderer) with hot-reload in development. It is the standard for modern Electron + Vite projects.

### Monaco Editor
`monaco-editor` directly (not a wrapper library) — gives full control over custom language registration, themes, and keybindings. We register a `ghidra-c` language for the pseudocode output with custom token patterns.

### Ghidra over IDA/Binary Ninja
- Free, open-source, Apache 2.0
- Best-in-class C decompiler output quality (on par with IDA's Hex-Rays)
- Headless mode with full scripting API
- Active development (11.3, February 2025)
- LLM4Decompile (the best AI decompilation research model) uses Ghidra output as training data

### LLVM/Clang for recompilation
- Cross-platform, cross-architecture
- Clang gives rich error messages usable in the editor
- LLVM IR as intermediate format allows architecture-agnostic optimization
- Available on all three platforms via system package or bundled binaries

---

## 5. UI Design System

### Design Language: "Dark Glass"

The aesthetic is precision instrumentation — the interface of a tool that costs nothing but feels like it costs everything. Black backgrounds, luminous accents, surgical typography.

```
Color System (Tailwind CSS custom tokens):
─────────────────────────────────────────
Background layers:
  --bg-void:      #030507   (deepest, app background)
  --bg-base:      #090d12   (panels, sidebars)
  --bg-surface:   #0f1520   (cards, editor background)
  --bg-elevated:  #161e2e   (modals, popovers, hover)
  --bg-border:    #1e2d42   (dividers, subtle borders)

Accent (electric cyan — the signature color):
  --accent-primary:   #00d4ff   (active states, highlights)
  --accent-secondary: #0099cc   (secondary actions)
  --accent-glow:      #00d4ff33 (glow effects, focus rings)

Status colors:
  --status-ok:      #00ff9d   (success, clean)
  --status-warn:    #ffaa00   (warning)
  --status-error:   #ff4444   (error, vulnerability)
  --status-ai:      #a855f7   (AI-generated content indicator)

Text:
  --text-primary:   #e8f4fd   (primary content)
  --text-secondary: #7a9ab8   (labels, metadata)
  --text-muted:     #3d5a78   (disabled, placeholders)
  --text-code:      #c9e8ff   (code, hex values)
```

### Typography
- **Code / Editor**: JetBrains Mono 13px — the definitive monospace for code
- **UI Labels**: Inter 13px — system-quality sans-serif
- **Headings**: Inter 600 weight
- Line heights: 1.6 for prose, 1.5 for code

### Layout System
- Three-column layout: **sidebar (280px)** | **editor (flex)** | **right panel (360px)**
- All panels collapsible to icon rail (48px)
- Sidebar and right panel widths user-resizable (min 200px / max 600px)
- Status bar: 28px fixed bottom
- Title bar: 40px custom (frameless window, draggable)
- **No horizontal scrollbars anywhere** — content wraps or truncates with `title` tooltip

### Component Patterns

**GlassCard**: The primary container primitive.
```css
background: rgba(15, 21, 32, 0.8);
border: 1px solid rgba(30, 45, 66, 0.6);
backdrop-filter: blur(12px);
border-radius: 8px;
```

**Active/Focus glow** (used on selected function, focused input):
```css
box-shadow: 0 0 0 1px #00d4ff, 0 0 16px rgba(0, 212, 255, 0.15);
```

**AI content indicator**: A subtle left border in `--status-ai` (#a855f7) on any AI-generated annotation.

**Progress indicators**: Ring-style (SVG strokeDasharray animation), never progress bars. Feels more precise.

**Entropy chart**: Canvas-based, section bars with color gradient from `--status-ok` (low entropy, normal code) through yellow to `--status-error` (high entropy, likely packed/encrypted).

### Monaco Theme: "Softy Dark"
Custom Monaco theme registered as `softy-dark`:
- Background: `#090d12`
- Selection: `rgba(0, 212, 255, 0.15)`
- Line highlight: `rgba(14, 20, 32, 0.8)`
- Token colors: keywords cyan `#00d4ff`, types teal `#00e5cc`, strings gold `#ffcc66`, comments muted `#3d5a78`, numbers orange `#ff9933`, AI-renamed symbols purple `#b880ff`

### Micro-interactions
- Function tree items: 150ms ease slide-in on first load, staggered 20ms per item
- Panel switches: 200ms ease opacity + 4px translate
- AI streaming text: characters appear with `opacity: 0 → 1` fade, not hard append
- Compile status: pulsing ring during compilation, solid check on success
- Drop zone: scale 1.02 + glow border on drag-over

---

## 6. IPC Contract

All IPC uses typed channels defined in `electron/ipc/channels.ts`. The preload script exposes a `window.softy` API:

```typescript
// preload.ts exposed API shape
interface SoftyAPI {
  // Decompilation
  decompile: {
    open(filePath: string, options: DecompileOptions): Promise<BinaryInfo>
    streamFunctions(projectId: string): void           // starts IPC stream
    onFunction(cb: (fn: DecompiledFunction) => void): () => void
    onProgress(cb: (p: DecompileProgress) => void): () => void
    onComplete(cb: (summary: DecompileSummary) => void): () => void
    cancel(projectId: string): Promise<void>
  }

  // Compilation
  compile: {
    build(projectId: string, options: CompileOptions): Promise<CompileResult>
    patch(projectId: string, functionId: string, code: string): Promise<PatchResult>
    assemble(asm: string, arch: Arch): Promise<Uint8Array>
    onLog(cb: (line: string) => void): () => void
  }

  // AI
  ai: {
    chat(message: AIMessage, context: AIContext): void   // starts stream
    onChunk(cb: (chunk: string) => void): () => void
    onComplete(cb: (response: AIResponse) => void): () => void
    rename(functionId: string, provider: AIProvider): Promise<RenameResult>
    explain(functionId: string, provider: AIProvider): Promise<string>
    findVulnerabilities(projectId: string): Promise<Vulnerability[]>
    getProviders(): Promise<AIProviderStatus[]>
    testProvider(provider: AIProvider): Promise<boolean>
  }

  // Resources
  resources: {
    list(projectId: string): Promise<ResourceNode[]>
    get(resourceId: string): Promise<ResourceData>
    preview(resourceId: string): Promise<ResourcePreview>
    save(resourceId: string, data: Uint8Array): Promise<void>
    inject(projectId: string, resourceId: string, data: Uint8Array): Promise<void>
  }

  // Metadata
  meta: {
    get(projectId: string): Promise<BinaryMetadata>
    getEntropy(projectId: string): Promise<EntropyData>
    getStrings(projectId: string, filter?: StringFilter): Promise<StringEntry[]>
    getImports(projectId: string): Promise<ImportEntry[]>
    getExports(projectId: string): Promise<ExportEntry[]>
  }

  // VS Code
  vscode: {
    export(projectId: string, targetDir?: string): Promise<string>
    openInVSCode(projectId: string): Promise<void>
    isInstalled(): Promise<boolean>
    watchProject(projectId: string): Promise<void>
  }

  // Projects
  projects: {
    list(): Promise<ProjectSummary[]>
    get(projectId: string): Promise<Project>
    delete(projectId: string): Promise<void>
    getFunction(functionId: string): Promise<DecompiledFunction>
    saveFunction(functionId: string, code: string): Promise<void>
  }

  // Dialog
  dialog: {
    openFile(): Promise<string | null>
    saveFile(defaultName: string): Promise<string | null>
  }
}
```

### IPC Event Channels (Main → Renderer)
```
softy:decompile:function     — DecompiledFunction (streamed per function)
softy:decompile:progress     — { phase, current, total, message }
softy:decompile:complete     — DecompileSummary
softy:decompile:error        — { code, message, tool }
softy:compile:log            — { line, level }
softy:compile:complete       — CompileResult
softy:ai:chunk               — { text, sessionId }
softy:ai:complete            — AIResponse
softy:vscode:change          — { functionId, code }  (VS Code sync)
```

---

## 7. Decompilation Pipeline

### Phase 1: Binary Intake (`file-analyzer.ts`)

```typescript
interface BinaryInfo {
  format: 'PE' | 'ELF' | 'MachO' | 'WASM' | 'JavaClass' | 'DEX' | 'Raw'
  arch: 'x86' | 'x86_64' | 'ARM' | 'ARM64' | 'MIPS' | 'RISC-V' | 'PPC' | 'Unknown'
  bits: 32 | 64
  endian: 'little' | 'big'
  os: 'Windows' | 'Linux' | 'macOS' | 'Android' | 'Unknown'
  compiler: string | null   // e.g. "GCC 13.2", "MSVC 19.38", "Rust", "Go 1.22"
  entryPoint: number
  baseAddress: number
  fileSize: number
  hashes: { md5: string; sha1: string; sha256: string; ssdeep: string }
  isSigned: boolean
  isPacked: boolean         // heuristic from entropy
}
```

Detection uses:
- `file-type` npm package for magic bytes (primary)
- Custom magic byte table for formats `file-type` doesn't cover (firmware, DEX)
- PE: `pe-library` for parsing PE headers
- ELF: `elfinfo` for ELF header parsing
- Mach-O: `macho-parser` for Mach-O header parsing
- Compiler fingerprinting: known GCC/MSVC/Clang/Rust/Go metadata signatures

### Phase 2: Ghidra Headless Analysis

**Setup**: Softy bundles Ghidra scripts in `scripts/ghidra/`. On first run, Softy detects or downloads a Ghidra installation (bundled JRE).

**DecompileAll.java** — Post-analysis script that:
1. Iterates all functions in the program
2. Calls `DecompInterface.decompileFunction()` on each
3. Outputs JSON to stdout: `{ address, name, signature, cCode, disassembly, callers, callees, size }`
4. Streams output line-by-line (one JSON object per line = one function)

```typescript
// ghidra.ts
async function* runGhidraDecompile(
  binaryPath: string,
  projectDir: string
): AsyncGenerator<DecompiledFunction> {
  const proc = spawn(GHIDRA_HEADLESS, [
    projectDir, 'SoftyAnalysis',
    '-import', binaryPath,
    '-postScript', DECOMPILE_SCRIPT,
    '-scriptPath', SCRIPTS_DIR,
    '-deleteProject',
    '-noanalysis',    // skip if already analyzed
  ])

  for await (const line of readline(proc.stdout)) {
    if (line.startsWith('{')) {
      yield JSON.parse(line) as DecompiledFunction
    }
  }
}
```

**Timeout**: 30 seconds per function (Ghidra `decompileFunction(func, 30, monitor)`). Large/obfuscated functions time out gracefully with `// Decompilation timed out` comment.

### Phase 3: Radare2 Fast Analysis (Parallel)

r2 runs in parallel with Ghidra via `r2pipe` for:
- **Instant function list** before Ghidra finishes (so the UI shows something immediately)
- **Fast disassembly** for the disassembly pane (Ghidra disassembly is slower)
- **CFG (control flow graph)** data via `agj` command
- **Call graph** via `agCj` command
- **String extraction** via `izj` command
- **Import/export tables** via `iij` / `iEj`

```typescript
// r2.ts — uses r2pipe Node.js binding
import r2pipe from 'r2pipe'

async function analyzeQuick(path: string): Promise<QuickAnalysis> {
  const r2 = await r2pipe.openAsync(path)
  await r2.cmdAsync('aaa')   // analyze all

  const functions = JSON.parse(await r2.cmdAsync('aflj'))
  const imports = JSON.parse(await r2.cmdAsync('iij'))
  const exports = JSON.parse(await r2.cmdAsync('iEj'))
  const strings = JSON.parse(await r2.cmdAsync('izj'))
  const sections = JSON.parse(await r2.cmdAsync('iSj'))

  await r2.quit()
  return { functions, imports, exports, strings, sections }
}
```

### Phase 4: AI Enhancement

After each function decompiles (streamed), optionally send to AI for enrichment:

```typescript
// prompts/rename.ts
function buildRenamePrompt(fn: DecompiledFunction): string {
  return `You are an expert reverse engineer analyzing decompiled C code.

Binary context:
- Architecture: ${fn.arch}
- Compiler: ${fn.compiler ?? 'unknown'}
- Function address: ${fn.address}
- Called by: ${fn.callers.slice(0, 5).join(', ')}
- Calls: ${fn.callees.slice(0, 5).join(', ')}

Decompiled C code:
\`\`\`c
${fn.cCode}
\`\`\`

Task: Rename all variables and the function itself to meaningful, descriptive names.
Rules:
- Use camelCase for variables, PascalCase for function names
- Infer purpose from context (e.g., local_18 used as a loop counter → i or count)
- Identify common patterns (strlen, strcmp, malloc patterns)
- Return ONLY the renamed C code, no explanation
- Preserve all logic exactly, change only names`
}
```

**Chunking strategy for large binaries**: Context window limit = ~128k tokens. For functions > 2000 lines, chunk by basic block and process in parallel, then merge. For whole-binary analysis (vulnerability scan), process in sliding windows of 20 functions with 5-function overlap for context continuity.

### Decompilation Fallback Chain

```
Ghidra ──failure──► RetDec ──failure──► r2 pdc (radare2 built-in decompiler)
         timeout              timeout       │
                                           ▼
                                    Raw disassembly only
```

---

## 8. Compiler Pipeline

### Recompilation Flow

```
Modified C code
    │
    ▼
[Syntax validation] ← Monaco real-time (Monaco's built-in C language support)
    │
    ▼
[clang] -target {arch}-{os} -O1 -fno-inline -c -o function.o
    │
    ├── Success → object file
    └── Error → error markers in Monaco editor
    │
    ▼
[Patch Injection]
    ├── Function-level: find original function bytes by address,
    │   replace with new code bytes + fix call targets
    └── Full rebuild: link all object files → new binary
    │
    ▼
[Output binary]
```

### Clang Targets

| Original Arch | Clang Target Triple |
|---|---|
| x86 (32-bit) | `i386-unknown-linux-gnu` or `i386-pc-windows-msvc` |
| x86-64 | `x86_64-unknown-linux-gnu` or `x86_64-pc-windows-msvc` |
| ARM (32-bit) | `armv7-unknown-linux-gnueabihf` |
| ARM64 | `aarch64-unknown-linux-gnu` or `aarch64-apple-macosx` |
| MIPS | `mips-unknown-linux-gnu` |

### Patch Injection

For surgical function-level patching:
1. Compile new function to position-independent code (`-fPIC`)
2. Calculate size vs original function
3. If new ≤ original: overwrite in-place, fill remainder with NOPs
4. If new > original: append to end of text section, redirect original entry with `JMP new_addr`
5. Fix relocation entries if applicable

### Assembly-level patching (Keystone)

For precise byte-level edits without recompiling:
```typescript
import Keystone from 'keystone'

async function assemble(
  asm: string,
  arch: Arch,
  syntax: 'intel' | 'att' = 'intel'
): Promise<Uint8Array> {
  const ks = new Keystone(archToKS(arch), syntaxToKS(syntax))
  const [bytes, count] = ks.asm(asm, 0)
  ks.close()
  return new Uint8Array(bytes)
}
```

---

## 9. AI Integration

### Provider Abstraction

```typescript
// ai/ai-manager.ts
interface AIProvider {
  id: string
  name: string
  models: AIModel[]
  chat(messages: Message[], options: ChatOptions): AsyncGenerator<string>
  isAvailable(): Promise<boolean>
}

class AIManager {
  private providers: Map<string, AIProvider>

  async* stream(
    provider: string,
    model: string,
    messages: Message[]
  ): AsyncGenerator<string> {
    const p = this.providers.get(provider)
    if (!p) throw new Error(`Unknown provider: ${provider}`)
    yield* p.chat(messages, { model, stream: true })
  }
}
```

### Ollama Integration

```typescript
// ai/providers/ollama.ts
class OllamaProvider implements AIProvider {
  private baseUrl = 'http://localhost:11434'

  async* chat(messages: Message[], options: ChatOptions) {
    const res = await fetch(`${this.baseUrl}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: options.model,  // e.g. "deepseek-r1:14b"
        messages,
        stream: true,
        options: {
          num_ctx: 32768,    // context window
          temperature: 0.1   // low temp for code tasks
        }
      })
    })

    for await (const line of readLines(res.body)) {
      const data = JSON.parse(line)
      if (data.message?.content) yield data.message.content
      if (data.done) break
    }
  }

  async isAvailable(): Promise<boolean> {
    try {
      await fetch(`${this.baseUrl}/api/tags`, { signal: AbortSignal.timeout(2000) })
      return true
    } catch { return false }
  }
}
```

### Recommended Models

| Use Case | Ollama Model | Cloud Fallback |
|---|---|---|
| Variable rename + typing | `deepseek-r1:14b` | Claude 3.5 Sonnet |
| Function explanation | `codellama:34b` | GPT-4o |
| Vulnerability analysis | `deepseek-r1:32b` | Claude 3.5 Sonnet |
| Algorithm identification | `starcoder2:15b` | GPT-4o |
| Quick Q&A (fast) | `qwen2.5-coder:7b` | GPT-4o mini |

### Context Assembly for Large Binaries

For whole-binary operations (rename all, vulnerability scan), we cannot fit everything in one prompt. Strategy:

1. **Priority ranking**: Sort functions by reference count (high-reference = important) and process most important first
2. **Sliding window**: Process N functions per prompt with context from preceding batch summary
3. **Dependency graph**: Use the call graph to ensure callee context is included with caller
4. **Caching**: Cache AI responses per function + code hash in SQLite. Same code = skip AI call

### AI Panel UI Features
- Chat history persisted per project in SQLite
- "Ask about selection" — select code in Monaco → right-click → "Ask AI" pre-fills with selection
- Streaming display: text appears character-by-character with cursor indicator
- AI provider status badge in status bar (green = Ollama running, purple = cloud)
- Model selector in header bar of AI panel
- Token usage display per message
- "Apply to editor" button on rename/comment suggestions

---

## 10. Resources Browser

### Supported Resource Types

#### PE/COFF Resources (Windows)
- **RT_ICON** / **RT_GROUP_ICON**: Render icons at all sizes (16x16 to 256x256)
- **RT_BITMAP**: Render BMP images
- **RT_CURSOR**: Show cursor hotspot
- **RT_DIALOG**: Parse and display dialog templates as property tables
- **RT_MENU**: Display menu tree structure
- **RT_STRING**: String table (16 strings per block), fully editable
- **RT_VERSION**: VersionInfo struct (FileVersion, ProductName, CompanyName, etc.) with form editor
- **RT_MANIFEST**: XML manifest with formatted view + edit
- **RT_ACCELERATOR**: Keyboard shortcut table
- **RT_RCDATA**: Hex dump + heuristic detection (might be embedded PE, zip, etc.)
- **RT_HTML**: HTML content with preview

Library: `pe-library` (npm) for parsing; custom renderer components per type.

#### ELF Sections
- `.rodata`: Strings, constants
- `.data` / `.bss`: Initialized/uninitialized data
- `.debug_*`: DWARF debug info (parsed for source info if available)
- `.note.*`: Note sections (build ID, ABI info)
- Symbol table: `.symtab` / `.dynsym` with full name/type/binding display
- Dynamic section: `.dynamic` — library deps, RPATH, etc.
- Custom sections: hex dump + entropy

Library: `elfinfo` (npm) + custom section parser.

#### Mach-O
- `__TEXT/__text`: Code sections
- `__DATA/__data`: Data sections
- `__LINKEDIT`: Symbol table, string table
- Load commands: parsed and displayed (LC_LOAD_DYLIB, LC_MAIN, etc.)
- Code signature: extract entitlements (XML), team ID, signing status
- Embedded frameworks (in `Frameworks/` directory for bundles)
- Fat binary: show per-architecture slices

Library: `macho-parser` (npm).

### Resource Browser Architecture

```
ResourceNode {
  id: string
  name: string
  type: ResourceType
  format: string      // detected sub-type
  size: number
  offset: number
  children?: ResourceNode[]
  canEdit: boolean
  canPreview: boolean
}

ResourceData {
  raw: Uint8Array
  parsed?: any         // type-specific parsed form
}

ResourcePreview {
  type: 'image' | 'text' | 'xml' | 'hex' | 'table' | 'tree'
  content: any
}
```

### Resource Editing

For each editable resource type:
- **String table**: In-place text editing, save writes back to binary
- **Version info**: Form with FileVersion, ProductVersion, CompanyName fields
- **Manifest**: XML editor (Monaco with XML language) — validates XML before write-back
- **Icon**: "Replace icon" button → file picker → convert to correct BMP format and replace
- **RCDATA**: Hex editor (Monaco with hex language) — byte-level editing

Write-back: Load full binary into Buffer, seek to resource offset, write new bytes, handle size delta (shift subsequent data, update offsets in headers).

---

## 11. Binary Meta Panel

### Sections

#### File Overview
```
Name:         malware.exe
Size:         2.4 MB (2,473,984 bytes)
Format:       PE32+ (64-bit)
Architecture: x86-64
OS Target:    Windows (Vista+)
Compiler:     MSVC 19.38 (Visual Studio 2022)
Linker:       Microsoft Linker 14.38
Entry Point:  0x00001234 (.text)
Image Base:   0x0000000140000000
```

#### Hashes
```
MD5:     d41d8cd98f00b204e9800998ecf8427e
SHA-1:   da39a3ee5e6b4b0d3255bfef95601890afd80709
SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

#### Section Map (visual bar + table)
Visual: stacked colored bar showing each section as proportion of file size.
Table:
```
Name     VirtAddr   VirtSize   RawSize   Entropy   Flags
.text    0x1000     0x84200    0x84200   6.21      R-X (code)
.rdata   0x86000    0x1a400    0x1a400   4.87      R-- (readonly)
.data    0xa1000    0x3800     0x3800    2.14      RW- (data)
.rsrc    0xa5000    0x2800     0x2800    3.45      R-- (resources)
```

Color coding: entropy 0-5 = green, 5-7 = yellow, 7-8 = red

#### Imports / Exports
Grouped by DLL (PE) or library (ELF).
Searchable, sortable. Each import shows name, ordinal, address, and "known function" badge if it's a well-known API.

#### Strings
- Minimum 4 chars, configurable
- Encoding detection: ASCII, UTF-16LE, UTF-8
- Filterable by entropy (find interesting strings), length, content
- Copy to clipboard, "Find in code" (jumps to function referencing this string)

#### Compiler/Packer Detection
- Known compiler signatures: GCC version string, Delphi markers, .NET CLR header, Go buildinfo, Rust panic strings, Swift runtime refs
- Packer detection: UPX header, ASPack, Themida/WinLicense signatures, high-entropy sections
- Heuristic: if `entropy(entire file) > 7.2` → likely packed

---

## 12. VS Code Integration

### Export Structure

When "Open in VS Code" is clicked, Softy creates:

```
softy-export-{binaryName}/
├── .softy/
│   ├── project.json    # Project metadata, Softy project ID
│   └── map.json        # Address → function file mapping
├── src/
│   ├── functions/
│   │   ├── main.c             # Entry point function
│   │   ├── FUN_00401a30.c     # Each function in its own file
│   │   └── ...
│   ├── includes/
│   │   └── types.h            # Recovered structs and typedefs
│   └── strings.h              # Extracted string constants
├── disasm/
│   └── full.asm               # Full disassembly listing
├── .vscode/
│   ├── extensions.json        # Recommend softy-vscode extension
│   ├── tasks.json             # "Compile Back" build task
│   └── settings.json          # File associations for .softy extension
└── Makefile                   # make compile → runs Clang, sends back to Softy
```

### VS Code Extension (`softy-vscode`)

Package ID: `softy-binary.softy-vscode`

**Features**:
1. **Softy C language** — custom language ID `softy-c` with tokenizer for Ghidra-style pseudocode (`undefined1`, `undefined4`, `DAT_`, `FUN_` patterns)
2. **Outline view** — shows function signature, address, size
3. **Compile Back command** (`Ctrl+Shift+B → Softy: Compile Back`) — runs `make compile`, triggers Softy to apply patch
4. **Hover information** — hover over `FUN_` reference → shows function signature from map.json
5. **Bidirectional jump** — `Ctrl+Click` on `FUN_` opens that file; companion button opens same function in Softy
6. **File watcher** — detects saves, calls `softy-cli sync` which triggers IPC to Softy main process

### VS Code ↔ Softy Sync

```
VS Code saves FUN_00401a30.c
    │
    ▼
softy-vscode file watcher fires
    │
    ▼
Extension calls softy-cli sync --function 0x00401a30 --file ./src/functions/FUN_00401a30.c
    │
    ▼
softy-cli sends HTTP request to localhost:7823 (Softy's local sync server)
    │
    ▼
Softy main process IPC: softy:vscode:change event → renderer updates Monaco
```

---

## 13. Data Model & Storage

### SQLite Schema

```sql
-- Projects
CREATE TABLE projects (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  binary_path TEXT NOT NULL,
  binary_hash TEXT NOT NULL,
  format      TEXT,
  arch        TEXT,
  created_at  INTEGER,
  updated_at  INTEGER,
  meta_json   TEXT   -- BinaryMetadata as JSON
);

-- Decompiled functions
CREATE TABLE functions (
  id          TEXT PRIMARY KEY,
  project_id  TEXT REFERENCES projects(id) ON DELETE CASCADE,
  address     INTEGER NOT NULL,
  name        TEXT,
  original_name TEXT,
  signature   TEXT,
  c_code      TEXT,         -- original decompiled code
  edited_code TEXT,         -- user-modified code (NULL = unedited)
  ai_code     TEXT,         -- AI-enhanced code
  disassembly TEXT,         -- JSON disassembly
  size        INTEGER,
  callers     TEXT,         -- JSON array of addresses
  callees     TEXT,         -- JSON array of addresses
  ai_summary  TEXT,         -- AI explanation
  flags       TEXT,         -- JSON: { isPacked, hasVulns, isAIRenamed }
  UNIQUE(project_id, address)
);

-- AI conversations
CREATE TABLE ai_sessions (
  id          TEXT PRIMARY KEY,
  project_id  TEXT REFERENCES projects(id) ON DELETE CASCADE,
  function_id TEXT,
  messages    TEXT,   -- JSON array of {role, content, timestamp}
  created_at  INTEGER
);

-- Resources
CREATE TABLE resources (
  id          TEXT PRIMARY KEY,
  project_id  TEXT REFERENCES projects(id) ON DELETE CASCADE,
  type        TEXT,
  name        TEXT,
  path        TEXT,   -- tree path e.g. "Icons/16x16/0"
  offset      INTEGER,
  size        INTEGER,
  modified    INTEGER DEFAULT 0,
  data        BLOB    -- cached / modified data
);

-- Settings (key-value)
CREATE TABLE settings (
  key   TEXT PRIMARY KEY,
  value TEXT
);
```

### Settings Keys

```
ai.default_provider       = "ollama"
ai.ollama.base_url        = "http://localhost:11434"
ai.ollama.default_model   = "deepseek-r1:14b"
ai.openai.api_key         = (encrypted)
ai.anthropic.api_key      = (encrypted)
ai.openrouter.api_key     = (encrypted)
tools.ghidra_path         = "/opt/ghidra_11.3"
tools.clang_path          = "clang"    (or full path)
tools.nasm_path           = "nasm"
decompile.auto_ai_rename  = true
decompile.backend         = "ghidra"
editor.font_size          = 13
editor.theme              = "softy-dark"
vscode.path               = "/Applications/Visual Studio Code.app/..."
```

API keys stored encrypted using Electron's `safeStorage` API (OS keychain integration).

---

## 14. Implementation Phases

### Phase 0: Project Scaffolding (Week 1)

- [ ] Initialize with `electron-forge` + `electron-vite` template
- [ ] Configure TypeScript strict mode
- [ ] Set up Vue 3 + Pinia + Vue Router
- [ ] Configure Tailwind CSS v4 with custom design tokens
- [ ] Create custom frameless window with title bar
- [ ] Set up `better-sqlite3` with schema migrations
- [ ] Establish IPC contract with typed channels
- [ ] Configure `electron-forge` makers for macOS/Windows/Linux

**Deliverable**: Blank app window with titlebar, sidebar skeleton, correct colors. App opens and shows "Welcome" screen.

---

### Phase 1: Binary Intake + Metadata (Week 2)

- [ ] Implement `file-analyzer.ts` — format/arch detection, hashes, compiler fingerprinting
- [ ] Build `DropZone.vue` — beautiful drag-and-drop with animated feedback
- [ ] Build `MetaPanel.vue` — display all binary metadata
- [ ] Implement `EntropyChart.vue` — section entropy visualization with canvas
- [ ] Implement `resource-extractor.ts` — read PE/ELF/Mach-O resources
- [ ] Build `ResourceBrowser.vue` — tree view with type icons
- [ ] Build basic resource preview components (image, text, hex)
- [ ] IPC: `meta.*` and `resources.*` handlers
- [ ] SQLite: persist project on open, store metadata

**Deliverable**: Drop a binary → see format, arch, sections, entropy, imports, strings, resources. No decompilation yet.

---

### Phase 2: Decompilation Core (Weeks 3–4)

- [ ] Bundle Ghidra scripts (`DecompileAll.java`)
- [ ] Implement `ghidra.ts` — headless runner with streaming output parser
- [ ] Implement `r2.ts` — r2pipe quick analysis (runs first for instant function list)
- [ ] Implement `retdec.ts` — fallback CLI wrapper
- [ ] Implement `tool-manager.ts` — detect/install tools (bundled or system)
- [ ] `decompiler.ipc.ts` — streaming IPC with progress events
- [ ] `FunctionTree.vue` — virtual scroll list (handles 10k+ functions), searchable
- [ ] `CodeEditor.vue` — Monaco with `softy-dark` theme, `ghidra-c` language
- [ ] `DisasmPane.vue` — split pane with annotated disassembly
- [ ] Bidirectional navigation: Monaco line ↔ disassembly instruction
- [ ] Streaming progress display in status bar + analysis progress overlay
- [ ] Function persistence in SQLite

**Deliverable**: Drop binary → see function list populate in real-time → click function → see decompiled C code alongside disassembly.

---

### Phase 3: AI Integration (Week 5)

- [ ] Implement `ai-manager.ts` with provider abstraction
- [ ] `ollama.ts` provider — streaming, model list detection
- [ ] `openai.ts` provider — streaming, GPT-4o support
- [ ] `anthropic.ts` provider — streaming, Claude support
- [ ] `openrouter.ts` provider
- [ ] Prompt templates: rename, explain, vulnerability, type-recovery
- [ ] `AIPanel.vue` — streaming chat UI, message history, model selector
- [ ] "Ask about selection" context menu in Monaco
- [ ] Batch rename: AI-rename all functions in background (progress indicator)
- [ ] AI provider status in status bar
- [ ] `SettingsView.vue` — AI config: API keys, Ollama URL, default model
- [ ] AI response caching in SQLite

**Deliverable**: Ask AI questions about functions. One-click AI rename all. Vulnerability scan. All streaming.

---

### Phase 4: Compilation + Patching (Week 6)

- [ ] Implement `llvm.ts` — Clang invocation wrapper with error parsing
- [ ] Implement `keystone.ts` — node-keystone assembler wrapper
- [ ] Monaco real-time compilation error markers (parse Clang diagnostics)
- [ ] `DiffViewer.vue` — side-by-side byte diff before/after patch
- [ ] `compiler.ipc.ts` — build, patch, assemble handlers
- [ ] Function-level patch injection (surgical patching)
- [ ] Save modified binary via dialog
- [ ] Compile log display in status bar area

**Deliverable**: Edit decompiled C code → real-time error markers → Compile → modified binary saved.

---

### Phase 5: Resources Editing + VS Code (Week 7)

- [ ] `ResourceEditor.vue` — edit strings, version info, manifests
- [ ] `ImagePreview.vue` — inline icon/bitmap rendering
- [ ] `ManifestEditor.vue` — Monaco XML editor
- [ ] `VersionInfoEditor.vue` — form editor for PE version block
- [ ] String table editing with write-back
- [ ] Resource injection (replace with new file)
- [ ] `vscode.ipc.ts` — export project, watch changes, open VS Code
- [ ] `softy-vscode` extension: language, compile-back command, file watcher
- [ ] Local sync server (HTTP on 127.0.0.1:7823) for VS Code ↔ Softy sync

**Deliverable**: Edit resources and save back to binary. Export to VS Code and edit there with sync.

---

### Phase 6: Polish + Performance (Week 8)

- [ ] Virtual scrolling throughout (function tree, string table, symbol table)
- [ ] Keyboard navigation: all major actions have shortcuts
- [ ] `RecentFiles.vue` with last session state restoration
- [ ] Onboarding: first-run tool installation wizard (detect Ghidra, offer download)
- [ ] Error boundaries and graceful failure for all tool calls
- [ ] Accessibility: ARIA labels, keyboard focus management
- [ ] Micro-interactions: all animations at 60fps
- [ ] macOS: native menu bar integration
- [ ] Windows: taskbar progress during decompilation
- [ ] Performance: decompilation runs in worker threads where possible

---

### Phase 7: Packaging + Release (Week 9)

- [ ] `forge.config.ts` — makers for `.dmg` (macOS), `.exe` NSIS installer (Windows), `.AppImage`+`.deb` (Linux)
- [ ] Code signing setup (macOS notarization, Windows Authenticode)
- [ ] Auto-updater (`electron-updater`)
- [ ] Bundle Ghidra JRE (OpenJDK 21 slim)
- [ ] Bundle r2 and RetDec binaries per platform
- [ ] Bundle Clang/LLVM (or use system)
- [ ] GitHub Actions CI: build + sign + release pipeline

---

## 15. External Tool Dependencies

### Ghidra
- **Version**: 11.3 (latest)
- **Download**: https://github.com/NationalSecurityAgency/ghidra/releases
- **JRE**: OpenJDK 21 (bundled in app)
- **Integration**: Headless mode via `analyzeHeadless` script
- **License**: Apache 2.0

### Radare2
- **Version**: 5.9.x
- **npm**: `r2pipe` (Node.js binding)
- **Binaries**: bundled per platform (macOS arm64/x64, Windows x64, Linux x64)
- **License**: LGPLv3

### RetDec
- **Version**: 5.0.x
- **Binaries**: bundled per platform
- **Usage**: CLI `retdec-decompiler --backend-no-opts -o out.c binary`
- **License**: MIT

### LLVM/Clang
- **Strategy**: detect system installation first (`clang --version`), fall back to bundled
- **Bundled**: `@nicolo-ribaudo/clang-15-binaries` (npm, x86_64) or platform-specific binaries
- **Minimum version**: Clang 15

### Keystone Assembler
- **npm**: `keystone-engine` (prebuilt Node.js native module)
- Supports: x86, x86_64, ARM, ARM64, MIPS, SPARC, SystemZ, Hexagon, PowerPC
- **License**: GPL

### Key npm Packages

```json
{
  "dependencies": {
    "electron": "^33.0.0",
    "vue": "^3.5.0",
    "pinia": "^2.2.0",
    "vue-router": "^4.4.0",
    "@monaco-editor/loader": "^1.4.0",
    "better-sqlite3": "^9.6.0",
    "r2pipe": "^1.8.0",
    "file-type": "^19.5.0",
    "pe-library": "^0.4.0",
    "openai": "^4.67.0",
    "@anthropic-ai/sdk": "^0.32.0",
    "keystone-engine": "^0.9.2",
    "chokidar": "^4.0.0",
    "zod": "^3.23.0"
  },
  "devDependencies": {
    "electron-vite": "^2.3.0",
    "@electron-forge/cli": "^7.5.0",
    "@electron-forge/maker-dmg": "^7.5.0",
    "@electron-forge/maker-nsis": "^7.5.0",
    "vite": "^6.0.0",
    "typescript": "^5.6.0",
    "tailwindcss": "^4.0.0",
    "@tailwindcss/vite": "^4.0.0",
    "vitest": "^2.1.0"
  }
}
```

---

## 16. Testing Strategy

### Unit Tests (Vitest)
- `file-analyzer.ts` — test format detection on fixture binaries (small ELF, PE, Mach-O samples)
- `resource-extractor.ts` — test PE resource parsing
- Prompt builders — snapshot tests for AI prompt content
- IPC handlers — mock child_process, test output parsing

### Integration Tests
- Ghidra headless on sample binaries (check output structure)
- r2pipe analysis on sample binaries
- LLVM compilation of simple decompiled snippets
- AI provider connection tests (mock server for Ollama)

### E2E Tests (Playwright for Electron)
- Drop a binary → verify function list populated
- Click function → verify Monaco editor content
- AI rename → verify code changes in editor
- Open in VS Code → verify export directory structure

### Fixture Binaries
Keep a `test/fixtures/` directory with small representative binaries:
- `hello_world.elf` — simple x86_64 Linux ELF
- `hello_world.exe` — simple x86_64 PE
- `hello_world.macho` — simple ARM64 Mach-O
- `with_resources.exe` — PE with icons, version info, manifest
- `packed_upx.exe` — UPX-packed for entropy detection testing

---

## 17. Packaging & Distribution

### Electron Forge Config

```typescript
// forge.config.ts
export default {
  packagerConfig: {
    name: 'Softy',
    icon: './assets/icons/softy',
    extraResource: [
      './ghidra_11.3/',       // bundled Ghidra
      './tools/',             // r2, retdec, clang binaries
      './jre/',               // OpenJDK 21
    ],
    osxSign: { identity: 'Developer ID Application: ...' },
    osxNotarize: { appleId: process.env.APPLE_ID, ... },
  },
  makers: [
    { name: '@electron-forge/maker-dmg', config: { format: 'ULFO' } },
    { name: '@electron-forge/maker-nsis', config: { oneClick: false } },
    { name: '@electron-forge/maker-deb' },
    { name: '@electron-forge/maker-rpm' },
  ],
}
```

### Bundle Sizes
Ghidra (no JRE): ~500 MB — distributed as optional download on first run, not bundled.
App without Ghidra + models: ~150 MB installed.
Ollama models: user installs separately via Ollama GUI.

### First-Run Experience
1. Welcome screen with drop zone
2. Tool detection: scan PATH for `ghidra`, `clang`, `r2`
3. If not found: "Let's get you set up" wizard with download links and auto-install options for each tool
4. AI setup: "Would you like to use local AI (Ollama) or cloud AI? Or skip for now."
5. Done → drop your first binary

---

## 18. Future Roadmap

### v1.1
- **WASM decompilation**: Dedicated WASM → C pipeline using Binaryen
- **Java .class / JAR**: Use CFR or Procyon decompiler
- **.NET assemblies**: Use ILSpy in headless mode
- **Android DEX/APK**: Use jadx for Java decompilation

### v1.2
- **Collaborative sessions**: Share a project (binary + decompiled code) via encrypted link
- **Plugin system**: Allow custom decompiler backends, AI providers, resource handlers
- **Scripting API**: JavaScript scripting within Softy (automate analysis, batch operations)

### v1.3
- **Dynamic analysis integration**: Run binary in sandbox (QEMU), trace execution, annotate static analysis with runtime values
- **Diff mode**: Compare two versions of a binary (before/after patch)

### v2.0
- **Cloud sync**: Store projects (not binaries) in encrypted cloud, access from any machine
- **Team features**: Shared analysis workspace with real-time collaboration
- **AI training**: Opt-in contribution of renamed functions to improve shared model

---

*Built with the conviction that understanding software should not require a PhD — just the right tool.*
