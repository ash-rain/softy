# Softy

> Every binary hides a story. Softy lets you read it — and rewrite it.

---

Softy is a desktop application that does something no tool has done cleanly before: it takes any compiled binary — a `.exe`, an ELF executable, a `.dylib`, a firmware image — and transforms it into readable, editable, recompilable code. Not just disassembly. Not just hex. Real, human-readable C/C++ pseudocode that you can understand, modify, and build back into a working binary.

It uses AI not as a gimmick, but as the engine that makes the difference between *technically decompiled* and *actually understood*. Local models through Ollama for privacy. Cloud models when you need the best.

It is beautiful. It is fast. It just works.

---

## The Problem

Reverse engineering has always required an expert. You needed years learning IDA Pro, days setting up Ghidra, weeks understanding what the output even meant. The tools were built for the 1% who already knew everything.

The other 99% — developers who just want to understand a library they don't have source for, security researchers who found something suspicious, engineers maintaining old software with no source code — they were left with hex editors and confusion.

Softy fixes this.

---

## What Softy Does

**Drop any binary. Get readable code.**

Softy accepts ELF (Linux), PE/COFF (Windows .exe/.dll), Mach-O (macOS), WebAssembly, Java `.class` files, Android DEX, and raw firmware images. It detects the format automatically, selects the right analysis engine, and begins decompilation immediately.

**AI that actually helps.**

The raw output of any decompiler is still hard to read — variables named `local_18`, functions named `FUN_00401a30`, cryptic pointer arithmetic. Softy's AI layer renames everything to something meaningful, recovers data types, identifies algorithms, explains what each function does in plain English, and flags potential security issues. You can talk to it directly: *"What does this function do?"*, *"Find all places where user input is used without validation"*, *"Rename all variables to reflect their purpose."*

**Edit and recompile.**

The decompiled code opens in a Monaco editor — the same editor that powers VS Code. You make changes. Softy recompiles them back to a binary-compatible output using LLVM/Clang. For surgical patches you can work at the assembly level with the integrated assembler. The result is a modified binary that behaves exactly as you specify.

**Resources browser.**

Binaries aren't just code. PE files embed icons, cursors, dialog templates, manifests, version info, string tables. ELF files have debug sections, symbol tables, embedded data. Mach-O binaries carry entitlements, code signatures, embedded frameworks. Softy exposes all of it in a visual browser — preview images inline, read and edit strings, modify manifests, inspect every section and segment.

**VS Code integration.**

When you want more — a full IDE experience, git, extensions — export your decompiled project directly into VS Code with one click. Softy installs a companion VS Code extension that preserves syntax highlighting, jump-to-definition across decompiled functions, and a compile-back shortcut that syncs changes back to Softy.

---

## Core Features

### Decompilation Engine
- **Multi-architecture**: x86, x86-64, ARM, ARM64, MIPS, RISC-V, PowerPC
- **Multi-format**: PE/COFF, ELF, Mach-O, WASM, Java .class, Android DEX, raw binary
- **Backends**: Ghidra (primary, highest quality C output), Radare2/r2 (fast, secondary), RetDec (fallback)
- **Output**: C pseudocode, annotated disassembly, control flow graphs, call graphs
- **Streaming**: Results appear function-by-function as analysis progresses, not all-at-once

### AI Analysis Layer
- **Local (private)**: Ollama — runs entirely on your machine. Recommended models: `deepseek-r1:14b`, `codellama:34b`, `starcoder2:15b`
- **Cloud**: OpenAI GPT-4o, Anthropic Claude, OpenRouter (access to dozens of models)
- **Capabilities**:
  - Variable and function renaming with meaningful names
  - Type recovery and struct reconstruction
  - Algorithm identification (crypto, compression, hashing)
  - Natural-language function explanations
  - Security vulnerability detection
  - Interactive Q&A about any part of the binary
  - Automatic commentary generation

### Code Editor
- Monaco Editor with full syntax highlighting (C/C++, assembly, LLVM IR)
- Split view: decompiled C alongside annotated disassembly
- Bidirectional navigation: click C line → highlight assembly, click assembly → jump to C
- Real-time compilation errors as you edit
- Diff view before/after modification

### Resources Browser
- Visual tree of all embedded resources by type
- **PE resources**: Icons, bitmaps, cursors, dialogs, menus, accelerators, version info, manifests, string tables, custom data
- **ELF sections**: `.rodata`, `.debug_*`, symbol tables, DWARF info, embedded data blobs
- **Mach-O**: Segments, sections, dylib dependencies, entitlements, code signatures, embedded frameworks
- Inline preview: images render in-browser, XML/JSON formatted, strings searchable
- Edit mode: modify string values, replace images, patch version info, inject resources

### Binary Meta Panel
- Format, architecture, word size, endianness, OS target
- Compiler signature detection (GCC version, MSVC version, Clang, Rust, Go, Swift)
- Entry point, base address, load segments
- Import/export tables with resolved symbols
- Digital signatures and code signing status
- Section entropy visualization — instantly spot packed, encrypted, or compressed regions
- File hashes: MD5, SHA1, SHA256, SSDEEP (fuzzy)
- Strings extraction with entropy filtering

### Compilation Back
- Modified C → LLVM IR → native binary via Clang
- Function-level patch injection (recompile only changed functions, inject back)
- Full rebuild mode for complete source-level modifications
- Assembly-level patching via Keystone assembler
- Binary diff output showing exact byte changes

### VS Code Integration
- One-click "Open in VS Code" — exports decompiled project as a proper folder structure
- Companion VS Code extension (`softy-vscode`): custom language support, compile-back command, symbol navigation
- File watcher: changes saved in VS Code automatically sync back to Softy
- Integrated terminal within VS Code shows Softy's compile output

---

## Design Philosophy

Softy is designed around one principle: **the tool disappears**.

When you use Softy, you should not be thinking about Ghidra or LLVM or how to prompt an AI model. You should be thinking about the binary. Every interface decision is made to keep the binary — your actual work — at the center.

The UI is dark, precise, and quiet. Information surfaces when you need it, recedes when you don't. Color is used sparingly — to signal meaning, never decoration. The editor occupies 70% of your screen. Everything else is a panel.

We take design as seriously as engineering. A tool this powerful deserves an interface this refined.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Softy Desktop App                        │
│                    (Electron + Vue 3)                        │
├──────────────────────┬──────────────────────────────────────┤
│   Renderer Process   │         Main Process                 │
│   (Vue 3 + Vite)     │         (Node.js)                    │
│                      │                                      │
│  ┌────────────────┐  │  ┌─────────────┐  ┌──────────────┐  │
│  │ Welcome/Drop   │  │  │  Decompiler  │  │   Compiler   │  │
│  │    Zone        │◄─┼─►│  Controller  │  │  Controller  │  │
│  └────────────────┘  │  │             │  │              │  │
│  ┌────────────────┐  │  │  ┌────────┐ │  │ ┌──────────┐ │  │
│  │ Function Tree  │  │  │  │ Ghidra │ │  │ │LLVM/Clang│ │  │
│  │   Sidebar      │  │  │  │Headless│ │  │ │          │ │  │
│  └────────────────┘  │  │  └────────┘ │  │ └──────────┘ │  │
│  ┌────────────────┐  │  │  ┌────────┐ │  │ ┌──────────┐ │  │
│  │  Monaco Code   │  │  │  │Radare2 │ │  │ │ Keystone │ │  │
│  │    Editor      │  │  │  │ r2pipe │ │  │ │Assembler │ │  │
│  └────────────────┘  │  │  └────────┘ │  │ └──────────┘ │  │
│  ┌────────────────┐  │  │  ┌────────┐ │  └──────────────┘  │
│  │  Disassembly   │  │  │  │ RetDec │ │                    │
│  │     Pane       │  │  │  └────────┘ │  ┌──────────────┐  │
│  └────────────────┘  │  └─────────────┘  │  AI Provider  │  │
│  ┌────────────────┐  │                   │  Controller   │  │
│  │  Resources     │  │  ┌─────────────┐  │              │  │
│  │  Browser       │◄─┼─►│   Resource  │  │ ┌──────────┐ │  │
│  └────────────────┘  │  │   Extractor │  │ │  Ollama  │ │  │
│  ┌────────────────┐  │  └─────────────┘  │ │  Local   │ │  │
│  │  Meta Info     │  │                   │ └──────────┘ │  │
│  │    Panel       │◄─┼──────────────────►│ ┌──────────┐ │  │
│  └────────────────┘  │                   │ │ OpenAI/  │ │  │
│  ┌────────────────┐  │  ┌─────────────┐  │ │Anthropic │ │  │
│  │   AI Chat      │◄─┼─►│   SQLite    │  │ └──────────┘ │  │
│  │    Panel       │  │  │  Projects   │  └──────────────┘  │
│  └────────────────┘  │  └─────────────┘                    │
└──────────────────────┴─────────────────────────────────────┘
```

---

## Technology Stack

| Layer | Technology |
|---|---|
| Desktop runtime | Electron 33+ |
| UI framework | Vue 3 + Composition API |
| Build tool | Vite 6 |
| Styling | Tailwind CSS v4 |
| Editor | Monaco Editor |
| State management | Pinia |
| Packaging | Electron Forge |
| Primary decompiler | Ghidra 11.3 (headless) |
| Secondary decompiler | Radare2 + r2pipe |
| Fallback decompiler | RetDec |
| Compiler | LLVM/Clang |
| Assembler | Keystone |
| Format detection | `file-type` + custom magic bytes |
| AI local | Ollama HTTP API |
| AI cloud | OpenAI, Anthropic, OpenRouter |
| Database | SQLite via better-sqlite3 |
| Language | TypeScript throughout |

---

## System Requirements

| | Minimum | Recommended |
|---|---|---|
| OS | macOS 13, Windows 10, Ubuntu 22.04 | macOS 15, Windows 11, Ubuntu 24.04 |
| RAM | 8 GB | 32 GB (for local AI models) |
| Storage | 4 GB | 20 GB (Ghidra + AI models) |
| CPU | 4 cores | 8+ cores |
| GPU | — | NVIDIA/Apple Silicon (Ollama acceleration) |

Ghidra requires Java 21+. Softy bundles a JRE — no separate installation needed.

---

## Installation

### Quick Install (macOS / Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/ash-rain/softy/main/install.sh | bash
```

This will clone the repo, install dependencies, build the Docker backend, and start everything. Requires **git**, **Node.js >= 18**, and **Docker** (running).

### Options

```bash
# Custom install directory (default: ~/softy)
SOFTY_DIR=/opt/softy curl -fsSL https://raw.githubusercontent.com/ash-rain/softy/main/install.sh | bash

# Use a specific branch
SOFTY_BRANCH=dev curl -fsSL https://raw.githubusercontent.com/ash-rain/softy/main/install.sh | bash
```

### Manual Install

```bash
git clone https://github.com/ash-rain/softy.git
cd softy
npm install
npm run docker:build
npm run docker:up
npm run dev
```

---

## License

MIT — use it, fork it, build on it.

---

*"The people who are crazy enough to think they can reverse-engineer the world are the ones who do."*
