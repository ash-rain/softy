"""
/api/decompile — Ghidra headless decompilation with SSE streaming.
Each function is yielded as a JSON SSE event as Ghidra processes it.
Also provides r2pipe-based quick disassembly.
"""

import asyncio
import json
import os
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import AsyncGenerator

import r2pipe
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

router = APIRouter()

WORK_DIR         = os.environ.get("WORK_DIR",         "/work")
GHIDRA_HOME      = os.environ.get("GHIDRA_HOME",      "/opt/ghidra")
GHIDRA_PROJECTS  = os.environ.get("GHIDRA_PROJECTS_DIR", "/ghidra-projects")
SCRIPTS_DIR      = "/ghidra_scripts"

# In-memory session store: streamId → asyncio.Queue
_sessions: dict[str, asyncio.Queue] = {}


class DecompileRequest(BaseModel):
    filePath: str   # relative to WORK_DIR
    projectId: str
    backend: str = "ghidra"  # "ghidra" | "r2"


class QuickAnalysisRequest(BaseModel):
    filePath: str


def _resolve(rel: str) -> Path:
    p = Path(WORK_DIR) / rel
    if not p.exists():
        raise HTTPException(404, f"File not found: {rel}")
    return p


# ── Ghidra headless decompilation ─────────────────────────────────────────────

async def _run_ghidra(file_path: Path, project_id: str, queue: asyncio.Queue):
    """Spawn Ghidra headless, parse stdout JSON lines, put onto queue."""
    headless = Path(GHIDRA_HOME) / "support" / "analyzeHeadless"
    project_dir = Path(GHIDRA_PROJECTS) / project_id

    project_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(headless),
        str(project_dir), "SoftyAnalysis",
        "-import", str(file_path),
        "-postScript", "DecompileAll.java",
        "-scriptPath", SCRIPTS_DIR,
        "-deleteProject",
        "-scriptlog", "/dev/stderr",
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        total_sent = 0
        async for raw_line in proc.stdout:
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            if line.startswith("{"):
                try:
                    fn = json.loads(line)
                    fn["type"] = "function"
                    await queue.put(fn)
                    total_sent += 1
                    # Also emit progress
                    await queue.put({"type": "progress", "current": total_sent, "message": fn.get("name", "")})
                except json.JSONDecodeError:
                    pass

        await proc.wait()
        await queue.put({"type": "complete", "total": total_sent})

    except Exception as e:
        await queue.put({"type": "error", "message": str(e)})
    finally:
        await queue.put(None)  # sentinel


# ── r2 quick analysis ─────────────────────────────────────────────────────────

def _run_r2_analysis(file_path: Path) -> dict:
    """Synchronous r2pipe analysis — returns functions, imports, exports, strings."""
    r2 = r2pipe.open(str(file_path), flags=["-2"])  # -2 = no stderr
    try:
        r2.cmd("aaa")
        functions = json.loads(r2.cmd("aflj") or "[]")
        imports   = json.loads(r2.cmd("iij") or "[]")
        exports   = json.loads(r2.cmd("iEj") or "[]")
        sections  = json.loads(r2.cmd("iSj") or "[]")
        info      = json.loads(r2.cmd("ij") or "{}")
        return {
            "functions": functions,
            "imports": imports,
            "exports": exports,
            "sections": sections,
            "info": info,
        }
    finally:
        r2.quit()


async def _run_r2_decompile(file_path: Path, queue: asyncio.Queue):
    """r2 pdc (r2dec) decompilation, fallback when Ghidra not available."""
    loop = asyncio.get_event_loop()

    def _sync():
        r2 = r2pipe.open(str(file_path), flags=["-2"])
        try:
            r2.cmd("aaa")
            functions_raw = r2.cmd("aflj") or "[]"
            functions = json.loads(functions_raw)
            results = []
            for fn in functions:
                addr = fn.get("offset", 0)
                name = fn.get("name", f"fcn_{addr:08x}")
                r2.cmd(f"s {addr}")
                asm_raw = r2.cmd("pdfj") or "{}"
                try:
                    asm = json.loads(asm_raw)
                except json.JSONDecodeError:
                    asm = {}
                # r2 pdc (needs r2dec plugin) — fallback to raw disasm
                pdc = r2.cmd("pdcj") or ""
                results.append({
                    "address": addr,
                    "name": name,
                    "cCode": pdc if pdc else f"// {name}\n// (r2 decompiler not available)\nvoid {name}(void) {{\n  // address: 0x{addr:x}\n}}",
                    "disassembly": asm.get("ops", []),
                    "size": fn.get("size", 0),
                    "callers": [],
                    "callees": [],
                })
            return results
        finally:
            r2.quit()

    functions = await loop.run_in_executor(None, _sync)
    for i, fn in enumerate(functions):
        fn["type"] = "function"
        await queue.put(fn)
        await queue.put({"type": "progress", "current": i + 1, "total": len(functions), "message": fn["name"]})

    await queue.put({"type": "complete", "total": len(functions)})
    await queue.put(None)


# ── API routes ─────────────────────────────────────────────────────────────────

@router.post("/start")
async def start_decompile(req: DecompileRequest):
    """
    Start a decompilation job. Returns a streamId to connect to /stream/{id}.
    Decompilation runs in background; results stream via SSE.
    """
    file_path = _resolve(req.filePath)
    stream_id = str(uuid.uuid4())
    queue: asyncio.Queue = asyncio.Queue(maxsize=0)
    _sessions[stream_id] = queue

    backend = req.backend.lower()
    ghidra_available = (Path(GHIDRA_HOME) / "support" / "analyzeHeadless").exists()

    if backend == "ghidra" and ghidra_available:
        asyncio.create_task(_run_ghidra(file_path, req.projectId, queue))
    else:
        asyncio.create_task(_run_r2_decompile(file_path, queue))

    return {"streamId": stream_id, "backend": "ghidra" if (backend == "ghidra" and ghidra_available) else "r2"}


@router.get("/stream/{stream_id}")
async def stream_decompile(stream_id: str):
    """SSE endpoint — streams decompiled functions as they're produced."""
    queue = _sessions.get(stream_id)
    if queue is None:
        raise HTTPException(404, "Stream not found")

    async def generator() -> AsyncGenerator[dict, None]:
        try:
            while True:
                item = await asyncio.wait_for(queue.get(), timeout=120)
                if item is None:
                    break
                yield {"data": json.dumps(item)}
        except asyncio.TimeoutError:
            yield {"data": json.dumps({"type": "error", "message": "Decompilation timed out"})}
        finally:
            _sessions.pop(stream_id, None)

    return EventSourceResponse(generator())


@router.post("/quick")
async def quick_analysis(req: QuickAnalysisRequest):
    """
    Fast r2-based analysis: function list, imports, exports, sections.
    Returns immediately (synchronous). Used to populate the UI before Ghidra finishes.
    """
    file_path = _resolve(req.filePath)
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _run_r2_analysis, file_path)
    return result


@router.post("/disasm")
async def disassemble(req: QuickAnalysisRequest, address: int = 0, count: int = 100):
    """Disassemble N instructions starting at address using r2."""
    file_path = _resolve(req.filePath)

    def _sync():
        r2 = r2pipe.open(str(file_path), flags=["-2"])
        try:
            r2.cmd("aaa")
            r2.cmd(f"s {address}")
            ops = json.loads(r2.cmd(f"pdj {count}") or "[]")
            return ops
        finally:
            r2.quit()

    loop = asyncio.get_event_loop()
    ops = await loop.run_in_executor(None, _sync)
    return {"ops": ops}
