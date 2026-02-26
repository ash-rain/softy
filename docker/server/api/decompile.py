"""
/api/decompile — Ghidra headless decompilation with SSE streaming.
Each function is yielded as a JSON SSE event as Ghidra processes it.
Also provides r2pipe-based quick disassembly.
"""

import asyncio
import json
import os
import uuid
from pathlib import Path
from typing import AsyncGenerator

import r2pipe
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

router = APIRouter()

WORK_DIR        = os.environ.get("WORK_DIR",             "/work")
GHIDRA_HOME     = os.environ.get("GHIDRA_HOME",          "/opt/ghidra")
GHIDRA_PROJECTS = os.environ.get("GHIDRA_PROJECTS_DIR",  "/ghidra-projects")
SCRIPTS_DIR     = "/ghidra_scripts"

GHIDRA_TIMEOUT  = int(os.environ.get("GHIDRA_TIMEOUT", "900"))   # 15 min default
STREAM_TIMEOUT  = int(os.environ.get("STREAM_TIMEOUT",  "60"))   # 60s between events

# In-memory session store: streamId → asyncio.Queue
_sessions: dict[str, asyncio.Queue] = {}


class DecompileRequest(BaseModel):
    filePath:  str            # relative to WORK_DIR
    projectId: str
    backend:   str = "ghidra" # "ghidra" | "r2"


class QuickAnalysisRequest(BaseModel):
    filePath: str


def _resolve(rel: str) -> Path:
    """Resolve a work-dir-relative path and guard against traversal."""
    work = Path(WORK_DIR).resolve()
    p    = (work / rel).resolve()
    if not p.is_relative_to(work):
        raise HTTPException(400, "Path traversal not allowed")
    if not p.exists():
        raise HTTPException(404, f"File not found: {rel}")
    return p


# ── Ghidra headless decompilation ─────────────────────────────────────────────

async def _run_ghidra(file_path: Path, project_id: str, queue: asyncio.Queue) -> None:
    """Spawn Ghidra headless, parse stdout JSON lines, put onto queue."""
    headless    = Path(GHIDRA_HOME) / "support" / "analyzeHeadless"
    project_dir = Path(GHIDRA_PROJECTS) / project_id
    project_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(headless),
        str(project_dir), "SoftyAnalysis",
        "-import",    str(file_path),
        "-postScript", "DecompileAll.java",
        "-scriptPath", SCRIPTS_DIR,
        "-deleteProject",
        "-scriptlog", "/dev/stderr",
    ]

    async def _stream():
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        total_sent = 0
        async for raw_line in proc.stdout:
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line or not line.startswith("{"):
                continue
            try:
                fn = json.loads(line)
                fn["type"] = "function"
                await queue.put(fn)
                total_sent += 1
                await queue.put({"type": "progress", "current": total_sent,
                                 "message": fn.get("name", "")})
            except json.JSONDecodeError:
                pass
        await proc.wait()
        await queue.put({"type": "complete", "total": total_sent})

    try:
        await asyncio.wait_for(_stream(), timeout=GHIDRA_TIMEOUT)
    except asyncio.TimeoutError:
        await queue.put({"type": "error",
                         "message": f"Ghidra timed out after {GHIDRA_TIMEOUT}s"})
    except Exception as e:
        await queue.put({"type": "error", "message": str(e)})
    finally:
        await queue.put(None)  # sentinel


# ── r2 analysis ───────────────────────────────────────────────────────────────

def _run_r2_analysis(file_path: Path) -> dict:
    """Synchronous r2pipe analysis — returns functions, imports, exports, sections."""
    r2 = r2pipe.open(str(file_path), flags=["-2"])
    try:
        r2.cmd("aa")
        return {
            "functions": json.loads(r2.cmd("aflj") or "[]"),
            "imports":   json.loads(r2.cmd("iij")  or "[]"),
            "exports":   json.loads(r2.cmd("iEj")  or "[]"),
            "sections":  json.loads(r2.cmd("iSj")  or "[]"),
            "info":      json.loads(r2.cmd("ij")   or "{}"),
        }
    finally:
        r2.quit()


async def _run_r2_decompile(file_path: Path, queue: asyncio.Queue) -> None:
    """r2 pdc decompilation fallback when Ghidra is unavailable."""
    loop = asyncio.get_event_loop()

    def _sync():
        r2 = r2pipe.open(str(file_path), flags=["-2"])
        try:
            r2.cmd("aaa")
            functions = json.loads(r2.cmd("aflj") or "[]")
            results = []
            for fn in functions:
                addr = fn.get("offset", 0)
                name = fn.get("name", f"fcn_{addr:08x}")
                r2.cmd(f"s {addr}")
                asm = {}
                try:
                    asm = json.loads(r2.cmd("pdfj") or "{}")
                except json.JSONDecodeError:
                    pass
                pdc = r2.cmd("pdcj") or ""
                results.append({
                    "address":     addr,
                    "name":        name,
                    "cCode":       pdc if pdc else f"// {name}\nvoid {name}(void) {{\n  // 0x{addr:x}\n}}",
                    "disassembly": asm.get("ops", []),
                    "size":        fn.get("size", 0),
                    "callers":     [],
                    "callees":     [],
                })
            return results
        finally:
            r2.quit()

    functions = await loop.run_in_executor(None, _sync)
    for i, fn in enumerate(functions):
        fn["type"] = "function"
        await queue.put(fn)
        await queue.put({"type": "progress", "current": i + 1,
                         "total": len(functions), "message": fn["name"]})
    await queue.put({"type": "complete", "total": len(functions)})
    await queue.put(None)


# ── API routes ─────────────────────────────────────────────────────────────────

@router.post("/start")
async def start_decompile(req: DecompileRequest):
    """Start a decompilation job. Returns a streamId to connect to /stream/{id}."""
    file_path = _resolve(req.filePath)
    stream_id = str(uuid.uuid4())
    queue: asyncio.Queue = asyncio.Queue(maxsize=0)
    _sessions[stream_id] = queue

    backend          = req.backend.lower()
    ghidra_available = (Path(GHIDRA_HOME) / "support" / "analyzeHeadless").exists()
    use_ghidra       = backend == "ghidra" and ghidra_available

    if use_ghidra:
        asyncio.create_task(_run_ghidra(file_path, req.projectId, queue))
    else:
        asyncio.create_task(_run_r2_decompile(file_path, queue))

    return {
        "streamId": stream_id,
        "backend":  "ghidra" if use_ghidra else "r2",
    }


@router.get("/stream/{stream_id}")
async def stream_decompile(stream_id: str):
    """SSE endpoint — streams decompiled functions as they're produced."""
    queue = _sessions.get(stream_id)
    if queue is None:
        raise HTTPException(404, "Stream not found")

    async def generator() -> AsyncGenerator[dict, None]:
        try:
            while True:
                item = await asyncio.wait_for(queue.get(), timeout=STREAM_TIMEOUT)
                if item is None:
                    break
                yield {"data": json.dumps(item)}
        except asyncio.TimeoutError:
            yield {"data": json.dumps({"type": "error",
                                       "message": "Stream timed out — no data received"})}
        finally:
            _sessions.pop(stream_id, None)

    return EventSourceResponse(generator())


@router.post("/quick")
async def quick_analysis(req: QuickAnalysisRequest):
    """Fast r2 analysis: function list, imports, exports, sections."""
    file_path = _resolve(req.filePath)
    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(None, _run_r2_analysis, file_path),
            timeout=60,
        )
    except asyncio.TimeoutError:
        raise HTTPException(504, "r2 analysis timed out after 60s")
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
            return json.loads(r2.cmd(f"pdj {count}") or "[]")
        finally:
            r2.quit()

    loop = asyncio.get_event_loop()
    ops = await loop.run_in_executor(None, _sync)
    return {"ops": ops}
