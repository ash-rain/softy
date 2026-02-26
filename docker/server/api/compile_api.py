"""
/api/compile — Compile modified C code back to binary using Clang/LLVM.
Supports full rebuild and function-level patch generation.
"""

import asyncio
import base64
import os
import tempfile
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router   = APIRouter()
WORK_DIR = os.environ.get("WORK_DIR", "/work")

ARCH_TRIPLES = {
    "x86":    "i386-unknown-linux-gnu",
    "x86_64": "x86_64-unknown-linux-gnu",
    "arm":    "armv7-unknown-linux-gnueabihf",
    "arm64":  "aarch64-unknown-linux-gnu",
    "mips":   "mips-unknown-linux-gnu",
}

OS_OVERRIDES = {
    ("x86_64", "windows"): "x86_64-pc-windows-msvc",
    ("x86",    "windows"): "i386-pc-windows-msvc",
    ("arm64",  "macos"):   "aarch64-apple-macosx13.0",
    ("x86_64", "macos"):   "x86_64-apple-macosx13.0",
}


class CompileRequest(BaseModel):
    sourceCode:   str
    arch:         str = "x86_64"
    os:           str = "linux"
    optimize:     str = "O1"          # O0 O1 O2 Os
    outputFormat: str = "object"      # "object" | "asm" | "ir"
    extraFlags:   list[str] = []


class CompileResponse(BaseModel):
    success:      bool
    output:       str | None  # base64 for object; plain text for asm/ir
    outputFormat: str
    isText:       bool        # True when output is plain text (asm/ir)
    errors:       list[dict]
    warnings:     list[dict]
    sizeBytes:    int


class AssembleRequest(BaseModel):
    assembly: str
    arch:     str = "x86_64"
    syntax:   str = "intel"   # "intel" | "att"


def _parse_clang_diagnostics(stderr: str) -> tuple[list[dict], list[dict]]:
    errors, warnings = [], []
    for line in stderr.splitlines():
        if ": error:" in line:
            parts = line.split(":", 4)
            errors.append({
                "file":    parts[0] if parts else "",
                "line":    int(parts[1]) if len(parts) > 1 and parts[1].strip().isdigit() else 0,
                "col":     int(parts[2]) if len(parts) > 2 and parts[2].strip().isdigit() else 0,
                "message": parts[-1].strip(),
                "raw":     line,
            })
        elif ": warning:" in line:
            parts = line.split(":", 4)
            warnings.append({
                "file":    parts[0] if parts else "",
                "line":    int(parts[1]) if len(parts) > 1 and parts[1].strip().isdigit() else 0,
                "col":     int(parts[2]) if len(parts) > 2 and parts[2].strip().isdigit() else 0,
                "message": parts[-1].strip(),
                "raw":     line,
            })
    return errors, warnings


@router.post("", response_model=CompileResponse)
async def compile_code(req: CompileRequest):
    arch_key = req.arch.lower().replace("-", "_").replace(" ", "_")
    os_key   = req.os.lower()
    triple   = OS_OVERRIDES.get((arch_key, os_key)) or ARCH_TRIPLES.get(arch_key, "x86_64-unknown-linux-gnu")

    # Map output format to clang flags and file extension
    fmt_flags: list[str]
    if req.outputFormat == "object":
        fmt_flags = ["-c"]
        ext       = ".o"
        is_text   = False
    elif req.outputFormat == "asm":
        fmt_flags = ["-S"]
        ext       = ".s"
        is_text   = True
    elif req.outputFormat == "ir":
        fmt_flags = ["-emit-llvm", "-S"]
        ext       = ".ll"
        is_text   = True
    else:
        fmt_flags = ["-c"]
        ext       = ".o"
        is_text   = False

    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "input.c"
        out = Path(tmp) / f"output{ext}"
        src.write_text(req.sourceCode, encoding="utf-8")

        cmd = [
            "clang-17",
            f"-{req.optimize}",
            f"--target={triple}",
            "-fPIC",
            "-fno-builtin",
            *fmt_flags,
            *req.extraFlags,
            "-o", str(out),
            str(src),
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=120)
        stderr = stderr_bytes.decode("utf-8", errors="replace")

        errors, warnings = _parse_clang_diagnostics(stderr)
        success = proc.returncode == 0

        output_data = None
        size        = 0
        if success and out.exists():
            raw  = out.read_bytes()
            size = len(raw)
            if is_text:
                # Return assembly/IR as plain text (not base64)
                output_data = raw.decode("utf-8", errors="replace")
            else:
                output_data = base64.b64encode(raw).decode()

        return CompileResponse(
            success=success,
            output=output_data,
            outputFormat=req.outputFormat,
            isText=is_text,
            errors=errors,
            warnings=warnings,
            sizeBytes=size,
        )


@router.post("/assemble")
async def assemble_code(req: AssembleRequest):
    """Assemble x86/x86_64 with NASM."""
    arch = req.arch.lower()
    if arch not in ("x86", "x86_64"):
        raise HTTPException(422, f"Assembly for arch {req.arch} not yet supported. Only x86/x86_64.")

    with tempfile.TemporaryDirectory() as tmp:
        src  = Path(tmp) / "input.asm"
        out  = Path(tmp) / "output.o"
        bits = "64" if arch == "x86_64" else "32"
        fmt  = "elf64" if bits == "64" else "elf32"
        src.write_text(f"BITS {bits}\n{req.assembly}", encoding="utf-8")

        cmd = ["nasm", "-f", fmt, str(src), "-o", str(out)]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=30)
        stderr = stderr_bytes.decode("utf-8", errors="replace")

        if proc.returncode != 0:
            return {"success": False, "output": None,
                    "errors": [{"message": stderr.strip()}]}

        raw = out.read_bytes()
        return {
            "success": True,
            "output":  base64.b64encode(raw).decode(),
            "errors":  [],
        }
