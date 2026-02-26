"""
/api/compile — Compile modified C code back to binary using Clang/LLVM.
Supports full rebuild and function-level patch generation.
"""

import asyncio
import base64
import os
import tempfile
import uuid
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()
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
    sourceCode: str
    arch: str = "x86_64"
    os: str = "linux"
    optimize: str = "O1"           # O0, O1, O2, Os
    outputFormat: str = "object"   # "object" | "asm" | "ir"
    extraFlags: list[str] = []


class CompileResponse(BaseModel):
    success: bool
    output: str | None       # base64-encoded binary or text
    outputFormat: str
    errors: list[dict]
    warnings: list[dict]
    sizeBytes: int


class AssembleRequest(BaseModel):
    assembly: str
    arch: str = "x86_64"
    syntax: str = "intel"   # "intel" | "att"


def _parse_clang_diagnostics(stderr: str) -> tuple[list[dict], list[dict]]:
    errors, warnings = [], []
    for line in stderr.splitlines():
        if ": error:" in line:
            parts = line.split(":", 4)
            errors.append({
                "file": parts[0] if len(parts) > 0 else "",
                "line": int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0,
                "col":  int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0,
                "message": parts[-1].strip() if parts else line,
                "raw": line,
            })
        elif ": warning:" in line:
            parts = line.split(":", 4)
            warnings.append({
                "file": parts[0] if len(parts) > 0 else "",
                "line": int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0,
                "col":  int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0,
                "message": parts[-1].strip() if parts else line,
                "raw": line,
            })
    return errors, warnings


@router.post("", response_model=CompileResponse)
async def compile_code(req: CompileRequest):
    arch_key = req.arch.lower().replace("-", "_").replace(" ", "_")
    os_key   = req.os.lower()
    triple   = OS_OVERRIDES.get((arch_key, os_key)) or ARCH_TRIPLES.get(arch_key, "x86_64-unknown-linux-gnu")

    fmt_flag = {
        "object": "-c",
        "asm":    "-S",
        "ir":     "-emit-llvm -S",
    }.get(req.outputFormat, "-c")

    ext = {"object": ".o", "asm": ".s", "ir": ".ll"}.get(req.outputFormat, ".o")

    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "input.c"
        out = Path(tmp) / f"output{ext}"
        src.write_text(req.sourceCode)

        cmd = [
            "clang-17",
            f"-{req.optimize}",
            f"--target={triple}",
            "-fPIC",
            "-fno-builtin",
        ] + fmt_flag.split() + req.extraFlags + [
            "-o", str(out),
            str(src),
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr_bytes = await proc.communicate()
        stderr = stderr_bytes.decode("utf-8", errors="replace")

        errors, warnings = _parse_clang_diagnostics(stderr)
        success = proc.returncode == 0

        output_b64 = None
        size = 0
        if success and out.exists():
            raw = out.read_bytes()
            size = len(raw)
            if req.outputFormat == "object":
                output_b64 = base64.b64encode(raw).decode()
            else:
                output_b64 = base64.b64encode(raw).decode()

        return CompileResponse(
            success=success,
            output=output_b64,
            outputFormat=req.outputFormat,
            errors=errors,
            warnings=warnings,
            sizeBytes=size,
        )


@router.post("/assemble")
async def assemble_code(req: AssembleRequest):
    """Assemble with NASM (x86/x86_64 only) or clang (other arches)."""
    if req.arch.lower() in ("x86", "x86_64"):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "input.asm"
            out = Path(tmp) / "output.o"
            # NASM format header
            bits = "64" if req.arch.lower() == "x86_64" else "32"
            asm = f"BITS {bits}\n{req.assembly}"
            src.write_text(asm)
            cmd = ["nasm", "-f", "elf64" if bits == "64" else "elf32", str(src), "-o", str(out)]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr_bytes = await proc.communicate()
            stderr = stderr_bytes.decode()
            if proc.returncode != 0:
                return {"success": False, "output": None, "errors": [{"message": stderr}]}
            raw = out.read_bytes()
            return {"success": True, "output": base64.b64encode(raw).decode(), "errors": []}
    else:
        raise HTTPException(422, f"Assembly for arch {req.arch} not yet supported")
