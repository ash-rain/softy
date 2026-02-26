"""
Patch API — surgically replace a function's bytes in a compiled binary.

POST /api/patch/function
  Body: { filePath, functionAddress, functionSize, objectBase64 }
  Returns: patched binary as application/octet-stream

The workflow:
  1. Compile an edited function to a .o file (/api/compile)
  2. POST the base64 .o to this endpoint with the function's vaddr + size
  3. Receive the patched binary for download
"""

import base64
import os
import tempfile
from pathlib import Path

import lief
from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel

router = APIRouter()

WORK_DIR = os.environ.get("WORK_DIR", "/work")


def _resolve(rel: str) -> Path:
    work = Path(WORK_DIR).resolve()
    p    = (work / rel).resolve()
    if not p.is_relative_to(work):
        raise HTTPException(400, "Path traversal not allowed")
    if not p.exists():
        raise HTTPException(404, f"File not found: {rel}")
    return p


class PatchRequest(BaseModel):
    filePath:        str   # relative path to the binary
    functionAddress: str   # hex string, e.g. "0x401010" or "401010"
    functionSize:    int   # original function size in bytes (for bounds check + NOP padding)
    objectBase64:    str   # base64-encoded compiled .o file


@router.post("/function")
async def patch_function(req: PatchRequest) -> Response:
    target = _resolve(req.filePath)

    # Parse the virtual address
    addr_str = req.functionAddress.strip()
    if addr_str.startswith("0x") or addr_str.startswith("0X"):
        addr_str = addr_str[2:]
    try:
        vaddr = int(addr_str, 16)
    except ValueError:
        raise HTTPException(400, f"Invalid function address: {req.functionAddress!r}")

    if req.functionSize <= 0:
        raise HTTPException(400, f"functionSize must be > 0, got {req.functionSize}")

    # Decode the .o
    try:
        obj_bytes = base64.b64decode(req.objectBase64)
    except Exception as exc:
        raise HTTPException(400, f"Invalid base64 in objectBase64: {exc}") from exc

    # Extract .text from compiled object
    obj = lief.parse(list(obj_bytes))
    if obj is None:
        raise HTTPException(422, "Failed to parse compiled object file")

    text_section = obj.get_section(".text")
    if text_section is None:
        raise HTTPException(422, "Compiled object has no .text section — is this a valid object file?")

    new_code = bytes(text_section.content)
    if len(new_code) == 0:
        raise HTTPException(422, "Compiled .text section is empty")

    if len(new_code) > req.functionSize:
        raise HTTPException(400, (
            f"New code ({len(new_code)} bytes) is larger than the original function "
            f"({req.functionSize} bytes). Cannot patch without relocating. "
            "Try optimizing more aggressively (O2/Os) or simplifying the function."
        ))

    # Parse the target binary
    binary = lief.parse(str(target))
    if binary is None:
        raise HTTPException(422, "Failed to parse target binary")

    # Choose NOP byte(s) based on architecture
    try:
        arch_name = binary.header.machine_type.name.lower()
    except AttributeError:
        arch_name = ""

    pad_count = req.functionSize - len(new_code)
    if "aarch" in arch_name or ("arm" in arch_name and "64" in arch_name):
        # AArch64 NOP: 1f 20 03 d5 (little-endian)
        nop_word = b'\x1f\x20\x03\xd5'
        full_nops = (pad_count // 4) * nop_word + b'\x00' * (pad_count % 4)
    else:
        # x86/x86-64 NOP: 0x90
        full_nops = bytes([0x90] * pad_count)

    full_patch = list(new_code + full_nops)
    binary.patch_address(vaddr, full_patch)

    # Write to a temp file and read back the bytes
    with tempfile.NamedTemporaryFile(suffix=".patched", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        binary.write(str(tmp_path))
        patched = tmp_path.read_bytes()
    finally:
        tmp_path.unlink(missing_ok=True)

    filename = target.name + ".patched"
    return Response(
        content=patched,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
