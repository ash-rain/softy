"""
/api/analyze — Binary metadata extraction using lief + python-magic.
Returns format, architecture, compiler hints, hashes, sections, imports/exports, strings.
"""

import hashlib
import math
import os
from pathlib import Path
from typing import Optional

import lief
import magic
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()
WORK_DIR      = os.environ.get("WORK_DIR", "/work")
MAX_FILE_SIZE = int(os.environ.get("MAX_FILE_SIZE_MB", "500")) * 1024 * 1024  # 500 MB


class AnalyzeRequest(BaseModel):
    filePath: str  # relative to WORK_DIR


class SectionInfo(BaseModel):
    name: str
    virtualAddress: int
    virtualSize: int
    rawSize: int
    entropy: float
    flags: str


class ImportEntry(BaseModel):
    library: str
    name: str
    address: Optional[int] = None


class ExportEntry(BaseModel):
    name: str
    address: int
    ordinal: Optional[int] = None


class AnalyzeResponse(BaseModel):
    format: str
    arch: str
    bits: int
    endian: str
    os: str
    compiler: Optional[str]
    entryPoint: int
    baseAddress: int
    fileSize: int
    hashes: dict
    sections: list[SectionInfo]
    imports: list[ImportEntry]
    exports: list[ExportEntry]
    isPacked: bool
    isSigned: bool
    characteristics: dict


def _resolve(rel_path: str) -> Path:
    """Resolve relative path within WORK_DIR, guarding against traversal."""
    work = Path(WORK_DIR).resolve()
    p    = (work / rel_path).resolve()
    if not p.is_relative_to(work):
        raise HTTPException(400, "Path traversal not allowed")
    if not p.exists():
        raise HTTPException(404, f"File not found: {rel_path}")
    return p


def _hashes(data: bytes) -> dict:
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq   = [0] * 256
    for b in data:
        freq[b] += 1
    length  = len(data)
    entropy = 0.0
    for f in freq:
        if f > 0:
            p = f / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def _detect_compiler(binary) -> Optional[str]:
    """Heuristic compiler detection from known strings/sections."""
    try:
        if isinstance(binary, lief.PE.Binary):
            for d in binary.debug:
                if hasattr(d, 'pdb_filename') and d.pdb_filename:
                    pdb = d.pdb_filename.lower()
                    if 'rust' in pdb: return 'Rust'
                    if 'go'   in pdb: return 'Go'
            opt = binary.optional_header
            maj, minor = opt.major_linker_version, opt.minor_linker_version
            if maj == 14: return f"MSVC 19.{minor} (VS 2019-2022)"
            if maj == 12: return f"MSVC 19.{minor} (VS 2013)"
            if maj == 11: return "MSVC (VS 2012)"
        if isinstance(binary, lief.ELF.Binary):
            # Check .comment section for GCC/Clang version string
            for sec in binary.sections:
                if sec.name == ".comment":
                    comment = bytes(sec.content).decode("utf-8", errors="replace").strip("\x00").strip()
                    if comment:
                        for hint in ("GCC", "clang", "Clang", "LLVM", "rustc", "Go "):
                            if hint in comment:
                                # Return first null-terminated string
                                return comment.split("\x00")[0][:64]
    except Exception:
        pass
    return None


def _arch_str(arch) -> str:
    return {
        lief.ARCHITECTURES.X86:   "x86",
        lief.ARCHITECTURES.ARM:   "ARM",
        lief.ARCHITECTURES.ARM64: "ARM64",
        lief.ARCHITECTURES.MIPS:  "MIPS",
        lief.ARCHITECTURES.PPC:   "PowerPC",
        lief.ARCHITECTURES.RISCV: "RISC-V",
    }.get(arch, "Unknown")


def _os_str(binary) -> str:
    if isinstance(binary, lief.PE.Binary):    return "Windows"
    if isinstance(binary, lief.ELF.Binary):   return "Linux"
    if isinstance(binary, lief.MachO.Binary): return "macOS"
    return "Unknown"


@router.post("", response_model=AnalyzeResponse)
async def analyze_binary(req: AnalyzeRequest):
    path = _resolve(req.filePath)
    file_size = path.stat().st_size

    if file_size > MAX_FILE_SIZE:
        raise HTTPException(413, f"File too large ({file_size // 1_048_576} MB). Maximum is {MAX_FILE_SIZE // 1_048_576} MB.")

    raw    = path.read_bytes()
    binary = lief.parse(str(path))
    if binary is None:
        raise HTTPException(422, "Unsupported or corrupt binary format")

    # Format detection
    mime = magic.from_file(str(path), mime=True)
    if isinstance(binary, lief.PE.Binary):
        fmt = "PE"
    elif isinstance(binary, lief.ELF.Binary):
        fmt = "ELF"
    elif isinstance(binary, lief.MachO.FatBinary):
        fmt    = "MachO-Fat"
        binary = binary.at(0)
    elif isinstance(binary, lief.MachO.Binary):
        fmt = "MachO"
    else:
        fmt = {
            "application/x-dosexec":     "PE",
            "application/x-executable":  "ELF",
            "application/x-sharedlib":   "ELF",
            "application/x-mach-binary": "MachO",
        }.get(mime, "Unknown")

    arch   = _arch_str(binary.abstract.header.architecture)
    bits   = 64 if binary.abstract.header.is_64 else 32
    endian = "little" if binary.abstract.header.endianness == lief.ENDIANNESS.LITTLE else "big"
    os_    = _os_str(binary)

    try:
        entry = binary.abstract.entrypoint
    except Exception:
        entry = 0

    try:
        if   isinstance(binary, lief.PE.Binary):    base = binary.optional_header.imagebase
        elif isinstance(binary, lief.ELF.Binary):   base = binary.imagebase
        elif isinstance(binary, lief.MachO.Binary): base = binary.imagebase
        else:                                        base = 0
    except Exception:
        base = 0

    # Sections
    sections = []
    try:
        for s in binary.sections:
            name = getattr(s, 'name', '') or ''
            va   = getattr(s, 'virtual_address', 0) or 0
            vs   = getattr(s, 'virtual_size', getattr(s, 'size', 0)) or 0
            rs   = getattr(s, 'size', 0) or 0
            try:
                ent = _entropy(bytes(s.content))
            except Exception:
                ent = 0.0
            try:
                ch = s.characteristics if hasattr(s, 'characteristics') else s.flags
                flags_str = hex(int(ch))
            except Exception:
                flags_str = ""
            sections.append(SectionInfo(
                name=name, virtualAddress=va, virtualSize=vs,
                rawSize=rs, entropy=ent, flags=flags_str,
            ))
    except Exception:
        pass

    # Imports
    imports = []
    try:
        if isinstance(binary, lief.PE.Binary):
            for lib in binary.imports:
                for fn in lib.entries:
                    imports.append(ImportEntry(library=lib.name,
                                               name=fn.name or f"ord_{fn.ordinal}"))
        elif isinstance(binary, lief.ELF.Binary):
            for sym in binary.imported_symbols:
                imports.append(ImportEntry(library="", name=sym.name))
        elif isinstance(binary, lief.MachO.Binary):
            for imp in binary.imported_symbols:
                imports.append(ImportEntry(library="", name=imp.name))
    except Exception:
        pass

    # Exports
    exports = []
    try:
        if isinstance(binary, lief.PE.Binary) and binary.has_exports:
            for exp in binary.get_export().entries:
                exports.append(ExportEntry(name=exp.name or "", address=exp.address,
                                           ordinal=exp.ordinal))
        elif isinstance(binary, lief.ELF.Binary):
            for sym in binary.exported_symbols:
                exports.append(ExportEntry(name=sym.name, address=sym.value))
        elif isinstance(binary, lief.MachO.Binary):
            for sym in binary.exported_symbols:
                try:
                    exports.append(ExportEntry(name=sym.name, address=sym.value))
                except Exception:
                    pass
    except Exception:
        pass

    is_packed = any(s.entropy > 7.2 for s in sections)

    is_signed = False
    try:
        if isinstance(binary, lief.PE.Binary):
            is_signed = binary.has_signature
    except Exception:
        pass

    characteristics: dict = {}
    try:
        if isinstance(binary, lief.PE.Binary):
            characteristics["subsystem"]          = str(binary.optional_header.subsystem).split(".")[-1]
            characteristics["dllCharacteristics"] = hex(binary.optional_header.dll_characteristics)
    except Exception:
        pass

    return AnalyzeResponse(
        format=fmt, arch=arch, bits=bits, endian=endian, os=os_,
        compiler=_detect_compiler(binary),
        entryPoint=entry, baseAddress=base, fileSize=file_size,
        hashes=_hashes(raw),
        sections=sections,
        imports=imports[:500],
        exports=exports[:500],
        isPacked=is_packed, isSigned=is_signed,
        characteristics=characteristics,
    )


@router.get("/strings")
async def get_strings(filePath: str, minLen: int = 6, limit: int = 2000):
    """Extract printable ASCII strings from a binary. Runs in thread pool."""
    path = _resolve(filePath)

    if path.stat().st_size > MAX_FILE_SIZE:
        raise HTTPException(413, "File too large for string extraction")

    import asyncio

    def _extract() -> list[dict]:
        data    = path.read_bytes()
        results = []
        current: list[str] = []
        current_offset = 0
        for i, b in enumerate(data):
            if 0x20 <= b <= 0x7e:
                if not current:
                    current_offset = i
                current.append(chr(b))
            else:
                if len(current) >= minLen:
                    results.append({
                        "offset":   current_offset,
                        "value":    "".join(current),
                        "encoding": "ascii",
                    })
                current = []
            if len(results) >= limit:
                break
        # flush trailing
        if len(current) >= minLen:
            results.append({"offset": current_offset, "value": "".join(current), "encoding": "ascii"})
        return results

    loop    = asyncio.get_event_loop()
    results = await loop.run_in_executor(None, _extract)
    return {"strings": results, "total": len(results)}
