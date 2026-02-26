"""
/api/analyze — Binary metadata extraction using lief + python-magic.
Returns format, architecture, compiler hints, hashes, sections, imports/exports, strings.
"""

import hashlib
import os
import struct
from pathlib import Path
from typing import Optional

import lief
import magic
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()
WORK_DIR = os.environ.get("WORK_DIR", "/work")


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
    p = Path(WORK_DIR) / rel_path
    if not p.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {rel_path}")
    return p


def _hashes(path: Path) -> dict:
    data = path.read_bytes()
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    import math
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
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
            # Check PDB path
            debug = binary.debug
            for d in debug:
                if hasattr(d, 'pdb_filename') and d.pdb_filename:
                    pdb = d.pdb_filename.lower()
                    if 'rust' in pdb:
                        return 'Rust'
                    if 'go' in pdb:
                        return 'Go'

            # Check version resource
            if binary.has_resources:
                try:
                    rt_version = binary.resources_manager.version
                    if rt_version:
                        fi = rt_version.fixed_file_info
                        # MSVC file version in StringFileInfo
                        pass
                except Exception:
                    pass

            # Linker version
            opt = binary.optional_header
            maj, minor = opt.major_linker_version, opt.minor_linker_version
            if maj == 14:
                return f"MSVC 19.{minor} (VS 2019-2022)"
            elif maj == 12:
                return f"MSVC 19.{minor} (VS 2013)"
            elif maj == 11:
                return "MSVC (VS 2012)"

    except Exception:
        pass
    return None


def _arch_str(arch) -> str:
    mapping = {
        lief.ARCHITECTURES.X86:   "x86",
        lief.ARCHITECTURES.ARM:   "ARM",
        lief.ARCHITECTURES.ARM64: "ARM64",
        lief.ARCHITECTURES.MIPS:  "MIPS",
        lief.ARCHITECTURES.PPC:   "PowerPC",
        lief.ARCHITECTURES.RISCV: "RISC-V",
    }
    return mapping.get(arch, "Unknown")


def _os_str(binary) -> str:
    if isinstance(binary, lief.PE.Binary):
        return "Windows"
    if isinstance(binary, lief.ELF.Binary):
        return "Linux"
    if isinstance(binary, lief.MachO.Binary):
        return "macOS"
    return "Unknown"


@router.post("", response_model=AnalyzeResponse)
async def analyze_binary(req: AnalyzeRequest):
    path = _resolve(req.filePath)
    raw = path.read_bytes()
    file_size = len(raw)

    # lief parse
    binary = lief.parse(str(path))
    if binary is None:
        raise HTTPException(status_code=422, detail="Unsupported or corrupt binary format")

    # Magic-based format detection
    mime = magic.from_file(str(path), mime=True)
    fmt_map = {
        "application/x-dosexec":    "PE",
        "application/x-executable": "ELF",
        "application/x-sharedlib":  "ELF",
        "application/x-mach-binary":"MachO",
    }
    fmt = fmt_map.get(mime, type(binary).__module__.split(".")[1] if hasattr(binary, '__module__') else "Unknown")
    if isinstance(binary, lief.PE.Binary):
        fmt = "PE"
    elif isinstance(binary, lief.ELF.Binary):
        fmt = "ELF"
    elif isinstance(binary, lief.MachO.FatBinary):
        fmt = "MachO-Fat"
        binary = binary.at(0)  # use first slice
    elif isinstance(binary, lief.MachO.Binary):
        fmt = "MachO"

    arch   = _arch_str(binary.abstract.header.architecture)
    bits   = 64 if binary.abstract.header.is_64 else 32
    endian = "little" if binary.abstract.header.endianness == lief.ENDIANNESS.LITTLE else "big"
    os_    = _os_str(binary)

    # Entry point & base
    try:
        entry = binary.abstract.entrypoint
    except Exception:
        entry = 0
    try:
        if isinstance(binary, lief.PE.Binary):
            base = binary.optional_header.imagebase
        elif isinstance(binary, lief.ELF.Binary):
            base = binary.imagebase
        elif isinstance(binary, lief.MachO.Binary):
            base = binary.imagebase
        else:
            base = 0
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
                content = bytes(s.content)
                ent = _entropy(content)
            except Exception:
                ent = 0.0
            # Flags
            flags_parts = []
            try:
                ch = s.characteristics if hasattr(s, 'characteristics') else s.flags
                if hasattr(lief.PE.Section, 'CHARACTERISTICS'):
                    pass
                flags_parts.append(hex(int(ch)))
            except Exception:
                flags_parts.append("")
            sections.append(SectionInfo(
                name=name, virtualAddress=va, virtualSize=vs,
                rawSize=rs, entropy=ent, flags=" ".join(flags_parts)
            ))
    except Exception:
        pass

    # Imports
    imports = []
    try:
        if isinstance(binary, lief.PE.Binary):
            for lib in binary.imports:
                for fn in lib.entries:
                    imports.append(ImportEntry(library=lib.name, name=fn.name or f"ord_{fn.ordinal}"))
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
                exports.append(ExportEntry(name=exp.name or "", address=exp.address, ordinal=exp.ordinal))
        elif isinstance(binary, lief.ELF.Binary):
            for sym in binary.exported_symbols:
                exports.append(ExportEntry(name=sym.name, address=sym.value))
    except Exception:
        pass

    # Packed detection: any section with entropy > 7.2
    is_packed = any(s.entropy > 7.2 for s in sections)

    # Signed detection (PE only)
    is_signed = False
    try:
        if isinstance(binary, lief.PE.Binary):
            is_signed = binary.has_signature
    except Exception:
        pass

    # Characteristics
    characteristics: dict = {}
    try:
        if isinstance(binary, lief.PE.Binary):
            characteristics["subsystem"] = str(binary.optional_header.subsystem).split(".")[-1]
            characteristics["dllCharacteristics"] = hex(binary.optional_header.dll_characteristics)
    except Exception:
        pass

    return AnalyzeResponse(
        format=fmt,
        arch=arch,
        bits=bits,
        endian=endian,
        os=os_,
        compiler=_detect_compiler(binary),
        entryPoint=entry,
        baseAddress=base,
        fileSize=file_size,
        hashes=_hashes(path),
        sections=sections,
        imports=imports[:500],  # cap for large binaries
        exports=exports[:500],
        isPacked=is_packed,
        isSigned=is_signed,
        characteristics=characteristics,
    )


@router.get("/strings")
async def get_strings(filePath: str, minLen: int = 6, limit: int = 2000):
    """Extract printable strings from a binary."""
    path = _resolve(filePath)
    data = path.read_bytes()
    results = []
    current = []
    current_offset = 0

    i = 0
    while i < len(data):
        b = data[i]
        if 0x20 <= b <= 0x7e:
            if not current:
                current_offset = i
            current.append(chr(b))
        else:
            if len(current) >= minLen:
                results.append({
                    "offset": current_offset,
                    "value": "".join(current),
                    "encoding": "ascii",
                })
            current = []
        i += 1
        if len(results) >= limit:
            break

    return {"strings": results, "total": len(results)}
