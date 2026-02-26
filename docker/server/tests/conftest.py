"""
Shared pytest fixtures for the Softy Docker backend test suite.

Strategy:
- We patch WORK_DIR at the module level in each api sub-module by using
  monkeypatch on the module attribute directly (not just os.environ), because
  all api modules capture WORK_DIR at import time as a module-level constant.
- The `client` fixture creates a FastAPI TestClient against the real app.
- The `hello_elf` fixture writes a minimal but valid x86_64 ELF binary into
  the patched work directory and returns just the filename (relative path).
- The `hello_c_source` fixture returns a tiny C translation unit.
"""

import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Minimal valid x86_64 ELF64 binary
# ---------------------------------------------------------------------------
# Hand-crafted ELF64 executable for x86_64 Linux.
# The program section maps exactly the ELF header + one LOAD segment.
# The entry point executes:
#   mov rax, 60   ; sys_exit
#   xor rdi, rdi  ; status = 0
#   syscall
# This is 176 bytes total — small enough to be inlined as a hex literal.

_MINIMAL_ELF_HEX = (
    # ELF header (64 bytes)
    "7f454c46"  # magic
    "02"        # EI_CLASS  = ELFCLASS64
    "01"        # EI_DATA   = ELFDATA2LSB
    "01"        # EI_VERSION= EV_CURRENT
    "00"        # EI_OSABI  = ELFOSABI_NONE
    "0000000000000000"  # padding
    "0200"      # e_type  = ET_EXEC
    "3e00"      # e_machine = EM_X86_64
    "01000000"  # e_version = 1
    "b000400000000000"  # e_entry = 0x4000b0  (header + phdr = 0x40 + 0x38 + code offset)
    "4000000000000000"  # e_phoff = 64
    "0000000000000000"  # e_shoff = 0 (no sections)
    "00000000"  # e_flags = 0
    "4000"      # e_ehsize = 64
    "3800"      # e_phentsize = 56
    "0100"      # e_phnum = 1
    "4000"      # e_shentsize = 64
    "0000"      # e_shnum = 0
    "0000"      # e_shstrndx = 0
    # Program header (56 bytes)
    "01000000"          # p_type = PT_LOAD
    "05000000"          # p_flags = PF_R | PF_X
    "0000000000000000"  # p_offset = 0
    "0000400000000000"  # p_vaddr = 0x400000
    "0000400000000000"  # p_paddr = 0x400000
    "b000000000000000"  # p_filesz = 0xb0 = 176
    "b000000000000000"  # p_memsz  = 0xb0 = 176
    "0020000000000000"  # p_align = 0x200000
    # Code at offset 0xb0 = 176 — but we only have 120+56=176 bytes total,
    # so the code needs to sit right after the program header.
    # offset so far: 64 (ehdr) + 56 (phdr) = 120 = 0x78
    # entry = 0x400000 + 0x78 = 0x400078  → adjust e_entry above
    # Actually recalculate:  entry vaddr = 0x400000 + 0x78 = 0x400078
    # 48 c7 c0 3c000000  mov rax, 60
    # 48 31 ff           xor rdi, rdi
    # 0f 05              syscall
    "48c7c03c000000"  # mov rax, 60
    "4831ff"           # xor rdi, rdi
    "0f05"             # syscall
)

# Recalculate with correct entry.  The hex above has e_entry = 0x4000b0 which
# is wrong for a 176-byte file starting the code at offset 120 (0x78).
# Build it properly with struct instead.

import struct

def _build_minimal_elf() -> bytes:
    """
    Build a correct minimal ELF64 executable in memory.

    Layout:
      0x00 .. 0x3f : ELF header (64 bytes)
      0x40 .. 0x77 : Program header / PT_LOAD (56 bytes)
      0x78 .. 0x82 : Code (11 bytes): mov rax,60 / xor rdi,rdi / syscall
    Total: 131 bytes.  Load base = 0x400000, entry = 0x400078.
    """
    CODE = bytes.fromhex("48c7c03c0000004831ff0f05")  # 12 bytes
    LOAD_BASE = 0x400000
    EHDR_SIZE = 64
    PHDR_SIZE = 56
    CODE_OFFSET = EHDR_SIZE + PHDR_SIZE          # 0x78 = 120
    ENTRY_VADDR = LOAD_BASE + CODE_OFFSET         # 0x400078
    TOTAL_SIZE  = CODE_OFFSET + len(CODE)         # 132

    # ELF header — little-endian
    ehdr = struct.pack(
        "<4sBBBBxxxxxxxx"   # ident
        "HHIQQQIHHHHHH",
        b"\x7fELF",         # magic
        2,                  # EI_CLASS  ELFCLASS64
        1,                  # EI_DATA   ELFDATA2LSB
        1,                  # EI_VERSION
        0,                  # EI_OSABI
        2,                  # e_type   ET_EXEC
        0x3E,               # e_machine EM_X86_64
        1,                  # e_version
        ENTRY_VADDR,        # e_entry
        EHDR_SIZE,          # e_phoff
        0,                  # e_shoff
        0,                  # e_flags
        EHDR_SIZE,          # e_ehsize
        PHDR_SIZE,          # e_phentsize
        1,                  # e_phnum
        64,                 # e_shentsize
        0,                  # e_shnum
        0,                  # e_shstrndx
    )
    assert len(ehdr) == EHDR_SIZE, f"ehdr is {len(ehdr)} bytes, expected {EHDR_SIZE}"

    # Program header PT_LOAD
    phdr = struct.pack(
        "<IIQQQQQQ",
        1,              # p_type  PT_LOAD
        5,              # p_flags PF_R | PF_X
        0,              # p_offset
        LOAD_BASE,      # p_vaddr
        LOAD_BASE,      # p_paddr
        TOTAL_SIZE,     # p_filesz
        TOTAL_SIZE,     # p_memsz
        0x200000,       # p_align
    )
    assert len(phdr) == PHDR_SIZE, f"phdr is {len(phdr)} bytes, expected {PHDR_SIZE}"

    return ehdr + phdr + CODE


MINIMAL_ELF_BYTES: bytes = _build_minimal_elf()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def _elf_bytes() -> bytes:
    """Return the minimal ELF bytes (computed once per session)."""
    return MINIMAL_ELF_BYTES


@pytest.fixture()
def tmp_work_dir(tmp_path, monkeypatch):
    """
    Create a temp directory, set WORK_DIR env var, and also patch the
    module-level WORK_DIR constant in every api sub-module so that
    _resolve() functions see the new path even though they captured
    WORK_DIR at import time.
    """
    work = tmp_path / "work"
    work.mkdir()

    monkeypatch.setenv("WORK_DIR", str(work))

    # Patch the module-level constants that were already bound at import time.
    import api.analyze as _analyze
    import api.decompile as _decompile
    import api.compile_api as _compile_api
    import api.resources as _resources

    monkeypatch.setattr(_analyze,     "WORK_DIR", str(work))
    monkeypatch.setattr(_decompile,   "WORK_DIR", str(work))
    monkeypatch.setattr(_compile_api, "WORK_DIR", str(work))
    monkeypatch.setattr(_resources,   "WORK_DIR", str(work))

    return work


@pytest.fixture()
def hello_elf(tmp_work_dir, _elf_bytes) -> str:
    """
    Write the minimal ELF binary to the patched work directory.
    Returns the relative filename (suitable for filePath in requests).
    """
    filename = "hello.elf"
    (tmp_work_dir / filename).write_bytes(_elf_bytes)
    return filename


@pytest.fixture()
def hello_c_source() -> str:
    """A trivial C translation unit — compiles cleanly with clang."""
    return (
        "#include <stdint.h>\n"
        "int32_t add(int32_t a, int32_t b) { return a + b; }\n"
        "int32_t mul(int32_t a, int32_t b) { return a * b; }\n"
    )


@pytest.fixture()
def client(tmp_work_dir):
    """
    FastAPI TestClient.  We import the app here (after monkeypatching) so
    that any lazy module-level state is already correct for the test.
    The TestClient runs the ASGI app in-process with a real event loop.
    """
    # Add server root to sys.path so `from api import ...` works
    server_root = str(Path(__file__).parent.parent)
    if server_root not in sys.path:
        sys.path.insert(0, server_root)

    from main import app
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
