"""
Tests for /api/compile and /api/compile/assemble endpoints.

These tests call the REAL clang-17 / nasm executables; they are designed to
run inside the Docker container (or any environment where those tools are
installed at the expected paths).

If clang-17 is absent the tests are skipped rather than failed, so the suite
can still be run on developer machines without the full toolchain.
"""

import base64
import shutil

import pytest
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Helpers / skip guards
# ---------------------------------------------------------------------------

_CLANG_AVAILABLE  = shutil.which("clang-17") is not None
_NASM_AVAILABLE   = shutil.which("nasm") is not None

skip_no_clang = pytest.mark.skipif(
    not _CLANG_AVAILABLE,
    reason="clang-17 not installed — compile tests require the Docker environment",
)
skip_no_nasm = pytest.mark.skipif(
    not _NASM_AVAILABLE,
    reason="nasm not installed — assemble tests require the Docker environment",
)

# ---------------------------------------------------------------------------
# Shared C source snippets
# ---------------------------------------------------------------------------

C_ADD = "int add(int a, int b) { return a + b; }\n"
C_MUL = "int mul(int a, int b) { return a * b; }\n"
C_VALID = C_ADD + C_MUL

C_SYNTAX_ERROR = "int main() { this is invalid C }\n"

C_USES_STDLIB = (
    "#include <string.h>\n"
    "size_t my_strlen(const char *s) { return strlen(s); }\n"
)

ASM_VALID_X86_64 = "mov rax, 1\nxor rdi, rdi\nret\n"
ASM_INVALID      = "totally@@not##assembly!!!\n"


# ---------------------------------------------------------------------------
# /api/compile  (POST)
# ---------------------------------------------------------------------------

class TestCompileCode:

    @skip_no_clang
    def test_compile_object_success(self, client: TestClient, hello_c_source: str):
        """Compiling valid C to object format must succeed and return base64 output."""
        resp = client.post("/api/compile", json={
            "sourceCode": hello_c_source,
            "arch": "x86_64",
            "os": "linux",
            "optimize": "O1",
            "outputFormat": "object",
        })
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["success"] is True
        assert data["output"] is not None
        assert len(data["output"]) > 0

    @skip_no_clang
    def test_compile_object_is_valid_base64(self, client: TestClient, hello_c_source: str):
        """The object output must be valid base64-encoded bytes."""
        data = client.post("/api/compile", json={
            "sourceCode": hello_c_source,
            "outputFormat": "object",
        }).json()
        assert data["success"] is True
        decoded = base64.b64decode(data["output"])
        # An ELF object file starts with the ELF magic bytes
        assert decoded[:4] == b"\x7fELF"

    @skip_no_clang
    def test_compile_object_size_bytes(self, client: TestClient, hello_c_source: str):
        """sizeBytes must be positive on success and match decoded output length."""
        data = client.post("/api/compile", json={
            "sourceCode": hello_c_source,
            "outputFormat": "object",
        }).json()
        assert data["success"] is True
        assert data["sizeBytes"] > 0
        decoded = base64.b64decode(data["output"])
        assert data["sizeBytes"] == len(decoded)

    @skip_no_clang
    def test_compile_object_no_errors(self, client: TestClient, hello_c_source: str):
        """Valid C must produce zero errors."""
        data = client.post("/api/compile", json={
            "sourceCode": hello_c_source,
            "outputFormat": "object",
        }).json()
        assert data["errors"] == []

    @skip_no_clang
    def test_compile_syntax_error_fails(self, client: TestClient):
        """Invalid C syntax must return success=False."""
        resp = client.post("/api/compile", json={
            "sourceCode": C_SYNTAX_ERROR,
            "outputFormat": "object",
        })
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["success"] is False

    @skip_no_clang
    def test_compile_syntax_error_has_errors(self, client: TestClient):
        """Invalid C must yield a non-empty errors list."""
        data = client.post("/api/compile", json={
            "sourceCode": C_SYNTAX_ERROR,
            "outputFormat": "object",
        }).json()
        assert len(data["errors"]) > 0

    @skip_no_clang
    def test_compile_syntax_error_no_output(self, client: TestClient):
        """Failed compilation must produce null output."""
        data = client.post("/api/compile", json={
            "sourceCode": C_SYNTAX_ERROR,
            "outputFormat": "object",
        }).json()
        assert data["output"] is None

    @skip_no_clang
    def test_compile_syntax_error_size_zero(self, client: TestClient):
        """sizeBytes must be 0 when compilation fails."""
        data = client.post("/api/compile", json={
            "sourceCode": C_SYNTAX_ERROR,
            "outputFormat": "object",
        }).json()
        assert data["sizeBytes"] == 0

    @skip_no_clang
    def test_compile_asm_format_success(self, client: TestClient, hello_c_source: str):
        """Compiling to asm format must succeed."""
        resp = client.post("/api/compile", json={
            "sourceCode": hello_c_source,
            "outputFormat": "asm",
        })
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["success"] is True
        assert data["output"] is not None

    @skip_no_clang
    def test_compile_asm_format_contains_text(self, client: TestClient, hello_c_source: str):
        """
        Asm output (base64-encoded text) must decode to something that looks
        like assembly — specifically it should contain common AT&T or Intel
        directives / mnemonics.
        """
        data = client.post("/api/compile", json={
            "sourceCode": hello_c_source,
            "outputFormat": "asm",
        }).json()
        assert data["success"] is True
        text = base64.b64decode(data["output"]).decode("utf-8", errors="replace")
        # Assembly output should contain section markers or registers
        lower = text.lower()
        assert any(kw in lower for kw in (".text", "ret", "push", "mov", "add"))

    @skip_no_clang
    def test_compile_asm_output_format_field(self, client: TestClient, hello_c_source: str):
        """outputFormat in the response must echo 'asm'."""
        data = client.post("/api/compile", json={
            "sourceCode": hello_c_source,
            "outputFormat": "asm",
        }).json()
        assert data["outputFormat"] == "asm"

    @skip_no_clang
    def test_compile_ir_format_success(self, client: TestClient, hello_c_source: str):
        """Compiling to LLVM IR format must succeed."""
        resp = client.post("/api/compile", json={
            "sourceCode": hello_c_source,
            "outputFormat": "ir",
        })
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["success"] is True
        assert data["output"] is not None

    @skip_no_clang
    def test_compile_ir_output_looks_like_llvm(self, client: TestClient, hello_c_source: str):
        """LLVM IR output must decode to text containing 'define'."""
        data = client.post("/api/compile", json={
            "sourceCode": hello_c_source,
            "outputFormat": "ir",
        }).json()
        assert data["success"] is True
        text = base64.b64decode(data["output"]).decode("utf-8", errors="replace")
        assert "define" in text

    @skip_no_clang
    def test_compile_ir_output_format_field(self, client: TestClient, hello_c_source: str):
        """outputFormat in the response must echo 'ir'."""
        data = client.post("/api/compile", json={
            "sourceCode": hello_c_source,
            "outputFormat": "ir",
        }).json()
        assert data["outputFormat"] == "ir"

    @skip_no_clang
    def test_compile_different_opt_levels(self, client: TestClient, hello_c_source: str):
        """O0 and O2 must both succeed (just potentially different sizes)."""
        for opt in ("O0", "O2", "Os"):
            data = client.post("/api/compile", json={
                "sourceCode": hello_c_source,
                "outputFormat": "object",
                "optimize": opt,
            }).json()
            assert data["success"] is True, f"Failed with optimize={opt}"

    @skip_no_clang
    def test_compile_arm64_cross(self, client: TestClient, hello_c_source: str):
        """Cross-compiling to arm64/linux must succeed (clang is a cross compiler)."""
        data = client.post("/api/compile", json={
            "sourceCode": hello_c_source,
            "arch": "arm64",
            "os": "linux",
            "outputFormat": "object",
        }).json()
        assert data["success"] is True

    @skip_no_clang
    def test_compile_warnings_is_list(self, client: TestClient, hello_c_source: str):
        """warnings field must always be a list, even if empty."""
        data = client.post("/api/compile", json={
            "sourceCode": hello_c_source,
            "outputFormat": "object",
        }).json()
        assert isinstance(data["warnings"], list)

    @skip_no_clang
    def test_compile_warning_has_fields(self, client: TestClient):
        """
        When a warning-inducing snippet is compiled, each warning dict must have
        file, line, col, message, raw keys.
        """
        # Implicit int return triggers a warning in strict mode
        c_warn = "int maybe_warn(int x) { if (x) return x; }\n"
        data = client.post("/api/compile", json={
            "sourceCode": c_warn,
            "outputFormat": "object",
            "extraFlags": ["-Wreturn-type"],
        }).json()
        # We don't assert success here — the key thing is that if warnings exist
        # they have the correct shape.
        for w in data.get("warnings", []):
            assert "file"    in w
            assert "line"    in w
            assert "col"     in w
            assert "message" in w
            assert "raw"     in w

    def test_compile_missing_source_422(self, client: TestClient):
        """Omitting sourceCode must return a 422 validation error."""
        resp = client.post("/api/compile", json={
            "outputFormat": "object",
        })
        assert resp.status_code == 422

    def test_compile_empty_body_422(self, client: TestClient):
        """An empty JSON body must return a 422 validation error."""
        resp = client.post("/api/compile", json={})
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# /api/compile/assemble  (POST)
# ---------------------------------------------------------------------------

class TestAssembleCode:

    @skip_no_nasm
    def test_assemble_x86_64_success(self, client: TestClient):
        """Valid x86_64 assembly must return success=True."""
        resp = client.post("/api/compile/assemble", json={
            "assembly": ASM_VALID_X86_64,
            "arch": "x86_64",
        })
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["success"] is True

    @skip_no_nasm
    def test_assemble_x86_64_output_is_base64(self, client: TestClient):
        """Output must be valid base64-encoded ELF object data."""
        data = client.post("/api/compile/assemble", json={
            "assembly": ASM_VALID_X86_64,
            "arch": "x86_64",
        }).json()
        assert data["success"] is True
        decoded = base64.b64decode(data["output"])
        assert decoded[:4] == b"\x7fELF"

    @skip_no_nasm
    def test_assemble_x86_64_errors_empty_on_success(self, client: TestClient):
        """errors list must be empty when assembly succeeds."""
        data = client.post("/api/compile/assemble", json={
            "assembly": ASM_VALID_X86_64,
            "arch": "x86_64",
        }).json()
        assert data["errors"] == []

    @skip_no_nasm
    def test_assemble_x86_success(self, client: TestClient):
        """Valid 32-bit x86 assembly must also succeed."""
        asm32 = "mov eax, 1\nxor ebx, ebx\nint 0x80\n"
        resp = client.post("/api/compile/assemble", json={
            "assembly": asm32,
            "arch": "x86",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True

    @skip_no_nasm
    def test_assemble_invalid_fails(self, client: TestClient):
        """Garbage input must return success=False."""
        resp = client.post("/api/compile/assemble", json={
            "assembly": ASM_INVALID,
            "arch": "x86_64",
        })
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["success"] is False

    @skip_no_nasm
    def test_assemble_invalid_has_errors(self, client: TestClient):
        """Failed assembly must have a non-empty errors list."""
        data = client.post("/api/compile/assemble", json={
            "assembly": ASM_INVALID,
            "arch": "x86_64",
        }).json()
        assert data["success"] is False
        assert len(data["errors"]) > 0

    @skip_no_nasm
    def test_assemble_invalid_no_output(self, client: TestClient):
        """Failed assembly must have null output."""
        data = client.post("/api/compile/assemble", json={
            "assembly": ASM_INVALID,
            "arch": "x86_64",
        }).json()
        assert data["output"] is None

    def test_assemble_unsupported_arch_422(self, client: TestClient):
        """Requesting an unsupported arch must return 422."""
        resp = client.post("/api/compile/assemble", json={
            "assembly": "nop",
            "arch": "mips",
        })
        assert resp.status_code == 422

    def test_assemble_missing_assembly_422(self, client: TestClient):
        """Omitting assembly field must return a validation error."""
        resp = client.post("/api/compile/assemble", json={"arch": "x86_64"})
        assert resp.status_code == 422

    def test_assemble_empty_body_422(self, client: TestClient):
        """Empty body must return a validation error."""
        resp = client.post("/api/compile/assemble", json={})
        assert resp.status_code == 422
