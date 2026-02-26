"""
Tests for /api/analyze and /api/analyze/strings endpoints.

All tests use the real FastAPI app via TestClient (no Docker).
File resolution always goes through WORK_DIR which is patched to a temp
directory by the shared fixtures in conftest.py.
"""

import base64
import hashlib
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# /api/analyze  (POST)
# ---------------------------------------------------------------------------

class TestAnalyzeBinary:
    def test_analyze_elf_status_200(self, client: TestClient, hello_elf: str):
        """A valid ELF binary must return HTTP 200."""
        resp = client.post("/api/analyze", json={"filePath": hello_elf})
        assert resp.status_code == 200, resp.text

    def test_analyze_elf_format_field(self, client: TestClient, hello_elf: str):
        """format field must be 'ELF' for our minimal ELF64 binary."""
        data = client.post("/api/analyze", json={"filePath": hello_elf}).json()
        assert data["format"] == "ELF"

    def test_analyze_elf_arch_present(self, client: TestClient, hello_elf: str):
        """arch field must be a non-empty string."""
        data = client.post("/api/analyze", json={"filePath": hello_elf}).json()
        assert isinstance(data["arch"], str)
        assert len(data["arch"]) > 0

    def test_analyze_elf_bits(self, client: TestClient, hello_elf: str):
        """bits must be either 32 or 64; our ELF is 64-bit."""
        data = client.post("/api/analyze", json={"filePath": hello_elf}).json()
        assert data["bits"] in (32, 64)
        assert data["bits"] == 64

    def test_analyze_elf_endian(self, client: TestClient, hello_elf: str):
        """endian must be 'little' or 'big'; x86_64 is little-endian."""
        data = client.post("/api/analyze", json={"filePath": hello_elf}).json()
        assert data["endian"] in ("little", "big")
        assert data["endian"] == "little"

    def test_analyze_elf_os(self, client: TestClient, hello_elf: str):
        """os field must be a string; ELF maps to 'Linux'."""
        data = client.post("/api/analyze", json={"filePath": hello_elf}).json()
        assert isinstance(data["os"], str)
        assert data["os"] == "Linux"

    def test_analyze_elf_hashes_md5(self, client: TestClient, hello_elf: str, tmp_work_dir):
        """hashes.md5 must be a 32-character hex string and match the file."""
        data = client.post("/api/analyze", json={"filePath": hello_elf}).json()
        md5 = data["hashes"]["md5"]
        assert isinstance(md5, str)
        assert len(md5) == 32
        # Cross-check against Python's own computation
        raw = (tmp_work_dir / hello_elf).read_bytes()
        expected = hashlib.md5(raw).hexdigest()
        assert md5 == expected

    def test_analyze_elf_hashes_sha1(self, client: TestClient, hello_elf: str):
        """hashes.sha1 must be a 40-character hex string."""
        data = client.post("/api/analyze", json={"filePath": hello_elf}).json()
        sha1 = data["hashes"]["sha1"]
        assert isinstance(sha1, str)
        assert len(sha1) == 40

    def test_analyze_elf_hashes_sha256(self, client: TestClient, hello_elf: str):
        """hashes.sha256 must be a 64-character hex string."""
        data = client.post("/api/analyze", json={"filePath": hello_elf}).json()
        sha256 = data["hashes"]["sha256"]
        assert isinstance(sha256, str)
        assert len(sha256) == 64

    def test_analyze_elf_sections_is_list(self, client: TestClient, hello_elf: str):
        """sections must be a list (may be empty for a stripped tiny ELF)."""
        data = client.post("/api/analyze", json={"filePath": hello_elf}).json()
        assert isinstance(data["sections"], list)

    def test_analyze_elf_imports_is_list(self, client: TestClient, hello_elf: str):
        """imports must be a list."""
        data = client.post("/api/analyze", json={"filePath": hello_elf}).json()
        assert isinstance(data["imports"], list)

    def test_analyze_elf_exports_is_list(self, client: TestClient, hello_elf: str):
        """exports must be a list."""
        data = client.post("/api/analyze", json={"filePath": hello_elf}).json()
        assert isinstance(data["exports"], list)

    def test_analyze_elf_is_not_packed(self, client: TestClient, hello_elf: str):
        """A hand-crafted ELF with no high-entropy sections must not be flagged packed."""
        data = client.post("/api/analyze", json={"filePath": hello_elf}).json()
        assert data["isPacked"] is False

    def test_analyze_elf_is_not_signed(self, client: TestClient, hello_elf: str):
        """ELF binaries are never Authenticode-signed."""
        data = client.post("/api/analyze", json={"filePath": hello_elf}).json()
        assert data["isSigned"] is False

    def test_analyze_elf_file_size(self, client: TestClient, hello_elf: str, tmp_work_dir):
        """fileSize must match the actual file size on disk."""
        data = client.post("/api/analyze", json={"filePath": hello_elf}).json()
        actual_size = (tmp_work_dir / hello_elf).stat().st_size
        assert data["fileSize"] == actual_size

    def test_analyze_elf_entry_point_is_int(self, client: TestClient, hello_elf: str):
        """entryPoint must be a non-negative integer."""
        data = client.post("/api/analyze", json={"filePath": hello_elf}).json()
        assert isinstance(data["entryPoint"], int)
        assert data["entryPoint"] >= 0

    def test_analyze_elf_base_address_is_int(self, client: TestClient, hello_elf: str):
        """baseAddress must be a non-negative integer."""
        data = client.post("/api/analyze", json={"filePath": hello_elf}).json()
        assert isinstance(data["baseAddress"], int)
        assert data["baseAddress"] >= 0

    def test_analyze_elf_characteristics_is_dict(self, client: TestClient, hello_elf: str):
        """characteristics must be a dict (possibly empty for ELF)."""
        data = client.post("/api/analyze", json={"filePath": hello_elf}).json()
        assert isinstance(data["characteristics"], dict)

    def test_analyze_missing_file_404(self, client: TestClient):
        """Requesting a file that does not exist must return 404."""
        resp = client.post("/api/analyze", json={"filePath": "does_not_exist.elf"})
        assert resp.status_code == 404

    def test_analyze_missing_file_detail(self, client: TestClient):
        """The 404 response detail should mention the file name."""
        resp = client.post("/api/analyze", json={"filePath": "missing.bin"})
        body = resp.json()
        assert "missing.bin" in body.get("detail", "")

    def test_analyze_corrupt_binary_422(self, client: TestClient, tmp_work_dir):
        """A file that is not a valid binary must return 422."""
        bad = tmp_work_dir / "corrupt.bin"
        bad.write_text("not a binary\n")
        resp = client.post("/api/analyze", json={"filePath": "corrupt.bin"})
        assert resp.status_code == 422

    def test_analyze_corrupt_binary_detail(self, client: TestClient, tmp_work_dir):
        """The 422 response detail should describe the problem."""
        bad = tmp_work_dir / "garbage.bin"
        bad.write_bytes(b"\x00" * 16)   # 16 zero bytes — lief will fail to parse
        resp = client.post("/api/analyze", json={"filePath": "garbage.bin"})
        assert resp.status_code == 422
        assert resp.json().get("detail") is not None

    def test_analyze_empty_body_422(self, client: TestClient):
        """Sending an empty JSON body must return a validation error (422)."""
        resp = client.post("/api/analyze", json={})
        assert resp.status_code == 422

    def test_analyze_response_schema_keys(self, client: TestClient, hello_elf: str):
        """All expected top-level keys must be present in the response."""
        required = {
            "format", "arch", "bits", "endian", "os", "compiler",
            "entryPoint", "baseAddress", "fileSize", "hashes",
            "sections", "imports", "exports", "isPacked", "isSigned",
            "characteristics",
        }
        data = client.post("/api/analyze", json={"filePath": hello_elf}).json()
        assert required.issubset(data.keys())


# ---------------------------------------------------------------------------
# /api/analyze/strings  (GET)
# ---------------------------------------------------------------------------

class TestGetStrings:
    def test_strings_status_200(self, client: TestClient, hello_elf: str):
        """Must return HTTP 200 for a valid file."""
        resp = client.get("/api/analyze/strings", params={"filePath": hello_elf})
        assert resp.status_code == 200, resp.text

    def test_strings_is_list(self, client: TestClient, hello_elf: str):
        """strings key must be a list."""
        data = client.get("/api/analyze/strings", params={"filePath": hello_elf}).json()
        assert isinstance(data["strings"], list)

    def test_strings_total_matches_list_length(self, client: TestClient, hello_elf: str):
        """total field must equal len(strings)."""
        data = client.get("/api/analyze/strings", params={"filePath": hello_elf}).json()
        assert data["total"] == len(data["strings"])

    def test_strings_entry_shape(self, client: TestClient, tmp_work_dir):
        """
        Each string entry must have 'offset', 'value', 'encoding' keys.
        We write a file with a clearly detectable ASCII run to guarantee at
        least one result.
        """
        # 8 printable chars — longer than default minLen of 6
        payload = b"\x00\x01\x02" + b"HELLO_TS" + b"\x00"
        (tmp_work_dir / "strings_test.bin").write_bytes(payload)
        data = client.get(
            "/api/analyze/strings",
            params={"filePath": "strings_test.bin", "minLen": 6},
        ).json()
        assert len(data["strings"]) >= 1
        entry = data["strings"][0]
        assert "offset" in entry
        assert "value" in entry
        assert "encoding" in entry

    def test_strings_min_len_filters(self, client: TestClient, tmp_work_dir):
        """
        With minLen=100, a binary that has only short strings must return fewer
        (or equal) results than with the default minLen=6.
        """
        # Create a binary with two ASCII runs: one short (8 chars), one long
        short_run = b"SHORTSTR"           # 8 chars
        long_run  = b"A" * 120             # 120 chars — satisfies minLen=100
        payload   = short_run + b"\x00" + long_run + b"\x00"
        (tmp_work_dir / "minlen_test.bin").write_bytes(payload)

        default = client.get(
            "/api/analyze/strings",
            params={"filePath": "minlen_test.bin", "minLen": 6},
        ).json()
        strict = client.get(
            "/api/analyze/strings",
            params={"filePath": "minlen_test.bin", "minLen": 100},
        ).json()
        assert strict["total"] < default["total"]

    def test_strings_missing_file_404(self, client: TestClient):
        """Non-existent file must return 404."""
        resp = client.get(
            "/api/analyze/strings",
            params={"filePath": "no_such_file.bin"},
        )
        assert resp.status_code == 404

    def test_strings_limit_cap(self, client: TestClient, tmp_work_dir):
        """
        With limit=3 the response must contain at most 3 strings regardless of
        how many exist in the binary.
        """
        # Many short ASCII runs separated by null bytes
        payload = b"\x00".join(b"STRING%02d" % i for i in range(20)) + b"\x00"
        (tmp_work_dir / "limit_test.bin").write_bytes(payload)
        data = client.get(
            "/api/analyze/strings",
            params={"filePath": "limit_test.bin", "minLen": 6, "limit": 3},
        ).json()
        assert data["total"] <= 3

    def test_strings_encoding_ascii(self, client: TestClient, tmp_work_dir):
        """All returned strings from an ASCII-only file should have encoding='ascii'."""
        payload = b"\x00\x01" + b"TESTING123" + b"\x00"
        (tmp_work_dir / "encoding_test.bin").write_bytes(payload)
        data = client.get(
            "/api/analyze/strings",
            params={"filePath": "encoding_test.bin", "minLen": 6},
        ).json()
        for entry in data["strings"]:
            assert entry["encoding"] == "ascii"

    def test_strings_offset_is_int(self, client: TestClient, tmp_work_dir):
        """offset must be a non-negative integer."""
        payload = b"\xff\xff" + b"OFFSETCHECK" + b"\x00"
        (tmp_work_dir / "offset_test.bin").write_bytes(payload)
        data = client.get(
            "/api/analyze/strings",
            params={"filePath": "offset_test.bin", "minLen": 6},
        ).json()
        assert len(data["strings"]) >= 1
        assert isinstance(data["strings"][0]["offset"], int)
        assert data["strings"][0]["offset"] >= 0
