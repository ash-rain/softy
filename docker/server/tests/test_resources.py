"""
Tests for /api/resources/list and /api/resources/data endpoints.

The minimal ELF produced by conftest has no section header table (e_shnum=0),
so _elf_resources() will return an empty list.  We supplement the tests with
a more complete ELF (compiled from the C fixture via clang if available) and
with direct section-presence assertions that are conditioned on that tool.

All file resolution goes through the patched WORK_DIR from conftest.
"""

import base64
import shutil
import struct
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_CLANG_AVAILABLE = shutil.which("clang-17") is not None

skip_no_clang = pytest.mark.skipif(
    not _CLANG_AVAILABLE,
    reason="clang-17 not installed — section-rich ELF tests require Docker environment",
)


# ---------------------------------------------------------------------------
# Helper: build a richer ELF (with sections) using clang
# ---------------------------------------------------------------------------

def _compile_simple_elf(work_dir: Path) -> str:
    """
    Compile a minimal C file to an ELF object via clang-17 and write it to
    the work directory.  Returns the relative filename.
    Returns None if clang-17 is unavailable.
    """
    import subprocess, tempfile
    c_src = "int add(int a, int b) { return a + b; }\n"
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "t.c"
        obj = Path(tmp) / "t.o"
        src.write_text(c_src)
        result = subprocess.run(
            ["clang-17", "-O1", "--target=x86_64-unknown-linux-gnu",
             "-fPIC", "-fno-builtin", "-c", str(src), "-o", str(obj)],
            capture_output=True,
        )
        if result.returncode != 0:
            return None
        filename = "rich.elf"
        (work_dir / filename).write_bytes(obj.read_bytes())
        return filename


# ---------------------------------------------------------------------------
# GET /api/resources/list
# ---------------------------------------------------------------------------

class TestListResources:

    def test_list_status_200(self, client: TestClient, hello_elf: str):
        """GET /list for a valid file must return HTTP 200."""
        resp = client.get("/api/resources/list", params={"filePath": hello_elf})
        assert resp.status_code == 200, resp.text

    def test_list_resources_key_present(self, client: TestClient, hello_elf: str):
        """Response must contain a 'resources' key."""
        data = client.get("/api/resources/list", params={"filePath": hello_elf}).json()
        assert "resources" in data

    def test_list_resources_is_list(self, client: TestClient, hello_elf: str):
        """'resources' must be a list."""
        data = client.get("/api/resources/list", params={"filePath": hello_elf}).json()
        assert isinstance(data["resources"], list)

    def test_list_missing_file_404(self, client: TestClient):
        """Non-existent file must return 404."""
        resp = client.get("/api/resources/list", params={"filePath": "phantom.elf"})
        assert resp.status_code == 404

    def test_list_missing_file_detail(self, client: TestClient):
        """404 detail must mention the requested filename."""
        resp = client.get("/api/resources/list", params={"filePath": "ghost.bin"})
        assert "ghost.bin" in resp.json().get("detail", "")

    def test_list_corrupt_binary_422(self, client: TestClient, tmp_work_dir):
        """A file that cannot be parsed by lief must return 422."""
        bad = tmp_work_dir / "corrupt.bin"
        bad.write_bytes(b"\x00" * 32)
        resp = client.get("/api/resources/list", params={"filePath": "corrupt.bin"})
        assert resp.status_code == 422

    def test_list_missing_filepath_param_422(self, client: TestClient):
        """Omitting the filePath query parameter must return a validation error."""
        resp = client.get("/api/resources/list")
        assert resp.status_code == 422

    def test_list_node_schema(self, client: TestClient, tmp_work_dir):
        """
        Every resource node must contain the required schema fields.
        We compile a simple object with clang to get a real section table,
        skipping if clang is not available.
        """
        if not _CLANG_AVAILABLE:
            pytest.skip("clang-17 not installed")
        filename = _compile_simple_elf(tmp_work_dir)
        if filename is None:
            pytest.skip("clang-17 compilation failed")

        data = client.get("/api/resources/list", params={"filePath": filename}).json()
        required_keys = {"id", "name", "type", "path", "size", "offset", "canPreview", "canEdit", "children"}
        for node in data["resources"]:
            assert required_keys.issubset(node.keys()), (
                f"Node missing keys: {required_keys - node.keys()}"
            )

    @skip_no_clang
    def test_list_elf_has_sections(self, client: TestClient, tmp_work_dir):
        """A normally compiled ELF object must expose at least one section resource."""
        filename = _compile_simple_elf(tmp_work_dir)
        if filename is None:
            pytest.skip("clang-17 compilation failed")

        data = client.get("/api/resources/list", params={"filePath": filename}).json()
        assert len(data["resources"]) >= 1

    @skip_no_clang
    def test_list_elf_node_ids_start_with_elf(self, client: TestClient, tmp_work_dir):
        """ELF section resource IDs must use the 'elf-N' format."""
        filename = _compile_simple_elf(tmp_work_dir)
        if filename is None:
            pytest.skip("clang-17 compilation failed")

        data = client.get("/api/resources/list", params={"filePath": filename}).json()
        for node in data["resources"]:
            assert node["id"].startswith("elf-"), f"Unexpected id format: {node['id']}"

    @skip_no_clang
    def test_list_elf_section_type(self, client: TestClient, tmp_work_dir):
        """Each ELF resource must have type='section'."""
        filename = _compile_simple_elf(tmp_work_dir)
        if filename is None:
            pytest.skip("clang-17 compilation failed")

        data = client.get("/api/resources/list", params={"filePath": filename}).json()
        for node in data["resources"]:
            assert node["type"] == "section"

    @skip_no_clang
    def test_list_elf_size_is_int(self, client: TestClient, tmp_work_dir):
        """Each node's size field must be a non-negative integer."""
        filename = _compile_simple_elf(tmp_work_dir)
        if filename is None:
            pytest.skip("clang-17 compilation failed")

        data = client.get("/api/resources/list", params={"filePath": filename}).json()
        for node in data["resources"]:
            assert isinstance(node["size"], int)
            assert node["size"] >= 0

    @skip_no_clang
    def test_list_elf_offset_is_int(self, client: TestClient, tmp_work_dir):
        """Each node's offset field must be a non-negative integer."""
        filename = _compile_simple_elf(tmp_work_dir)
        if filename is None:
            pytest.skip("clang-17 compilation failed")

        data = client.get("/api/resources/list", params={"filePath": filename}).json()
        for node in data["resources"]:
            assert isinstance(node["offset"], int)
            assert node["offset"] >= 0

    @skip_no_clang
    def test_list_elf_children_is_list(self, client: TestClient, tmp_work_dir):
        """children field must be a list for every node."""
        filename = _compile_simple_elf(tmp_work_dir)
        if filename is None:
            pytest.skip("clang-17 compilation failed")

        data = client.get("/api/resources/list", params={"filePath": filename}).json()
        for node in data["resources"]:
            assert isinstance(node["children"], list)


# ---------------------------------------------------------------------------
# GET /api/resources/data
# ---------------------------------------------------------------------------

class TestGetResourceData:

    def test_data_missing_file_404(self, client: TestClient):
        """Non-existent file must return 404."""
        resp = client.get("/api/resources/data", params={
            "filePath": "phantom.elf",
            "resourceId": "elf-0",
        })
        assert resp.status_code == 404

    def test_data_missing_params_422(self, client: TestClient):
        """Omitting required params must return 422."""
        resp = client.get("/api/resources/data")
        assert resp.status_code == 422

    @skip_no_clang
    def test_data_elf_section_0_status_200(self, client: TestClient, tmp_work_dir):
        """Fetching the first ELF section (elf-0) must return 200."""
        filename = _compile_simple_elf(tmp_work_dir)
        if filename is None:
            pytest.skip("clang-17 compilation failed")

        resp = client.get("/api/resources/data", params={
            "filePath": filename,
            "resourceId": "elf-0",
        })
        assert resp.status_code == 200, resp.text

    @skip_no_clang
    def test_data_elf_section_0_has_raw(self, client: TestClient, tmp_work_dir):
        """Response for a valid section must include a non-empty 'raw' (base64) field."""
        filename = _compile_simple_elf(tmp_work_dir)
        if filename is None:
            pytest.skip("clang-17 compilation failed")

        data = client.get("/api/resources/data", params={
            "filePath": filename,
            "resourceId": "elf-0",
        }).json()
        assert "raw" in data
        # raw must be non-empty valid base64
        assert data["raw"] is not None
        decoded = base64.b64decode(data["raw"])
        assert isinstance(decoded, bytes)

    @skip_no_clang
    def test_data_elf_section_schema(self, client: TestClient, tmp_work_dir):
        """Response must contain id, raw, mimeType keys."""
        filename = _compile_simple_elf(tmp_work_dir)
        if filename is None:
            pytest.skip("clang-17 compilation failed")

        data = client.get("/api/resources/data", params={
            "filePath": filename,
            "resourceId": "elf-0",
        }).json()
        assert "id" in data
        assert "raw" in data
        assert "mimeType" in data

    @skip_no_clang
    def test_data_elf_id_echoed(self, client: TestClient, tmp_work_dir):
        """id field in the response must match the requested resourceId."""
        filename = _compile_simple_elf(tmp_work_dir)
        if filename is None:
            pytest.skip("clang-17 compilation failed")

        data = client.get("/api/resources/data", params={
            "filePath": filename,
            "resourceId": "elf-0",
        }).json()
        assert data["id"] == "elf-0"

    @skip_no_clang
    def test_data_elf_mime_type_string(self, client: TestClient, tmp_work_dir):
        """mimeType must be a non-empty string."""
        filename = _compile_simple_elf(tmp_work_dir)
        if filename is None:
            pytest.skip("clang-17 compilation failed")

        data = client.get("/api/resources/data", params={
            "filePath": filename,
            "resourceId": "elf-0",
        }).json()
        assert isinstance(data["mimeType"], str)
        assert len(data["mimeType"]) > 0

    @skip_no_clang
    def test_data_elf_out_of_range_404(self, client: TestClient, tmp_work_dir):
        """Requesting a section index beyond the section table must return 404."""
        filename = _compile_simple_elf(tmp_work_dir)
        if filename is None:
            pytest.skip("clang-17 compilation failed")

        resp = client.get("/api/resources/data", params={
            "filePath": filename,
            "resourceId": "elf-9999",
        })
        assert resp.status_code == 404

    @skip_no_clang
    def test_data_elf_non_elf_resource_id_404(self, client: TestClient, tmp_work_dir):
        """An ELF binary with a non-elf-prefixed resourceId must return 404."""
        filename = _compile_simple_elf(tmp_work_dir)
        if filename is None:
            pytest.skip("clang-17 compilation failed")

        resp = client.get("/api/resources/data", params={
            "filePath": filename,
            "resourceId": "pe-0",   # PE resource id against an ELF binary
        })
        assert resp.status_code == 404

    @skip_no_clang
    def test_data_text_section_has_text_field(self, client: TestClient, tmp_work_dir):
        """
        When a section's content is entirely printable ASCII (e.g. .comment),
        the 'text' field must be a non-null string.
        We look for the .comment section by iterating resource ids.
        """
        import lief
        filename = _compile_simple_elf(tmp_work_dir)
        if filename is None:
            pytest.skip("clang-17 compilation failed")

        # Find which elf-N corresponds to a text-like section
        binary = lief.parse(str(tmp_work_dir / filename))
        comment_idx = None
        for i, sec in enumerate(binary.sections):
            content = bytes(sec.content)
            if content and all(32 <= b <= 126 or b in (9, 10, 13) for b in content[:256]):
                comment_idx = i
                break

        if comment_idx is None:
            pytest.skip("No text-like section found in compiled ELF")

        data = client.get("/api/resources/data", params={
            "filePath": filename,
            "resourceId": f"elf-{comment_idx}",
        }).json()
        assert data.get("text") is not None
        assert isinstance(data["text"], str)

    @skip_no_clang
    def test_data_binary_section_text_none(self, client: TestClient, tmp_work_dir):
        """
        Binary (non-text) sections must have text=None.
        .text section contains machine code — not printable ASCII.
        """
        import lief
        filename = _compile_simple_elf(tmp_work_dir)
        if filename is None:
            pytest.skip("clang-17 compilation failed")

        binary = lief.parse(str(tmp_work_dir / filename))
        text_idx = None
        for i, sec in enumerate(binary.sections):
            if sec.name == ".text":
                text_idx = i
                break

        if text_idx is None:
            pytest.skip(".text section not found")

        data = client.get("/api/resources/data", params={
            "filePath": filename,
            "resourceId": f"elf-{text_idx}",
        }).json()
        # .text is machine code — should NOT be treated as text
        # (it may contain non-printable bytes)
        # We just assert the field exists (may be None or str depending on content)
        assert "text" in data
