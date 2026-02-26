"""
Tests for /api/decompile endpoints:
  POST /api/decompile/quick    — synchronous r2-based analysis
  POST /api/decompile/start    — start async decompilation, get streamId
  GET  /api/decompile/stream/{id} — SSE stream of decompiled functions
  POST /api/decompile/disasm   — disassemble at address

Strategy:
- /quick and /start tests run against the real r2pipe / radare2 tool.
  They are skipped if radare2 is not installed.
- Ghidra tests mock the filesystem check for the analyzeHeadless binary so
  that the backend falls back to r2 automatically — this avoids requiring a
  real Ghidra installation.
- SSE stream tests use TestClient's streaming support.
"""

import json
import os
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Skip guard
# ---------------------------------------------------------------------------

_R2_AVAILABLE = shutil.which("radare2") is not None or shutil.which("r2") is not None

skip_no_r2 = pytest.mark.skipif(
    not _R2_AVAILABLE,
    reason="radare2 not installed — decompile tests require the Docker environment",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _collect_sse_events(resp) -> list[dict]:
    """
    Parse an SSE response body into a list of decoded JSON event dicts.
    TestClient streams the body as text; each non-empty 'data: ...' line is
    a JSON event.
    """
    events = []
    for line in resp.text.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            payload = line[len("data:"):].strip()
            if payload:
                try:
                    events.append(json.loads(payload))
                except json.JSONDecodeError:
                    pass
    return events


# ---------------------------------------------------------------------------
# POST /api/decompile/quick
# ---------------------------------------------------------------------------

class TestQuickAnalysis:

    @skip_no_r2
    def test_quick_status_200(self, client: TestClient, hello_elf: str):
        """Quick analysis of a valid ELF must return HTTP 200."""
        resp = client.post("/api/decompile/quick", json={"filePath": hello_elf})
        assert resp.status_code == 200, resp.text

    @skip_no_r2
    def test_quick_functions_is_list(self, client: TestClient, hello_elf: str):
        """functions key must be a list (possibly empty for a tiny binary)."""
        data = client.post("/api/decompile/quick", json={"filePath": hello_elf}).json()
        assert isinstance(data["functions"], list)

    @skip_no_r2
    def test_quick_imports_is_list(self, client: TestClient, hello_elf: str):
        """imports key must be a list."""
        data = client.post("/api/decompile/quick", json={"filePath": hello_elf}).json()
        assert isinstance(data["imports"], list)

    @skip_no_r2
    def test_quick_exports_is_list(self, client: TestClient, hello_elf: str):
        """exports key must be a list."""
        data = client.post("/api/decompile/quick", json={"filePath": hello_elf}).json()
        assert isinstance(data["exports"], list)

    @skip_no_r2
    def test_quick_sections_is_list(self, client: TestClient, hello_elf: str):
        """sections key must be a list."""
        data = client.post("/api/decompile/quick", json={"filePath": hello_elf}).json()
        assert isinstance(data["sections"], list)

    @skip_no_r2
    def test_quick_info_is_dict(self, client: TestClient, hello_elf: str):
        """info key must be a dict."""
        data = client.post("/api/decompile/quick", json={"filePath": hello_elf}).json()
        assert isinstance(data["info"], dict)

    @skip_no_r2
    def test_quick_response_keys(self, client: TestClient, hello_elf: str):
        """All expected top-level keys must be present in the quick analysis response."""
        required = {"functions", "imports", "exports", "sections", "info"}
        data = client.post("/api/decompile/quick", json={"filePath": hello_elf}).json()
        assert required.issubset(data.keys())

    def test_quick_missing_file_404(self, client: TestClient):
        """Non-existent file must return 404."""
        resp = client.post("/api/decompile/quick", json={"filePath": "no_such.elf"})
        assert resp.status_code == 404

    def test_quick_missing_file_detail(self, client: TestClient):
        """404 detail must mention the requested file."""
        resp = client.post("/api/decompile/quick", json={"filePath": "ghost.bin"})
        assert "ghost.bin" in resp.json().get("detail", "")

    def test_quick_empty_body_422(self, client: TestClient):
        """Missing filePath must return 422."""
        resp = client.post("/api/decompile/quick", json={})
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# POST /api/decompile/start
# ---------------------------------------------------------------------------

class TestDecompileStart:

    def _patch_ghidra_absent(self):
        """Return a context manager that makes Ghidra's analyzeHeadless appear absent."""
        # The code does: Path(GHIDRA_HOME) / "support" / "analyzeHeadless").exists()
        # We patch Path.exists to return False for that specific path.
        return patch("pathlib.Path.exists", return_value=False)

    @skip_no_r2
    def test_start_r2_status_200(self, client: TestClient, hello_elf: str):
        """Starting an r2 decompilation job must return HTTP 200."""
        resp = client.post("/api/decompile/start", json={
            "filePath": hello_elf,
            "projectId": "test_project",
            "backend": "r2",
        })
        assert resp.status_code == 200, resp.text

    @skip_no_r2
    def test_start_r2_returns_stream_id(self, client: TestClient, hello_elf: str):
        """Response must include a non-empty streamId."""
        data = client.post("/api/decompile/start", json={
            "filePath": hello_elf,
            "projectId": "test_project",
            "backend": "r2",
        }).json()
        assert "streamId" in data
        assert isinstance(data["streamId"], str)
        assert len(data["streamId"]) > 0

    @skip_no_r2
    def test_start_r2_backend_field(self, client: TestClient, hello_elf: str):
        """When r2 is requested (and Ghidra absent), response backend must be 'r2'."""
        data = client.post("/api/decompile/start", json={
            "filePath": hello_elf,
            "projectId": "test_project",
            "backend": "r2",
        }).json()
        assert data["backend"] == "r2"

    @skip_no_r2
    def test_start_ghidra_falls_back_to_r2(self, client: TestClient, hello_elf: str):
        """
        When ghidra backend is requested but analyzeHeadless does not exist,
        the response must report backend='r2' (graceful fallback).
        """
        import api.decompile as _decompile_mod
        with patch.object(Path, "exists", return_value=False):
            data = client.post("/api/decompile/start", json={
                "filePath": hello_elf,
                "projectId": "ghidra_test",
                "backend": "ghidra",
            }).json()
        assert data["backend"] == "r2"

    def test_start_missing_file_404(self, client: TestClient):
        """Non-existent file must return 404."""
        resp = client.post("/api/decompile/start", json={
            "filePath": "phantom.elf",
            "projectId": "p1",
            "backend": "r2",
        })
        assert resp.status_code == 404

    def test_start_empty_body_422(self, client: TestClient):
        """Missing required fields must return 422."""
        resp = client.post("/api/decompile/start", json={})
        assert resp.status_code == 422

    def test_start_missing_project_id_422(self, client: TestClient, hello_elf: str):
        """Missing projectId must return 422."""
        resp = client.post("/api/decompile/start", json={
            "filePath": hello_elf,
            "backend": "r2",
        })
        assert resp.status_code == 422

    @skip_no_r2
    def test_start_unique_stream_ids(self, client: TestClient, hello_elf: str):
        """Each call to /start must return a distinct streamId."""
        ids = set()
        for _ in range(3):
            data = client.post("/api/decompile/start", json={
                "filePath": hello_elf,
                "projectId": "uniqueness_test",
                "backend": "r2",
            }).json()
            ids.add(data["streamId"])
        assert len(ids) == 3


# ---------------------------------------------------------------------------
# GET /api/decompile/stream/{id}
# ---------------------------------------------------------------------------

class TestDecompileStream:

    def test_stream_not_found_404(self, client: TestClient):
        """Connecting to a non-existent streamId must return 404."""
        resp = client.get("/api/decompile/stream/nonexistent-stream-id-xyz")
        assert resp.status_code == 404

    def test_stream_not_found_detail(self, client: TestClient):
        """404 response must include a detail message."""
        resp = client.get("/api/decompile/stream/does-not-exist-abc")
        assert resp.json().get("detail") is not None

    @skip_no_r2
    def test_stream_r2_complete_event(self, client: TestClient, hello_elf: str):
        """
        After starting an r2 decompilation and consuming the SSE stream to
        completion, there must be at least one 'complete' event.
        """
        # Start the job
        start_data = client.post("/api/decompile/start", json={
            "filePath": hello_elf,
            "projectId": "stream_complete_test",
            "backend": "r2",
        }).json()
        stream_id = start_data["streamId"]

        # Consume the stream
        with client.get(f"/api/decompile/stream/{stream_id}", stream=True) as resp:
            assert resp.status_code == 200
            events = _collect_sse_events(resp)

        event_types = [e.get("type") for e in events]
        assert "complete" in event_types, (
            f"Expected 'complete' event, got types: {event_types}"
        )

    @skip_no_r2
    def test_stream_r2_complete_event_has_total(self, client: TestClient, hello_elf: str):
        """The 'complete' event must have a 'total' key."""
        start_data = client.post("/api/decompile/start", json={
            "filePath": hello_elf,
            "projectId": "stream_total_test",
            "backend": "r2",
        }).json()
        stream_id = start_data["streamId"]

        with client.get(f"/api/decompile/stream/{stream_id}", stream=True) as resp:
            events = _collect_sse_events(resp)

        complete_events = [e for e in events if e.get("type") == "complete"]
        assert len(complete_events) >= 1
        assert "total" in complete_events[0]
        assert isinstance(complete_events[0]["total"], int)

    @skip_no_r2
    def test_stream_r2_function_events(self, client: TestClient, hello_elf: str):
        """
        If r2 identifies any functions, they must appear as 'function' events.
        Our minimal ELF is very small so it may have 0 functions — that is
        acceptable; we only check the shape when functions ARE present.
        """
        start_data = client.post("/api/decompile/start", json={
            "filePath": hello_elf,
            "projectId": "stream_fn_test",
            "backend": "r2",
        }).json()
        stream_id = start_data["streamId"]

        with client.get(f"/api/decompile/stream/{stream_id}", stream=True) as resp:
            events = _collect_sse_events(resp)

        fn_events = [e for e in events if e.get("type") == "function"]
        for fn in fn_events:
            assert "address" in fn
            assert "name" in fn
            assert "cCode" in fn

    @skip_no_r2
    def test_stream_consumed_once(self, client: TestClient, hello_elf: str):
        """
        After a stream is fully consumed, the second GET on the same streamId
        must return 404 (the session is cleaned up after the sentinel).
        """
        start_data = client.post("/api/decompile/start", json={
            "filePath": hello_elf,
            "projectId": "stream_once_test",
            "backend": "r2",
        }).json()
        stream_id = start_data["streamId"]

        # First consume
        with client.get(f"/api/decompile/stream/{stream_id}", stream=True) as resp:
            _collect_sse_events(resp)  # drain

        # Second attempt — session should be gone
        resp2 = client.get(f"/api/decompile/stream/{stream_id}")
        assert resp2.status_code == 404


# ---------------------------------------------------------------------------
# POST /api/decompile/disasm
# ---------------------------------------------------------------------------

class TestDisassemble:

    @skip_no_r2
    def test_disasm_status_200(self, client: TestClient, hello_elf: str):
        """Disassemble request for a valid file must return 200."""
        resp = client.post(
            "/api/decompile/disasm",
            json={"filePath": hello_elf},
            params={"address": 0, "count": 10},
        )
        assert resp.status_code == 200, resp.text

    @skip_no_r2
    def test_disasm_ops_is_list(self, client: TestClient, hello_elf: str):
        """ops key must be a list."""
        data = client.post(
            "/api/decompile/disasm",
            json={"filePath": hello_elf},
            params={"address": 0, "count": 10},
        ).json()
        assert isinstance(data["ops"], list)

    def test_disasm_missing_file_404(self, client: TestClient):
        """Non-existent file must return 404."""
        resp = client.post(
            "/api/decompile/disasm",
            json={"filePath": "missing.elf"},
            params={"address": 0, "count": 5},
        )
        assert resp.status_code == 404

    def test_disasm_empty_body_422(self, client: TestClient):
        """Missing filePath must return 422."""
        resp = client.post("/api/decompile/disasm", json={})
        assert resp.status_code == 422
