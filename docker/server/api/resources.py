"""
/api/resources — Extract and list embedded resources from PE/ELF/Mach-O binaries.
"""

import base64
import os
from pathlib import Path
from typing import Optional

import lief
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router   = APIRouter()
WORK_DIR = os.environ.get("WORK_DIR", "/work")


class ResourceNode(BaseModel):
    id:         str
    name:       str
    type:       str
    path:       str
    size:       int
    offset:     int
    canPreview: bool
    canEdit:    bool
    children:   list["ResourceNode"] = []


ResourceNode.model_rebuild()


class ResourceDataResponse(BaseModel):
    id:       str
    raw:      str            # base64
    mimeType: str
    text:     Optional[str] = None   # decoded text if text-like


def _resolve(rel: str) -> Path:
    work = Path(WORK_DIR).resolve()
    p    = (work / rel).resolve()
    if not p.is_relative_to(work):
        raise HTTPException(400, "Path traversal not allowed")
    if not p.exists():
        raise HTTPException(404, f"File not found: {rel}")
    return p


PE_TYPE_NAMES = {
    1: "RT_CURSOR", 2: "RT_BITMAP", 3: "RT_ICON", 4: "RT_MENU",
    5: "RT_DIALOG", 6: "RT_STRING", 7: "RT_FONTDIR", 8: "RT_FONT",
    9: "RT_ACCELERATOR", 10: "RT_RCDATA", 11: "RT_MESSAGETABLE",
    12: "RT_GROUP_CURSOR", 14: "RT_GROUP_ICON", 16: "RT_VERSION",
    17: "RT_DLGINCLUDE", 19: "RT_PLUGPLAY", 20: "RT_VXD",
    21: "RT_ANICURSOR", 22: "RT_ANIICON", 23: "RT_HTML", 24: "RT_MANIFEST",
}

PREVIEWABLE = {"RT_ICON", "RT_BITMAP", "RT_GROUP_ICON", "RT_HTML", "RT_MANIFEST",
               "RT_STRING", "RT_VERSION"}
EDITABLE    = {"RT_STRING", "RT_VERSION", "RT_MANIFEST", "RT_RCDATA"}


def _guess_mime(resource_type: str, header: bytes) -> str:
    if resource_type in ("RT_ICON", "RT_BITMAP", "RT_GROUP_ICON", "RT_CURSOR"):
        return "image/bmp"
    if resource_type == "RT_HTML":    return "text/html"
    if resource_type == "RT_MANIFEST": return "application/xml"
    if resource_type in ("RT_STRING", "RT_VERSION"): return "text/plain"
    if len(header) >= 4:
        if header[:4] == b"\x89PNG": return "image/png"
        if header[:2] == b"BM":      return "image/bmp"
        if header[:3] == b"\xff\xd8\xff": return "image/jpeg"
        if header[:4] == b"RIFF":   return "audio/wav"
    return "application/octet-stream"


def _pe_resources(binary: lief.PE.Binary) -> list[ResourceNode]:
    if not binary.has_resources:
        return []

    nodes: list[ResourceNode] = []
    # Store data-leaf content indexed by node id for /data endpoint
    _pe_data_cache: dict[str, bytes] = {}
    counter = [0]

    def _walk(node, path: str, depth: int, parent_type: str) -> list[ResourceNode]:
        if depth > 4:
            return []
        result = []
        if not node.is_directory:
            return result
        for child in node.childs:
            counter[0] += 1
            child_id   = f"pe-{counter[0]}"
            name       = child.name if child.name else str(child.id)
            type_name  = PE_TYPE_NAMES.get(child.id, name) if depth == 0 else name
            child_path = f"{path}/{type_name}" if path else type_name

            if child.is_data_entry:
                # Leaf node
                try:
                    data   = bytes(child.content)
                    size   = len(data)
                    offset = getattr(child, "offset_to_data", 0)
                except Exception:
                    data   = b""
                    size   = 0
                    offset = 0
                can_preview = parent_type in PREVIEWABLE
                can_edit    = parent_type in EDITABLE
                result.append(ResourceNode(
                    id=child_id, name=name, type="data",
                    path=child_path, size=size, offset=offset,
                    canPreview=can_preview, canEdit=can_edit,
                    children=[],
                ))
                _pe_data_cache[child_id] = data
            else:
                # Directory node — recurse
                children = _walk(child, child_path, depth + 1, type_name if depth == 0 else parent_type)
                result.append(ResourceNode(
                    id=child_id, name=type_name, type="directory",
                    path=child_path, size=0, offset=0,
                    canPreview=False, canEdit=False,
                    children=children,
                ))

        return result

    try:
        nodes = _walk(binary.resources, "", 0, "")
    except Exception:
        pass

    # Attach cache to nodes for data retrieval
    # We stash it in a module-level dict keyed by filePath hash (set by caller)
    return nodes, _pe_data_cache  # type: ignore[return-value]


def _elf_resources(binary: lief.ELF.Binary) -> list[ResourceNode]:
    nodes = []
    for i, section in enumerate(binary.sections):
        name = section.name or f".section_{i}"
        try:
            size = len(bytes(section.content))
        except Exception:
            size = section.size
        nodes.append(ResourceNode(
            id=f"elf-{i}", name=name, type="section",
            path=name, size=size, offset=section.offset,
            canPreview=name in (".rodata", ".data", ".comment",
                                ".note.gnu.build-id", ".gnu_debuglink"),
            canEdit=False, children=[],
        ))
    return nodes


def _macho_resources(binary: lief.MachO.Binary) -> list[ResourceNode]:
    nodes = []
    for i, section in enumerate(binary.sections):
        name = f"{section.segment_name},{section.name}".strip(",")
        try:
            size = len(bytes(section.content))
        except Exception:
            size = section.size
        nodes.append(ResourceNode(
            id=f"macho-{i}", name=name, type="section",
            path=name, size=size, offset=section.offset,
            canPreview=section.name in ("__cstring", "__const", "__text"),
            canEdit=False, children=[],
        ))
    return nodes


# Module-level PE data cache: file_hash → {node_id: bytes}
_pe_cache: dict[str, dict[str, bytes]] = {}


@router.get("/list")
async def list_resources(filePath: str):
    path   = _resolve(filePath)
    binary = lief.parse(str(path))
    if binary is None:
        raise HTTPException(422, "Could not parse binary")

    if isinstance(binary, lief.MachO.FatBinary):
        binary = binary.at(0)

    if isinstance(binary, lief.PE.Binary):
        nodes, cache = _pe_resources(binary)  # type: ignore[misc]
        file_key = str(path)
        _pe_cache[file_key] = cache
    elif isinstance(binary, lief.ELF.Binary):
        nodes = _elf_resources(binary)
    elif isinstance(binary, lief.MachO.Binary):
        nodes = _macho_resources(binary)
    else:
        nodes = []

    return {"resources": [n.model_dump() for n in nodes]}


@router.get("/data")
async def get_resource_data(filePath: str, resourceId: str):
    """Return raw bytes (base64) for a specific resource."""
    path   = _resolve(filePath)
    binary = lief.parse(str(path))
    if binary is None:
        raise HTTPException(422, "Could not parse binary")

    if isinstance(binary, lief.MachO.FatBinary):
        binary = binary.at(0)

    # ELF section data
    if isinstance(binary, lief.ELF.Binary) and resourceId.startswith("elf-"):
        try:
            idx      = int(resourceId.split("-")[1])
            sections = list(binary.sections)
            if idx >= len(sections):
                raise HTTPException(404, "Section not found")
            content  = bytes(sections[idx].content)
            is_text  = all(32 <= b <= 126 or b in (9, 10, 13) for b in content[:512])
            return ResourceDataResponse(
                id=resourceId,
                raw=base64.b64encode(content).decode(),
                mimeType="text/plain" if is_text else "application/octet-stream",
                text=content.decode("utf-8", errors="replace") if is_text else None,
            )
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(500, str(e))

    # MachO section data
    if isinstance(binary, lief.MachO.Binary) and resourceId.startswith("macho-"):
        try:
            idx      = int(resourceId.split("-")[1])
            sections = list(binary.sections)
            if idx >= len(sections):
                raise HTTPException(404, "Section not found")
            content  = bytes(sections[idx].content)
            is_text  = all(32 <= b <= 126 or b in (9, 10, 13) for b in content[:512])
            return ResourceDataResponse(
                id=resourceId,
                raw=base64.b64encode(content).decode(),
                mimeType="text/plain" if is_text else "application/octet-stream",
                text=content.decode("utf-8", errors="replace") if is_text else None,
            )
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(500, str(e))

    # PE resource data (from cache populated by /list)
    if isinstance(binary, lief.PE.Binary) and resourceId.startswith("pe-"):
        file_key = str(path)
        cache    = _pe_cache.get(file_key)
        if cache is None:
            # Re-run list to populate cache
            _, cache = _pe_resources(binary)  # type: ignore[misc]
            _pe_cache[file_key] = cache
        content = cache.get(resourceId)
        if content is None:
            raise HTTPException(404, "PE resource not found")
        header   = content[:16]
        mime     = _guess_mime("", header)
        is_text  = mime.startswith("text/")
        return ResourceDataResponse(
            id=resourceId,
            raw=base64.b64encode(content).decode(),
            mimeType=mime,
            text=content.decode("utf-8", errors="replace") if is_text else None,
        )

    raise HTTPException(404, "Resource not found or format not supported")
