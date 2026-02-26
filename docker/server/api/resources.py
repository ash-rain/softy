"""
/api/resources — Extract and list embedded resources from PE/ELF/Mach-O binaries.
Uses lief for parsing; returns a tree of resources with type/name/size/offset.
"""

import base64
import json
import os
from pathlib import Path
from typing import Optional

import lief
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()
WORK_DIR = os.environ.get("WORK_DIR", "/work")


class ResourceNode(BaseModel):
    id: str
    name: str
    type: str
    path: str
    size: int
    offset: int
    canPreview: bool
    canEdit: bool
    children: list["ResourceNode"] = []


ResourceNode.model_rebuild()


class ResourceDataResponse(BaseModel):
    id: str
    raw: str          # base64
    mimeType: str
    text: Optional[str] = None   # if text-like


def _resolve(rel: str) -> Path:
    p = Path(WORK_DIR) / rel
    if not p.exists():
        raise HTTPException(404, f"File not found: {rel}")
    return p


PE_TYPE_NAMES = {
    1:  "RT_CURSOR",
    2:  "RT_BITMAP",
    3:  "RT_ICON",
    4:  "RT_MENU",
    5:  "RT_DIALOG",
    6:  "RT_STRING",
    7:  "RT_FONTDIR",
    8:  "RT_FONT",
    9:  "RT_ACCELERATOR",
    10: "RT_RCDATA",
    11: "RT_MESSAGETABLE",
    12: "RT_GROUP_CURSOR",
    14: "RT_GROUP_ICON",
    16: "RT_VERSION",
    17: "RT_DLGINCLUDE",
    19: "RT_PLUGPLAY",
    20: "RT_VXD",
    21: "RT_ANICURSOR",
    22: "RT_ANIICON",
    23: "RT_HTML",
    24: "RT_MANIFEST",
}


def _pe_resources(binary: lief.PE.Binary) -> list[ResourceNode]:
    if not binary.has_resources:
        return []

    nodes: list[ResourceNode] = []
    idx = [0]

    def _walk(node, path: str = "", depth: int = 0):
        if depth > 3:
            return

        if node.is_directory:
            for child in node.childs:
                name = child.name if child.name else str(child.id)
                type_name = PE_TYPE_NAMES.get(child.id, name) if depth == 0 else name
                child_path = f"{path}/{type_name}" if path else type_name
                idx[0] += 1
                child_node = ResourceNode(
                    id=f"pe-{idx[0]}",
                    name=type_name,
                    type="directory",
                    path=child_path,
                    size=0,
                    offset=0,
                    canPreview=False,
                    canEdit=False,
                    children=[],
                )
                _walk(child, child_path, depth + 1)
                if child.is_data_entry:
                    # leaf
                    data = child.content
                    size = len(data) if data else 0
                    offset = child.offset_to_data if hasattr(child, 'offset_to_data') else 0
                    # Determine preview/edit capabilities
                    parent_type = path.split("/")[0] if path else ""
                    can_preview = parent_type in ("RT_ICON", "RT_BITMAP", "RT_GROUP_ICON", "RT_HTML", "RT_MANIFEST", "RT_STRING", "RT_VERSION")
                    can_edit    = parent_type in ("RT_STRING", "RT_VERSION", "RT_MANIFEST", "RT_RCDATA")
                    mime = _guess_mime(parent_type, data[:16] if data else b"")
                    child_node.type = "data"
                    child_node.size = size
                    child_node.offset = offset
                    child_node.canPreview = can_preview
                    child_node.canEdit = can_edit
                nodes.append(child_node)

    try:
        _walk(binary.resources)
    except Exception:
        pass

    return nodes


def _guess_mime(resource_type: str, header: bytes) -> str:
    if resource_type in ("RT_ICON", "RT_BITMAP", "RT_GROUP_ICON", "RT_CURSOR"):
        return "image/bmp"
    if resource_type == "RT_HTML":
        return "text/html"
    if resource_type in ("RT_MANIFEST",):
        return "application/xml"
    if resource_type in ("RT_STRING", "RT_VERSION"):
        return "text/plain"
    # Sniff
    if header[:4] == b"\x89PNG":
        return "image/png"
    if header[:2] in (b"BM",):
        return "image/bmp"
    if header[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if header[:4] == b"RIFF":
        return "audio/wav"
    return "application/octet-stream"


def _elf_resources(binary: lief.ELF.Binary) -> list[ResourceNode]:
    nodes = []
    for i, section in enumerate(binary.sections):
        name = section.name or f".section_{i}"
        try:
            content = bytes(section.content)
            size = len(content)
        except Exception:
            size = section.size
        nodes.append(ResourceNode(
            id=f"elf-{i}",
            name=name,
            type="section",
            path=name,
            size=size,
            offset=section.offset,
            canPreview=name in (".rodata", ".data", ".comment", ".note.gnu.build-id"),
            canEdit=False,
            children=[],
        ))
    return nodes


def _macho_resources(binary: lief.MachO.Binary) -> list[ResourceNode]:
    nodes = []
    for i, section in enumerate(binary.sections):
        name = f"{section.segment_name},{section.name}".strip(",")
        try:
            content = bytes(section.content)
            size = len(content)
        except Exception:
            size = section.size
        nodes.append(ResourceNode(
            id=f"macho-{i}",
            name=name,
            type="section",
            path=name,
            size=size,
            offset=section.offset,
            canPreview=False,
            canEdit=False,
            children=[],
        ))
    return nodes


@router.get("/list")
async def list_resources(filePath: str):
    path = _resolve(filePath)
    binary = lief.parse(str(path))
    if binary is None:
        raise HTTPException(422, "Could not parse binary")

    if isinstance(binary, lief.PE.Binary):
        nodes = _pe_resources(binary)
    elif isinstance(binary, lief.ELF.Binary):
        nodes = _elf_resources(binary)
    elif isinstance(binary, lief.MachO.Binary):
        nodes = _macho_resources(binary)
    elif isinstance(binary, lief.MachO.FatBinary):
        nodes = _macho_resources(binary.at(0))
    else:
        nodes = []

    return {"resources": [n.model_dump() for n in nodes]}


@router.get("/data")
async def get_resource_data(filePath: str, resourceId: str):
    """Return raw bytes (base64) for a specific resource."""
    path = _resolve(filePath)
    binary = lief.parse(str(path))
    if binary is None:
        raise HTTPException(422, "Could not parse binary")

    # For ELF: resourceId = "elf-{index}"
    if isinstance(binary, lief.ELF.Binary) and resourceId.startswith("elf-"):
        idx = int(resourceId.split("-")[1])
        sections = list(binary.sections)
        if idx >= len(sections):
            raise HTTPException(404, "Section not found")
        content = bytes(sections[idx].content)
        is_text = all(32 <= b <= 126 or b in (9, 10, 13) for b in content[:256])
        return ResourceDataResponse(
            id=resourceId,
            raw=base64.b64encode(content).decode(),
            mimeType="text/plain" if is_text else "application/octet-stream",
            text=content.decode("utf-8", errors="replace") if is_text else None,
        )

    raise HTTPException(404, "Resource not found or extraction not supported for this format")
