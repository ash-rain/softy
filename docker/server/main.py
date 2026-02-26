"""
Softy Tools Backend — FastAPI server running inside Docker.
Provides REST + SSE API for binary analysis, decompilation, compilation,
and resource extraction. All file paths are relative to /work (volume mount).
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import os
import logging

from api import analyze, decompile, compile_api, resources, patch_api

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("softy")


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("Softy Tools Backend starting up")
    log.info(f"  WORK_DIR          = {os.environ.get('WORK_DIR', '/work')}")
    log.info(f"  GHIDRA_HOME       = {os.environ.get('GHIDRA_HOME', '/opt/ghidra')}")
    log.info(f"  GHIDRA_PROJECTS   = {os.environ.get('GHIDRA_PROJECTS_DIR', '/ghidra-projects')}")
    yield
    log.info("Softy Tools Backend shutting down")


app = FastAPI(
    title="Softy Tools Backend",
    version="0.1.0",
    description="Binary analysis, decompilation, compilation, and resource extraction",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze.router,     prefix="/api/analyze",     tags=["analyze"])
app.include_router(decompile.router,   prefix="/api/decompile",   tags=["decompile"])
app.include_router(compile_api.router, prefix="/api/compile",     tags=["compile"])
app.include_router(resources.router,   prefix="/api/resources",   tags=["resources"])
app.include_router(patch_api.router,   prefix="/api/patch",       tags=["patch"])


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}
