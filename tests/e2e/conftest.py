"""E2E test configuration — real MCP servers, not mocks."""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

# ── Repository root ──────────────────────────────────────────────────────────

CORVUS_ROOT = Path(__file__).parent.parent.parent

# ── Absolute paths to local MCP server binaries ─────────────────────────────

KESTREL_EXE = Path(r"C:\Proyectos\Kestrel\.venv\Scripts\kestrel-mcp.exe")
LLAMASCOPE_EXE = Path(
    r"C:\Proyectos\CobaltoSec\sectors\red-team\llamascope-mcp\.venv\Scripts\llamascope-mcp.exe"
)
UVX_EXE = Path(r"C:\opsec\runner\.venv\Scripts\uvx.exe")


def _has(path: Path) -> bool:
    return path.exists()


def _has_cmd(name: str) -> bool:
    return shutil.which(name) is not None


# ── Skip markers ─────────────────────────────────────────────────────────────

skip_no_kestrel = pytest.mark.skipif(
    not _has(KESTREL_EXE),
    reason=f"kestrel-mcp not found at {KESTREL_EXE}",
)
skip_no_llamascope = pytest.mark.skipif(
    not _has(LLAMASCOPE_EXE),
    reason=f"llamascope-mcp not found at {LLAMASCOPE_EXE}",
)
skip_no_uvx = pytest.mark.skipif(
    not _has(UVX_EXE),
    reason=f"uvx not found at {UVX_EXE}",
)
skip_no_npx = pytest.mark.skipif(
    not _has_cmd("npx"),
    reason="npx not found in PATH",
)


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "e2e: end-to-end tests against real MCP servers (skipped in CI by default)",
    )
