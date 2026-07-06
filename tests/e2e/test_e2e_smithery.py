"""E2E tests — Smithery MCP servers (HTTP remote + discover pipeline).

Run with:  pytest -m e2e -v tests/e2e/test_e2e_smithery.py --timeout=300
Excluded from CI default run (pytest -m "not e2e").

Targets used:
  arxiv  — https://arxiv.run.tools/mcp — Smithery-hosted, public no-auth,
            confirmed responding to MCP initialize.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from corvus.batch import BatchTarget, run_batch

from .conftest import CORVUS_ROOT, skip_no_npx

# ── Timeouts ─────────────────────────────────────────────────────────────────

_TIMEOUT = 60
_TGT_TIMEOUT = 180

# ── Helpers ───────────────────────────────────────────────────────────────────


def _assert_report(report_path: Path) -> dict:
    assert report_path.exists(), f"report.json not found: {report_path}"
    data = json.loads(report_path.read_text(encoding="utf-8"))
    assert "findings" in data, "report.json missing 'findings'"
    assert "target" in data, "report.json missing 'target'"
    assert isinstance(data["findings"], list)
    return data


def _assert_no_error(result_targets: list[dict], name: str) -> None:
    matched = [t for t in result_targets if t["name"] == name]
    assert matched, f"No result entry for target '{name}'"
    fc = matched[0]["finding_count"]
    if "error" in fc:
        msg = fc["error"] or "<timeout>"
        pytest.fail(f"Target '{name}' failed: {msg}")


# ── Tests ─────────────────────────────────────────────────────────────────────


@pytest.mark.e2e
@skip_no_npx
async def test_smithery_arxiv_http_scan(tmp_path: Path) -> None:
    """Scan arxiv Smithery remote server via HTTP transport — must enumerate tools."""
    targets = [BatchTarget("arxiv", "http", None, "https://arxiv.run.tools/mcp")]
    result = await run_batch(targets, tmp_path, timeout=_TIMEOUT, target_timeout=_TGT_TIMEOUT)

    _assert_no_error(result.targets, "arxiv")
    data = _assert_report(tmp_path / "arxiv" / "report.json")
    tools = data.get("surface", {}).get("tools", [])
    assert len(tools) >= 1, f"arxiv must expose ≥1 tool, got {len(tools)}"


@pytest.mark.e2e
@skip_no_npx
async def test_smithery_arxiv_http_report_structure(tmp_path: Path) -> None:
    """arxiv HTTP scan report must include modules_run and surface sections."""
    targets = [BatchTarget("arxiv", "http", None, "https://arxiv.run.tools/mcp")]
    result = await run_batch(targets, tmp_path, timeout=_TIMEOUT, target_timeout=_TGT_TIMEOUT)

    _assert_no_error(result.targets, "arxiv")
    data = _assert_report(tmp_path / "arxiv" / "report.json")
    assert "modules_run" in data, "report.json must include 'modules_run'"
    assert len(data["modules_run"]) >= 10, "must have run ≥10 modules"
    assert "surface" in data, "report.json must include 'surface' section"


@pytest.mark.e2e
@skip_no_npx
async def test_smithery_discover_produces_candidates(tmp_path: Path) -> None:
    """discover.py --source smithery must exit 0 and write a YAML with ≥1 target."""
    proc = subprocess.run(
        [
            sys.executable, str(CORVUS_ROOT / "scripts" / "discover.py"),
            "--source", "smithery",
            "--min-downloads", "0",
            "--output-dir", str(tmp_path),
            "--tier", "CS09-TEST",
        ],
        cwd=str(CORVUS_ROOT),
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert proc.returncode == 0, f"discover.py exited {proc.returncode}:\n{proc.stderr[-2000:]}"

    yamls = list(tmp_path.glob("candidates-*.yaml"))
    assert yamls, "No candidates-*.yaml written by discover.py"

    content = yamls[0].read_text(encoding="utf-8")
    assert "transport:" in content, "YAML must contain at least one target entry"
    assert "status: pending" in content, "Entries must have status: pending"
