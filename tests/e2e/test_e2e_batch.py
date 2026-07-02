"""E2E tests — corvus batch against real MCP servers.

Run with:  pytest -m e2e -v --timeout=300
Excluded from CI default run (pytest -m "not e2e").
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from corvus.batch import BatchTarget, run_batch

from .conftest import (
    KESTREL_EXE,
    LLAMASCOPE_EXE,
    UVX_EXE,
    skip_no_kestrel,
    skip_no_llamascope,
    skip_no_npx,
    skip_no_uvx,
)

# ── Shared timeouts ──────────────────────────────────────────────────────────

_TIMEOUT = 60        # seconds per MCP request
_TGT_TIMEOUT = 180   # seconds max per target
_TGT_TIMEOUT_NPX = 300  # npx targets may need to install deps on first run


# ── Helpers ──────────────────────────────────────────────────────────────────


def _assert_report(report_path: Path) -> dict:
    """Assert report.json exists, is valid JSON, and has the required keys."""
    assert report_path.exists(), f"report.json not found: {report_path}"
    data = json.loads(report_path.read_text(encoding="utf-8"))
    assert "findings" in data, "report.json missing 'findings' key"
    assert "target" in data, "report.json missing 'target' key"
    assert isinstance(data["findings"], list), "'findings' must be a list"
    return data


def _assert_no_error(result_targets: list[dict], name: str) -> None:
    """Assert a named target did not record an error."""
    matched = [t for t in result_targets if t["name"] == name]
    assert matched, f"No result entry for target '{name}'"
    fc = matched[0]["finding_count"]
    if "error" in fc:
        msg = fc["error"] or "<timeout — target_timeout exceeded>"
        pytest.fail(f"Target '{name}' failed: {msg}")


# ── Batch E2E tests ──────────────────────────────────────────────────────────


@pytest.mark.e2e
@skip_no_kestrel
@skip_no_llamascope
async def test_batch_kestrel_llamascope(tmp_path: Path) -> None:
    """Batch scan of kestrel + llamascope — both must produce valid report.json."""
    targets = [
        BatchTarget("kestrel", "stdio", [str(KESTREL_EXE)], None),
        BatchTarget("llamascope", "stdio", [str(LLAMASCOPE_EXE)], None),
    ]
    result = await run_batch(
        targets, tmp_path, timeout=_TIMEOUT, target_timeout=_TGT_TIMEOUT
    )

    assert len(result.targets) == 2
    for name in ("kestrel", "llamascope"):
        _assert_no_error(result.targets, name)
        _assert_report(tmp_path / name / "report.json")


@pytest.mark.e2e
@skip_no_kestrel
@skip_no_llamascope
async def test_batch_summary_has_score(tmp_path: Path) -> None:
    """Batch summary.md must contain Score column and N/100 values."""
    targets = [
        BatchTarget("kestrel", "stdio", [str(KESTREL_EXE)], None),
        BatchTarget("llamascope", "stdio", [str(LLAMASCOPE_EXE)], None),
    ]
    result = await run_batch(
        targets, tmp_path, timeout=_TIMEOUT, target_timeout=_TGT_TIMEOUT
    )

    summary = result.summary_md()
    assert "Score" in summary, "Summary must have a Score column"
    assert "/100" in summary, "Score column must contain N/100 values"
    assert "kestrel" in summary
    assert "llamascope" in summary


@pytest.mark.e2e
@skip_no_kestrel
@skip_no_llamascope
async def test_batch_combined_sarif(tmp_path: Path) -> None:
    """Batch with --sarif must produce combined.sarif with one run per target."""
    targets = [
        BatchTarget("kestrel", "stdio", [str(KESTREL_EXE)], None),
        BatchTarget("llamascope", "stdio", [str(LLAMASCOPE_EXE)], None),
    ]
    await run_batch(
        targets, tmp_path,
        timeout=_TIMEOUT, target_timeout=_TGT_TIMEOUT,
        sarif=True,
    )

    combined = tmp_path / "combined.sarif"
    assert combined.exists(), "combined.sarif must be written when sarif=True"

    data = json.loads(combined.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 2, "combined.sarif must have one run per target"

    ids = {r.get("automationDetails", {}).get("id") for r in data["runs"]}
    assert "kestrel" in ids
    assert "llamascope" in ids


@pytest.mark.e2e
@skip_no_kestrel
async def test_batch_kestrel_static_modules(tmp_path: Path) -> None:
    """kestrel-mcp scan must enumerate at least 1 tool and produce a parseable report."""
    targets = [BatchTarget("kestrel", "stdio", [str(KESTREL_EXE)], None)]
    await run_batch(targets, tmp_path, timeout=_TIMEOUT, target_timeout=_TGT_TIMEOUT)

    data = _assert_report(tmp_path / "kestrel" / "report.json")
    surface = data.get("surface", {})
    tools = surface.get("tools", [])
    assert len(tools) > 0, "kestrel-mcp must expose at least 1 tool"


@pytest.mark.e2e
@skip_no_llamascope
async def test_batch_llamascope_static_modules(tmp_path: Path) -> None:
    """llamascope-mcp scan must enumerate at least 1 tool and produce a parseable report."""
    targets = [BatchTarget("llamascope", "stdio", [str(LLAMASCOPE_EXE)], None)]
    await run_batch(targets, tmp_path, timeout=_TIMEOUT, target_timeout=_TGT_TIMEOUT)

    data = _assert_report(tmp_path / "llamascope" / "report.json")
    surface = data.get("surface", {})
    tools = surface.get("tools", [])
    assert len(tools) > 0, "llamascope-mcp must expose at least 1 tool"


@pytest.mark.e2e
@skip_no_uvx
async def test_batch_sqlite(tmp_path: Path) -> None:
    """mcp-server-sqlite via uvx must enumerate SQL tools and produce a report."""
    db_path = tmp_path / "test.db"
    targets = [
        BatchTarget(
            "sqlite",
            "stdio",
            [str(UVX_EXE), "mcp-server-sqlite", "--db-path", str(db_path)],
            None,
        )
    ]
    result = await run_batch(
        targets, tmp_path, timeout=_TIMEOUT, target_timeout=_TGT_TIMEOUT
    )

    _assert_no_error(result.targets, "sqlite")
    data = _assert_report(tmp_path / "sqlite" / "report.json")
    surface = data.get("surface", {})
    tool_names = [t.get("name", "") for t in surface.get("tools", [])]
    sql_tools = [n for n in tool_names if any(kw in n for kw in ("query", "sql", "table", "list"))]
    assert sql_tools, f"Expected SQL-related tools, got: {tool_names}"


@pytest.mark.e2e
@skip_no_npx
async def test_batch_everything(tmp_path: Path) -> None:
    """server-everything via npx must enumerate multiple tools."""
    targets = [
        BatchTarget(
            "everything",
            "stdio",
            ["npx", "@modelcontextprotocol/server-everything"],
            None,
        )
    ]
    result = await run_batch(
        targets, tmp_path,
        timeout=_TIMEOUT,
        target_timeout=_TGT_TIMEOUT_NPX,
    )

    _assert_no_error(result.targets, "everything")
    data = _assert_report(tmp_path / "everything" / "report.json")
    surface = data.get("surface", {})
    tools = surface.get("tools", [])
    assert len(tools) >= 5, f"server-everything must expose ≥5 tools, got {len(tools)}"


@pytest.mark.e2e
@skip_no_kestrel
@skip_no_llamascope
async def test_batch_skip_existing(tmp_path: Path) -> None:
    """skip_existing=True must not re-scan targets that already have report.json."""
    targets = [
        BatchTarget("kestrel", "stdio", [str(KESTREL_EXE)], None),
    ]
    # First run
    result1 = await run_batch(
        targets, tmp_path, timeout=_TIMEOUT, target_timeout=_TGT_TIMEOUT
    )
    report = tmp_path / "kestrel" / "report.json"
    mtime_before = report.stat().st_mtime

    # Second run with skip_existing
    result2 = await run_batch(
        targets, tmp_path,
        timeout=_TIMEOUT, target_timeout=_TGT_TIMEOUT,
        skip_existing=True,
    )

    mtime_after = report.stat().st_mtime
    assert mtime_after == mtime_before, "report.json must not be rewritten when skip_existing=True"

    skipped = result2.targets[0]["finding_count"]
    assert "skipped" in skipped, f"Expected skipped=True in finding_count, got {skipped}"
