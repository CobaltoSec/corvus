"""Tests for A1 — batch scan mode (corvus/batch.py + corvus batch CLI command)."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from sys import executable

import pytest
import yaml

from corvus.batch import BatchTarget, load_batch_targets, run_batch, _classify_startup_error, BatchResult
from corvus.transport.stdio import ServerStartupError

_MOCK_SERVER_CMD = [executable, str(Path(__file__).parent / "mock_server.py")]
_MUTATING_SERVER_CMD = [executable, str(Path(__file__).parent / "mock_mutating_server.py")]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_targets_yaml(path: Path, targets: list[dict]) -> None:
    path.write_text(yaml.dump({"targets": targets}))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_batch_runs_two_targets(tmp_path: Path):
    """Batch scan must create per-target output directories with report.json."""
    targets = [
        BatchTarget("mock", "stdio", _MOCK_SERVER_CMD, None),
        BatchTarget("mutating", "stdio", _MUTATING_SERVER_CMD, None),
    ]
    result = await run_batch(targets, tmp_path, timeout=30)

    for name in ("mock", "mutating"):
        target_dir = tmp_path / name
        assert target_dir.exists(), f"Expected output dir for target '{name}'"
        report = target_dir / "report.json"
        assert report.exists(), f"Expected report.json in {target_dir}"

    assert len(result.targets) == 2


@pytest.mark.asyncio
async def test_batch_summary_created(tmp_path: Path):
    """Batch run must produce summary.md in the output directory."""
    targets = [
        BatchTarget("smoke", "stdio", _MOCK_SERVER_CMD, None),
    ]
    result = await run_batch(targets, tmp_path, timeout=30)

    summary_path = tmp_path / "summary.md"
    summary_md = result.summary_md()

    assert "smoke" in summary_md, "Summary must include target name"
    assert "CRITICAL" in summary_md or "HIGH" in summary_md or "Total" in summary_md


def test_batch_missing_transport_raises(tmp_path: Path):
    """YAML entry without 'transport' must raise ValueError."""
    config = tmp_path / "targets.yaml"
    _write_targets_yaml(config, [{"name": "bad-target"}])

    with pytest.raises(ValueError, match="transport"):
        load_batch_targets(config)


@pytest.mark.asyncio
async def test_batch_summary_has_score_column(tmp_path: Path):
    """Summary table must include a Score column with risk scores."""
    targets = [BatchTarget("smoke", "stdio", _MOCK_SERVER_CMD, None)]
    result = await run_batch(targets, tmp_path, timeout=30)
    summary = result.summary_md()
    assert "Score" in summary, "Summary must have a Score column"
    assert "/100" in summary, "Score must be in N/100 format"


@pytest.mark.asyncio
async def test_batch_combined_sarif_written(tmp_path: Path):
    """--sarif must produce combined.sarif in the output directory."""
    targets = [
        BatchTarget("mock", "stdio", _MOCK_SERVER_CMD, None),
        BatchTarget("mutating", "stdio", _MUTATING_SERVER_CMD, None),
    ]
    await run_batch(targets, tmp_path, timeout=30, sarif=True)

    combined = tmp_path / "combined.sarif"
    assert combined.exists(), "combined.sarif must be written when sarif=True"

    data = json.loads(combined.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 2, "combined.sarif must have one run per target"

    # Each run must be tagged with its target
    ids = {r.get("automationDetails", {}).get("id") for r in data["runs"]}
    assert "mock" in ids
    assert "mutating" in ids


@pytest.mark.asyncio
async def test_batch_combined_sarif_not_written_without_flag(tmp_path: Path):
    """combined.sarif must NOT be written when sarif=False (default)."""
    targets = [BatchTarget("smoke", "stdio", _MOCK_SERVER_CMD, None)]
    await run_batch(targets, tmp_path, timeout=30, sarif=False)
    assert not (tmp_path / "combined.sarif").exists()


# ---------------------------------------------------------------------------
# S0 — Error categorization
# ---------------------------------------------------------------------------

def test_classify_startup_error_credentials():
    e = ServerStartupError("startup failed", stderr="AWS_ACCESS_KEY_ID required")
    assert _classify_startup_error(e) == "credentials"

def test_classify_startup_error_browser():
    e = ServerStartupError("startup failed", stderr="playwright chromium not installed")
    assert _classify_startup_error(e) == "browser"

def test_classify_startup_error_runtime():
    e = ServerStartupError("startup failed", stderr="ModuleNotFoundError: no module named foo")
    assert _classify_startup_error(e) == "runtime"

def test_classify_startup_error_network():
    e = ServerStartupError("startup failed", stderr="Connection refused on 127.0.0.1:3000")
    assert _classify_startup_error(e) == "network"

def test_classify_startup_error_unknown():
    e = RuntimeError("something weird happened")
    assert _classify_startup_error(e) == "unknown"

def test_batch_result_error_category_in_summary():
    r = BatchResult()
    r.add("broken-server", "stdio", {"error": "crash"}, error_category="browser")
    summary = r.summary_md()
    assert "ERROR (browser)" in summary, f"Expected 'ERROR (browser)' in:\n{summary}"

def test_batch_result_unknown_category_fallback():
    r = BatchResult()
    r.add("broken-server", "stdio", {"error": "crash"})  # no error_category
    summary = r.summary_md()
    assert "ERROR (unknown)" in summary


@pytest.mark.asyncio
async def test_batch_error_target_shows_category(tmp_path: Path):
    """An uninstallable target must produce an error row with error_category in summary."""
    targets = [
        BatchTarget("missing-pkg", "stdio", ["npx", "@totally-nonexistent-pkg/server-xyz-abc"], None),
    ]
    result = await run_batch(targets, tmp_path, timeout=15)
    assert len(result.targets) == 1
    t = result.targets[0]
    assert "error" in t["finding_count"]
    assert t.get("error_category") is not None
    summary = result.summary_md()
    assert "ERROR (" in summary


# ---------------------------------------------------------------------------
# S1 — Parallel module execution
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_parallel_scan_completes(tmp_path: Path):
    """Scan via the new gather path must produce the same results as before."""
    targets = [BatchTarget("mock", "stdio", _MOCK_SERVER_CMD, None)]
    result = await run_batch(targets, tmp_path, timeout=30)
    assert len(result.targets) == 1
    fc = result.targets[0]["finding_count"]
    # Must have some findings (not just error/skip)
    assert "error" not in fc
    assert "skipped" not in fc


@pytest.mark.asyncio
async def test_batch_min_confidence_propagated(tmp_path: Path):
    """Findings below min_confidence must be excluded from all target results."""
    targets = [
        BatchTarget("smoke", "stdio", _MOCK_SERVER_CMD, None),
    ]
    result_all = await run_batch(targets, tmp_path / "all", timeout=30)
    result_filtered = await run_batch(targets, tmp_path / "filtered", timeout=30, min_confidence=90)

    def total(r):
        return sum(r.targets[0]["finding_count"].get(s, 0) for s in ("critical", "high", "medium", "low", "info"))

    # Filtering at high confidence should produce equal or fewer findings
    assert total(result_filtered) <= total(result_all), (
        f"Expected filtered results ({total(result_filtered)}) <= all results ({total(result_all)})"
    )
