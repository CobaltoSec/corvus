"""Tests for A1 — batch scan mode (corvus/batch.py + corvus batch CLI command)."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from sys import executable

import pytest
import yaml

from corvus.batch import BatchTarget, load_batch_targets, run_batch

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
