"""E2E timing tests — verify parallel module execution is actually faster.

Run with:  pytest -m e2e tests/e2e/test_e2e_parallel.py -v
Excluded from CI default run (pytest -m "not e2e").
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from corvus.batch import BatchTarget, run_batch

from .conftest import skip_no_npx

_TIMEOUT = 60
_TGT_TIMEOUT = 300


@pytest.mark.e2e
@skip_no_npx
async def test_parallel_scan_faster_than_double_sequential(tmp_path: Path):
    """Parallel module execution (asyncio.gather) must complete a scan in well
    under 2× the time that the slowest single-module baseline would take.

    We measure total wall-clock time for scanning server-everything (a complex
    server with many tools and resources). With 32 modules in parallel, the
    theoretical max speedup vs sequential is 32×. A 3× speedup is a reasonable
    minimum bar — we assert < 180s which is well under the sequential ~600s cap.
    """
    targets = [
        BatchTarget(
            "server-everything",
            "stdio",
            ["npx", "-y", "@modelcontextprotocol/server-everything"],
            None,
        )
    ]
    t0 = time.monotonic()
    result = await run_batch(targets, tmp_path, timeout=_TIMEOUT, target_timeout=_TGT_TIMEOUT)
    elapsed = time.monotonic() - t0

    assert len(result.targets) == 1
    fc = result.targets[0]["finding_count"]
    assert "error" not in fc, f"Scan failed: {fc.get('error')}"

    # With parallelism, a full 34-module scan of server-everything should finish
    # in well under 3 minutes even on a slow Windows machine.
    assert elapsed < 180, f"Scan took {elapsed:.1f}s — expected < 180s with parallel modules"


@pytest.mark.e2e
@skip_no_npx
async def test_parallel_two_targets_concurrent(tmp_path: Path):
    """Two targets scanned concurrently (default -j 5) must both produce reports."""
    targets = [
        BatchTarget(
            "everything",
            "stdio",
            ["npx", "-y", "@modelcontextprotocol/server-everything"],
            None,
        ),
        BatchTarget(
            "filesystem",
            "stdio",
            ["npx", "-y", "@modelcontextprotocol/server-filesystem", str(tmp_path)],
            None,
        ),
    ]
    result = await run_batch(targets, tmp_path, timeout=_TIMEOUT, target_timeout=_TGT_TIMEOUT)

    assert len(result.targets) == 2
    for t in result.targets:
        assert "error" not in t["finding_count"], (
            f"Target {t['name']} errored: {t['finding_count'].get('error')}"
        )
        report_path = tmp_path / t["name"] / "report.json"
        assert report_path.exists(), f"Missing report for {t['name']}"
