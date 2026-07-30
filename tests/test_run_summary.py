"""Tests for corvus/run_summary.py — post-run batch funnel summary."""
from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from corvus.run_summary import generate_batch_summary


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_generate_batch_summary_creates_file(tmp_path: Path):
    """generate_batch_summary must create a .md file in the given output_dir."""
    out = generate_batch_summary(
        run_name="targets-v08",
        targets_total=10,
        targets_ok=8,
        targets_error=2,
        raw_findings=42,
        severity_counts={"critical": 3, "high": 7},
        output_dir=tmp_path,
    )
    assert out.exists(), "Expected output file to exist"
    assert out.suffix == ".md"
    assert out.parent == tmp_path
    today = date.today().isoformat()
    assert out.name == f"run-targets-v08-{today}.md"


def test_generate_batch_summary_content(tmp_path: Path):
    """The generated markdown must contain the funnel table with correct values."""
    out = generate_batch_summary(
        run_name="cs18",
        targets_total=100,
        targets_ok=82,
        targets_error=18,
        raw_findings=376,
        severity_counts={"critical": 5, "high": 12, "medium": 20, "low": 30},
        output_dir=tmp_path,
    )
    content = out.read_text(encoding="utf-8")

    today = date.today().isoformat()
    assert f"## Corvus cs18 — {today}" in content
    assert "Targets totales | 100" in content
    assert "Targets OK | 82" in content
    assert "Targets ERROR | 18" in content
    assert "Raw findings | 376" in content

    # Severities must appear in canonical order
    lines = content.splitlines()
    sev_lines = [l for l in lines if any(s in l for s in ("Critical", "High", "Medium", "Low"))]
    assert len(sev_lines) == 4
    assert "Critical" in sev_lines[0]
    assert "High" in sev_lines[1]
    assert "Medium" in sev_lines[2]
    assert "Low" in sev_lines[3]

    # Values are present
    assert "| 5 |" in sev_lines[0]
    assert "| 12 |" in sev_lines[1]


def test_generate_batch_summary_empty(tmp_path: Path):
    """targets_total=0 must not raise ZeroDivisionError and produce a valid file."""
    out = generate_batch_summary(
        run_name="empty-run",
        targets_total=0,
        targets_ok=0,
        targets_error=0,
        raw_findings=0,
        severity_counts={},
        output_dir=tmp_path,
    )
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    # Zero-safe percentages
    assert "0%" in content or "0.0%" in content
    assert "Targets totales | 0" in content
