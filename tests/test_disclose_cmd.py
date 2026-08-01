"""Tests for corvus disclose CLI command (SQLite-based implementation)."""
from __future__ import annotations

import datetime
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from corvus.cli import app

runner = CliRunner()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ibis_db(home_dir: Path) -> Path:
    """Create .ibis/ibis.db under home_dir with three sample advisories."""
    ibis_dir = home_dir / ".ibis"
    ibis_dir.mkdir(parents=True, exist_ok=True)
    db_path = ibis_dir / "ibis.db"

    today = datetime.date.today()
    crit_date = (today + datetime.timedelta(days=3)).isoformat()
    high_date = (today + datetime.timedelta(days=10)).isoformat()
    pub_date = (today + datetime.timedelta(days=1)).isoformat()

    con = sqlite3.connect(str(db_path))
    con.execute("""
        CREATE TABLE advisories (
            ghsa_id   TEXT,
            package   TEXT,
            ecosystem TEXT,
            severity  TEXT,
            state     TEXT,
            publish_by TEXT
        )
    """)
    con.executemany("INSERT INTO advisories VALUES (?, ?, ?, ?, ?, ?)", [
        ("GHSA-test-crit", "pkg-crit", "PyPI", "CRITICAL", "draft",     crit_date),
        ("GHSA-test-high", "pkg-high", "PyPI", "HIGH",     "draft",     high_date),
        ("GHSA-test-pub",  "pkg-pub",  "PyPI", "CRITICAL", "published", pub_date),
    ])
    con.commit()
    con.close()
    return db_path


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_disclose_dry_run_lists_pending_advisories():
    """--days 15 --dry-run: shows both draft advisories; omits published one; no ibis commands."""
    with tempfile.TemporaryDirectory() as tmpdir:
        home = Path(tmpdir)
        _make_ibis_db(home)

        with patch.object(Path, "home", return_value=home):
            result = runner.invoke(app, ["disclose", "--days", "15", "--dry-run"])

    assert result.exit_code == 0, result.output
    assert "GHSA-test-crit" in result.output
    assert "GHSA-test-high" in result.output
    assert "GHSA-test-pub" not in result.output   # state=published → filtered
    assert "ibis publish" not in result.output     # --dry-run suppresses commands


def test_disclose_filters_by_days():
    """--days 5 shows only the advisory due in 3 days, not the one due in 10."""
    with tempfile.TemporaryDirectory() as tmpdir:
        home = Path(tmpdir)
        _make_ibis_db(home)

        with patch.object(Path, "home", return_value=home):
            result = runner.invoke(app, ["disclose", "--days", "5", "--dry-run"])

    assert result.exit_code == 0, result.output
    assert "GHSA-test-crit" in result.output
    assert "GHSA-test-high" not in result.output  # 10 days > cutoff of 5


def test_disclose_filters_by_severity():
    """--severity high with wide window shows only HIGH advisory, not CRITICAL."""
    with tempfile.TemporaryDirectory() as tmpdir:
        home = Path(tmpdir)
        _make_ibis_db(home)

        with patch.object(Path, "home", return_value=home):
            result = runner.invoke(app, ["disclose", "--days", "15", "--severity", "high", "--dry-run"])

    assert result.exit_code == 0, result.output
    assert "GHSA-test-high" in result.output
    assert "GHSA-test-crit" not in result.output  # severity=CRITICAL, not HIGH


def test_disclose_handles_missing_ibis_dir():
    """Exit code 1 with clear message when ~/.ibis/ibis.db does not exist."""
    with tempfile.TemporaryDirectory() as tmpdir:
        home = Path(tmpdir)  # no .ibis/ subdirectory created

        with patch.object(Path, "home", return_value=home):
            result = runner.invoke(app, ["disclose"])

    assert result.exit_code == 1
    output_lower = result.output.lower()
    assert "not found" in output_lower or "ibis" in output_lower
