"""Tests for corvus disclose CLI command (updated for SQLite-based implementation)."""
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


def _make_minimal_db(home_dir: Path) -> None:
    """Create a minimal ~/.ibis/ibis.db with one draft advisory."""
    ibis_dir = home_dir / ".ibis"
    ibis_dir.mkdir(parents=True, exist_ok=True)
    db_path = ibis_dir / "ibis.db"
    today = datetime.date.today()
    due = (today + datetime.timedelta(days=3)).isoformat()
    con = sqlite3.connect(str(db_path))
    con.execute("""
        CREATE TABLE advisories (
            ghsa_id TEXT, package TEXT, ecosystem TEXT,
            severity TEXT, state TEXT, publish_by TEXT
        )
    """)
    con.execute("INSERT INTO advisories VALUES (?, ?, ?, ?, ?, ?)",
                ("GHSA-test-xxxx", "pkg", "PyPI", "HIGH", "draft", due))
    con.commit()
    con.close()


def test_disclose_dry_run():
    """--dry-run: exits 0, does not print ibis publish commands."""
    with tempfile.TemporaryDirectory() as tmpdir:
        home = Path(tmpdir)
        _make_minimal_db(home)
        with patch.object(Path, "home", return_value=home):
            result = runner.invoke(app, ["disclose", "--dry-run"])
    assert result.exit_code == 0, result.output
    assert "ibis publish" not in result.output


def test_disclose_no_ibis():
    """Exit code 1 when ibis.db is missing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        home = Path(tmpdir)  # no .ibis/ created
        with patch.object(Path, "home", return_value=home):
            result = runner.invoke(app, ["disclose"])
    assert result.exit_code != 0
