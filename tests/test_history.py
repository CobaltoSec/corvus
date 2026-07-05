"""Tests for corvus.history — SQLite scan history."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from corvus.history import (
    aggregate_stats,
    get_scanned_packages,
    is_recently_scanned,
    list_scans,
    record_scan,
)


@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    return tmp_path / "test_history.db"


def test_record_and_retrieve(tmp_db: Path) -> None:
    rid = record_scan("pkg-a", "ok", raw_count=5, corvus_version="1.2.0", db=tmp_db)
    assert rid == 1
    rows = list_scans(db=tmp_db)
    assert len(rows) == 1
    assert rows[0]["pkg_name"] == "pkg-a"
    assert rows[0]["status"] == "ok"
    assert rows[0]["raw_count"] == 5


def test_is_recently_scanned_true(tmp_db: Path) -> None:
    record_scan("pkg-b", "ok", db=tmp_db)
    assert is_recently_scanned("pkg-b", within_days=30, db=tmp_db)


def test_is_recently_scanned_false_for_error(tmp_db: Path) -> None:
    record_scan("pkg-c", "error", error_category="browser", db=tmp_db)
    assert not is_recently_scanned("pkg-c", within_days=30, db=tmp_db)


def test_is_recently_scanned_unknown_pkg(tmp_db: Path) -> None:
    assert not is_recently_scanned("never-scanned", db=tmp_db)


def test_get_scanned_packages(tmp_db: Path) -> None:
    record_scan("pkg-x", "ok", db=tmp_db)
    record_scan("pkg-y", "error", db=tmp_db)
    pkgs = get_scanned_packages(db=tmp_db)
    assert "pkg-x" in pkgs
    assert "pkg-y" in pkgs


def test_aggregate_stats(tmp_db: Path) -> None:
    record_scan("s1", "ok", raw_count=10, db=tmp_db)
    record_scan("s2", "ok", raw_count=20, db=tmp_db)
    record_scan("s3", "error", error_category="browser", db=tmp_db)
    stats = aggregate_stats(db=tmp_db)
    assert stats["total"] == 3
    assert stats["ok"] == 2
    assert stats["error"] == 1
    assert stats["total_raw"] == 30
    assert stats["error_breakdown"] == {"browser": 1}


def test_list_scans_filter_case_study(tmp_db: Path) -> None:
    record_scan("pkg-cs7", "ok", case_study="CS07", db=tmp_db)
    record_scan("pkg-cs8", "ok", case_study="CS08", db=tmp_db)
    rows = list_scans(case_study="CS07", db=tmp_db)
    assert len(rows) == 1
    assert rows[0]["pkg_name"] == "pkg-cs7"


def test_list_scans_filter_pkg(tmp_db: Path) -> None:
    record_scan("mongodb-mcp-server", "ok", db=tmp_db)
    record_scan("postgres-mcp", "ok", db=tmp_db)
    rows = list_scans(pkg_filter="mongo", db=tmp_db)
    assert len(rows) == 1
    assert "mongodb" in rows[0]["pkg_name"]


def test_no_db_returns_empty(tmp_db: Path) -> None:
    assert list_scans(db=tmp_db) == []
    assert aggregate_stats(db=tmp_db) == {}
    assert get_scanned_packages(db=tmp_db) == set()
    assert not is_recently_scanned("x", db=tmp_db)
