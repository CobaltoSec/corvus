"""SQLite-backed scan history for Corvus.

Default DB: ~/.corvus/history.db (overridable via CORVUS_HISTORY_DB env var).
"""
from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, Optional


def default_db_path() -> Path:
    return Path(os.environ.get("CORVUS_HISTORY_DB", Path.home() / ".corvus" / "history.db"))


@contextmanager
def _conn(db: Path) -> Generator[sqlite3.Connection, None, None]:
    db.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()


def _ensure_schema(con: sqlite3.Connection) -> None:
    con.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            pkg_name        TEXT    NOT NULL,
            scan_date       TEXT    NOT NULL,
            status          TEXT    NOT NULL,
            error_category  TEXT,
            raw_count       INTEGER NOT NULL DEFAULT 0,
            tp_count        INTEGER,
            fp_count        INTEGER,
            corvus_version  TEXT    NOT NULL DEFAULT '',
            case_study      TEXT
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_pkg ON scans(pkg_name)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_date ON scans(scan_date)")


def record_scan(
    pkg_name: str,
    status: str,
    raw_count: int = 0,
    error_category: Optional[str] = None,
    tp_count: Optional[int] = None,
    fp_count: Optional[int] = None,
    corvus_version: str = "",
    case_study: Optional[str] = None,
    db: Optional[Path] = None,
) -> int:
    """Insert a scan record; return the new row id."""
    path = db or default_db_path()
    now = datetime.now(timezone.utc).isoformat()
    with _conn(path) as con:
        _ensure_schema(con)
        cur = con.execute(
            """INSERT INTO scans
               (pkg_name, scan_date, status, error_category, raw_count,
                tp_count, fp_count, corvus_version, case_study)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (pkg_name, now, status, error_category, raw_count,
             tp_count, fp_count, corvus_version, case_study),
        )
        return cur.lastrowid  # type: ignore[return-value]


def is_recently_scanned(pkg_name: str, within_days: int = 30, db: Optional[Path] = None) -> bool:
    """True if pkg_name has a non-error scan record within the last `within_days` days."""
    path = db or default_db_path()
    if not path.exists():
        return False
    with _conn(path) as con:
        _ensure_schema(con)
        row = con.execute(
            """SELECT COUNT(*) FROM scans
               WHERE pkg_name = ?
                 AND status != 'error'
                 AND scan_date >= datetime('now', ? || ' days')""",
            (pkg_name, f"-{within_days}"),
        ).fetchone()
        return bool(row and row[0] > 0)


def get_scanned_packages(db: Optional[Path] = None) -> set[str]:
    """Return the set of all pkg_names ever scanned (any status)."""
    path = db or default_db_path()
    if not path.exists():
        return set()
    with _conn(path) as con:
        _ensure_schema(con)
        rows = con.execute("SELECT DISTINCT pkg_name FROM scans").fetchall()
        return {r[0] for r in rows}


def list_scans(
    limit: int = 50,
    case_study: Optional[str] = None,
    pkg_filter: Optional[str] = None,
    db: Optional[Path] = None,
) -> list[dict]:
    path = db or default_db_path()
    if not path.exists():
        return []
    with _conn(path) as con:
        _ensure_schema(con)
        clauses, params = [], []
        if case_study:
            clauses.append("case_study LIKE ?")
            params.append(f"{case_study}%")
        if pkg_filter:
            clauses.append("pkg_name LIKE ?")
            params.append(f"%{pkg_filter}%")
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = con.execute(
            f"SELECT * FROM scans {where} ORDER BY scan_date DESC LIMIT ?",
            params + [limit],
        ).fetchall()
        return [dict(r) for r in rows]


def aggregate_stats(db: Optional[Path] = None) -> dict:
    path = db or default_db_path()
    if not path.exists():
        return {}
    with _conn(path) as con:
        _ensure_schema(con)
        row = con.execute("""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN status='ok'    THEN 1 ELSE 0 END) as ok_count,
                SUM(CASE WHEN status='error' THEN 1 ELSE 0 END) as error_count,
                SUM(CASE WHEN status='skip'  THEN 1 ELSE 0 END) as skip_count,
                SUM(raw_count) as total_raw,
                AVG(CASE WHEN status='ok' THEN raw_count END) as avg_raw_ok
            FROM scans
        """).fetchone()
        cats = con.execute("""
            SELECT error_category, COUNT(*) as cnt
            FROM scans WHERE status='error' AND error_category IS NOT NULL
            GROUP BY error_category ORDER BY cnt DESC
        """).fetchall()
        return {
            "total": row["total"],
            "ok": row["ok_count"],
            "error": row["error_count"],
            "skip": row["skip_count"],
            "total_raw": row["total_raw"] or 0,
            "avg_raw_ok": round(row["avg_raw_ok"] or 0, 1),
            "error_breakdown": {r["error_category"]: r["cnt"] for r in cats},
        }
