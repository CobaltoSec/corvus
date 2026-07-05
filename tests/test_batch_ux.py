"""Tests for RT-CORVUS-SCALE-A: S2 (inline targets), S3 (concurrency), S4 (on_status)."""
from __future__ import annotations

from pathlib import Path
from sys import executable

import pytest

from corvus.cli import _build_inline_targets, _name_from_cmd, _name_from_url
from corvus.batch import BatchTarget, run_batch

_MOCK_SERVER_CMD = [executable, str(Path(__file__).parent / "mock_server.py")]


# ── S2: name derivation helpers ───────────────────────────────────────────────


def test_name_from_cmd_npx_scoped():
    assert _name_from_cmd("npx @modelcontextprotocol/server-everything") == "server-everything"


def test_name_from_cmd_uvx_with_flags():
    assert _name_from_cmd("uvx mcp-server-sqlite --db-path /tmp/test.db") == "mcp-server-sqlite"


def test_name_from_cmd_python_module():
    assert _name_from_cmd("python -m kestrel_mcp") == "kestrel_mcp"


def test_name_from_cmd_python3_module_dotted():
    # First component of dotted module path
    assert _name_from_cmd("python3 -m llamascope.server") == "llamascope"


def test_name_from_cmd_bare_npx():
    assert _name_from_cmd("npx foo-server") == "foo-server"


def test_name_from_url_with_port():
    assert _name_from_url("http://localhost:3000/mcp") == "localhost-3000"


def test_name_from_url_no_port():
    assert _name_from_url("https://api.example.com/mcp") == "api.example.com"


def test_name_from_url_ip_with_port():
    assert _name_from_url("http://127.0.0.1:8080/") == "127.0.0.1-8080"


# ── S2: _build_inline_targets ─────────────────────────────────────────────────


def test_build_inline_targets_stdio():
    targets = _build_inline_targets(["npx foo-server", "npx bar-server"], [])
    assert len(targets) == 2
    assert targets[0].name == "foo-server"
    assert targets[0].transport == "stdio"
    assert targets[0].cmd is not None
    assert targets[1].name == "bar-server"


def test_build_inline_targets_http():
    targets = _build_inline_targets([], ["http://localhost:3000/mcp"])
    assert len(targets) == 1
    assert targets[0].name == "localhost-3000"
    assert targets[0].transport == "http"
    assert targets[0].url == "http://localhost:3000/mcp"


def test_build_inline_targets_mixed():
    targets = _build_inline_targets(["npx foo"], ["http://localhost:9000/"])
    assert len(targets) == 2
    assert {t.transport for t in targets} == {"stdio", "http"}


def test_build_inline_targets_deduplicates_names():
    targets = _build_inline_targets(["npx foo", "npx foo"], [])
    assert targets[0].name == "foo"
    assert targets[1].name == "foo-2"


def test_build_inline_targets_empty():
    assert _build_inline_targets([], []) == []


# ── S3: concurrency parameter ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_batch_accepts_concurrency(tmp_path: Path):
    """run_batch should accept concurrency=1 without error."""
    targets = [BatchTarget("mock", "stdio", _MOCK_SERVER_CMD, None)]
    result = await run_batch(targets, tmp_path, timeout=30, concurrency=1)
    assert len(result.targets) == 1


@pytest.mark.asyncio
async def test_run_batch_concurrency_default(tmp_path: Path):
    """run_batch should work with default concurrency."""
    targets = [BatchTarget("mock", "stdio", _MOCK_SERVER_CMD, None)]
    result = await run_batch(targets, tmp_path, timeout=30)
    assert len(result.targets) == 1


# ── S4: on_status callback ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_batch_on_status_fires_start_and_done(tmp_path: Path):
    """on_status must be called with 'start' then 'done' for a successful scan."""
    events: list[tuple[str, str]] = []

    def on_status(name: str, status: str, detail: dict) -> None:
        events.append((name, status))

    targets = [BatchTarget("mock", "stdio", _MOCK_SERVER_CMD, None)]
    await run_batch(targets, tmp_path, timeout=30, on_status=on_status)

    assert ("mock", "start") in events
    assert ("mock", "done") in events


@pytest.mark.asyncio
async def test_batch_on_status_done_includes_finding_count(tmp_path: Path):
    """on_status 'done' detail must include finding_count dict."""
    details: dict = {}

    def on_status(name: str, status: str, detail: dict) -> None:
        if status == "done":
            details.update(detail)

    targets = [BatchTarget("mock", "stdio", _MOCK_SERVER_CMD, None)]
    await run_batch(targets, tmp_path, timeout=30, on_status=on_status)

    assert "finding_count" in details
    assert isinstance(details["finding_count"], dict)


@pytest.mark.asyncio
async def test_batch_on_status_skipped(tmp_path: Path):
    """on_status must fire 'skipped' when skip_existing=True and report exists."""
    # Pre-create a fake report.json so skip_existing triggers
    target_dir = tmp_path / "mock"
    target_dir.mkdir()
    (target_dir / "report.json").write_text("{}")

    events: list[tuple[str, str]] = []

    def on_status(name: str, status: str, detail: dict) -> None:
        events.append((name, status))

    targets = [BatchTarget("mock", "stdio", _MOCK_SERVER_CMD, None)]
    await run_batch(targets, tmp_path, timeout=30, skip_existing=True, on_status=on_status)

    assert ("mock", "skipped") in events
    assert ("mock", "start") not in events
