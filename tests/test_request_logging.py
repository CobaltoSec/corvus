"""C1 — Request/Response Capture tests."""
import json
import pytest
from pathlib import Path

from .conftest import MOCK_SERVER_CMD
from corvus.transport.stdio import StdioTransport
from corvus.discovery.enumerator import MCPEnumerator
from corvus.core.session import ScanSession
from corvus.modules.dynamic.cmd_injection import CmdInjectionModule as ParamInjectionModule
from corvus.reporting.report import ReportGenerator


@pytest.mark.asyncio
async def test_exchanges_empty_by_default():
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        await t.send_request("tools/list")
    assert t.exchanges == []


@pytest.mark.asyncio
async def test_exchanges_captured_when_enabled():
    async with StdioTransport(MOCK_SERVER_CMD, log_requests=True) as t:
        await t.initialize()
        await t.send_request("tools/list")
    # initialize() calls send_request twice (initialize + tools/list above = 2+ requests)
    assert len(t.exchanges) >= 1
    assert t.exchanges[-1].method == "tools/list"


@pytest.mark.asyncio
async def test_exchange_fields_complete():
    async with StdioTransport(MOCK_SERVER_CMD, log_requests=True) as t:
        await t.initialize()
        await t.send_request("tools/call", {"name": "echo", "arguments": {"message": "hi"}})
    ex = t.exchanges[-1]
    assert ex.method == "tools/call"
    assert ex.params == {"name": "echo", "arguments": {"message": "hi"}}
    assert ex.duration_ms >= 0
    assert ex.ts != ""
    assert ex.result is not None
    assert ex.error is None


@pytest.mark.asyncio
async def test_exchanges_written_to_jsonl(tmp_path):
    async with StdioTransport(MOCK_SERVER_CMD, log_requests=True) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", tmp_path)
        await ParamInjectionModule().run(surface, t, session)

    result = session.to_result(surface, ["param-injection"], exchanges=list(t.exchanges))
    gen = ReportGenerator(tmp_path)
    gen.write(result)

    jsonl_path = tmp_path / "exchanges.jsonl"
    assert jsonl_path.exists(), "exchanges.jsonl should be written when exchanges are present"

    lines = jsonl_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) > 0

    data = json.loads(lines[0])
    assert "method" in data
    assert "duration_ms" in data
    assert "ts" in data
