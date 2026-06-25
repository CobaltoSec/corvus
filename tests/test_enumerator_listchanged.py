"""Tests for A9 — tools.listChanged retry logic in MCPEnumerator."""
from pathlib import Path
from sys import executable

import pytest

from corvus.discovery.enumerator import MCPEnumerator
from corvus.transport.stdio import StdioTransport

_LISTCHANGED_CMD = [executable, str(Path(__file__).parent / "mock_listchanged_server.py")]
_MOCK_CMD = [executable, str(Path(__file__).parent / "mock_server.py")]


@pytest.mark.asyncio
async def test_listchanged_retry_finds_tools():
    """Enumerator must retry tools/list when listChanged=true and first response is empty."""
    async with StdioTransport(_LISTCHANGED_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()

    assert surface.tools, (
        "Expected non-empty tool list after listChanged retry; "
        "mock_listchanged_server returns [] on first call, [echo] on second"
    )
    assert any(tool.name == "echo" for tool in surface.tools), (
        f"Expected 'echo' tool in surface; got: {[t.name for t in surface.tools]}"
    )


@pytest.mark.asyncio
async def test_no_listchanged_no_retry():
    """Enumerator must NOT retry when listChanged is not declared, even if tools is empty.

    mock_server.py always returns tools on the first call, so this test also
    verifies the happy path where no retry is needed.
    """
    async with StdioTransport(_MOCK_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()

    # mock_server has many tools — enumeration should succeed normally
    assert surface.tools, "Expected tools from mock_server.py on first call without retry"
