import pytest
from .conftest import MOCK_SERVER_CMD
from corvus.transport.stdio import StdioTransport
from corvus.discovery.enumerator import MCPEnumerator


@pytest.mark.asyncio
async def test_enumerate_surface():
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()

    assert surface.server_name == "mock-vulnerable-server"
    assert len(surface.tools) == 5
    tool_names = [t.name for t in surface.tools]
    assert "echo" in tool_names
    assert "get_time" in tool_names
    assert "run_diagnostic" in tool_names


@pytest.mark.asyncio
async def test_tool_has_schema():
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()

    echo = next(t for t in surface.tools if t.name == "echo")
    assert "message" in echo.input_schema.get("properties", {})
