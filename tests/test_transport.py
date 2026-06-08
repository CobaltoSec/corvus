import pytest
from .conftest import MOCK_SERVER_CMD
from corvus.transport.stdio import StdioTransport


@pytest.mark.asyncio
async def test_connect_and_initialize():
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        result = await t.initialize()
    assert result["serverInfo"]["name"] == "mock-vulnerable-server"
    assert result["protocolVersion"] == "2024-11-05"


@pytest.mark.asyncio
async def test_tools_list():
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        await t.initialize()
        result = await t.send_request("tools/list")
    assert "tools" in result
    names = [tool["name"] for tool in result["tools"]]
    assert "echo" in names
    assert "get_time" in names


@pytest.mark.asyncio
async def test_tool_call_echo():
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        await t.initialize()
        result = await t.send_request("tools/call", {
            "name": "echo",
            "arguments": {"message": "hello"},
        })
    text = result["content"][0]["text"]
    assert text == "hello"
