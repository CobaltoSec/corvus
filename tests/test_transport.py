import sys
import pytest
from .conftest import MOCK_SERVER_CMD
from corvus.transport.stdio import StdioTransport, ServerStartupError


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


# C2 — Stderr Capture + Startup Validation

@pytest.mark.asyncio
async def test_crashing_server_raises_startup_error():
    cmd = [sys.executable, "-c",
           "import sys; sys.stderr.write('DB connection failed\\n'); sys.exit(1)"]
    with pytest.raises(ServerStartupError) as exc_info:
        async with StdioTransport(cmd) as t:
            pass
    assert "DB connection failed" in exc_info.value.stderr


@pytest.mark.asyncio
async def test_startup_error_contains_exit_code():
    cmd = [sys.executable, "-c", "import sys; sys.exit(42)"]
    with pytest.raises(ServerStartupError) as exc_info:
        async with StdioTransport(cmd) as t:
            pass
    assert "42" in str(exc_info.value)


@pytest.mark.asyncio
async def test_valid_server_not_affected_by_startup_check():
    # Regression: legitimate servers still connect normally
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        result = await t.initialize()
    assert result["serverInfo"]["name"] == "mock-vulnerable-server"
