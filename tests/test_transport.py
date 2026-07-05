import asyncio
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


# Notification-skipping: server emits notifications/tools/list_changed before response

_NOTIFY_BEFORE_TOOLS_SERVER = """
import json, sys

def send(msg):
    sys.stdout.write(json.dumps(msg) + "\\n")
    sys.stdout.flush()

for line in sys.stdin:
    msg = json.loads(line)
    method = msg.get("method", "")
    if method == "initialize":
        send({"jsonrpc":"2.0","id":msg["id"],"result":{
            "protocolVersion":"2024-11-05",
            "capabilities":{"tools":{"listChanged":True}},
            "serverInfo":{"name":"notify-first","version":"1.0"}
        }})
    elif method == "notifications/initialized":
        pass
    elif method == "tools/list":
        # Emit notification BEFORE the response — simulates server-everything behavior
        send({"jsonrpc":"2.0","method":"notifications/tools/list_changed"})
        send({"jsonrpc":"2.0","id":msg["id"],"result":{
            "tools":[{"name":"probe","description":"probe tool","inputSchema":{"type":"object","properties":{}}}]
        }})
    else:
        send({"jsonrpc":"2.0","id":msg.get("id"),"result":{}})
"""


@pytest.mark.asyncio
async def test_notification_before_response_skipped():
    cmd = [sys.executable, "-c", _NOTIFY_BEFORE_TOOLS_SERVER]
    async with StdioTransport(cmd) as t:
        await t.initialize()
        result = await t.send_request("tools/list") or {}
    tools = result.get("tools", [])
    assert len(tools) == 1
    assert tools[0]["name"] == "probe"


# ---------------------------------------------------------------------------
# S1-A — Multiplexed reader: concurrent send_request
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_concurrent_requests_all_resolved():
    """Five concurrent send_request calls must all return without hanging."""
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        await t.initialize()
        results = await asyncio.gather(
            *[t.send_request("tools/list") for _ in range(5)],
            return_exceptions=True,
        )
    for r in results:
        assert not isinstance(r, Exception), f"Concurrent request raised: {r}"
        assert "tools" in r


@pytest.mark.asyncio
async def test_concurrent_echo_routing():
    """Concurrent echo calls must return the correct payload to each caller."""
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        await t.initialize()
        results = await asyncio.gather(
            t.send_request("tools/call", {"name": "echo", "arguments": {"message": "A"}}),
            t.send_request("tools/call", {"name": "echo", "arguments": {"message": "B"}}),
            t.send_request("tools/call", {"name": "echo", "arguments": {"message": "C"}}),
        )
    texts = {r["content"][0]["text"] for r in results}
    assert texts == {"A", "B", "C"}, f"Responses got mixed: {texts}"


@pytest.mark.asyncio
async def test_pause_resume_reader():
    """pause_reader / resume_reader must not crash and transport stays functional after."""
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        await t.initialize()
        await t.pause_reader()
        assert t._reader_task is None
        await t.resume_reader()
        assert t._reader_task is not None
        result = await t.send_request("tools/list")
        assert "tools" in result
