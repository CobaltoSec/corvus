"""Integration tests for HttpTransport against a live mock HTTP server."""
import os

import pytest

from tests.mock_http_server import MockHTTPServer
from corvus.transport.http import HttpTransport
from corvus.discovery.enumerator import MCPEnumerator


@pytest.fixture(scope="module")
def http_server():
    s = MockHTTPServer()
    s.start()
    yield s
    s.stop()


@pytest.mark.asyncio
async def test_http_initialize(http_server):
    async with HttpTransport(http_server.url) as t:
        result = await t.initialize()
    assert result["serverInfo"]["name"] == "mock-vulnerable-server"
    assert result["protocolVersion"] == "2024-11-05"


@pytest.mark.asyncio
async def test_http_tools_list(http_server):
    async with HttpTransport(http_server.url) as t:
        await t.initialize()
        result = await t.send_request("tools/list")
    names = [tool["name"] for tool in result["tools"]]
    assert "echo" in names
    assert "get_time" in names
    assert "bash" in names


@pytest.mark.asyncio
async def test_http_tool_call_echo(http_server):
    async with HttpTransport(http_server.url) as t:
        await t.initialize()
        result = await t.send_request(
            "tools/call", {"name": "echo", "arguments": {"message": "corvus-http"}}
        )
    text = result["content"][0]["text"]
    assert text == "corvus-http"


@pytest.mark.asyncio
async def test_http_enumerate_surface(http_server):
    async with HttpTransport(http_server.url) as t:
        surface = await MCPEnumerator(t).enumerate()
    assert surface.server_name == "mock-vulnerable-server"
    assert len(surface.tools) >= 6
    tool_names = {t.name for t in surface.tools}
    assert {"echo", "bash", "get_time", "run_diagnostic"}.issubset(tool_names)


@pytest.mark.asyncio
async def test_http_custom_headers_forwarded(http_server):
    """Custom headers passed to HttpTransport must reach the server."""
    async with HttpTransport(
        http_server.url,
        headers={"Authorization": "Bearer test-token-xyz"},
    ) as t:
        await t.initialize()
    # http.server lowercases header names
    assert http_server.last_headers.get("authorization") == "Bearer test-token-xyz"


@pytest.mark.asyncio
async def test_proxy_env_var_accepted(http_server):
    """CORVUS_PROXY env var must be read and passed to httpx without raising an error.

    We verify the proxy is accepted at construction time (connect()) by inspecting
    the underlying httpx.AsyncClient rather than making a full request through a
    non-existent proxy server.
    """
    os.environ["CORVUS_PROXY"] = "http://127.0.0.1:9999"
    try:
        t = HttpTransport(http_server.url)
        await t.connect()
        # Verify the client was created (proxy URL accepted by httpx constructor)
        assert t._client is not None, "AsyncClient should be initialised after connect()"
        await t.disconnect()
    finally:
        del os.environ["CORVUS_PROXY"]
