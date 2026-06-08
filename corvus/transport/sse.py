from __future__ import annotations

from typing import Any

from .base import MCPTransport


class SSETransport(MCPTransport):
    """
    Transport for MCP servers exposed over HTTP with Server-Sent Events.
    Implements the streamable HTTP MCP transport spec.

    TODO: implement in v0.2.0
    """

    def __init__(self, url: str, timeout: float = 30.0):
        self.url = url
        self.timeout = timeout

    async def connect(self) -> None:
        raise NotImplementedError("HTTP/SSE transport is not yet implemented")

    async def disconnect(self) -> None:
        pass

    async def send_request(self, method: str, params: dict[str, Any] | None = None) -> Any:
        raise NotImplementedError("HTTP/SSE transport is not yet implemented")

    async def send_notification(self, method: str, params: dict[str, Any] | None = None) -> None:
        raise NotImplementedError("HTTP/SSE transport is not yet implemented")
