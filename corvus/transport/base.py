from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class JSONRPCError(Exception):
    def __init__(self, code: int, message: str, data: Any = None):
        self.code = code
        self.message = message
        self.data = data
        super().__init__(f"JSON-RPC {code}: {message}")


class MCPTransport(ABC):
    """Abstract base for MCP JSON-RPC transports."""

    @abstractmethod
    async def connect(self) -> None: ...

    @abstractmethod
    async def disconnect(self) -> None: ...

    @abstractmethod
    async def send_request(self, method: str, params: dict[str, Any] | None = None) -> Any:
        """Send a JSON-RPC request and return the result. Raises JSONRPCError on error response."""
        ...

    @abstractmethod
    async def send_notification(self, method: str, params: dict[str, Any] | None = None) -> None:
        """Send a JSON-RPC notification (no response expected)."""
        ...

    async def initialize(self) -> dict[str, Any]:
        result = await self.send_request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "corvus", "version": "0.1.0"},
        })
        await self.send_notification("notifications/initialized")
        return result or {}

    async def __aenter__(self) -> "MCPTransport":
        await self.connect()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.disconnect()
