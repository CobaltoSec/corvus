from __future__ import annotations

import asyncio
import json
from typing import Any

from .base import JSONRPCError, MCPTransport


class StdioTransport(MCPTransport):
    """
    Transport for MCP servers launched as a subprocess.
    Communicates via stdin/stdout using newline-delimited JSON-RPC 2.0.
    """

    def __init__(self, command: list[str], timeout: float = 30.0):
        self.command = command
        self.timeout = timeout
        self._process: asyncio.subprocess.Process | None = None
        self._req_id = 0

    async def connect(self) -> None:
        self._process = await asyncio.create_subprocess_exec(
            *self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    async def disconnect(self) -> None:
        if self._process is None:
            return
        try:
            self._process.terminate()
            await asyncio.wait_for(self._process.wait(), timeout=5.0)
        except (asyncio.TimeoutError, ProcessLookupError):
            self._process.kill()

    async def send_request(self, method: str, params: dict[str, Any] | None = None) -> Any:
        self._req_id += 1
        msg: dict[str, Any] = {"jsonrpc": "2.0", "id": self._req_id, "method": method}
        if params is not None:
            msg["params"] = params

        await self._write(msg)
        raw = await asyncio.wait_for(self._process.stdout.readline(), timeout=self.timeout)
        if not raw:
            raise RuntimeError("Server closed stdout unexpectedly")

        response = json.loads(raw.decode())
        if "error" in response:
            err = response["error"]
            raise JSONRPCError(err.get("code", -1), err.get("message", "unknown"), err.get("data"))
        return response.get("result")

    async def send_notification(self, method: str, params: dict[str, Any] | None = None) -> None:
        msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        await self._write(msg)

    async def _write(self, msg: dict[str, Any]) -> None:
        line = (json.dumps(msg) + "\n").encode()
        self._process.stdin.write(line)
        await self._process.stdin.drain()
