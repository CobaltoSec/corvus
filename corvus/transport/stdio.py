from __future__ import annotations

import asyncio
import datetime
import json
import shutil
import subprocess
import sys
import time
from typing import Any

from .base import JSONRPCError, MCPTransport
from ..core.models import RawExchange


class ServerStartupError(RuntimeError):
    """Raised when an MCP server process exits immediately after launch."""
    def __init__(self, message: str, stderr: str = ""):
        super().__init__(message)
        self.stderr = stderr


class StdioTransport(MCPTransport):
    """
    Transport for MCP servers launched as a subprocess.
    Communicates via stdin/stdout using newline-delimited JSON-RPC 2.0.
    """

    def __init__(self, command: list[str], timeout: float = 30.0, log_requests: bool = False):
        self.command = command
        self.timeout = timeout
        self._log_requests = log_requests
        self._process: asyncio.subprocess.Process | None = None
        self._req_id = 0
        self._exchanges: list[RawExchange] = []

    @property
    def exchanges(self) -> list[RawExchange]:
        return self._exchanges

    async def connect(self) -> None:
        cmd = list(self.command)

        # On Windows, .cmd/.bat scripts (e.g. npx.cmd, node.cmd) cannot be
        # launched with create_subprocess_exec — they require shell=True.
        if sys.platform == "win32" and cmd:
            resolved = shutil.which(cmd[0])
            if resolved and resolved.lower().endswith((".cmd", ".bat")):
                self._process = await asyncio.create_subprocess_shell(
                    subprocess.list2cmdline(cmd),
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            else:
                self._process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
        else:
            self._process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        # Detect immediate crash: wait up to 300ms for the process to exit.
        # If it exits, it crashed before handling any requests.
        try:
            await asyncio.wait_for(self._process.wait(), timeout=0.3)
            stderr_bytes = b""
            try:
                stderr_bytes = await asyncio.wait_for(
                    self._process.stderr.read(), timeout=1.0
                )
            except asyncio.TimeoutError:
                pass
            stderr_text = stderr_bytes.decode(errors="replace").strip()
            raise ServerStartupError(
                f"MCP server exited immediately (code {self._process.returncode})"
                + (f": {stderr_text}" if stderr_text else ""),
                stderr=stderr_text,
            )
        except asyncio.TimeoutError:
            pass  # Still running — startup OK

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

        t0 = time.monotonic()
        await self._write(msg)
        raw = await asyncio.wait_for(self._process.stdout.readline(), timeout=self.timeout)
        duration_ms = (time.monotonic() - t0) * 1000

        if not raw:
            raise RuntimeError("Server closed stdout unexpectedly")

        response = json.loads(raw.decode())
        if "error" in response:
            err = response["error"]
            if self._log_requests:
                self._exchanges.append(RawExchange(
                    ts=datetime.datetime.now().isoformat(),
                    method=method,
                    params=params or {},
                    error=err.get("message", "unknown"),
                    duration_ms=duration_ms,
                ))
            raise JSONRPCError(err.get("code", -1), err.get("message", "unknown"), err.get("data"))

        result = response.get("result")
        if self._log_requests:
            self._exchanges.append(RawExchange(
                ts=datetime.datetime.now().isoformat(),
                method=method,
                params=params or {},
                result=result,
                duration_ms=duration_ms,
            ))
        return result

    async def send_notification(self, method: str, params: dict[str, Any] | None = None) -> None:
        msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        await self._write(msg)

    async def _write(self, msg: dict[str, Any]) -> None:
        line = (json.dumps(msg) + "\n").encode()
        self._process.stdin.write(line)
        await self._process.stdin.drain()
