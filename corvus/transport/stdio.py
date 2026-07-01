from __future__ import annotations

import asyncio
import datetime
import json
import os
import shutil
import subprocess
import sys
import threading
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

    def __init__(
        self,
        command: list[str],
        timeout: float = 30.0,
        log_requests: bool = False,
        startup_timeout: float = 45.0,
        env: dict[str, str] | None = None,
    ):
        self.command = command
        self.timeout = timeout
        self._startup_timeout = startup_timeout
        self._log_requests = log_requests
        self._env = env  # Extra env vars merged on top of os.environ at connect time
        self._process: asyncio.subprocess.Process | None = None
        self._req_id = 0
        self._exchanges: list[RawExchange] = []
        self._watchdog_timer: threading.Timer | None = None

    @property
    def exchanges(self) -> list[RawExchange]:
        return self._exchanges

    async def connect(self) -> None:
        cmd = list(self.command)
        # Merge extra env vars on top of the current environment so the subprocess
        # still has PATH, APPDATA, etc. — required for npx/node to resolve binaries.
        proc_env = {**os.environ, **self._env} if self._env else None

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
                    env=proc_env,
                )
            else:
                self._process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=proc_env,
                )
        else:
            self._process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=proc_env,
            )
        # Detect immediate crash: wait up to 2s for the process to exit.
        # If it exits, it crashed before handling any requests.
        # 2s is needed on Windows where interpreter startup (Python, node) can take 500ms-1.5s.
        try:
            await asyncio.wait_for(self._process.wait(), timeout=2.0)
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

        # Startup watchdog: kills the process if it doesn't respond within startup_timeout.
        # Defends against npx hanging on workspace/config lookup before the MCP handshake.
        # threading.Timer runs in its own thread — not blocked by the event loop's readline().
        if self._startup_timeout > 0:
            self._watchdog_timer = threading.Timer(
                self._startup_timeout, self._kill_process_tree
            )
            self._watchdog_timer.daemon = True
            self._watchdog_timer.start()

    def _kill_process_tree(self) -> None:
        """Kill the subprocess and all descendants (sync-safe, callable from threads)."""
        if self._process is None or self._process.returncode is not None:
            return
        try:
            if sys.platform == "win32":
                # taskkill /F /T kills the full tree so child node processes
                # release the stdout pipe and don't block readline().
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(self._process.pid)],
                    capture_output=True,
                )
            else:
                self._process.kill()
        except (ProcessLookupError, OSError):
            pass

    async def disconnect(self) -> None:
        if self._watchdog_timer is not None:
            self._watchdog_timer.cancel()
            self._watchdog_timer = None
        if self._process is None:
            return
        # Close stdin first so the server receives EOF and can exit cleanly.
        # This also prevents "socket.send() raised exception" from asyncio when
        # the pipe is written to after the process is dead.
        if self._process.stdin and not self._process.stdin.is_closing():
            self._process.stdin.close()
        try:
            self._process.terminate()
            await asyncio.wait_for(self._process.wait(), timeout=5.0)
        except (asyncio.TimeoutError, ProcessLookupError):
            self._kill_process_tree()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                pass

    async def send_request(self, method: str, params: dict[str, Any] | None = None) -> Any:
        self._req_id += 1
        req_id = self._req_id
        msg: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            msg["params"] = params

        t0 = time.monotonic()
        await self._write(msg)

        # Loop until we get the response matching req_id.
        # Servers may emit notifications (no "id") or unrelated messages before
        # the actual response — skip those rather than treating them as the result.
        while True:
            elapsed = time.monotonic() - t0
            remaining = self.timeout - elapsed
            if remaining <= 0:
                raise asyncio.TimeoutError()
            try:
                raw = await asyncio.wait_for(
                    self._process.stdout.readline(), timeout=remaining
                )
            except asyncio.TimeoutError:
                if self._process and self._process.returncode is None:
                    self._kill_process_tree()
                raise
            if not raw:
                raise RuntimeError("Server closed stdout unexpectedly")
            response = json.loads(raw.decode())
            if response.get("id") == req_id:
                break
            # Notification or out-of-order message — skip

        duration_ms = (time.monotonic() - t0) * 1000

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
        if self._watchdog_timer is not None:
            self._watchdog_timer.cancel()
            self._watchdog_timer = None
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
        try:
            self._process.stdin.write(line)
            await self._process.stdin.drain()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
