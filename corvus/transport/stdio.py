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
        # Multiplexed reader — routes responses to per-req_id Futures
        self._pending: dict[int, asyncio.Future] = {}
        self._reader_task: asyncio.Task | None = None
        self._write_lock: asyncio.Lock | None = None  # created in connect() (needs running loop)
        self._dead: bool = False  # set when the reader loop exits unexpectedly (server crash)

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
                    limit=10 * 1024 * 1024,
                )
            else:
                self._process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=proc_env,
                    limit=10 * 1024 * 1024,
                )
        else:
            self._process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=proc_env,
                limit=10 * 1024 * 1024,
            )
        # Detect immediate crash: wait up to 5s for the process to exit.
        # If it exits, it crashed before handling any requests.
        # 5s needed on Windows where Python/node can take 3+ seconds to start and crash.
        try:
            await asyncio.wait_for(self._process.wait(), timeout=5.0)
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

        # Initialize write lock and start multiplexed reader
        self._write_lock = asyncio.Lock()
        self._reader_task = asyncio.create_task(self._reader_loop())

        # Startup watchdog: kills the process if it doesn't respond within startup_timeout.
        # Defends against npx hanging on workspace/config lookup before the MCP handshake.
        # threading.Timer runs in its own thread — not blocked by the event loop's readline().
        if self._startup_timeout > 0:
            self._watchdog_timer = threading.Timer(
                self._startup_timeout, self._kill_process_tree
            )
            self._watchdog_timer.daemon = True
            self._watchdog_timer.start()

    async def _reader_loop(self) -> None:
        """Background task: read all stdout lines and route responses to waiting Futures.

        On EOF or pipe error (server crash), fails all pending Futures so callers
        get an immediate exception instead of waiting for the per-request timeout.
        On task cancellation (pause_reader), stops cleanly without touching Futures —
        the caller guarantees no pending Futures at that point.
        """
        assert self._process is not None
        _cancelled = False
        try:
            while True:
                try:
                    raw = await self._process.stdout.readline()
                except asyncio.CancelledError:
                    _cancelled = True
                    raise  # re-raise so task.cancel() propagates correctly
                except Exception:
                    break  # pipe error — fall through to finally
                if not raw:
                    break  # EOF
                try:
                    response = json.loads(raw.decode())
                except json.JSONDecodeError:
                    continue
                if not isinstance(response, dict):
                    continue  # ignore batch arrays and other non-dict messages
                req_id = response.get("id")
                if req_id is not None:
                    fut = self._pending.get(req_id)
                    if fut is not None and not fut.done():
                        fut.set_result(response)
                # Notifications (no "id") are silently discarded
        finally:
            if not _cancelled:
                # EOF or pipe error — mark transport dead and fail pending Futures immediately
                self._dead = True
                err = RuntimeError("Server closed stdout unexpectedly")
                for fut in list(self._pending.values()):
                    if not fut.done():
                        fut.set_exception(err)

    async def pause_reader(self) -> None:
        """Stop the multiplexed reader so a module can access stdout directly (e.g. cancellation_probe)."""
        if self._reader_task and not self._reader_task.done():
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
            self._reader_task = None

    async def resume_reader(self) -> None:
        """Restart the multiplexed reader after a pause."""
        if self._process and self._process.returncode is None:
            self._reader_task = asyncio.create_task(self._reader_loop())

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
        # Cancel reader task and fail any pending requests
        if self._reader_task and not self._reader_task.done():
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
            self._reader_task = None
        err = RuntimeError("Transport disconnected")
        for fut in list(self._pending.values()):
            if not fut.done():
                fut.set_exception(err)
        self._pending.clear()

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
        if self._dead:
            raise RuntimeError("Transport is disconnected (server process died)")
        self._req_id += 1
        req_id = self._req_id
        msg: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            msg["params"] = params

        t0 = time.monotonic()

        if self._reader_task is not None:
            # Multiplexed mode: register a Future, write, and await the reader to resolve it
            loop = asyncio.get_running_loop()
            fut: asyncio.Future = loop.create_future()
            self._pending[req_id] = fut
            try:
                lock = self._write_lock
                if lock is not None:
                    async with lock:
                        await self._write(msg)
                else:
                    await self._write(msg)
                try:
                    response = await asyncio.wait_for(fut, timeout=self.timeout)
                except asyncio.TimeoutError:
                    if self._process and self._process.returncode is None:
                        self._kill_process_tree()
                    raise
            finally:
                self._pending.pop(req_id, None)
        else:
            # Fallback (reader paused or not started): legacy sequential readline loop
            await self._write(msg)
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
