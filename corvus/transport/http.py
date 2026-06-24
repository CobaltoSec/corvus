from __future__ import annotations

import datetime
import time
from typing import Any

import httpx

from .base import JSONRPCError, MCPTransport
from ..core.models import RawExchange


class HttpTransport(MCPTransport):
    """
    HTTP transport for MCP servers using JSON-RPC over POST requests.

    Implements the MCP Streamable HTTP transport spec (direct JSON response path).
    For each request, POSTs the JSON-RPC message to the server URL and reads the
    synchronous JSON response. SSE streaming responses are not supported.
    """

    def __init__(
        self,
        url: str,
        timeout: float = 30.0,
        headers: dict[str, str] | None = None,
        log_requests: bool = False,
    ):
        self.url = url
        self.timeout = timeout
        self._extra_headers = headers or {}
        self._log_requests = log_requests
        self._client: httpx.AsyncClient | None = None
        self._req_id = 0
        self._exchanges: list[RawExchange] = []

    @property
    def exchanges(self) -> list[RawExchange]:
        return self._exchanges

    async def connect(self) -> None:
        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                **self._extra_headers,
            },
        )

    async def disconnect(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def send_request(self, method: str, params: dict[str, Any] | None = None) -> Any:
        assert self._client is not None, "Transport not connected"
        self._req_id += 1
        msg: dict[str, Any] = {"jsonrpc": "2.0", "id": self._req_id, "method": method}
        if params is not None:
            msg["params"] = params

        t0 = time.monotonic()
        try:
            resp = await self._client.post(self.url, json=msg)
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise JSONRPCError(
                -32603,
                f"HTTP {exc.response.status_code}",
                exc.response.text[:300],
            ) from exc
        except httpx.RequestError as exc:
            raise RuntimeError(f"HTTP request failed: {exc}") from exc

        duration_ms = (time.monotonic() - t0) * 1000
        data = resp.json()
        if "error" in data:
            err = data["error"]
            if self._log_requests:
                self._exchanges.append(RawExchange(
                    ts=datetime.datetime.now().isoformat(),
                    method=method,
                    params=params or {},
                    error=err.get("message", "unknown"),
                    duration_ms=duration_ms,
                ))
            raise JSONRPCError(
                err.get("code", -1),
                err.get("message", "unknown"),
                err.get("data"),
            )

        result = data.get("result")
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
        if self._client is None:
            return
        msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        try:
            await self._client.post(self.url, json=msg)
        except Exception:
            pass
