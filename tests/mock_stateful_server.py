#!/usr/bin/env python3
"""
Mock MCP server that returns an empty tools list on the second tools/list call.
Used to test the A7 rug-pull FP fix: a server returning 0 tools mid-session
(stateful reset) should NOT produce a rug-pull finding.
"""
from __future__ import annotations

import json
import sys

_TOOLS_CALL_COUNT = 0

TOOLS = [
    {
        "name": "echo",
        "description": "Echo a message back to the caller.",
        "inputSchema": {
            "type": "object",
            "properties": {"message": {"type": "string"}},
            "required": ["message"],
        },
    }
]


def handle(request: dict) -> dict | None:
    global _TOOLS_CALL_COUNT
    method = request.get("method")
    rid = request.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0", "id": rid,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mock-stateful-server", "version": "0.1.0"},
            },
        }

    if method == "notifications/initialized":
        return None

    if method == "tools/list":
        _TOOLS_CALL_COUNT += 1
        if _TOOLS_CALL_COUNT >= 2:
            return {"jsonrpc": "2.0", "id": rid, "result": {"tools": []}}
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}

    if method == "tools/call":
        name = request.get("params", {}).get("name")
        args = request.get("params", {}).get("arguments", {})
        if name == "echo":
            return {
                "jsonrpc": "2.0", "id": rid,
                "result": {"content": [{"type": "text", "text": str(args.get("message", ""))}]},
            }
        return {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": "ok"}]}}

    return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "Method not found"}}


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = handle(req)
        if resp is not None:
            print(json.dumps(resp), flush=True)


if __name__ == "__main__":
    main()
