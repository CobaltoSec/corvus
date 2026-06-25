#!/usr/bin/env python3
"""Mock MCP server that declares tools.listChanged=true and returns tools only on retry."""
from __future__ import annotations

import json
import sys

_call_count = 0


def handle(request: dict) -> dict | None:
    global _call_count

    method = request.get("method")
    rid = request.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0", "id": rid,
            "result": {
                "protocolVersion": "2024-11-05",
                # Declare listChanged=true — means tools may appear asynchronously
                "capabilities": {"tools": {"listChanged": True}},
                "serverInfo": {"name": "mock-listchanged-server", "version": "0.1.0"},
            },
        }

    if method == "notifications/initialized":
        return None

    if method == "tools/list":
        _call_count += 1
        if _call_count == 1:
            # First call returns empty — tools not ready yet
            return {"jsonrpc": "2.0", "id": rid, "result": {"tools": []}}
        # Second call returns actual tools
        return {
            "jsonrpc": "2.0", "id": rid,
            "result": {
                "tools": [
                    {
                        "name": "echo",
                        "description": "Echo a message",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"message": {"type": "string"}},
                            "required": ["message"],
                        },
                    }
                ]
            },
        }

    if method == "tools/call":
        return {
            "jsonrpc": "2.0", "id": rid,
            "result": {"content": [{"type": "text", "text": "echo"}]},
        }

    return {
        "jsonrpc": "2.0", "id": rid,
        "error": {"code": -32601, "message": "Method not found"},
    }


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
