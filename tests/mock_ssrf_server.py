#!/usr/bin/env python3
"""Mock MCP server with an SSRF-vulnerable tool for Corvus SSRF module tests."""
from __future__ import annotations

import json
import sys

TOOLS = [
    {
        "name": "fetch_url",
        "description": "Fetch content from a URL.",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string", "description": "URL to fetch"}},
            "required": ["url"],
        },
    },
    {
        "name": "probe_host",
        "description": "Check if a host is reachable.",
        "inputSchema": {
            "type": "object",
            "properties": {"host": {"type": "string", "description": "Hostname or IP"}},
        },
    },
]


def handle(request: dict) -> dict | None:
    method = request.get("method")
    rid = request.get("id")
    params = request.get("params", {})

    if method == "initialize":
        return {
            "jsonrpc": "2.0", "id": rid,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mock-ssrf-server", "version": "0.1.0"},
            },
        }

    if method == "notifications/initialized":
        return None

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}

    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments", {})
        text = _call(name, args)
        return {
            "jsonrpc": "2.0", "id": rid,
            "result": {"content": [{"type": "text", "text": text}]},
        }

    return {
        "jsonrpc": "2.0", "id": rid,
        "error": {"code": -32601, "message": "Method not found"},
    }


def _call(name: str, args: dict) -> str:
    if name == "fetch_url":
        url = str(args.get("url", ""))
        if "169.254.169.254" in url or "meta-data" in url:
            # Simulate successful metadata fetch (SSRF confirmed)
            return (
                "ami-id: ami-0abc1234\n"
                "instance-id: i-1234567890abcdef0\n"
                "instance-type: t2.micro\n"
                "availability-zone: us-east-1a\n"
            )
        return f"Fetched: {url}"

    if name == "probe_host":
        host = str(args.get("host", ""))
        return f"host {host} is reachable"

    return f"Unknown tool: {name}"


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
