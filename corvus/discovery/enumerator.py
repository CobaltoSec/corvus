from __future__ import annotations

from ..core.models import MCPSurface, PromptSpec, ResourceSpec, ToolSpec
from ..transport.base import MCPTransport


class MCPEnumerator:
    """Enumerates the full attack surface of an MCP server."""

    def __init__(self, transport: MCPTransport):
        self.transport = transport

    async def enumerate(self) -> MCPSurface:
        init = await self.transport.initialize()
        info = init.get("serverInfo", {})
        surface = MCPSurface(
            server_name=info.get("name", ""),
            server_version=info.get("version", ""),
            protocol_version=init.get("protocolVersion", ""),
        )
        surface.tools = await self._list_tools()
        surface.resources = await self._list_resources()
        surface.prompts = await self._list_prompts()
        return surface

    async def _list_tools(self) -> list[ToolSpec]:
        try:
            result = await self.transport.send_request("tools/list") or {}
            return [
                ToolSpec(
                    name=t["name"],
                    description=t.get("description", ""),
                    input_schema=t.get("inputSchema", {}),
                )
                for t in result.get("tools", [])
            ]
        except Exception:
            return []

    async def _list_resources(self) -> list[ResourceSpec]:
        try:
            result = await self.transport.send_request("resources/list") or {}
            return [
                ResourceSpec(
                    uri=r["uri"],
                    name=r.get("name", ""),
                    description=r.get("description", ""),
                    mime_type=r.get("mimeType"),
                )
                for r in result.get("resources", [])
            ]
        except Exception:
            return []

    async def _list_prompts(self) -> list[PromptSpec]:
        try:
            result = await self.transport.send_request("prompts/list") or {}
            return [
                PromptSpec(
                    name=p["name"],
                    description=p.get("description", ""),
                    arguments=p.get("arguments", []),
                )
                for p in result.get("prompts", [])
            ]
        except Exception:
            return []
