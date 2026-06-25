from __future__ import annotations

import asyncio

from ..core.models import MCPSurface, PromptSpec, ResourceSpec, ToolSpec
from ..transport.base import MCPTransport

# A9: delay before retrying tools/list on servers that declare listChanged=true
_LIST_CHANGED_RETRY_DELAY = 2.0


class MCPEnumerator:
    """Enumerates the full attack surface of an MCP server."""

    def __init__(self, transport: MCPTransport):
        self.transport = transport

    async def enumerate(self) -> MCPSurface:
        init = await self.transport.initialize()
        info = init.get("serverInfo", {})
        capabilities = init.get("capabilities", {})
        list_changed = capabilities.get("tools", {}).get("listChanged", False)

        surface = MCPSurface(
            server_name=info.get("name", ""),
            server_version=info.get("version", ""),
            protocol_version=init.get("protocolVersion", ""),
        )
        surface.tools = await self._list_tools(list_changed=list_changed)
        surface.resources = await self._list_resources()
        surface.prompts = await self._list_prompts()
        return surface

    async def _list_tools(self, list_changed: bool = False) -> list[ToolSpec]:
        try:
            result = await self.transport.send_request("tools/list") or {}
            tools = result.get("tools", [])

            # A9: if server declared listChanged capability and returned no tools,
            # wait briefly and retry once — tools may appear asynchronously.
            if list_changed and len(tools) == 0:
                await asyncio.sleep(_LIST_CHANGED_RETRY_DELAY)
                result = await self.transport.send_request("tools/list") or {}
                tools = result.get("tools", [])

            return [
                ToolSpec(
                    name=t["name"],
                    description=t.get("description", ""),
                    input_schema=t.get("inputSchema", {}),
                )
                for t in tools
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
