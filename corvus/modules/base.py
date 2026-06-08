from __future__ import annotations

from abc import ABC, abstractmethod

from ..core.models import Finding, MCPSurface
from ..core.session import ScanSession
from ..transport.base import MCPTransport


class ScanModule(ABC):
    owasp_id: str = ""
    category: str = ""
    name: str = ""
    description: str = ""
    is_static: bool = False

    @abstractmethod
    async def run(
        self,
        surface: MCPSurface,
        transport: MCPTransport,
        session: ScanSession,
    ) -> list[Finding]: ...
