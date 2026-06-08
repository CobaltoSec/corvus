from __future__ import annotations

import time
import uuid
from pathlib import Path

from .models import Finding, MCPSurface, ScanResult


class ScanSession:
    """Tracks state during an active scan."""

    def __init__(self, target: str, transport: str, output_dir: Path):
        self.id = str(uuid.uuid4())[:8]
        self.target = target
        self.transport = transport
        self.output_dir = output_dir
        self.findings: list[Finding] = []
        self._start = time.monotonic()
        self._counter = 0

    def add_finding(self, finding: Finding) -> None:
        self._counter += 1
        finding.id = f"CORVUS-{self._counter:03d}"
        self.findings.append(finding)

    def to_result(self, surface: MCPSurface, modules_run: list[str]) -> ScanResult:
        return ScanResult(
            target=self.target,
            transport=self.transport,
            surface=surface,
            findings=self.findings,
            modules_run=modules_run,
            duration_seconds=time.monotonic() - self._start,
        )
