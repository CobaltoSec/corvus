from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Union

from pydantic import BaseModel, Field


class ScanConfig(BaseModel):
    """Default scan settings loaded from [scan] in corvus.toml.

    CLI flags override each field individually; the merge happens in cli._scan.
    """

    transport: str = "stdio"
    cmd: str | None = None
    url: str | None = None
    modules: Union[str, list[str]] = "all"
    output_dir: str | None = None
    timeout: int = 30
    sarif: bool = False
    fail_on: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    plugin_dirs: list[str] = Field(default_factory=list)


class CorvusConfig(BaseModel):
    scan: ScanConfig = Field(default_factory=ScanConfig)


def load_config(path: Path) -> CorvusConfig:
    """Parse and validate a corvus.toml file.

    Raises FileNotFoundError if the file does not exist.
    Raises ValueError (via pydantic) if the file is invalid.
    """
    with open(path, "rb") as fh:
        raw = tomllib.load(fh)
    return CorvusConfig.model_validate(raw)
