"""
External module discovery for Corvus.

Two discovery paths:
1. **entry_points** group ``corvus.modules`` — for pip-installable plugins.
2. **plugin directories** — any *.py file in the directory is loaded and
   inspected for ScanModule subclasses.

Usage example (pyproject.toml of a third-party package):

    [project.entry-points."corvus.modules"]
    my-check = "mypackage.checks:MyModule"

Or via CLI:

    corvus scan --plugin-dir ./custom-checks/ --cmd "..."
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .modules.base import ScanModule


def discover_plugins(
    plugin_dirs: list[str | Path] | None = None,
    use_entry_points: bool = True,
) -> dict[str, type[ScanModule]]:
    """Return a name→class mapping of all discovered external modules.

    Built-in modules are NOT included — callers merge this dict with
    ``_ALL_MODULES`` from cli.py, with plugins taking precedence on name
    conflicts (enabling built-in override).
    """
    from .modules.base import ScanModule as _Base

    found: dict[str, type[_Base]] = {}

    # --- 1. Entry-points (installed packages) ---
    if use_entry_points:
        _discover_entry_points(found, _Base)

    # --- 2. Local plugin directories ---
    for raw in (plugin_dirs or []):
        plugin_dir = Path(raw)
        if not plugin_dir.is_dir():
            continue
        for py_file in sorted(plugin_dir.glob("*.py")):
            _load_file_plugins(py_file, found, _Base)

    return found


def _discover_entry_points(
    registry: dict[str, type],
    base_cls: type,
) -> None:
    try:
        from importlib.metadata import entry_points

        eps = entry_points(group="corvus.modules")
        for ep in eps:
            try:
                cls = ep.load()
                if (
                    isinstance(cls, type)
                    and issubclass(cls, base_cls)
                    and cls is not base_cls
                ):
                    instance = cls()
                    if instance.name:
                        registry[instance.name] = cls
            except Exception:
                pass
    except Exception:
        pass


def _load_file_plugins(
    path: Path,
    registry: dict[str, type],
    base_cls: type,
) -> None:
    """Load ScanModule subclasses from a single .py file.

    Uses a namespaced module key (``corvus_plugin_<stem>``) to avoid
    sys.modules collisions with unrelated modules of the same stem name.
    """
    spec = importlib.util.spec_from_file_location(f"corvus_plugin_{path.stem}", path)
    if spec is None or spec.loader is None:
        return
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
    except Exception:
        return
    for obj in vars(mod).values():
        if (
            isinstance(obj, type)
            and issubclass(obj, base_cls)
            and obj is not base_cls
            and getattr(obj, "name", None)
        ):
            try:
                instance = obj()
                if instance.name:
                    registry[instance.name] = obj
            except Exception:
                pass
