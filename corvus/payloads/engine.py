from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

_DATA = Path(__file__).parent / "data"

_FIELD_CLASSIFIERS: list[tuple[str, re.Pattern[str]]] = [
    ("command", re.compile(r"\b(cmd|command|exec|run|shell|bash|sh|execute|invoke|script)\b", re.I)),
    ("path",    re.compile(r"\b(path|file|dir|folder|filename|filepath|directory|location)\b", re.I)),
    ("url",     re.compile(r"\b(url|uri|endpoint|host|server|address|link|href|target)\b", re.I)),
    ("sql",     re.compile(r"\b(query|sql|filter|where|select|search|lookup|expression)\b", re.I)),
    ("prompt",  re.compile(r"\b(prompt|message|text|content|input|instruction|query|ask)\b", re.I)),
]


class PayloadEngine:
    def __init__(self):
        with open(_DATA / "injection.yaml") as f:
            self._injection: dict[str, list[str]] = yaml.safe_load(f)
        with open(_DATA / "traversal.yaml") as f:
            self._traversal: dict[str, list[str]] = yaml.safe_load(f)
        with open(_DATA / "schema_bypass.yaml") as f:
            self._schema_bypass: dict[str, Any] = yaml.safe_load(f)

    def classify_field(self, field_name: str, field_schema: dict[str, Any]) -> str:
        """Return the injection category most appropriate for this field."""
        text = f"{field_name} {field_schema.get('description', '')}".lower()
        for category, pattern in _FIELD_CLASSIFIERS:
            if pattern.search(text):
                return category
        return "generic_string"

    def get_payloads(self, category: str) -> list[str]:
        """Return injection payloads for the given field category."""
        payloads = self._injection.get(category, self._injection["generic_string"])
        if category == "path":
            payloads = payloads + self._traversal.get("unix", [])
        return payloads

    def benign_default(self, field_type: str) -> Any:
        """Return a safe benign value for a given JSON Schema type."""
        return {
            "string":  "test",
            "integer": 1,
            "number":  1.0,
            "boolean": False,
            "array":   [],
            "object":  {},
        }.get(field_type, "test")

    def schema_bypass_payloads(self, field_type: str) -> list[Any]:
        """Return out-of-schema inputs for the given field type."""
        if field_type == "integer":
            wrong = self._schema_bypass.get("wrong_type_for_integer", [])
            boundary = self._schema_bypass.get("boundary_integers", [])
            return wrong + boundary
        if field_type == "boolean":
            return self._schema_bypass.get("wrong_type_for_boolean", [])
        if field_type == "string":
            length = self._schema_bypass.get("oversized_string_length", 65536)
            return [None, 12345, True, "A" * length]
        return [None, "", 0, False]

    def build_args(
        self,
        properties: dict[str, Any],
        required: list[str],
        target_param: str,
        payload: Any,
    ) -> dict[str, Any]:
        """Build a tool call arguments dict with payload in the target field."""
        args: dict[str, Any] = {}
        for name, schema in properties.items():
            if name == target_param:
                args[name] = payload
            elif name in required:
                args[name] = self.benign_default(schema.get("type", "string"))
        return args
