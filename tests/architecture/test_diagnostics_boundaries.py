"""Static TEL-001 dependency, field, and no-export assertions."""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

from mycogni.application.diagnostics import ConnectorCode, ConnectorVersionCode, FieldName

ROOT = Path(__file__).parents[2]
DIAGNOSTIC_SOURCES = (
    ROOT / "src/mycogni/application/diagnostics.py",
    ROOT / "src/mycogni/adapters/diagnostics/local_json.py",
    ROOT / "src/mycogni/adapters/diagnostics/policy.py",
)
FORBIDDEN_IMPORTS = {
    "httpx",
    "logging",
    "opentelemetry",
    "requests",
    "socket",
    "subprocess",
    "urllib",
    "uvicorn",
}
FORBIDDEN_FIELD_PARTS = {
    "body",
    "content",
    "cookie",
    "email",
    "exception_message",
    "header",
    "html",
    "mail",
    "page",
    "path",
    "peer",
    "query",
    "selector",
    "title",
    "traceback",
    "url",
}


def _imports(path: Path) -> Iterator[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            yield from (alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            yield (node.module or "").partition(".")[0]


def test_diagnostic_modules_have_no_network_export_or_framework_logging_dependency() -> None:
    for path in DIAGNOSTIC_SOURCES:
        imported = set(_imports(path))
        assert not imported & FORBIDDEN_IMPORTS, f"{path}: {imported & FORBIDDEN_IMPORTS}"


def test_field_catalog_cannot_represent_raw_capture_surfaces() -> None:
    field_names = {field.value for field in FieldName}
    assert all(
        forbidden not in field_name
        for field_name in field_names
        for forbidden in FORBIDDEN_FIELD_PARTS
    )
    assert set(ConnectorCode) == {ConnectorCode.SYNTHETIC_PEOPLE_SEARCH}
    assert set(ConnectorVersionCode) == {ConnectorVersionCode.SYNTHETIC_0_1_0}
