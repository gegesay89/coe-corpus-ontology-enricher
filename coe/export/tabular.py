"""Deterministic CSV projection of run artifacts.

Every JSONL artifact in a run output directory is flattened to a CSV with a
stable, sorted column order. Nested values (objects and arrays) are embedded
as canonical JSON strings so no information is lost. The exporter reads only
recognized artifact names and never rewrites the source directory.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from coe.canonical import JsonValue
from coe.errors import ContractError

_EXPORTABLE = (
    "ambiguity_counts.jsonl",
    "associations.jsonl",
    "candidate_sets.jsonl",
    "candidate_terms.jsonl",
    "coding_counts.jsonl",
    "lexical_forms.jsonl",
    "matches.jsonl",
    "phrase_aggregates.jsonl",
    "unmapped.jsonl",
)
_MAX_ARTIFACT_BYTES = 1_000_000_000


def _flatten(value: JsonValue) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, str)):
        return str(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _rows(path: Path) -> list[dict[str, JsonValue]]:
    if path.stat().st_size > _MAX_ARTIFACT_BYTES:
        raise ContractError("RESOURCE_LIMIT", "An artifact exceeds the export size limit.", path.name, 4)
    rows: list[dict[str, JsonValue]] = []
    with path.open("rb") as handle:
        for line in handle:
            if not line.strip():
                raise ContractError("SCHEMA_INVALID", "An artifact contains a blank line.", path.name, 3)
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ContractError("SCHEMA_INVALID", "Every artifact row must be an object.", path.name, 3)
            rows.append(value)
    return rows


def export_csv(run_path: Path, output_path: Path) -> dict[str, JsonValue]:
    """Flatten each recognized artifact of a run directory into CSV files."""

    if not run_path.is_dir():
        raise ContractError("FILE_MISSING", "The run output directory is unavailable.", "export", 3)
    output_path.mkdir(parents=True, exist_ok=True)
    exported: dict[str, JsonValue] = {}
    for name in _EXPORTABLE:
        source = run_path / name
        if not source.is_file():
            continue
        rows = _rows(source)
        columns: list[str] = sorted({key for row in rows for key in row})
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(columns)
        for row in rows:
            writer.writerow([_flatten(row.get(column)) for column in columns])
        target = output_path / f"{name.removesuffix('.jsonl')}.csv"
        target.write_text(buffer.getvalue(), encoding="utf-8")
        exported[target.name] = len(rows)
    if not exported:
        raise ContractError("FILE_MISSING", "The run directory contains no exportable artifacts.", "export", 3)
    return {"csv_export_schema_version": "1.0.0", "files": exported, "status": "succeeded"}
