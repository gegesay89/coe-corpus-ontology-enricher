"""SKOS/Turtle export of a protected-local aggregate output.

Emits one skos:Concept per coding row, with the standard code carried as
skos:notation, dataset-observed surface forms as skos:altLabel (the most
frequent form doubles as skos:prefLabel), and document co-occurrence
associations as skos:related. The Turtle is hand-emitted with strict string
escaping so the exporter adds no runtime dependency, and rows are ordered
deterministically.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from coe.canonical import JsonValue
from coe.errors import ContractError

_MAX_ARTIFACT_BYTES = 1_000_000_000
DEFAULT_BASE_IRI = "urn:coe:scheme:protected-aggregate"


def _read_rows(path: Path) -> list[dict[str, JsonValue]]:
    if not path.is_file():
        raise ContractError("FILE_MISSING", "A protected artifact is missing for export.", path.name, 3)
    if path.stat().st_size > _MAX_ARTIFACT_BYTES:
        raise ContractError("RESOURCE_LIMIT", "An artifact exceeds the export size limit.", path.name, 4)
    rows: list[dict[str, JsonValue]] = []
    with path.open("rb") as handle:
        for line in handle:
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ContractError("SCHEMA_INVALID", "Every artifact row must be an object.", path.name, 3)
            rows.append(value)
    return rows


def _escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")


def _concept_iri(system_uri: str, code: str) -> str:
    digest = hashlib.sha256(f"{system_uri}|{code}".encode()).hexdigest()[:32]
    return f"urn:coe:concept:{digest}"


def export_skos(run_path: Path, output_path: Path, *, base_iri: str = DEFAULT_BASE_IRI) -> dict[str, JsonValue]:
    """Write a SKOS Turtle file for one protected-local output directory."""

    if not run_path.is_dir():
        raise ContractError("FILE_MISSING", "The protected output directory is unavailable.", "export", 3)
    report_path = run_path / "run_report.json"
    if not report_path.is_file():
        raise ContractError("FILE_MISSING", "The protected run report is missing.", "export", 3)
    report = json.loads(report_path.read_bytes())
    if not isinstance(report, dict) or "run_fingerprint" not in report:
        raise ContractError("SCHEMA_INVALID", "The protected run report is invalid.", "export", 3)
    fingerprint = str(report["run_fingerprint"])

    coding_rows = _read_rows(run_path / "coding_counts.jsonl")
    lexical_rows = _read_rows(run_path / "lexical_forms.jsonl")
    association_rows = _read_rows(run_path / "associations.jsonl")

    concepts: dict[tuple[str, str], dict[str, JsonValue]] = {}
    for row in coding_rows:
        concepts[(str(row["system_uri"]), str(row["code"]))] = row
    labels: dict[tuple[str, str], list[tuple[int, str, str]]] = {}
    for row in lexical_rows:
        key = (str(row["system_uri"]), str(row["code"]))
        labels.setdefault(key, []).append(
            (-int(row["occurrence_count"]), str(row["form"]), str(row["match_method"]))  # type: ignore[arg-type]
        )

    lines: list[str] = [
        "@prefix skos: <http://www.w3.org/2004/02/skos/core#> .",
        "@prefix dcterms: <http://purl.org/dc/terms/> .",
        "@prefix coe: <urn:coe:vocab:> .",
        "",
        f"<{base_iri}> a skos:ConceptScheme ;",
        '    dcterms:title "COE corpus-enriched clinical concept scheme" ;',
        f'    coe:runFingerprint "{_escape(fingerprint)}" .',
        "",
    ]
    for (system_uri, code), row in sorted(concepts.items()):
        iri = _concept_iri(system_uri, code)
        lines.append(f"<{iri}> a skos:Concept ;")
        lines.append(f"    skos:inScheme <{base_iri}> ;")
        lines.append(f'    skos:notation "{_escape(code)}" ;')
        lines.append(f"    coe:systemUri <{system_uri}> ;")
        lines.append(f'    coe:releaseId "{_escape(str(row["release_id"]))}" ;')
        lines.append(f"    coe:documentCount {int(row['exact_match_document_count'])} ;")  # type: ignore[arg-type]
        lines.append(f"    coe:occurrenceCount {int(row['exact_match_occurrence_count'])} ;")  # type: ignore[arg-type]
        concept_labels = sorted(labels.get((system_uri, code), ()))
        if concept_labels:
            preferred = concept_labels[0][1]
            lines.append(f'    skos:prefLabel "{_escape(preferred)}"@en ;')
            for _, form, _method in concept_labels:
                lines.append(f'    skos:altLabel "{_escape(form)}"@en ;')
        lines[-1] = lines[-1].rstrip(" ;") + " ."
        lines.append("")
    related_count = 0
    for row in association_rows:
        first = _concept_iri(str(row["system_uri_a"]), str(row["code_a"]))
        second = _concept_iri(str(row["system_uri_b"]), str(row["code_b"]))
        if (str(row["system_uri_a"]), str(row["code_a"])) in concepts and (
            str(row["system_uri_b"]),
            str(row["code_b"]),
        ) in concepts:
            lines.append(f"<{first}> skos:related <{second}> .")
            related_count += 1
    text = "\n".join(lines).rstrip("\n") + "\n"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(text, encoding="utf-8")
    return {
        "concept_count": len(concepts),
        "label_count": sum(len(items) for items in labels.values()),
        "related_count": related_count,
        "skos_export_schema_version": "1.0.0",
        "status": "succeeded",
    }
