from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from coe.demo import create_demo
from coe.errors import ContractError
from coe.export.skos import export_skos
from coe.export.tabular import export_csv
from coe.pipeline import run_v0
from coe.protected import ProtectedLimits, run_protected_local
from coe.terminology.exact import DesignationHit


def _demo_run(tmp_path: Path) -> Path:
    demo = tmp_path / "demo"
    create_demo(demo)
    output = tmp_path / "run-output"
    run_v0(
        snapshot_path=demo / "snapshot",
        reference_paths=(demo / "reference",),
        config_path=demo / "coe_config.json",
        curation_snapshot="genesis-v0",
        output_path=output,
    )
    return output


def test_csv_export_flattens_run_artifacts_deterministically(tmp_path: Path) -> None:
    run_dir = _demo_run(tmp_path)
    out = tmp_path / "csv"
    summary = export_csv(run_dir, out)
    assert summary["status"] == "succeeded"
    assert "candidate_sets.csv" in summary["files"]  # type: ignore[operator]

    with (out / "candidate_sets.csv").open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    source_rows = [
        json.loads(line) for line in (run_dir / "candidate_sets.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert len(rows) == len(source_rows)
    assert rows[0]["primary_normalized_form"] == source_rows[0]["primary_normalized_form"]

    # Re-export is byte-identical (determinism).
    first = (out / "candidate_sets.csv").read_bytes()
    export_csv(run_dir, out)
    assert (out / "candidate_sets.csv").read_bytes() == first


def test_csv_export_fails_closed_on_missing_directory(tmp_path: Path) -> None:
    with pytest.raises(ContractError) as caught:
        export_csv(tmp_path / "missing", tmp_path / "csv")
    assert caught.value.code == "FILE_MISSING"


@dataclass(frozen=True)
class _Reference:
    system_uri: str = "urn:coe:test:skos"
    release_id: str = "skos-release-1"
    code_catalog: frozenset[str] = frozenset({"C1", "C4"})


class _Index:
    def __init__(self) -> None:
        self.reference = _Reference()

    def lookup(self, key: str, *, kind: str, variant: str) -> tuple[DesignationHit, ...]:
        if kind == "preferred" and key.casefold() == "heart attack":
            return (DesignationHit(code="C1", method="exact_preferred", variant=variant),)
        if kind == "preferred" and key.casefold() == "hypertension":
            return (DesignationHit(code="C4", method="exact_preferred", variant=variant),)
        return ()


def _protected_run(tmp_path: Path) -> Path:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    for number in range(3):
        (corpus / f"note-{number}.txt").write_text("Heart attack. HTN.", encoding="utf-8")
    attestation = tmp_path / "attestation.json"
    attestation.write_text(
        json.dumps(
            {
                "approval_refs": {"data_owner": "OWNER", "privacy": "PRIVACY"},
                "approved": True,
                "attestation_schema_version": "1.1.0",
                "lexical_output_approved": True,
                "output_classification": "protected_aggregate",
                "profile": "protected_phi_local",
                "retention_policy_id": "local-30-days",
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "protected-output"
    run_protected_local(
        corpus_path=corpus,
        attestation_path=attestation,
        indexes=(_Index(),),
        output_path=output,
        limits=ProtectedLimits(min_cell_document_count=3),
    )
    return output


def test_skos_export_builds_concepts_labels_and_relations(tmp_path: Path) -> None:
    output = _protected_run(tmp_path)
    target = tmp_path / "scheme.ttl"
    summary = export_skos(output, target)
    assert summary["status"] == "succeeded"
    assert summary["concept_count"] == 2
    text = target.read_text(encoding="utf-8")
    assert "skos:ConceptScheme" in text
    assert 'skos:notation "C1"' in text
    assert 'skos:notation "C4"' in text
    # The dataset synonym HTN becomes a label for the hypertension concept.
    assert 'skos:altLabel "HTN"@en' in text
    assert "skos:related" in text
    assert "coe:runFingerprint" in text

    # Deterministic output.
    first = target.read_bytes()
    export_skos(output, target)
    assert target.read_bytes() == first


def test_skos_export_requires_protected_artifacts(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ContractError) as caught:
        export_skos(empty, tmp_path / "scheme.ttl")
    assert caught.value.code == "FILE_MISSING"
