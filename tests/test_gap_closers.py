"""Targeted regression tests for previously untested behavior.

Covers the tf-idf computation against an independent float oracle, the v0
grounding-failure branches, and the licensed reference-set build/verify happy
path that the protected deployment gates on.
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
from datetime import date, timedelta
from decimal import Decimal
from pathlib import Path

import pytest

from coe.contracts.config import AnalysisConfig, MiningConfig, ResourceLimits
from coe.contracts.snapshot import Document
from coe.demo import create_demo
from coe.errors import ContractError
from coe.mining.ngrams import aggregate_phrases
from coe.pipeline import run_v0
from coe.terminology.exact import validate_grounding
from coe.terminology.licensed_set import build_licensed_index_set, verify_licensed_index_set

_SET_NAMES = ("cpt", "hcpcs", "icd10cm", "icd10pcs", "loinc", "rxnorm", "snomed")


def _config(min_document_frequency: int = 1) -> AnalysisConfig:
    return AnalysisConfig(
        config_id="test",
        note_types=("synthetic_note",),
        languages=("en",),
        terminologies=(),
        mining=MiningConfig(
            min_ngram_tokens=1,
            max_ngram_tokens=2,
            min_document_frequency=min_document_frequency,
            max_unique_phrases=10_000,
        ),
        resource_limits=ResourceLimits(
            max_documents=100,
            max_snapshot_bytes=1_000_000,
            max_document_bytes=100_000,
            max_tokens_per_document=10_000,
            max_ngrams_per_document=100_000,
            max_output_records=100_000,
            max_candidates_per_phrase_system=20,
        ),
        algorithms={},
        canonical_value={},
        semantic_sha256="",
    )


def _document(number: int, text: str) -> Document:
    return Document(
        doc_id=f"00000000-0000-4000-8000-00000000000{number}",
        path=f"documents/{number}.txt",
        sha256="0" * 64,
        byte_count=len(text),
        character_count=len(text),
        note_type="synthetic_note",
        language="en",
        extraction_method="synthetic_fixture",
        text=text,
    )


def test_tf_idf_matches_independent_float_oracle() -> None:
    # "alpha" appears twice in one of two documents:
    # tf = 1 + ln(2); idf = ln((2 + 1) / (1 + 1)) + 1.
    documents = (_document(1, "alpha alpha"), _document(2, "beta"))
    aggregates = {item.primary: item for item in aggregate_phrases(documents, _config())}
    actual = Decimal(aggregates["alpha"].max_sublinear_tf_idf)
    expected = (1 + math.log(2)) * (1 + math.log(3 / 2))
    assert abs(actual - Decimal(str(expected))) <= Decimal("0.000001")

    # A term in both documents: tf = 1 + ln(1) = 1; idf = ln(3/3) + 1 = 1.
    shared = (_document(1, "gamma"), _document(2, "gamma"))
    aggregates = {item.primary: item for item in aggregate_phrases(shared, _config())}
    assert aggregates["gamma"].max_sublinear_tf_idf == "1.000000"


def test_min_document_frequency_filters_phrases() -> None:
    documents = (_document(1, "alpha beta"), _document(2, "beta"))
    aggregates = {item.primary for item in aggregate_phrases(documents, _config(min_document_frequency=2))}
    assert "beta" in aggregates
    assert "alpha" not in aggregates


def test_validate_grounding_failure_branches(tmp_path: Path) -> None:
    demo = tmp_path / "demo"
    create_demo(demo)
    output = tmp_path / "output"
    run_v0(
        snapshot_path=demo / "snapshot",
        reference_paths=(demo / "reference",),
        config_path=demo / "coe_config.json",
        curation_snapshot="genesis-v0",
        output_path=output,
    )
    from coe.contracts.reference import inspect_reference_bundle

    reference = inspect_reference_bundle(demo / "reference", environment="synthetic")

    unknown_release = (
        {
            "system_uri": "urn:coe:unknown",
            "release_id": "not-a-release",
            "candidates": [],
        },
    )
    with pytest.raises(ContractError) as caught:
        validate_grounding(unknown_release, (reference,))
    assert caught.value.code == "GROUNDING_FAILED"

    foreign_code = (
        {
            "system_uri": reference.system_uri,
            "release_id": reference.release_id,
            "candidates": [{"code": "NOT-IN-CATALOG"}],
        },
    )
    with pytest.raises(ContractError) as caught:
        validate_grounding(foreign_code, (reference,))
    assert caught.value.code == "GROUNDING_FAILED"


def _mini_set_fixture(root: Path) -> tuple[Path, Path, Path]:
    source = root / "normalized"
    source.mkdir()
    header = ["system", "code", "display", "aliases", "source", "version", "effective_date"]
    profiles: dict[str, object] = {}
    for position, name in enumerate(_SET_NAMES):
        csv_path = source / f"{name}.csv"
        with csv_path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream, lineterminator="\n")
            writer.writerow(header)
            writer.writerow([name.upper(), f"X{position}0", f"{name} concept", "", "Fixture", "1", "2026-01-01"])
        raw = csv_path.read_bytes()
        profiles[name] = {
            "alias_count": 0,
            "alias_sources": [{"column": "aliases", "delimiter": "|"}],
            "byte_count": len(raw),
            "code_pattern": "^X[0-9]+$",
            "columns": header,
            "effective_date": "2026-01-01",
            "file_name": f"{name}.csv",
            "language": "en",
            "license_policy": "private-local-analysis",
            "max_aliases_per_code": 8,
            "max_code_length": 8,
            "max_designation_chars": 256,
            "normalized_sha256": hashlib.sha256(raw).hexdigest(),
            "property_columns": [],
            "publisher": "Fixture publisher",
            "required_notices": ["Fixture content."],
            "row_count": 1,
            "source_label": "Fixture",
            "source_uri": f"urn:example:{name}-source",
            "status_rule": {"basis": "fixture membership", "mode": "all_active"},
            "system_label": name.upper(),
            "system_name": f"{name} fixture codes",
            "system_uri": f"urn:example:{name}-codes",
            "version": "1",
        }
    spec_path = root / "spec.json"
    spec_path.write_text(
        json.dumps({"importer_version": "1.0.0", "schema_version": "1.0.0", "terminologies": profiles}),
        encoding="utf-8",
    )
    today = date.today()
    entitlement_path = root / "entitlement.json"
    entitlement_path.write_text(
        json.dumps(
            {
                "asserted_by_role": "project_owner",
                "asserted_on": (today - timedelta(days=1)).isoformat(),
                "assertion_ref": "fixture-entitlement-assertion",
                "controlled_uses": {
                    "analysis_use_permitted": True,
                    "copy_derived_indexes_to_authorized_project_hosts": True,
                    "create_private_derived_indexes": True,
                },
                "license_evidence_status": "not_attached_to_portable_bundle",
                "public_redistribution_status": "not_asserted",
                "review_due_on": (today + timedelta(days=365)).isoformat(),
                "schema_version": "1.0.0",
                "terminologies": list(_SET_NAMES),
            }
        ),
        encoding="utf-8",
    )
    return source, spec_path, entitlement_path


def test_reference_set_build_and_verify_happy_path(tmp_path: Path) -> None:
    source, spec_path, entitlement_path = _mini_set_fixture(tmp_path)
    output = tmp_path / "references"

    built = build_licensed_index_set(
        source_dir=source,
        output_dir=output,
        entitlement_path=entitlement_path,
        specs_path=spec_path,
    )
    assert built["reference_set_manifest_schema_version"] == "1.0.0"
    assert int(built["index_count"]) == 7
    assert built["patient_data_included"] is False

    verified = verify_licensed_index_set(output)
    assert verified["reference_set_manifest_schema_version"] == "1.0.0"
    assert int(verified["index_count"]) == 7
    file_names = sorted(str(record["file_name"]) for record in verified["indexes"])  # type: ignore[index]
    assert file_names == sorted(f"{name}.sqlite3" for name in _SET_NAMES)

    # The set build is atomic and re-runnable only with overwrite.
    with pytest.raises(Exception):
        build_licensed_index_set(
            source_dir=source,
            output_dir=output,
            entitlement_path=entitlement_path,
            specs_path=spec_path,
        )
    rebuilt = build_licensed_index_set(
        source_dir=source,
        output_dir=output,
        entitlement_path=entitlement_path,
        specs_path=spec_path,
        overwrite=True,
    )
    assert int(rebuilt["index_count"]) == 7
