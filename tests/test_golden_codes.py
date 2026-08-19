"""Golden known-code smoke: clinical codes through the licensed SQLite path.

The condition and observation fixtures use a handful of widely published clinical
codes and their common clinical terms, so a systematic import corruption (for
example a swapped code/display column mapping) cannot pass unnoticed the way a
purely self-referential round-trip can. The procedure fixture is synthetic: it
exists to exercise a second code shape and carries no publisher descriptors.
"""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

from coe.protected import ProtectedLimits, run_protected_local
from coe.protected_verify import verify_protected_output
from coe.terminology.licensed import SQLiteTerminologyIndex, build_licensed_index

_GOLDEN = {
    "snomedmini": {
        "system_label": "SNOMEDCT-MINI",
        "system_uri": "http://snomed.info/sct",
        "code_pattern": "^[0-9]{6,18}$",
        "rows": [
            ("386661006", "Fever", "febrile|pyrexia"),
            ("73211009", "Diabetes mellitus", "DM - diabetes mellitus"),
            ("38341003", "Hypertensive disorder", "hypertension|high blood pressure"),
            ("22298006", "Myocardial infarction", "heart attack"),
        ],
    },
    "procmini": {
        "system_label": "PROC-MINI",
        "system_uri": "urn:example:procedure-fixture",
        "code_pattern": "^[0-9]{5}$",
        "rows": [
            ("10001", "Fixture procedure alpha", ""),
            ("10002", "Fixture procedure beta", "fixture procedure"),
        ],
    },
    "loincmini": {
        "system_label": "LOINC-MINI",
        "system_uri": "http://loinc.org",
        "code_pattern": "^[0-9]{1,5}-[0-9]$",
        "rows": [
            ("8302-2", "Body height", "height"),
            ("29463-7", "Body weight", "weight"),
        ],
    },
}


def _build_index(root: Path, name: str) -> Path:
    profile = _GOLDEN[name]
    header = ["system", "code", "display", "aliases", "source", "version", "effective_date"]
    source = root / f"{name}.csv"
    with source.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(header)
        for code, display, aliases in profile["rows"]:
            writer.writerow([profile["system_label"], code, display, aliases, "Golden fixture", "1", "2026-01-01"])
    raw = source.read_bytes()
    spec = {
        "importer_version": "1.0.0",
        "schema_version": "1.0.0",
        "terminologies": {
            name: {
                "alias_count": sum(len([a for a in aliases.split("|") if a]) for _, _, aliases in profile["rows"]),
                "alias_sources": [{"column": "aliases", "delimiter": "|"}],
                "byte_count": len(raw),
                "code_pattern": profile["code_pattern"],
                "columns": header,
                "effective_date": "2026-01-01",
                "file_name": f"{name}.csv",
                "language": "en",
                "license_policy": "private-local-analysis",
                "max_aliases_per_code": 8,
                "max_code_length": 18,
                "max_designation_chars": 256,
                "normalized_sha256": hashlib.sha256(raw).hexdigest(),
                "property_columns": [],
                "publisher": "Golden fixture publisher",
                "required_notices": ["Fixture content for regression testing."],
                "row_count": len(profile["rows"]),
                "source_label": "Golden fixture",
                "source_uri": f"urn:example:{name}-source",
                "status_rule": {"basis": "fixture membership", "mode": "all_active"},
                "system_label": profile["system_label"],
                "system_name": name,
                "system_uri": profile["system_uri"],
                "version": "1",
            }
        },
    }
    spec_path = root / f"{name}-spec.json"
    spec_path.write_text(json.dumps(spec), encoding="utf-8")
    index = root / f"{name}.sqlite3"
    build_licensed_index(source, index, name, specs_path=spec_path, entitlement_ref="GOLDEN-FIXTURE-LICENSE")
    return index


def _attestation(path: Path) -> None:
    path.write_text(
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


def test_golden_clinical_codes_ground_end_to_end(tmp_path: Path) -> None:
    indexes = tuple(_build_index(tmp_path, name) for name in ("snomedmini", "procmini", "loincmini"))
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    for number in range(3):
        (corpus / f"note-{number}.txt").write_text(
            "Patient reports fever and diabetes mellitus. HTN noted. Body height recorded. Prior heart attack.",
            encoding="utf-8",
        )
    attestation = tmp_path / "attestation.json"
    _attestation(attestation)
    output = tmp_path / "output"

    with (
        SQLiteTerminologyIndex(indexes[0]) as snomed,
        SQLiteTerminologyIndex(indexes[1]) as procedures,
        SQLiteTerminologyIndex(indexes[2]) as loinc,
    ):
        run_protected_local(
            corpus_path=corpus,
            attestation_path=attestation,
            indexes=(snomed, procedures, loinc),
            output_path=output,
            limits=ProtectedLimits(min_cell_document_count=3),
        )
        verified = verify_protected_output(output_path=output, indexes=(snomed, procedures, loinc))
    assert verified["status"] == "passed"

    coding = {
        row["code"]: row
        for row in (
            json.loads(line) for line in (output / "coding_counts.jsonl").read_text(encoding="utf-8").splitlines()
        )
    }
    # Golden groundings: fever, diabetes mellitus, hypertension (via the HTN
    # abbreviation variant), myocardial infarction (via the "heart attack"
    # alias), and LOINC body height.
    assert coding["386661006"]["exact_match_document_count"] == 3
    assert coding["73211009"]["exact_match_document_count"] == 3
    assert coding["38341003"]["exact_match_document_count"] == 3
    assert coding["22298006"]["exact_match_document_count"] == 3
    assert coding["8302-2"]["exact_match_document_count"] == 3

    lexical = [json.loads(line) for line in (output / "lexical_forms.jsonl").read_text(encoding="utf-8").splitlines()]
    methods = {(row["code"], row["form"]): row["match_method"] for row in lexical}
    assert methods[("38341003", "HTN")] == "variant_abbreviation"
    assert methods[("22298006", "heart attack")] == "exact_alias"
    # "Prior heart attack" is a past mention, so that form is historical while
    # the affirmed findings stay current-clinical.
    contexts_by_form = {(row["code"], row["form"]): row["context"] for row in lexical}
    assert contexts_by_form[("22298006", "heart attack")] == "historical"
    assert contexts_by_form[("386661006", "fever")] == "current_clinical"
    assert contexts_by_form[("38341003", "HTN")] == "current_clinical"

    context = {
        (row["code"], row["context"])
        for row in (
            json.loads(line) for line in (output / "context_counts.jsonl").read_text(encoding="utf-8").splitlines()
        )
    }
    assert ("386661006", "current_clinical") in context
    assert ("22298006", "historical") in context
    # The negation-free golden note produces no negated evidence at all.
    assert not any(label == "negated" for _, label in context)

    associations = [
        json.loads(line) for line in (output / "associations.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    pairs = {(row["code_a"], row["code_b"]) for row in associations}
    assert ("386661006", "73211009") in pairs


def test_golden_codes_direct_lookup_smoke(tmp_path: Path) -> None:
    index_path = _build_index(tmp_path, "snomedmini")
    with SQLiteTerminologyIndex(index_path) as index:
        fever = index.lookup("fever", kind="preferred", variant="casefold")
        assert [hit.code for hit in fever] == ["386661006"]
        diabetes = index.lookup("diabetes mellitus", kind="preferred", variant="casefold")
        assert [hit.code for hit in diabetes] == ["73211009"]
        pyrexia = index.lookup("pyrexia", kind="alias", variant="casefold")
        assert [hit.code for hit in pyrexia] == ["386661006"]
        assert index.lookup("no such term", kind="preferred", variant="casefold") == ()
