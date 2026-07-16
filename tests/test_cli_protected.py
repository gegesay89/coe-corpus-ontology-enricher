from __future__ import annotations

import csv
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from coe.terminology.licensed import build_licensed_index


def _index(root: Path, name: str = "test") -> Path:
    header = ["system", "code", "display", "aliases", "source", "version", "effective_date"]
    source = root / f"{name}.csv"
    with source.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(header)
        writer.writerow(["TEST", "U1", "Alpha finding", "Alpha", "Private release", "1", "2026-01-01"])
    raw = source.read_bytes()
    profile = {
        "importer_version": "1.0.0",
        "schema_version": "1.0.0",
        "terminologies": {
            name: {
                "alias_count": 1,
                "alias_sources": [{"column": "aliases", "delimiter": "|"}],
                "byte_count": len(raw),
                "code_pattern": "^U[0-9]+$",
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
                "publisher": "Test publisher",
                "required_notices": ["Private test content."],
                "row_count": 1,
                "source_label": "Private release",
                "source_uri": f"urn:example:{name}-source",
                "status_rule": {"basis": "fixture membership", "mode": "all_active"},
                "system_label": "TEST",
                "system_name": "Private test codes",
                "system_uri": f"urn:example:{name}-codes",
                "version": "1",
            }
        },
    }
    spec = root / f"{name}-spec.json"
    spec.write_text(json.dumps(profile), encoding="utf-8")
    index = root / f"{name}.sqlite3"
    build_licensed_index(source, index, name, specs_path=spec, entitlement_ref="TEST-LICENSE")
    return index


def test_cli_protected_run_is_aggregate_only(tmp_path: Path) -> None:
    project = Path(__file__).resolve().parents[1]
    index = _index(tmp_path)
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "patient-name-must-not-export.txt").write_text("Alpha finding.", encoding="utf-8")
    attestation = tmp_path / "attestation.json"
    attestation_value = {
        "approval_refs": {"data_owner": "OWNER-APPROVAL", "privacy": "PRIVACY-APPROVAL"},
        "approved": True,
        "attestation_schema_version": "1.0.0",
        "output_classification": "protected_aggregate",
        "profile": "protected_phi_local",
        "retention_policy_id": "RESTRICTED-LOCAL-30D",
    }
    attestation.write_text(json.dumps(attestation_value), encoding="utf-8")
    output = tmp_path / "out"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "coe",
            "protected",
            "run",
            "--corpus",
            str(corpus),
            "--attestation",
            str(attestation),
            "--index",
            str(index),
            "--output",
            str(output),
        ],
        cwd=project,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout
    assert json.loads(completed.stdout)["status"] == "succeeded"
    exported = b"".join(path.read_bytes() for path in output.iterdir())
    assert b"Alpha finding" not in exported
    assert b"patient-name-must-not-export" not in exported
    rows = [json.loads(line) for line in (output / "coding_counts.jsonl").read_text(encoding="utf-8").splitlines()]
    assert rows[0]["code"] == "U1"
    schemas = project / "schemas/protected/1.0.0"
    cases = [
        ("data_use_attestation.schema.json", attestation_value),
        ("coding_count.schema.json", rows[0]),
        (
            "ambiguity_count.schema.json",
            json.loads((output / "ambiguity_counts.jsonl").read_text(encoding="utf-8").splitlines()[0]),
        ),
        ("run_report.schema.json", json.loads((output / "run_report.json").read_text(encoding="utf-8"))),
    ]
    for schema_name, instance in cases:
        schema = json.loads((schemas / schema_name).read_text(encoding="utf-8"))
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(instance)


def test_cli_protected_verify_uses_seven_verified_sqlite_releases(tmp_path: Path) -> None:
    project = Path(__file__).resolve().parents[1]
    indexes = tuple(_index(tmp_path, f"test{number}") for number in range(7))
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "record.txt").write_text("Alpha finding.", encoding="utf-8")
    attestation = tmp_path / "attestation.json"
    attestation.write_text(
        json.dumps(
            {
                "approval_refs": {"data_owner": "OWNER", "privacy": "PRIVACY"},
                "approved": True,
                "attestation_schema_version": "1.0.0",
                "output_classification": "protected_aggregate",
                "profile": "protected_phi_local",
                "retention_policy_id": "RESTRICTED-LOCAL-30D",
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "out"
    index_arguments = [argument for index in indexes for argument in ("--index", str(index))]
    run = subprocess.run(
        [
            sys.executable,
            "-m",
            "coe",
            "protected",
            "run",
            "--corpus",
            str(corpus),
            "--attestation",
            str(attestation),
            *index_arguments,
            "--output",
            str(output),
        ],
        cwd=project,
        check=False,
        capture_output=True,
        text=True,
    )
    assert run.returncode == 0, run.stdout

    verified = subprocess.run(
        [
            sys.executable,
            "-m",
            "coe",
            "protected",
            "verify",
            "--output",
            str(output),
            *index_arguments,
        ],
        cwd=project,
        check=False,
        capture_output=True,
        text=True,
    )

    assert verified.returncode == 0, verified.stdout
    assert json.loads(verified.stdout) == {
        "ambiguity_row_count": 7,
        "coding_count_row_count": 7,
        "run_fingerprint": json.loads((output / "run_report.json").read_text(encoding="utf-8"))["run_fingerprint"],
        "semantic_output_sha256": json.loads((output / "run_report.json").read_text(encoding="utf-8"))[
            "semantic_output_sha256"
        ],
        "status": "passed",
        "terminology_count": 7,
        "verification_schema_version": "protected-output-verification-1.0.0",
    }
