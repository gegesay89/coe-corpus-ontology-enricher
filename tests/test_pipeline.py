from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from coe.benchmark import benchmark_reference
from coe.canonical import canonical_json_line, sha256_bytes, sha256_canonical
from coe.contracts.reference import inspect_reference_bundle
from coe.demo import create_demo
from coe.errors import ContractError, OutputExistsError
from coe.pipeline import run_v0


def _run(root: Path, output: Path, *, overwrite: bool = False) -> dict[str, object]:
    return run_v0(
        snapshot_path=root / "snapshot",
        reference_paths=(root / "reference",),
        config_path=root / "coe_config.json",
        curation_snapshot="genesis-v0",
        output_path=output,
        overwrite=overwrite,
    )


def _jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_exact_matching_preserves_ambiguity_and_grounding(demo_root: Path, tmp_path: Path) -> None:
    output = tmp_path / "out"
    _run(demo_root, output)
    rows = _jsonl(output / "candidate_sets.jsonl")
    by_phrase = {str(row["primary_normalized_form"]): row for row in rows}

    assert by_phrase["Atrial fibrillation"]["algorithmic_outcome"] == "grounded_unique"
    assert by_phrase["Type 2 diabetes"]["algorithmic_outcome"] == "grounded_unique"
    assert by_phrase["Blue toe pattern"]["algorithmic_outcome"] == "unmapped"
    mi = by_phrase["MI"]
    assert mi["algorithmic_outcome"] == "grounded_ambiguous"
    assert [candidate["code"] for candidate in mi["candidates"]] == ["U200", "U201"]
    assert all(row["acceptance_state"] == "pending" for row in rows if row["algorithmic_outcome"] != "unmapped")
    assert by_phrase["Blue toe pattern"]["acceptance_state"] is None

    catalog = inspect_reference_bundle(demo_root / "reference").code_catalog
    emitted = {candidate["code"] for row in rows for candidate in row["candidates"]}
    assert emitted <= catalog
    assert "U202" not in emitted


def test_equivalent_reruns_are_byte_identical(tmp_path: Path) -> None:
    first_demo = tmp_path / "demo-one"
    second_demo = tmp_path / "demo-two"
    create_demo(first_demo)
    create_demo(second_demo)
    first_summary = _run(first_demo, tmp_path / "out-one")
    second_summary = _run(second_demo, tmp_path / "out-two")
    assert first_summary["run_fingerprint"] == second_summary["run_fingerprint"]
    assert first_summary["semantic_content_sha256"] == second_summary["semantic_content_sha256"]
    first_files = sorted(path.name for path in (tmp_path / "out-one").iterdir())
    second_files = sorted(path.name for path in (tmp_path / "out-two").iterdir())
    assert first_files == second_files
    for filename in first_files:
        assert (tmp_path / "out-one" / filename).read_bytes() == (tmp_path / "out-two" / filename).read_bytes()


def test_artifact_manifest_hashes_actual_bytes_and_exports_no_document_ids(demo_root: Path, tmp_path: Path) -> None:
    output = tmp_path / "out"
    _run(demo_root, output)
    manifest = json.loads((output / "artifact_manifest.json").read_text(encoding="utf-8"))
    for descriptor in manifest["files"]:
        raw = (output / descriptor["path"]).read_bytes()
        assert descriptor["byte_count"] == len(raw)
        assert descriptor["sha256"] == sha256_bytes(raw)
    expected_semantic_digest = sha256_canonical(
        {
            "digest_schema_version": "coe-v0-semantic-artifacts-v1",
            "files": manifest["files"],
            "run_fingerprint": manifest["run_fingerprint"],
        },
        domain=b"coe.semantic-artifacts.v0",
    )
    assert manifest["semantic_content_sha256"] == expected_semantic_digest
    exported = b"".join(path.read_bytes() for path in output.iterdir())
    assert str(demo_root).encode("utf-8") not in exported
    for document in _jsonl(demo_root / "snapshot/documents.jsonl"):
        assert str(document["doc_id"]).encode("utf-8") not in exported


def test_semantic_config_change_changes_run_fingerprint(demo_root: Path, tmp_path: Path) -> None:
    first = _run(demo_root, tmp_path / "out-one")
    config_path = demo_root / "coe_config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["config_id"] = "offline-synthetic-demo-v0-reconfigured"
    config_path.write_bytes(canonical_json_line(config))
    second = _run(demo_root, tmp_path / "out-two")
    assert first["run_fingerprint"] != second["run_fingerprint"]


def test_failed_preflight_leaves_no_partial_output(demo_root: Path, tmp_path: Path) -> None:
    document = next((demo_root / "snapshot" / "documents").iterdir())
    document.write_text("corrupt", encoding="utf-8")
    output = tmp_path / "out"
    with pytest.raises(ContractError):
        _run(demo_root, output)
    assert not output.exists()


def test_failed_overwrite_preserves_prior_output(demo_root: Path, tmp_path: Path) -> None:
    output = tmp_path / "out"
    output.mkdir()
    marker = output / "marker.txt"
    marker.write_text("keep", encoding="utf-8")
    document = next((demo_root / "snapshot" / "documents").iterdir())
    document.write_text("corrupt", encoding="utf-8")
    with pytest.raises(ContractError):
        _run(demo_root, output, overwrite=True)
    assert marker.read_text(encoding="utf-8") == "keep"


def test_existing_output_requires_explicit_overwrite(demo_root: Path, tmp_path: Path) -> None:
    output = tmp_path / "out"
    _run(demo_root, output)
    with pytest.raises(OutputExistsError):
        _run(demo_root, output)


def test_cli_runs_clean_fixture_end_to_end(tmp_path: Path) -> None:
    project = Path(__file__).resolve().parents[1]
    demo = tmp_path / "cli-demo"
    output = tmp_path / "cli-out"
    create = subprocess.run(
        [sys.executable, "-m", "coe", "demo", "create", str(demo)],
        cwd=project,
        check=False,
        capture_output=True,
        text=True,
    )
    assert create.returncode == 0, create.stdout
    run = subprocess.run(
        [
            sys.executable,
            "-m",
            "coe",
            "run",
            "--snapshot",
            str(demo / "snapshot"),
            "--reference",
            str(demo / "reference"),
            "--config",
            str(demo / "coe_config.json"),
            "--curation-snapshot",
            "genesis-v0",
            "--output",
            str(output),
        ],
        cwd=project,
        check=False,
        capture_output=True,
        text=True,
    )
    assert run.returncode == 0, run.stdout
    assert json.loads(run.stdout)["status"] == "succeeded"
    assert (output / "artifact_manifest.json").is_file()


def test_committed_json_schemas_are_valid_json() -> None:
    project = Path(__file__).resolve().parents[1]
    schemas = sorted((project / "schemas").rglob("*.json"))
    assert schemas
    for schema in schemas:
        value = json.loads(schema.read_text(encoding="utf-8"))
        assert value["$schema"] == "https://json-schema.org/draft/2020-12/schema"


def test_reference_benchmark_is_bounded_and_machine_readable(demo_root: Path) -> None:
    result = benchmark_reference(demo_root / "reference", lookup_count=100)
    assert result["status"] == "completed"
    assert result["lookup_count"] == 100
    assert result["lookup_hit_count"] >= 100
    assert result["fixture_only"] is True


def test_versioned_schemas_validate_demo_inputs_and_outputs(demo_root: Path, tmp_path: Path) -> None:
    project = Path(__file__).resolve().parents[1]
    output = tmp_path / "schema-output"
    _run(demo_root, output)
    cases: list[tuple[Path, object]] = [
        (
            project / "schemas/snapshot/1.0.0/snapshot_manifest.schema.json",
            json.loads((demo_root / "snapshot/snapshot_manifest.json").read_text(encoding="utf-8")),
        ),
        (
            project / "schemas/snapshot/1.0.0/deidentification_attestation.schema.json",
            json.loads((demo_root / "snapshot/deidentification_attestation.json").read_text(encoding="utf-8")),
        ),
        (
            project / "schemas/reference/1.0.0/terminology_release_manifest.schema.json",
            json.loads((demo_root / "reference/terminology_release_manifest.json").read_text(encoding="utf-8")),
        ),
        (
            project / "schemas/config/1.1.0/analysis_config.schema.json",
            json.loads((demo_root / "coe_config.json").read_text(encoding="utf-8")),
        ),
        (
            project / "schemas/run/1.0.0/run_manifest.schema.json",
            json.loads((output / "run_manifest.json").read_text(encoding="utf-8")),
        ),
        (
            project / "schemas/run/1.0.0/run_report.schema.json",
            json.loads((output / "run_report.json").read_text(encoding="utf-8")),
        ),
        (
            project / "schemas/run/1.0.0/artifact_manifest.schema.json",
            json.loads((output / "artifact_manifest.json").read_text(encoding="utf-8")),
        ),
    ]
    document_schema = project / "schemas/snapshot/1.0.0/document.schema.json"
    cases.extend((document_schema, row) for row in _jsonl(demo_root / "snapshot/documents.jsonl"))
    coding_schema = project / "schemas/reference/1.0.0/coding.schema.json"
    cases.extend((coding_schema, row) for row in _jsonl(demo_root / "reference/codings.jsonl"))
    designation_schema = project / "schemas/reference/1.0.0/designation.schema.json"
    cases.extend((designation_schema, row) for row in _jsonl(demo_root / "reference/designations.jsonl"))
    phrase_schema = project / "schemas/run/1.0.0/phrase_aggregate.schema.json"
    cases.extend((phrase_schema, row) for row in _jsonl(output / "phrase_aggregates.jsonl"))
    candidate_schema = project / "schemas/run/1.1.0/candidate_set.schema.json"
    cases.extend((candidate_schema, row) for row in _jsonl(output / "candidate_sets.jsonl"))
    for schema_path, instance in cases:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(instance)
