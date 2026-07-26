from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

import pytest

from coe.canonical import canonical_json_line
from coe.errors import ContractError
from coe.protected import ProtectedLimits, run_protected_local
from coe.protected_verify import verify_protected_output
from coe.terminology.exact import DesignationHit


@dataclass(frozen=True)
class _Reference:
    system_uri: str
    release_id: str
    code_catalog: frozenset[str]


class _Index:
    def __init__(self, number: int, *, grounded: bool = True) -> None:
        codes = frozenset({f"C{number}A", f"C{number}B"}) if grounded else frozenset()
        self.number = number
        self.reference = _Reference(f"urn:coe:test:system:{number}", f"release-{number}", codes)

    def lookup(self, key: str, *, kind: str, variant: str) -> tuple[DesignationHit, ...]:
        if self.number == 0 and kind == "preferred" and key == "heart attack":
            return (DesignationHit("C0A", "exact_preferred", variant),)
        if self.number == 1 and kind == "alias" and key.casefold() == "mi":
            return (
                DesignationHit("C1A", "exact_alias", variant),
                DesignationHit("C1B", "exact_alias", variant),
            )
        return ()


def _write_attestation(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "approval_refs": {"data_owner": "OWNER", "privacy": "PRIVACY", "security": "SECURITY"},
                "approved": True,
                "attestation_schema_version": "1.1.0",
                "lexical_output_approved": False,
                "output_classification": "protected_aggregate",
                "profile": "protected_phi_local",
                "retention_policy_id": "local-30-days",
            }
        ),
        encoding="utf-8",
    )


def _valid_output(tmp_path: Path) -> tuple[Path, tuple[_Index, ...]]:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "record.txt").write_text("Heart attack. MI.", encoding="utf-8")
    attestation = tmp_path / "attestation.json"
    _write_attestation(attestation)
    output = tmp_path / "output"
    indexes = tuple(_Index(number) for number in range(7))
    run_protected_local(
        corpus_path=corpus,
        attestation_path=attestation,
        indexes=indexes,
        output_path=output,
        limits=ProtectedLimits(min_cell_document_count=1),
    )
    return output, indexes


def _read_report(output: Path) -> dict[str, object]:
    return json.loads((output / "run_report.json").read_text(encoding="utf-8"))


def _write_report(output: Path, report: dict[str, object]) -> None:
    (output / "run_report.json").write_bytes(canonical_json_line(report))  # type: ignore[arg-type]


def test_verify_protected_output_recomputes_integrity_and_grounding(tmp_path: Path) -> None:
    output, indexes = _valid_output(tmp_path)

    result = verify_protected_output(output_path=output, indexes=indexes)

    assert result == {
        "ambiguity_row_count": 7,
        "association_row_count": 0,
        "candidate_term_row_count": 0,
        "coding_count_row_count": 1,
        "lexical_form_row_count": 0,
        "run_fingerprint": _read_report(output)["run_fingerprint"],
        "semantic_output_sha256": _read_report(output)["semantic_output_sha256"],
        "status": "passed",
        "terminology_count": 7,
        "verification_schema_version": "protected-output-verification-1.1.0",
    }


def test_verify_requires_the_releases_the_run_was_bound_to(tmp_path: Path) -> None:
    output, indexes = _valid_output(tmp_path)

    with pytest.raises(ContractError) as captured:
        verify_protected_output(output_path=output, indexes=indexes[:-1])

    assert captured.value.code == "TERMINOLOGY_MISMATCH"


def test_verify_accepts_runs_with_fewer_than_seven_releases(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "record.txt").write_text("Heart attack. MI.", encoding="utf-8")
    attestation = tmp_path / "attestation.json"
    _write_attestation(attestation)
    output = tmp_path / "small-output"
    indexes = (_Index(0), _Index(1))
    run_protected_local(
        corpus_path=corpus,
        attestation_path=attestation,
        indexes=indexes,
        output_path=output,
        limits=ProtectedLimits(min_cell_document_count=1),
    )

    result = verify_protected_output(output_path=output, indexes=indexes)

    assert result["status"] == "passed"
    assert result["terminology_count"] == 2


def test_verify_rejects_non_exact_inventory(tmp_path: Path) -> None:
    output, indexes = _valid_output(tmp_path)
    (output / "unexpected.txt").write_text("must fail", encoding="utf-8")

    with pytest.raises(ContractError) as captured:
        verify_protected_output(output_path=output, indexes=indexes)

    assert captured.value.code == "INVENTORY_INVALID"


def test_verify_rejects_hardlinked_artifact(tmp_path: Path) -> None:
    output, indexes = _valid_output(tmp_path)
    os.link(output / "coding_counts.jsonl", tmp_path / "outside-link.jsonl")

    with pytest.raises(ContractError) as captured:
        verify_protected_output(output_path=output, indexes=indexes)

    assert captured.value.code == "HARDLINK"


def test_verify_rejects_symlinked_artifact(tmp_path: Path) -> None:
    output, indexes = _valid_output(tmp_path)
    artifact = output / "coding_counts.jsonl"
    outside = tmp_path / "outside.jsonl"
    outside.write_bytes(artifact.read_bytes())
    artifact.unlink()
    artifact.symlink_to(outside)

    with pytest.raises(ContractError) as captured:
        verify_protected_output(output_path=output, indexes=indexes)

    assert captured.value.code == "REPARSE_POINT"


def test_verify_rejects_noncanonical_report(tmp_path: Path) -> None:
    output, indexes = _valid_output(tmp_path)
    report = _read_report(output)
    (output / "run_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    with pytest.raises(ContractError) as captured:
        verify_protected_output(output_path=output, indexes=indexes)

    assert captured.value.code == "CANONICALIZATION_FAILED"


def test_verify_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    output, indexes = _valid_output(tmp_path)
    raw = (output / "run_report.json").read_bytes()
    (output / "run_report.json").write_bytes(b'{"status":"succeeded","status":"succeeded"}\n')

    with pytest.raises(ContractError) as captured:
        verify_protected_output(output_path=output, indexes=indexes)

    assert captured.value.code == "DUPLICATE_JSON_KEY"
    assert raw


def test_verify_rejects_artifact_digest_or_count_mismatch(tmp_path: Path) -> None:
    output, indexes = _valid_output(tmp_path)
    report = _read_report(output)
    report["artifacts"][0]["row_count"] = 6  # type: ignore[index]
    _write_report(output, report)

    with pytest.raises(ContractError) as captured:
        verify_protected_output(output_path=output, indexes=indexes)

    assert captured.value.code == "ARTIFACT_INTEGRITY_FAILED"


def test_verify_rejects_semantic_digest_mismatch(tmp_path: Path) -> None:
    output, indexes = _valid_output(tmp_path)
    report = _read_report(output)
    report["semantic_output_sha256"] = "0" * 64
    _write_report(output, report)

    with pytest.raises(ContractError) as captured:
        verify_protected_output(output_path=output, indexes=indexes)

    assert captured.value.code == "SEMANTIC_INTEGRITY_FAILED"


def test_verify_rejects_run_fingerprint_mismatch(tmp_path: Path) -> None:
    output, indexes = _valid_output(tmp_path)
    report = _read_report(output)
    report["run_fingerprint"] = "0" * 64
    _write_report(output, report)

    with pytest.raises(ContractError) as captured:
        verify_protected_output(output_path=output, indexes=indexes)

    assert captured.value.code == "RUN_INTEGRITY_FAILED"


def test_verify_rejects_coding_outside_catalog_without_leaking_value_or_path(tmp_path: Path) -> None:
    output, indexes = _valid_output(tmp_path)
    ungrounded = (_Index(0, grounded=False), *indexes[1:])

    with pytest.raises(ContractError) as captured:
        verify_protected_output(output_path=output, indexes=ungrounded)

    assert captured.value.code == "GROUNDING_FAILED"
    assert "C0A" not in str(captured.value)
    assert str(output) not in str(captured.value)


def test_verify_rejects_ambiguity_identity_mismatch(tmp_path: Path) -> None:
    output, indexes = _valid_output(tmp_path)
    artifact = output / "ambiguity_counts.jsonl"
    rows = [json.loads(line) for line in artifact.read_text(encoding="utf-8").splitlines()]
    rows[0]["release_id"] = "wrong-release"
    raw = b"".join(canonical_json_line(row) for row in rows)
    artifact.write_bytes(raw)
    report = _read_report(output)
    report["artifacts"][0]["byte_count"] = len(raw)  # type: ignore[index]
    report["artifacts"][0]["sha256"] = __import__("hashlib").sha256(raw).hexdigest()  # type: ignore[index]
    _write_report(output, report)

    with pytest.raises(ContractError) as captured:
        verify_protected_output(output_path=output, indexes=indexes)

    assert captured.value.code == "GROUNDING_FAILED"


def test_verify_rejects_inconsistent_processing_and_grounding_totals(tmp_path: Path) -> None:
    output, indexes = _valid_output(tmp_path)
    report = _read_report(output)
    report["grounding"]["candidate_count_checked"] = 0  # type: ignore[index]
    _write_report(output, report)

    with pytest.raises(ContractError) as captured:
        verify_protected_output(output_path=output, indexes=indexes)

    assert captured.value.code == "TOTALS_INVALID"


def test_verify_rejects_oversized_jsonl_row_before_parsing(tmp_path: Path) -> None:
    output, indexes = _valid_output(tmp_path)
    (output / "coding_counts.jsonl").write_bytes(b"{" + (b"x" * 16_384) + b"}\n")

    with pytest.raises(ContractError) as captured:
        verify_protected_output(output_path=output, indexes=indexes)

    assert captured.value.code == "RESOURCE_LIMIT"
