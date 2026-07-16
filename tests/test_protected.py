from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

import coe.protected as protected
from coe.errors import ContractError, OutputExistsError
from coe.protected import ProtectedLimits, run_protected_local
from coe.terminology.exact import DesignationHit


@dataclass(frozen=True)
class _Reference:
    system_uri: str = "urn:coe:test:protected"
    release_id: str = "protected-release-1"
    code_catalog: frozenset[str] = frozenset({"C1", "C2", "C3"})


class _Index:
    def __init__(self, *, grounded: bool = True) -> None:
        self.reference = _Reference(code_catalog=frozenset({"C1", "C2", "C3"}) if grounded else frozenset())
        self.lookup_calls = 0

    def lookup(self, key: str, *, kind: str, variant: str) -> tuple[DesignationHit, ...]:
        self.lookup_calls += 1
        if kind == "preferred" and key == "heart attack":
            return (DesignationHit(code="C1", method="exact_preferred", variant=variant),)
        if kind == "alias" and key.casefold() == "mi":
            return (
                DesignationHit(code="C2", method="exact_alias", variant=variant),
                DesignationHit(code="C3", method="exact_alias", variant=variant),
            )
        return ()


def _write_attestation(path: Path, *, approved: bool = True, profile: str = "protected_phi_local") -> None:
    path.write_text(
        json.dumps(
            {
                "approval_refs": {
                    "data_owner": "OWNER-SECRET-REF",
                    "privacy": "PRIVACY-SECRET-REF",
                    "security": "SECURITY-SECRET-REF",
                },
                "approved": approved,
                "attestation_schema_version": "1.0.0",
                "output_classification": "protected_aggregate",
                "profile": profile,
                "retention_policy_id": "protected-local-30-day",
            }
        ),
        encoding="utf-8",
    )


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    corpus = tmp_path / "protected-corpus"
    (corpus / "nested").mkdir(parents=True)
    (corpus / "alice_record.txt").write_text("Heart attack. MI. Patient Alice secret-unmapped-value.", encoding="utf-8")
    (corpus / "nested" / "second_record.TXT").write_text("heart attack. MI.", encoding="utf-8")
    attestation = tmp_path / "attestation.json"
    _write_attestation(attestation)
    return corpus, attestation, tmp_path / "protected-output"


def _jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_protected_runner_emits_only_sanitized_aggregate_counts(tmp_path: Path) -> None:
    corpus, attestation, output = _fixture(tmp_path)
    index = _Index()

    summary = run_protected_local(
        corpus_path=corpus,
        attestation_path=attestation,
        indexes=(index,),
        output_path=output,
    )

    assert summary["status"] == "succeeded"
    assert sorted(path.name for path in output.iterdir()) == [
        "ambiguity_counts.jsonl",
        "coding_counts.jsonl",
        "run_report.json",
    ]
    assert _jsonl(output / "coding_counts.jsonl") == [
        {
            "code": "C1",
            "coding_count_schema_version": "1.0.0",
            "distinct_matched_form_count": 2,
            "exact_match_document_count": 2,
            "exact_match_occurrence_count": 2,
            "release_id": "protected-release-1",
            "system_uri": "urn:coe:test:protected",
        }
    ]
    assert _jsonl(output / "ambiguity_counts.jsonl") == [
        {
            "ambiguity_count_schema_version": "1.0.0",
            "ambiguous_document_count": 2,
            "ambiguous_form_count": 1,
            "ambiguous_occurrence_count": 2,
            "release_id": "protected-release-1",
            "system_uri": "urn:coe:test:protected",
        }
    ]
    report = json.loads((output / "run_report.json").read_text(encoding="utf-8"))
    assert report["matching"] == {
        "device": "cpu",
        "method": "exact_preferred_and_alias",
        "nvidia_preflight": "not_required",
    }
    assert report["grounding"]["status"] == "passed"
    assert report["attestation"]["attestation_sha256"] == hashlib.sha256(attestation.read_bytes()).hexdigest()

    emitted = b"".join(path.read_bytes() for path in output.iterdir())
    for forbidden in (
        b"alice_record",
        b"second_record",
        b"Heart attack",
        b"heart attack",
        b"MI",
        b"Alice",
        b"secret-unmapped-value",
        b"OWNER-SECRET-REF",
        b"PRIVACY-SECRET-REF",
        str(corpus).encode(),
    ):
        assert forbidden not in emitted


def test_protected_fingerprint_is_path_free_but_content_sensitive(tmp_path: Path) -> None:
    first_corpus, attestation, first_output = _fixture(tmp_path)
    first = run_protected_local(
        corpus_path=first_corpus,
        attestation_path=attestation,
        indexes=(_Index(),),
        output_path=first_output,
    )

    second_corpus = tmp_path / "renamed-corpus"
    (second_corpus / "different" / "layout").mkdir(parents=True)
    first_documents = sorted(
        (path.read_bytes() for path in first_corpus.rglob("*") if path.is_file()), key=lambda raw: raw
    )
    (second_corpus / "different" / "layout" / "renamed-one.txt").write_bytes(first_documents[1])
    (second_corpus / "renamed-two.txt").write_bytes(first_documents[0])
    second = run_protected_local(
        corpus_path=second_corpus,
        attestation_path=attestation,
        indexes=(_Index(),),
        output_path=tmp_path / "second-output",
    )
    assert first["run_fingerprint"] == second["run_fingerprint"]

    changed = (second_corpus / "renamed-two.txt").read_text(encoding="utf-8") + " unmatched-change."
    (second_corpus / "renamed-two.txt").write_text(changed, encoding="utf-8")
    third = run_protected_local(
        corpus_path=second_corpus,
        attestation_path=attestation,
        indexes=(_Index(),),
        output_path=tmp_path / "third-output",
    )
    assert first["run_fingerprint"] != third["run_fingerprint"]


@pytest.mark.parametrize(
    ("approved", "profile", "expected_code"),
    [
        (False, "protected_phi_local", "ATTESTATION_INVALID"),
        (True, "synthetic", "UNSAFE_PROFILE"),
    ],
)
def test_attestation_fails_before_terminology_lookup(
    tmp_path: Path, approved: bool, profile: str, expected_code: str
) -> None:
    corpus, attestation, output = _fixture(tmp_path)
    _write_attestation(attestation, approved=approved, profile=profile)
    index = _Index()
    with pytest.raises(ContractError) as caught:
        run_protected_local(
            corpus_path=corpus,
            attestation_path=attestation,
            indexes=(index,),
            output_path=output,
        )
    assert caught.value.code == expected_code
    assert index.lookup_calls == 0
    assert not output.exists()


def test_nvidia_preflight_is_fail_closed_and_matching_remains_cpu(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    corpus, attestation, output = _fixture(tmp_path)
    index = _Index()

    def fail_probe(*, require_nvidia: bool = False) -> dict[str, object]:
        assert require_nvidia is True
        raise ContractError("NVIDIA_GPU_REQUIRED", "GPU gate failed.", "runtime", 4)

    monkeypatch.setattr(protected, "probe_host", fail_probe)
    with pytest.raises(ContractError) as caught:
        run_protected_local(
            corpus_path=corpus,
            attestation_path=attestation,
            indexes=(index,),
            output_path=output,
            require_nvidia=True,
        )
    assert caught.value.code == "NVIDIA_GPU_REQUIRED"
    assert index.lookup_calls == 0

    monkeypatch.setattr(protected, "probe_host", lambda **_: {"status": "passed"})
    run_protected_local(
        corpus_path=corpus,
        attestation_path=attestation,
        indexes=(index,),
        output_path=output,
        require_nvidia=True,
    )
    report = json.loads((output / "run_report.json").read_text(encoding="utf-8"))
    assert report["matching"]["nvidia_preflight"] == "passed"
    assert report["matching"]["device"] == "cpu"


def test_symlinks_and_windows_reparse_points_are_rejected(tmp_path: Path) -> None:
    corpus, attestation, output = _fixture(tmp_path)
    external = tmp_path / "external.txt"
    external.write_text("heart attack", encoding="utf-8")
    try:
        (corpus / "linked.txt").symlink_to(external)
    except OSError:
        pytest.skip("Symbolic links are unavailable in this environment")
    with pytest.raises(ContractError) as caught:
        run_protected_local(
            corpus_path=corpus,
            attestation_path=attestation,
            indexes=(_Index(),),
            output_path=output,
        )
    assert caught.value.code == "REPARSE_POINT"

    regular = tmp_path / "regular"
    regular.write_text("x", encoding="utf-8")
    fake_stat = SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=0x400)
    assert protected._is_reparse_or_link(regular, fake_stat) is True


def test_single_hard_link_to_external_file_is_rejected(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    external = tmp_path / "external.txt"
    external.write_text("licensed phrase", encoding="utf-8")
    try:
        os.link(external, corpus / "linked.txt")
    except OSError:
        pytest.skip("Hard links are unavailable in this environment")

    with pytest.raises(ContractError, match="Hard-linked corpus files"):
        protected._collect_text_files(corpus, ProtectedLimits())


@pytest.mark.parametrize(
    "limits",
    [
        ProtectedLimits(max_files=1),
        ProtectedLimits(max_file_bytes=8),
        ProtectedLimits(max_tokens_per_file=2),
        ProtectedLimits(max_ngrams_per_file=2),
        ProtectedLimits(max_unique_phrases=1),
    ],
)
def test_corpus_resource_limits_fail_without_output(tmp_path: Path, limits: ProtectedLimits) -> None:
    corpus, attestation, output = _fixture(tmp_path)
    with pytest.raises(ContractError) as caught:
        run_protected_local(
            corpus_path=corpus,
            attestation_path=attestation,
            indexes=(_Index(),),
            output_path=output,
            limits=limits,
        )
    assert caught.value.code == "RESOURCE_LIMIT"
    assert not output.exists()


def test_total_processing_limits_and_invalid_utf8_fail_closed(tmp_path: Path) -> None:
    _, attestation, output = _fixture(tmp_path)
    corpus = tmp_path / "total-limit-corpus"
    corpus.mkdir()
    (corpus / "one.txt").write_text("one two", encoding="utf-8")
    (corpus / "two.txt").write_text("three four", encoding="utf-8")
    limits = ProtectedLimits(max_tokens_per_file=3, max_total_tokens=3, max_ngram_tokens=1)
    with pytest.raises(ContractError) as caught:
        run_protected_local(
            corpus_path=corpus,
            attestation_path=attestation,
            indexes=(_Index(),),
            output_path=output,
            limits=limits,
        )
    assert caught.value.code == "RESOURCE_LIMIT"

    for path in corpus.iterdir():
        path.unlink()
    (corpus / "invalid.txt").write_bytes(b"\xff\xfe")
    with pytest.raises(ContractError) as caught:
        run_protected_local(
            corpus_path=corpus,
            attestation_path=attestation,
            indexes=(_Index(),),
            output_path=output,
        )
    assert caught.value.code == "UTF8_INVALID"
    assert not output.exists()


def test_grounding_and_candidate_collision_fail_closed(tmp_path: Path) -> None:
    corpus, attestation, output = _fixture(tmp_path)
    with pytest.raises(ContractError) as caught:
        run_protected_local(
            corpus_path=corpus,
            attestation_path=attestation,
            indexes=(_Index(grounded=False),),
            output_path=output,
        )
    assert caught.value.code == "GROUNDING_FAILED"

    with pytest.raises(ContractError) as caught:
        run_protected_local(
            corpus_path=corpus,
            attestation_path=attestation,
            indexes=(_Index(),),
            output_path=output,
            limits=ProtectedLimits(max_candidates_per_phrase_system=1),
        )
    assert caught.value.code == "RESOURCE_LIMIT"
    assert not output.exists()


def test_output_boundary_and_atomic_failure_preserve_prior_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    corpus, attestation, output = _fixture(tmp_path)
    with pytest.raises(ContractError) as caught:
        run_protected_local(
            corpus_path=corpus,
            attestation_path=attestation,
            indexes=(_Index(),),
            output_path=corpus / "output",
        )
    assert caught.value.code == "PATH_INVALID"

    ancestor_output = tmp_path / "ancestor-output"
    nested_corpus = ancestor_output / "corpus"
    nested_corpus.mkdir(parents=True)
    protected_file = nested_corpus / "must-survive.txt"
    protected_file.write_text("heart attack", encoding="utf-8")
    with pytest.raises(ContractError) as caught:
        run_protected_local(
            corpus_path=nested_corpus,
            attestation_path=attestation,
            indexes=(_Index(),),
            output_path=ancestor_output,
            overwrite=True,
        )
    assert caught.value.code == "PATH_INVALID"
    assert protected_file.read_text(encoding="utf-8") == "heart attack"

    run_protected_local(
        corpus_path=corpus,
        attestation_path=attestation,
        indexes=(_Index(),),
        output_path=output,
    )
    previous = {path.name: path.read_bytes() for path in output.iterdir()}
    with pytest.raises(OutputExistsError):
        run_protected_local(
            corpus_path=corpus,
            attestation_path=attestation,
            indexes=(_Index(),),
            output_path=output,
        )

    def fail_report(*_: object, **__: object) -> object:
        raise RuntimeError("injected materialization failure")

    monkeypatch.setattr(protected, "write_json", fail_report)
    with pytest.raises(RuntimeError):
        run_protected_local(
            corpus_path=corpus,
            attestation_path=attestation,
            indexes=(_Index(),),
            output_path=output,
            overwrite=True,
        )
    assert {path.name: path.read_bytes() for path in output.iterdir()} == previous
    assert not any(path.name.startswith(f".{output.name}.tmp-") for path in output.parent.iterdir())


def test_limit_contract_and_index_metadata_are_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(ContractError):
        ProtectedLimits(max_ngram_tokens=9)
    with pytest.raises(ContractError):
        ProtectedLimits(max_total_bytes=5, max_file_bytes=6)

    corpus, attestation, output = _fixture(tmp_path)
    with pytest.raises(ContractError) as caught:
        run_protected_local(
            corpus_path=corpus,
            attestation_path=attestation,
            indexes=(),
            output_path=output,
        )
    assert caught.value.code == "TERMINOLOGY_INVALID"
    assert not output.exists()
