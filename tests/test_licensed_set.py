from __future__ import annotations

import json
from pathlib import Path

import pytest

from coe.errors import ContractError
from coe.terminology import licensed_set


def test_set_verifier_rejects_non_directory(tmp_path: Path) -> None:
    path = tmp_path / "missing"
    with pytest.raises(ContractError, match="missing or unsafe"):
        licensed_set.verify_licensed_index_set(path)


def test_entitlement_is_bound_into_set_manifest(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    class Assertion:
        assertion_ref = "approval"
        assertion_sha256 = "a" * 64
        asserted_on = "2026-07-16"
        review_due_on = "2027-07-16"

    class Metadata:
        terminology = "test"
        system_uri = "urn:test"
        system_name = "Test"
        version = "1"
        effective_date = "2026-01-01"
        release_id = "release"
        source_sha256 = "b" * 64
        profile_sha256 = "c" * 64
        content_set_sha256 = "d" * 64
        manifest_sha256 = "e" * 64
        index_sha256 = "f" * 64
        code_count = 1
        alias_count = 0
        designation_count = 1
        active_count = 1
        inactive_count = 0

    monkeypatch.setattr(licensed_set, "inspect_terminology_entitlement", lambda _: Assertion())
    (tmp_path / "test.sqlite3").write_bytes(b"index")
    entitlement = tmp_path / "source-entitlement.json"
    entitlement.write_text("{}\n", encoding="utf-8")
    manifest = licensed_set._write_set_manifest(tmp_path, (Metadata(),), entitlement)
    assert manifest["entitlement"]["assertion_sha256"] == "a" * 64  # type: ignore[index]
    assert manifest["patient_data_included"] is False
    parsed = json.loads((tmp_path / licensed_set.SET_MANIFEST).read_text(encoding="utf-8"))
    assert parsed == manifest


def test_overwrite_rejects_source_nested_below_output_before_any_mutation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    output = tmp_path / "reference-set"
    source = output / "licensed-sources"
    source.mkdir(parents=True)
    sentinel = source / "must-survive.csv"
    sentinel.write_bytes(b"licensed-source-sentinel")

    def unexpected_call(*_args: object, **_kwargs: object) -> object:
        pytest.fail("overlap validation must run before profile or entitlement loading")

    monkeypatch.setattr(licensed_set, "load_terminology_specs", unexpected_call)
    monkeypatch.setattr(licensed_set, "inspect_terminology_entitlement", unexpected_call)
    with pytest.raises(ContractError, match="PATH_OVERLAP"):
        licensed_set.build_licensed_index_set(
            source_dir=source,
            output_dir=output,
            entitlement_path=tmp_path / "unused-entitlement.json",
            overwrite=True,
        )
    assert sentinel.read_bytes() == b"licensed-source-sentinel"
    assert source.is_dir()
    assert output.is_dir()


def test_rejects_output_nested_below_source(tmp_path: Path) -> None:
    source = tmp_path / "licensed-sources"
    source.mkdir()
    output = source / "derived" / "reference-set"
    with pytest.raises(ContractError, match="PATH_OVERLAP"):
        licensed_set.build_licensed_index_set(
            source_dir=source,
            output_dir=output,
            entitlement_path=tmp_path / "unused-entitlement.json",
        )
    assert not output.exists()


def test_rejects_equal_source_and_output_after_realpath_resolution(tmp_path: Path) -> None:
    source = tmp_path / "licensed-sources"
    source.mkdir()
    equivalent_output = source / "not-created" / ".."
    with pytest.raises(ContractError, match="PATH_OVERLAP"):
        licensed_set.build_licensed_index_set(
            source_dir=source,
            output_dir=equivalent_output,
            entitlement_path=tmp_path / "unused-entitlement.json",
            overwrite=True,
        )
    assert source.is_dir()
