from __future__ import annotations

import json
from pathlib import Path

import pytest

import coe.demo as demo_module
from coe.canonical import canonical_json_line
from coe.contracts.config import inspect_analysis_config
from coe.contracts.reference import inspect_reference_bundle, validate_reference_bundle
from coe.contracts.snapshot import inspect_snapshot_bundle, validate_snapshot_bundle
from coe.demo import create_demo
from coe.errors import ContractError


def test_valid_snapshot_reference_and_config_pass(demo_root: Path) -> None:
    snapshot = inspect_snapshot_bundle(demo_root / "snapshot")
    reference = inspect_reference_bundle(demo_root / "reference")
    config = inspect_analysis_config(demo_root / "coe_config.json", snapshot, (reference,))
    assert len(snapshot.documents) == 4
    assert len(reference.codings) == 6
    assert config.config_id == "offline-synthetic-demo-v0"


def test_reference_rejects_git_lfs_pointer(demo_root: Path) -> None:
    (demo_root / "reference" / "codings.jsonl").write_text(
        "version https://git-lfs.github.com/spec/v1\noid sha256:" + "0" * 64 + "\nsize 123\n",
        encoding="utf-8",
    )
    report = validate_reference_bundle(demo_root / "reference")
    assert report.status == "failed"
    assert report.issues[0].code == "LFS_POINTER"


def test_snapshot_rejects_document_hash_mismatch(demo_root: Path) -> None:
    document = next((demo_root / "snapshot" / "documents").iterdir())
    document.write_text(document.read_text(encoding="utf-8") + " changed", encoding="utf-8")
    report = validate_snapshot_bundle(demo_root / "snapshot")
    assert report.status == "failed"
    assert report.issues[0].code == "HASH_MISMATCH"


def test_snapshot_rejects_extra_file(demo_root: Path) -> None:
    (demo_root / "snapshot" / "documents" / "undeclared.txt").write_text("synthetic", encoding="utf-8")
    report = validate_snapshot_bundle(demo_root / "snapshot")
    assert report.status == "failed"
    assert report.issues[0].code == "FILE_EXTRA"


def test_snapshot_rejects_symlink(demo_root: Path) -> None:
    document = next((demo_root / "snapshot" / "documents").iterdir())
    document.unlink()
    document.symlink_to(demo_root / "coe_config.json")
    report = validate_snapshot_bundle(demo_root / "snapshot")
    assert report.status == "failed"
    assert report.issues[0].code == "SYMLINK"


def test_snapshot_rejects_duplicate_document_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    duplicate_id = "00000000-0000-4000-8000-000000000099"
    monkeypatch.setattr(
        demo_module,
        "_DOCUMENTS",
        ((duplicate_id, "Synthetic text one."), (duplicate_id, "Synthetic text two.")),
    )
    root = tmp_path / "duplicate-demo"
    create_demo(root)
    report = validate_snapshot_bundle(root / "snapshot")
    assert report.status == "failed"
    assert report.issues[0].code == "DOC_ID_DUPLICATE"


def test_sensitive_canary_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        demo_module,
        "_DOCUMENTS",
        (("00000000-0000-4000-8000-000000000098", "Contact patient@example.com."),),
    )
    root = tmp_path / "sensitive-demo"
    create_demo(root)
    report = validate_snapshot_bundle(root / "snapshot")
    assert report.status == "failed"
    assert report.issues[0].code == "PRIVACY_FINDING"


def test_snapshot_rejects_byte_identical_documents(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        demo_module,
        "_DOCUMENTS",
        (
            ("00000000-0000-4000-8000-000000000096", "Identical synthetic template."),
            ("00000000-0000-4000-8000-000000000097", "Identical synthetic template."),
        ),
    )
    root = tmp_path / "duplicate-content-demo"
    create_demo(root)
    report = validate_snapshot_bundle(root / "snapshot")
    assert report.status == "failed"
    assert report.issues[0].code == "DOC_CONTENT_DUPLICATE"


def test_config_rejects_unknown_secret_field(demo_root: Path) -> None:
    path = demo_root / "coe_config.json"
    config = json.loads(path.read_text(encoding="utf-8"))
    config["api_key"] = "must-not-be-accepted"
    path.write_bytes(canonical_json_line(config))
    with pytest.raises(ContractError, match="SCHEMA_INVALID"):
        inspect_analysis_config(path)
