"""Deterministic, PHI-free demo bundle generator."""

from __future__ import annotations

import os
import shutil
import tempfile
import uuid
from pathlib import Path

from coe.canonical import JsonValue, canonical_json_line, sha256_bytes, sha256_canonical
from coe.contracts.reference import CONTENT_HASH_SCHEMA as REFERENCE_CONTENT_HASH_SCHEMA
from coe.contracts.snapshot import CONTENT_HASH_SCHEMA as SNAPSHOT_CONTENT_HASH_SCHEMA
from coe.errors import OutputExistsError

SNAPSHOT_ID = "10000000-0000-4000-8000-000000000001"
RELEASE_ID = "20000000-0000-4000-8000-000000000001"
SYSTEM_URI = "urn:coe:synthetic:terminology:demo"

_DOCUMENTS = (
    (
        "00000000-0000-4000-8000-000000000001",
        "Atrial fibrillation and hypertension. MI appears in this synthetic teaching note. Blue toe pattern.",
    ),
    (
        "00000000-0000-4000-8000-000000000002",
        "Atrial fibrillation remains documented. MI appears again. Blue toe pattern.",
    ),
    (
        "00000000-0000-4000-8000-000000000003",
        "Type 2 diabetes and hypertension. Routine synthetic follow up.",
    ),
    (
        "00000000-0000-4000-8000-000000000004",
        "Type 2 diabetes remains documented. Routine synthetic follow up.",
    ),
)


def _write(path: Path, raw: bytes) -> None:
    path.write_bytes(raw)


def _checksum_bytes(raw_by_path: dict[str, bytes]) -> bytes:
    return "".join(f"{sha256_bytes(raw_by_path[path])}  {path}\n" for path in sorted(raw_by_path)).encode("utf-8")


def _create_snapshot(root: Path) -> None:
    snapshot = root / "snapshot"
    documents_dir = snapshot / "documents"
    documents_dir.mkdir(parents=True)
    document_rows: list[dict[str, JsonValue]] = []
    document_descriptors: list[dict[str, JsonValue]] = []
    raw_by_path: dict[str, bytes] = {}
    total_bytes = 0
    total_characters = 0
    for doc_id, text in _DOCUMENTS:
        path = f"documents/{doc_id}.txt"
        raw = text.encode("utf-8")
        _write(snapshot / path, raw)
        raw_by_path[path] = raw
        total_bytes += len(raw)
        total_characters += len(text)
        digest = sha256_bytes(raw)
        document_rows.append(
            {
                "byte_count": len(raw),
                "character_count": len(text),
                "doc_id": doc_id,
                "extraction_method": "synthetic_fixture",
                "language": "en",
                "note_type": "synthetic_note",
                "path": path,
                "sha256": digest,
            }
        )
        document_descriptors.append({"byte_count": len(raw), "path": path, "sha256": digest})
    index_raw = b"".join(canonical_json_line(row) for row in document_rows)
    _write(snapshot / "documents.jsonl", index_raw)
    raw_by_path["documents.jsonl"] = index_raw
    index_digest = sha256_bytes(index_raw)

    attestation: dict[str, JsonValue] = {
        "approved_for_coe_processing": True,
        "approver_ref": "TEST-ONLY",
        "attestation_schema_version": "1.0.0",
        "created_at": "2026-01-01T00:00:00Z",
        "data_classification": "synthetic_phi_free",
        "direct_identifiers_detected": False,
        "documents_index_sha256": index_digest,
        "findings_count": 0,
        "method": "synthetic_fixture",
        "profile": {"name": "coe-synthetic-fixture", "version": "1.0.0"},
        "scanner_tools": [{"name": "coe-sensitive-canary", "version": "1.0.0"}],
        "snapshot_id": SNAPSHOT_ID,
        "status": "passed",
    }
    attestation_raw = canonical_json_line(attestation)
    _write(snapshot / "deidentification_attestation.json", attestation_raw)
    raw_by_path["deidentification_attestation.json"] = attestation_raw
    attestation_digest = sha256_bytes(attestation_raw)

    content_set_sha256 = sha256_canonical(
        {
            "companions": [
                {"path": "deidentification_attestation.json", "sha256": attestation_digest},
                {"path": "documents.jsonl", "sha256": index_digest},
            ],
            "content_hash_schema_version": SNAPSHOT_CONTENT_HASH_SCHEMA,
            "documents": sorted(document_descriptors, key=lambda item: str(item["path"])),
        }
    )
    manifest: dict[str, JsonValue] = {
        "content_set_sha256": content_set_sha256,
        "created_at": "2026-01-01T00:00:00Z",
        "deidentification_attestation": {
            "byte_count": len(attestation_raw),
            "path": "deidentification_attestation.json",
            "sha256": attestation_digest,
        },
        "deidentification_profile": {"name": "coe-synthetic-fixture", "version": "1.0.0"},
        "document_count": len(_DOCUMENTS),
        "documents_index": {
            "byte_count": len(index_raw),
            "path": "documents.jsonl",
            "sha256": index_digest,
        },
        "documents_schema_version": "1.0.0",
        "extraction_method_counts": {"synthetic_fixture": len(_DOCUMENTS)},
        "language_counts": {"en": len(_DOCUMENTS)},
        "manifest_schema_version": "1.0.0",
        "note_type_counts": {"synthetic_note": len(_DOCUMENTS)},
        "parent_snapshot_id": None,
        "privacy_approval_ref": "TEST-ONLY",
        "retention_policy_id": "fixture-only",
        "snapshot_id": SNAPSHOT_ID,
        "snapshot_iri": f"urn:coe:synthetic:snapshot:{SNAPSHOT_ID}",
        "source_environment_classification": "synthetic",
        "total_bytes": total_bytes,
        "total_characters": total_characters,
        "upstream_extractor": {"name": "coe-demo-generator", "version": "1.0.0"},
    }
    manifest_raw = canonical_json_line(manifest)
    _write(snapshot / "snapshot_manifest.json", manifest_raw)
    raw_by_path["snapshot_manifest.json"] = manifest_raw
    _write(snapshot / "checksums.sha256", _checksum_bytes(raw_by_path))


def _create_reference(root: Path) -> str:
    reference = root / "reference"
    reference.mkdir(parents=True)
    coding_rows: list[dict[str, JsonValue]] = [
        {"active": True, "code": "U100", "definition": None, "properties": {}, "semantic_types": ["finding"]},
        {"active": True, "code": "U200", "definition": None, "properties": {}, "semantic_types": ["finding"]},
        {"active": True, "code": "U201", "definition": None, "properties": {}, "semantic_types": ["finding"]},
        {"active": True, "code": "U300", "definition": None, "properties": {}, "semantic_types": ["finding"]},
        {"active": True, "code": "U400", "definition": None, "properties": {}, "semantic_types": ["finding"]},
        {"active": True, "code": "U500", "definition": None, "properties": {}, "semantic_types": ["finding"]},
    ]
    labels = {
        "U100": ("Atrial fibrillation", ("AF",)),
        "U200": ("Myocardial infarction", ("heart attack", "MI")),
        "U201": ("Mitral insufficiency", ("mitral regurgitation", "MI")),
        "U300": ("Hypertension", ("high blood pressure", "HTN")),
        "U400": ("Type 2 diabetes mellitus", ("type 2 diabetes", "T2DM")),
        "U500": ("Fever", ("pyrexia",)),
    }
    designation_rows: list[dict[str, JsonValue]] = []
    for code, (preferred, aliases) in labels.items():
        designation_rows.append(
            {"code": code, "kind": "preferred", "language": "en", "source": "synthetic-publisher", "value": preferred}
        )
        for alias in aliases:
            designation_rows.append(
                {"code": code, "kind": "alias", "language": "en", "source": "synthetic-publisher", "value": alias}
            )
    designation_rows.sort(key=lambda item: (str(item["code"]), str(item["kind"]), str(item["value"])))
    codings_raw = b"".join(canonical_json_line(row) for row in coding_rows)
    designations_raw = b"".join(canonical_json_line(row) for row in designation_rows)
    _write(reference / "codings.jsonl", codings_raw)
    _write(reference / "designations.jsonl", designations_raw)
    coding_descriptor: dict[str, JsonValue] = {
        "byte_count": len(codings_raw),
        "path": "codings.jsonl",
        "row_count": len(coding_rows),
        "schema_version": "1.0.0",
        "sha256": sha256_bytes(codings_raw),
    }
    designation_descriptor: dict[str, JsonValue] = {
        "byte_count": len(designations_raw),
        "path": "designations.jsonl",
        "row_count": len(designation_rows),
        "schema_version": "1.0.0",
        "sha256": sha256_bytes(designations_raw),
    }
    content_set_sha256 = sha256_canonical(
        {
            "content_hash_schema_version": REFERENCE_CONTENT_HASH_SCHEMA,
            "payloads": sorted([coding_descriptor, designation_descriptor], key=lambda item: str(item["path"])),
        }
    )
    manifest: dict[str, JsonValue] = {
        "active_policy": "include_active_and_inactive",
        "code_format": {"max_length": 8, "pattern": "^[A-Z][0-9]{3}$"},
        "coding_schema_version": "1.0.0",
        "content_set_sha256": content_set_sha256,
        "designation_schema_version": "1.0.0",
        "effective_date": "2026-01-01",
        "entitlement": {
            "allowed_derived_uses": ["test"],
            "allowed_export_profiles": ["synthetic-internal"],
            "analysis_use_permitted": True,
            "approval_ref": "TEST-ONLY",
            "owner_ref": "TEST-ONLY",
            "permitted_environments": ["synthetic"],
            "review_date": "2099-12-31",
        },
        "files": {"codings": coding_descriptor, "designations": designation_descriptor},
        "language": "en",
        "manifest_schema_version": "1.0.0",
        "notices": ["Synthetic terminology for COE tests only; not for clinical use."],
        "publisher": "COE synthetic fixture generator",
        "relationship_policy": "none",
        "release_id": RELEASE_ID,
        "source_uri": "urn:coe:synthetic:source:demo-v0",
        "system_name": "COE Synthetic Demo Terminology",
        "system_uri": SYSTEM_URI,
        "version": "demo-v0",
    }
    manifest_raw = canonical_json_line(manifest)
    _write(reference / "terminology_release_manifest.json", manifest_raw)
    _write(
        reference / "checksums.sha256",
        _checksum_bytes(
            {
                "codings.jsonl": codings_raw,
                "designations.jsonl": designations_raw,
                "terminology_release_manifest.json": manifest_raw,
            }
        ),
    )
    return sha256_bytes(manifest_raw)


def _create_config(root: Path, manifest_sha256: str) -> None:
    config: dict[str, JsonValue] = {
        "algorithms": {
            "index_schema": "coe-in-memory-exact/1.0.0-synthetic-only",
            "normalizer": "coe-conservative/1.0.0",
            "span_matcher": "coe-exact-span/1.0.0",
            "tokenizer": "coe-regex-tokenizer/1.0.0",
        },
        "config_id": "offline-synthetic-demo-v0",
        "config_schema_version": "1.0.0",
        "execution_profile": "offline_synthetic_v0",
        "languages": ["en"],
        "matching": {
            "active_only": True,
            "ambiguity_policy": "preserve",
            "auto_acceptance_policy_id": "disabled-v0",
            "canonical_target_policy": "none-review-required",
            "layers": ["exact_preferred", "exact_alias"],
            "max_candidates_per_phrase_system": 20,
        },
        "mining": {
            "max_ngram_tokens": 3,
            "max_unique_phrases": 10000,
            "method": "sentence_bounded_token_ngrams",
            "min_document_frequency": 2,
            "min_ngram_tokens": 1,
        },
        "normalization": {
            "casefold_variant": "unicode-casefold",
            "collapse_whitespace": True,
            "primary": "case-sensitive",
            "profile_id": "coe-conservative",
            "unicode_form": "NFC",
            "version": "1.0.0",
        },
        "note_types": ["synthetic_note"],
        "privacy": {
            "canary_set_version": "1.0.0",
            "fail_closed": True,
            "profile_id": "synthetic-canary-only",
            "version": "1.0.0",
        },
        "random_seed": 0,
        "resource_limits": {
            "max_document_bytes": 100000,
            "max_documents": 100,
            "max_ngrams_per_document": 100000,
            "max_output_records": 100000,
            "max_snapshot_bytes": 1000000,
            "max_tokens_per_document": 10000,
        },
        "terminologies": [
            {
                "candidate_priority": 1,
                "manifest_sha256": manifest_sha256,
                "release_id": RELEASE_ID,
                "system_uri": SYSTEM_URI,
            }
        ],
    }
    _write(root / "coe_config.json", canonical_json_line(config))


def create_demo(root: Path, *, overwrite: bool = False) -> dict[str, JsonValue]:
    if root.exists() and not overwrite:
        raise OutputExistsError()
    root.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{root.name}.tmp-", dir=root.parent))
    backup: Path | None = None
    try:
        _create_snapshot(temporary)
        manifest_sha256 = _create_reference(temporary)
        _create_config(temporary, manifest_sha256)
        if root.exists():
            backup = root.parent / f".{root.name}.backup-{uuid.uuid4().hex}"
            os.replace(root, backup)
        try:
            os.replace(temporary, root)
        except Exception:
            if backup is not None and backup.exists() and not root.exists():
                os.replace(backup, root)
            raise
        if backup is not None:
            shutil.rmtree(backup)
        return {
            "config": "coe_config.json",
            "profile": "offline-synthetic-v0",
            "reference": "reference",
            "snapshot": "snapshot",
            "status": "created",
        }
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
