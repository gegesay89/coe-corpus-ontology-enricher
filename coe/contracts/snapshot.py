"""Immutable synthetic snapshot contract and fail-closed preflight."""

from __future__ import annotations

import re
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from coe.canonical import (
    JsonValue,
    check_sha256,
    load_json_bytes,
    load_jsonl_bytes,
    normalized_relative_path,
    read_stable_file,
    require_bool,
    require_exact_keys,
    require_int,
    require_object,
    require_string,
    sha256_bytes,
    sha256_canonical,
)
from coe.contracts.report import Issue, PreflightReport
from coe.errors import ContractError

SNAPSHOT_MANIFEST = "snapshot_manifest.json"
DOCUMENT_INDEX = "documents.jsonl"
ATTESTATION = "deidentification_attestation.json"
CHECKSUMS = "checksums.sha256"
CONTENT_HASH_SCHEMA = "coe-snapshot-content-v1"
MAX_COMPANION_BYTES = 5_000_000
MAX_DOCUMENT_BYTES_CEILING = 10_000_000
MAX_SNAPSHOT_BYTES_CEILING = 100_000_000
MAX_DOCUMENTS_CEILING = 10_000

_SENSITIVE_PATTERNS = (
    re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"\b(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}\b"),
    re.compile(r"\b(?:MRN|medical record number)\s*[:#-]?\s*[A-Z0-9-]{5,}\b", re.IGNORECASE),
    re.compile(r"COE-SENSITIVE-CANARY", re.IGNORECASE),
)


@dataclass(frozen=True, slots=True)
class Document:
    doc_id: str
    path: str
    sha256: str
    byte_count: int
    character_count: int
    note_type: str
    language: str
    extraction_method: str
    text: str


@dataclass(frozen=True, slots=True)
class SnapshotBundle:
    snapshot_id: str
    snapshot_iri: str
    content_set_sha256: str
    manifest_sha256: str
    source_environment_classification: str
    documents: tuple[Document, ...]
    note_types: tuple[str, ...]
    languages: tuple[str, ...]
    checked_files: int


def _parse_uuid(value: JsonValue, location: str) -> str:
    text = require_string(value, location)
    try:
        parsed = uuid.UUID(text)
    except ValueError as exc:
        raise ContractError("SCHEMA_INVALID", "Expected a canonical UUID.", location, 2) from exc
    if str(parsed) != text:
        raise ContractError("SCHEMA_INVALID", "Expected a lowercase canonical UUID.", location, 2)
    return text


def _parse_utc_timestamp(value: JsonValue, location: str) -> str:
    text = require_string(value, location)
    if not text.endswith("Z"):
        raise ContractError("SCHEMA_INVALID", "Timestamps must use UTC with a trailing Z.", location, 2)
    try:
        datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise ContractError("SCHEMA_INVALID", "Expected an RFC 3339 UTC timestamp.", location, 2) from exc
    return text


def _parse_absolute_uri(value: JsonValue, location: str) -> str:
    text = require_string(value, location)
    parsed = urlparse(text)
    if not parsed.scheme or (parsed.scheme in {"http", "https"} and not parsed.netloc):
        raise ContractError("SCHEMA_INVALID", "Expected an absolute URI.", location, 2)
    return text


def _parse_tool(value: JsonValue, location: str) -> tuple[str, str]:
    obj = require_object(value, location)
    require_exact_keys(obj, ("name", "version"), (), location)
    return require_string(obj["name"], f"{location}.name"), require_string(obj["version"], f"{location}.version")


def _parse_file_digest(value: JsonValue, expected_path: str, location: str) -> tuple[str, int, str]:
    obj = require_object(value, location)
    require_exact_keys(obj, ("path", "byte_count", "sha256"), (), location)
    path = normalized_relative_path(require_string(obj["path"], f"{location}.path"))
    if path != expected_path:
        raise ContractError(
            "SCHEMA_INVALID", "Companion manifest path does not match the contract.", f"{location}.path", 2
        )
    byte_count = require_int(obj["byte_count"], f"{location}.byte_count")
    digest = check_sha256(require_string(obj["sha256"], f"{location}.sha256"), f"{location}.sha256")
    return path, byte_count, digest


def _parse_count_map(value: JsonValue, location: str) -> dict[str, int]:
    obj = require_object(value, location)
    result: dict[str, int] = {}
    for key, count in obj.items():
        if not key:
            raise ContractError("SCHEMA_INVALID", "Summary keys cannot be empty.", location, 2)
        result[key] = require_int(count, f"{location}.{key}")
    return result


def _validate_root_layout(root: Path) -> None:
    if root.is_symlink():
        raise ContractError("SYMLINK", "The bundle root cannot be a symbolic link.", ".", 4)
    if not root.is_dir():
        raise ContractError("FILE_MISSING", "The snapshot bundle directory is missing.", ".", 3)
    allowed = {SNAPSHOT_MANIFEST, DOCUMENT_INDEX, ATTESTATION, CHECKSUMS, "documents"}
    for child in root.iterdir():
        if child.is_symlink():
            raise ContractError("SYMLINK", "Symbolic links are not permitted in bundles.", child.name, 4)
        if child.name not in allowed:
            raise ContractError("FILE_EXTRA", "The snapshot bundle contains an unexpected entry.", child.name, 3)
    documents_dir = root / "documents"
    if documents_dir.is_symlink() or not documents_dir.is_dir():
        raise ContractError("FILE_MISSING", "The documents directory is missing or unsafe.", "documents", 3)
    for child in documents_dir.iterdir():
        if child.is_symlink():
            raise ContractError("SYMLINK", "Symbolic links are not permitted in bundles.", f"documents/{child.name}", 4)
        if not child.is_file():
            raise ContractError(
                "NONREGULAR", "Nested or non-regular document entries are not permitted.", f"documents/{child.name}", 4
            )


def _parse_checksums(raw: bytes) -> dict[str, str]:
    if raw.startswith(b"version https://git-lfs.github.com/spec/v1"):
        raise ContractError("LFS_POINTER", "A Git LFS pointer was supplied instead of content.", CHECKSUMS, 3)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError("UTF8_INVALID", "The checksum index is not valid UTF-8.", CHECKSUMS, 3) from exc
    if raw and not raw.endswith(b"\n"):
        raise ContractError("CHECKSUM_INDEX_INVALID", "The checksum index must end with a newline.", CHECKSUMS, 3)
    result: dict[str, str] = {}
    for line in text.splitlines():
        if len(line) < 67 or line[64:66] != "  ":
            raise ContractError("CHECKSUM_INDEX_INVALID", "A checksum index row is malformed.", CHECKSUMS, 3)
        digest = check_sha256(line[:64], CHECKSUMS)
        path = normalized_relative_path(line[66:])
        if path in result:
            raise ContractError("CHECKSUM_INDEX_INVALID", "The checksum index contains a duplicate path.", CHECKSUMS, 3)
        result[path] = digest
    return result


def inspect_snapshot_bundle(root: Path) -> SnapshotBundle:
    _validate_root_layout(root)
    manifest_raw = read_stable_file(root / SNAPSHOT_MANIFEST, SNAPSHOT_MANIFEST, MAX_COMPANION_BYTES)
    manifest = require_object(load_json_bytes(manifest_raw, SNAPSHOT_MANIFEST), SNAPSHOT_MANIFEST)
    required_manifest = (
        "manifest_schema_version",
        "documents_schema_version",
        "snapshot_id",
        "snapshot_iri",
        "created_at",
        "source_environment_classification",
        "document_count",
        "total_bytes",
        "total_characters",
        "note_type_counts",
        "language_counts",
        "extraction_method_counts",
        "documents_index",
        "deidentification_attestation",
        "content_set_sha256",
        "upstream_extractor",
        "deidentification_profile",
        "privacy_approval_ref",
        "retention_policy_id",
        "parent_snapshot_id",
    )
    require_exact_keys(manifest, required_manifest, (), SNAPSHOT_MANIFEST)
    if manifest["manifest_schema_version"] != "1.0.0" or manifest["documents_schema_version"] != "1.0.0":
        raise ContractError("SCHEMA_INVALID", "Unsupported snapshot schema version.", SNAPSHOT_MANIFEST, 2)
    snapshot_id = _parse_uuid(manifest["snapshot_id"], f"{SNAPSHOT_MANIFEST}.snapshot_id")
    snapshot_iri = _parse_absolute_uri(manifest["snapshot_iri"], f"{SNAPSHOT_MANIFEST}.snapshot_iri")
    _parse_utc_timestamp(manifest["created_at"], f"{SNAPSHOT_MANIFEST}.created_at")
    source_classification = require_string(
        manifest["source_environment_classification"],
        f"{SNAPSHOT_MANIFEST}.source_environment_classification",
    )
    if source_classification != "synthetic":
        raise ContractError("UNSAFE_PROFILE", "v0 accepts synthetic snapshots only.", SNAPSHOT_MANIFEST, 4)
    expected_document_count = require_int(manifest["document_count"], f"{SNAPSHOT_MANIFEST}.document_count")
    if expected_document_count > MAX_DOCUMENTS_CEILING:
        raise ContractError("RESOURCE_LIMIT", "The snapshot exceeds the v0 document ceiling.", SNAPSHOT_MANIFEST, 4)
    expected_total_bytes = require_int(manifest["total_bytes"], f"{SNAPSHOT_MANIFEST}.total_bytes")
    expected_total_characters = require_int(manifest["total_characters"], f"{SNAPSHOT_MANIFEST}.total_characters")
    if expected_total_bytes > MAX_SNAPSHOT_BYTES_CEILING:
        raise ContractError("RESOURCE_LIMIT", "The snapshot exceeds the v0 byte ceiling.", SNAPSHOT_MANIFEST, 4)
    expected_note_types = _parse_count_map(manifest["note_type_counts"], f"{SNAPSHOT_MANIFEST}.note_type_counts")
    expected_languages = _parse_count_map(manifest["language_counts"], f"{SNAPSHOT_MANIFEST}.language_counts")
    expected_extraction = _parse_count_map(
        manifest["extraction_method_counts"], f"{SNAPSHOT_MANIFEST}.extraction_method_counts"
    )
    _, index_byte_count, index_digest = _parse_file_digest(
        manifest["documents_index"], DOCUMENT_INDEX, f"{SNAPSHOT_MANIFEST}.documents_index"
    )
    _, attestation_byte_count, attestation_digest = _parse_file_digest(
        manifest["deidentification_attestation"], ATTESTATION, f"{SNAPSHOT_MANIFEST}.deidentification_attestation"
    )
    expected_content_digest = check_sha256(
        require_string(manifest["content_set_sha256"], f"{SNAPSHOT_MANIFEST}.content_set_sha256"),
        f"{SNAPSHOT_MANIFEST}.content_set_sha256",
    )
    _parse_tool(manifest["upstream_extractor"], f"{SNAPSHOT_MANIFEST}.upstream_extractor")
    manifest_deidentification_profile = _parse_tool(
        manifest["deidentification_profile"], f"{SNAPSHOT_MANIFEST}.deidentification_profile"
    )
    if require_string(manifest["privacy_approval_ref"], f"{SNAPSHOT_MANIFEST}.privacy_approval_ref") != "TEST-ONLY":
        raise ContractError("ATTESTATION_INVALID", "v0 requires the TEST-ONLY privacy approval.", SNAPSHOT_MANIFEST, 4)
    if require_string(manifest["retention_policy_id"], f"{SNAPSHOT_MANIFEST}.retention_policy_id") != "fixture-only":
        raise ContractError(
            "ATTESTATION_INVALID", "v0 requires the fixture-only retention policy.", SNAPSHOT_MANIFEST, 4
        )
    if manifest["parent_snapshot_id"] is not None:
        _parse_uuid(manifest["parent_snapshot_id"], f"{SNAPSHOT_MANIFEST}.parent_snapshot_id")

    index_raw = read_stable_file(root / DOCUMENT_INDEX, DOCUMENT_INDEX, MAX_COMPANION_BYTES)
    if index_raw.startswith(b"version https://git-lfs.github.com/spec/v1"):
        raise ContractError("LFS_POINTER", "A Git LFS pointer was supplied instead of content.", DOCUMENT_INDEX, 3)
    if len(index_raw) != index_byte_count or sha256_bytes(index_raw) != index_digest:
        raise ContractError(
            "HASH_MISMATCH", "The document index does not match its manifest digest.", DOCUMENT_INDEX, 3
        )
    rows = load_jsonl_bytes(index_raw, DOCUMENT_INDEX)
    if len(rows) != expected_document_count:
        raise ContractError(
            "COUNT_MISMATCH", "The document index row count does not match the manifest.", DOCUMENT_INDEX, 3
        )

    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    seen_casefolded_paths: set[str] = set()
    records: list[tuple[dict[str, JsonValue], str, str]] = []
    for row_number, row in enumerate(rows, start=1):
        location = f"{DOCUMENT_INDEX}:{row_number}"
        require_exact_keys(
            row,
            (
                "doc_id",
                "path",
                "sha256",
                "byte_count",
                "character_count",
                "note_type",
                "language",
                "extraction_method",
            ),
            ("subject_group_id",),
            location,
        )
        doc_id = _parse_uuid(row["doc_id"], f"{location}.doc_id")
        if doc_id in seen_ids:
            raise ContractError("DOC_ID_DUPLICATE", "The document index contains a duplicate document ID.", location, 3)
        seen_ids.add(doc_id)
        path = normalized_relative_path(require_string(row["path"], f"{location}.path"))
        if path != f"documents/{doc_id}.txt":
            raise ContractError(
                "PATH_INVALID", "Document filenames must contain only their opaque UUID.", f"{location}.path", 4
            )
        if path in seen_paths or path.casefold() in seen_casefolded_paths:
            raise ContractError("PATH_COLLISION", "Document paths collide after normalization.", f"{location}.path", 4)
        seen_paths.add(path)
        seen_casefolded_paths.add(path.casefold())
        if row.get("subject_group_id") is not None:
            raise ContractError("UNSAFE_PROFILE", "Subject grouping is disabled in offline synthetic v0.", location, 4)
        records.append((row, doc_id, path))

    actual_paths = {f"documents/{child.name}" for child in (root / "documents").iterdir()}
    missing = seen_paths - actual_paths
    extra = actual_paths - seen_paths
    if missing:
        raise ContractError("FILE_MISSING", "A document declared by the index is missing.", sorted(missing)[0], 3)
    if extra:
        raise ContractError("FILE_EXTRA", "The documents directory contains an undeclared file.", sorted(extra)[0], 3)

    documents: list[Document] = []
    total_bytes = 0
    total_characters = 0
    note_types: Counter[str] = Counter()
    languages: Counter[str] = Counter()
    extraction_methods: Counter[str] = Counter()
    document_digests: set[str] = set()
    content_descriptors: list[dict[str, JsonValue]] = []
    for row, doc_id, path in records:
        raw = read_stable_file(root / path, path, MAX_DOCUMENT_BYTES_CEILING)
        if raw.startswith(b"version https://git-lfs.github.com/spec/v1"):
            raise ContractError("LFS_POINTER", "A Git LFS pointer was supplied instead of document content.", path, 3)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ContractError("UTF8_INVALID", "A document is not valid UTF-8.", path, 3) from exc
        actual_digest = sha256_bytes(raw)
        declared_digest = check_sha256(require_string(row["sha256"], f"{path}.sha256"), f"{path}.sha256")
        declared_bytes = require_int(row["byte_count"], f"{path}.byte_count")
        declared_characters = require_int(row["character_count"], f"{path}.character_count")
        if actual_digest != declared_digest:
            raise ContractError("HASH_MISMATCH", "A document does not match its declared digest.", path, 3)
        if actual_digest in document_digests:
            raise ContractError(
                "DOC_CONTENT_DUPLICATE",
                "The snapshot contains byte-identical documents; duplicate handling must be explicit before analysis.",
                path,
                3,
            )
        document_digests.add(actual_digest)
        if len(raw) != declared_bytes or len(text) != declared_characters:
            raise ContractError("COUNT_MISMATCH", "A document does not match its declared size.", path, 3)
        if any(pattern.search(text) for pattern in _SENSITIVE_PATTERNS):
            raise ContractError(
                "PRIVACY_FINDING", "The synthetic privacy canary scanner found a prohibited pattern.", path, 4
            )
        note_type = require_string(row["note_type"], f"{path}.note_type")
        language = require_string(row["language"], f"{path}.language")
        extraction_method = require_string(row["extraction_method"], f"{path}.extraction_method")
        total_bytes += len(raw)
        total_characters += len(text)
        note_types[note_type] += 1
        languages[language] += 1
        extraction_methods[extraction_method] += 1
        content_descriptors.append({"byte_count": len(raw), "path": path, "sha256": actual_digest})
        documents.append(
            Document(
                doc_id=doc_id,
                path=path,
                sha256=actual_digest,
                byte_count=len(raw),
                character_count=len(text),
                note_type=note_type,
                language=language,
                extraction_method=extraction_method,
                text=text,
            )
        )
    if (
        total_bytes != expected_total_bytes
        or total_characters != expected_total_characters
        or dict(sorted(note_types.items())) != dict(sorted(expected_note_types.items()))
        or dict(sorted(languages.items())) != dict(sorted(expected_languages.items()))
        or dict(sorted(extraction_methods.items())) != dict(sorted(expected_extraction.items()))
    ):
        raise ContractError(
            "COUNT_MISMATCH", "Snapshot aggregate counts do not match the manifest.", SNAPSHOT_MANIFEST, 3
        )

    attestation_raw = read_stable_file(root / ATTESTATION, ATTESTATION, MAX_COMPANION_BYTES)
    if attestation_raw.startswith(b"version https://git-lfs.github.com/spec/v1"):
        raise ContractError("LFS_POINTER", "A Git LFS pointer was supplied instead of content.", ATTESTATION, 3)
    if len(attestation_raw) != attestation_byte_count or sha256_bytes(attestation_raw) != attestation_digest:
        raise ContractError("HASH_MISMATCH", "The attestation does not match its manifest digest.", ATTESTATION, 3)
    attestation = require_object(load_json_bytes(attestation_raw, ATTESTATION), ATTESTATION)
    require_exact_keys(
        attestation,
        (
            "attestation_schema_version",
            "snapshot_id",
            "created_at",
            "data_classification",
            "method",
            "profile",
            "status",
            "documents_index_sha256",
            "approved_for_coe_processing",
            "approver_ref",
            "findings_count",
            "direct_identifiers_detected",
            "scanner_tools",
        ),
        (),
        ATTESTATION,
    )
    if attestation["attestation_schema_version"] != "1.0.0":
        raise ContractError("ATTESTATION_INVALID", "Unsupported attestation schema version.", ATTESTATION, 4)
    if _parse_uuid(attestation["snapshot_id"], f"{ATTESTATION}.snapshot_id") != snapshot_id:
        raise ContractError("ATTESTATION_INVALID", "The attestation is bound to a different snapshot.", ATTESTATION, 4)
    _parse_utc_timestamp(attestation["created_at"], f"{ATTESTATION}.created_at")
    attestation_profile = _parse_tool(attestation["profile"], f"{ATTESTATION}.profile")
    scanners = attestation["scanner_tools"]
    if not isinstance(scanners, list) or not scanners:
        raise ContractError("ATTESTATION_INVALID", "At least one synthetic scanner must be recorded.", ATTESTATION, 4)
    for index, scanner in enumerate(scanners):
        _parse_tool(scanner, f"{ATTESTATION}.scanner_tools[{index}]")
    attestation_ok = (
        attestation["data_classification"] == "synthetic_phi_free"
        and attestation["method"] == "synthetic_fixture"
        and attestation["status"] == "passed"
        and attestation_profile == manifest_deidentification_profile
        and attestation["documents_index_sha256"] == index_digest
        and require_bool(attestation["approved_for_coe_processing"], f"{ATTESTATION}.approved_for_coe_processing")
        and attestation["approver_ref"] == "TEST-ONLY"
        and require_int(attestation["findings_count"], f"{ATTESTATION}.findings_count") == 0
        and not require_bool(attestation["direct_identifiers_detected"], f"{ATTESTATION}.direct_identifiers_detected")
    )
    if not attestation_ok:
        raise ContractError(
            "ATTESTATION_INVALID",
            "The synthetic de-identification attestation is not approved or not bound.",
            ATTESTATION,
            4,
        )

    content_payload: dict[str, JsonValue] = {
        "companions": sorted(
            [
                {"path": DOCUMENT_INDEX, "sha256": index_digest},
                {"path": ATTESTATION, "sha256": attestation_digest},
            ],
            key=lambda item: str(item["path"]),
        ),
        "content_hash_schema_version": CONTENT_HASH_SCHEMA,
        "documents": sorted(content_descriptors, key=lambda item: str(item["path"])),
    }
    actual_content_digest = sha256_canonical(content_payload)
    if actual_content_digest != expected_content_digest:
        raise ContractError(
            "CONTENT_DIGEST_MISMATCH", "The snapshot content-set digest is invalid.", SNAPSHOT_MANIFEST, 3
        )

    checksums_raw = read_stable_file(root / CHECKSUMS, CHECKSUMS, MAX_COMPANION_BYTES)
    checksums = _parse_checksums(checksums_raw)
    expected_checksum_paths = {SNAPSHOT_MANIFEST, DOCUMENT_INDEX, ATTESTATION, *seen_paths}
    if checksums.keys() != expected_checksum_paths:
        raise ContractError(
            "CHECKSUM_INDEX_INVALID", "The checksum index is not an exact file inventory.", CHECKSUMS, 3
        )
    actual_raw_by_path = {
        SNAPSHOT_MANIFEST: manifest_raw,
        DOCUMENT_INDEX: index_raw,
        ATTESTATION: attestation_raw,
    }
    for document in documents:
        actual_raw_by_path[document.path] = document.text.encode("utf-8")
    for path, raw in actual_raw_by_path.items():
        if checksums[path] != sha256_bytes(raw):
            raise ContractError("HASH_MISMATCH", "A checksum index entry does not match its file.", path, 3)

    return SnapshotBundle(
        snapshot_id=snapshot_id,
        snapshot_iri=snapshot_iri,
        content_set_sha256=actual_content_digest,
        manifest_sha256=sha256_bytes(manifest_raw),
        source_environment_classification=source_classification,
        documents=tuple(sorted(documents, key=lambda item: item.doc_id)),
        note_types=tuple(sorted(note_types)),
        languages=tuple(sorted(languages)),
        checked_files=len(expected_checksum_paths) + 1,
    )


def validate_snapshot_bundle(root: Path) -> PreflightReport:
    try:
        bundle = inspect_snapshot_bundle(root)
    except ContractError as exc:
        severity = "security" if exc.exit_code == 4 else "error"
        return PreflightReport(
            kind="snapshot",
            status="failed",
            issues=(
                Issue(
                    code=exc.code,
                    severity=severity,
                    check_id="snapshot_contract",
                    safe_message=exc.safe_message,
                    relative_location=exc.relative_location,
                ),
            ),
        )
    return PreflightReport(
        kind="snapshot",
        status="passed",
        subject_id=bundle.snapshot_id,
        manifest_sha256=bundle.manifest_sha256,
        content_set_sha256=bundle.content_set_sha256,
        checked_files=bundle.checked_files,
        measurements={
            "document_count": len(bundle.documents),
            "total_bytes": sum(document.byte_count for document in bundle.documents),
        },
    )
