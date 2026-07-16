"""Atomic build and verification of a complete controlled terminology index set."""

from __future__ import annotations

import os
import shutil
import tempfile
import uuid
from pathlib import Path

from coe.canonical import (
    JsonValue,
    canonical_json_line,
    check_sha256,
    load_json,
    require_exact_keys,
    require_int,
    require_object,
    require_string,
    sha256_bytes,
    sha256_canonical,
)
from coe.errors import ContractError, OutputExistsError
from coe.governance import inspect_terminology_entitlement
from coe.terminology.licensed import (
    LicensedIndexMetadata,
    build_licensed_index,
    load_terminology_specs,
    verify_licensed_index,
)

SET_MANIFEST = "reference_set_manifest.json"
CHECKSUMS = "checksums.sha256"
ENTITLEMENT = "terminology_entitlement_assertion.json"


def _reject_source_output_overlap(source_dir: Path, output_dir: Path) -> None:
    try:
        source_real = source_dir.resolve(strict=True)
        output_real = output_dir.resolve(strict=False)
    except OSError as exc:
        raise ContractError(
            "PATH_INVALID",
            "The terminology source or output path could not be resolved safely.",
            ".",
            4,
        ) from exc
    if source_real == output_real or source_real in output_real.parents or output_real in source_real.parents:
        raise ContractError(
            "PATH_OVERLAP",
            "The terminology source and reference-set output paths must be disjoint.",
            ".",
            4,
        )


def _index_record(metadata: LicensedIndexMetadata) -> dict[str, JsonValue]:
    return {
        "active_count": metadata.active_count,
        "alias_count": metadata.alias_count,
        "code_count": metadata.code_count,
        "content_set_sha256": metadata.content_set_sha256,
        "designation_count": metadata.designation_count,
        "effective_date": metadata.effective_date,
        "file_name": f"{metadata.terminology}.sqlite3",
        "inactive_count": metadata.inactive_count,
        "index_sha256": metadata.index_sha256,
        "manifest_sha256": metadata.manifest_sha256,
        "profile_sha256": metadata.profile_sha256,
        "release_id": metadata.release_id,
        "source_sha256": metadata.source_sha256,
        "system_name": metadata.system_name,
        "system_uri": metadata.system_uri,
        "terminology": metadata.terminology,
        "version": metadata.version,
    }


def _write_set_manifest(
    directory: Path,
    metadata: tuple[LicensedIndexMetadata, ...],
    entitlement_path: Path,
) -> dict[str, JsonValue]:
    assertion = inspect_terminology_entitlement(entitlement_path)
    entitlement_target = directory / ENTITLEMENT
    shutil.copyfile(entitlement_path, entitlement_target)
    indexes = [_index_record(item) for item in sorted(metadata, key=lambda item: item.terminology)]
    content_sha256 = sha256_canonical(
        {
            "entitlement_assertion_sha256": assertion.assertion_sha256,
            "indexes": indexes,
            "set_content_schema_version": "coe-licensed-reference-set-v1",
        },
        domain=b"coe-licensed-reference-set-v1",
    )
    manifest: dict[str, JsonValue] = {
        "entitlement": {
            "asserted_on": assertion.asserted_on,
            "assertion_ref": assertion.assertion_ref,
            "assertion_sha256": assertion.assertion_sha256,
            "public_redistribution_status": "not_asserted",
            "review_due_on": assertion.review_due_on,
        },
        "index_count": len(indexes),
        "indexes": indexes,
        "patient_data_included": False,
        "reference_set_manifest_schema_version": "1.0.0",
        "set_content_sha256": content_sha256,
        "usage_profile": "private-controlled-analysis",
    }
    manifest_path = directory / SET_MANIFEST
    manifest_path.write_bytes(canonical_json_line(manifest))
    checksum_rows = [
        f"{item.index_sha256}  {item.terminology}.sqlite3"
        for item in sorted(metadata, key=lambda item: item.terminology)
    ]
    checksum_rows.append(f"{sha256_bytes(manifest_path.read_bytes())}  {SET_MANIFEST}")
    checksum_rows.append(f"{sha256_bytes(entitlement_target.read_bytes())}  {ENTITLEMENT}")
    checksum_rows.sort(key=lambda row: row[66:])
    (directory / CHECKSUMS).write_text("\n".join(checksum_rows) + "\n", encoding="utf-8", newline="\n")
    return manifest


def build_licensed_index_set(
    *,
    source_dir: Path,
    output_dir: Path,
    entitlement_path: Path,
    specs_path: Path | None = None,
    overwrite: bool = False,
) -> dict[str, JsonValue]:
    """Build every pinned release and publish the complete directory atomically."""

    if source_dir.is_symlink() or not source_dir.is_dir():
        raise ContractError("SOURCE_INVALID", "The terminology source directory is missing or unsafe.", ".", 4)
    _reject_source_output_overlap(source_dir, output_dir)
    if output_dir.is_symlink():
        raise ContractError("OUTPUT_INVALID", "The reference-set output cannot be a symbolic link.", ".", 4)
    if output_dir.exists() and not output_dir.is_dir():
        raise ContractError("OUTPUT_INVALID", "The reference-set output must be a directory.", ".", 4)
    if output_dir.exists() and not overwrite:
        raise OutputExistsError()
    specs = load_terminology_specs(specs_path)
    assertion = inspect_terminology_entitlement(entitlement_path)
    parent = output_dir.parent
    parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}.tmp-", dir=parent))
    backup: Path | None = None
    try:
        indexes: list[LicensedIndexMetadata] = []
        for terminology, spec in sorted(specs.items()):
            if terminology not in assertion.terminologies:
                raise ContractError(
                    "ENTITLEMENT_INVALID", "A terminology release is absent from the entitlement.", terminology, 5
                )
            indexes.append(
                build_licensed_index(
                    source_dir / spec.file_name,
                    temporary / f"{terminology}.sqlite3",
                    terminology,
                    specs_path=specs_path,
                    entitlement_ref=assertion.binding_ref,
                )
            )
        manifest = _write_set_manifest(temporary, tuple(indexes), entitlement_path)
        verify_licensed_index_set(temporary)
        if output_dir.exists():
            backup = parent / f".{output_dir.name}.backup-{uuid.uuid4().hex}"
            os.replace(output_dir, backup)
        try:
            os.replace(temporary, output_dir)
        except Exception:
            if backup is not None and backup.exists() and not output_dir.exists():
                os.replace(backup, output_dir)
            raise
        if backup is not None:
            shutil.rmtree(backup)
        return manifest
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def _parse_checksums(path: Path) -> dict[str, str]:
    raw = path.read_bytes()
    if not raw.endswith(b"\n"):
        raise ContractError("CHECKSUM_INDEX_INVALID", "The checksum index must end with a newline.", CHECKSUMS, 3)
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ContractError("CHECKSUM_INDEX_INVALID", "The checksum index is not UTF-8.", CHECKSUMS, 3) from exc
    result: dict[str, str] = {}
    for line in lines:
        if len(line) < 67 or line[64:66] != "  ":
            raise ContractError("CHECKSUM_INDEX_INVALID", "A checksum row is malformed.", CHECKSUMS, 3)
        digest = check_sha256(line[:64], CHECKSUMS)
        file_name = line[66:]
        if Path(file_name).name != file_name or file_name in result:
            raise ContractError("CHECKSUM_INDEX_INVALID", "A checksum path is invalid.", CHECKSUMS, 3)
        result[file_name] = digest
    return result


def verify_licensed_index_set(directory: Path) -> dict[str, JsonValue]:
    """Verify the exact file inventory and each immutable index in a set."""

    if directory.is_symlink() or not directory.is_dir():
        raise ContractError("INDEX_SET_INVALID", "The reference-set directory is missing or unsafe.", ".", 4)
    for child in directory.iterdir():
        if child.is_symlink() or not child.is_file():
            raise ContractError("INDEX_SET_INVALID", "The reference set contains an unsafe entry.", child.name, 4)
    manifest_path = directory / SET_MANIFEST
    checksums_path = directory / CHECKSUMS
    manifest = require_object(load_json(manifest_path, SET_MANIFEST), SET_MANIFEST)
    require_exact_keys(
        manifest,
        (
            "reference_set_manifest_schema_version",
            "usage_profile",
            "patient_data_included",
            "entitlement",
            "index_count",
            "indexes",
            "set_content_sha256",
        ),
        (),
        SET_MANIFEST,
    )
    if (
        manifest["reference_set_manifest_schema_version"] != "1.0.0"
        or manifest["usage_profile"] != "private-controlled-analysis"
        or manifest["patient_data_included"] is not False
    ):
        raise ContractError("INDEX_SET_INVALID", "The reference-set profile is invalid.", SET_MANIFEST, 3)
    entitlement = require_object(manifest["entitlement"], f"{SET_MANIFEST}.entitlement")
    require_exact_keys(
        entitlement,
        (
            "asserted_on",
            "assertion_ref",
            "assertion_sha256",
            "public_redistribution_status",
            "review_due_on",
        ),
        (),
        f"{SET_MANIFEST}.entitlement",
    )
    assertion_sha = check_sha256(
        require_string(entitlement["assertion_sha256"], f"{SET_MANIFEST}.entitlement.assertion_sha256"),
        f"{SET_MANIFEST}.entitlement.assertion_sha256",
    )
    if entitlement["public_redistribution_status"] != "not_asserted":
        raise ContractError("INDEX_SET_INVALID", "The reference-set export boundary is invalid.", SET_MANIFEST, 3)
    bundled_assertion = inspect_terminology_entitlement(directory / ENTITLEMENT)
    if (
        bundled_assertion.assertion_sha256 != assertion_sha
        or bundled_assertion.assertion_ref != entitlement["assertion_ref"]
        or bundled_assertion.asserted_on != entitlement["asserted_on"]
        or bundled_assertion.review_due_on != entitlement["review_due_on"]
    ):
        raise ContractError("INDEX_SET_INVALID", "The bundled entitlement does not match the manifest.", ENTITLEMENT, 3)
    raw_indexes = manifest["indexes"]
    if not isinstance(raw_indexes, list):
        raise ContractError("INDEX_SET_INVALID", "The index inventory must be a list.", SET_MANIFEST, 3)
    expected_count = require_int(manifest["index_count"], f"{SET_MANIFEST}.index_count", minimum=1)
    if len(raw_indexes) != expected_count:
        raise ContractError("INDEX_SET_INVALID", "The index count is inconsistent.", SET_MANIFEST, 3)
    verified_records: list[dict[str, JsonValue]] = []
    verified_digests: dict[str, str] = {}
    seen_terms: set[str] = set()
    for position, raw_record in enumerate(raw_indexes):
        record = require_object(raw_record, f"{SET_MANIFEST}.indexes[{position}]")
        terminology = require_string(record.get("terminology"), f"{SET_MANIFEST}.indexes[{position}].terminology")
        file_name = require_string(record.get("file_name"), f"{SET_MANIFEST}.indexes[{position}].file_name")
        if file_name != f"{terminology}.sqlite3" or terminology in seen_terms:
            raise ContractError("INDEX_SET_INVALID", "The index identity is duplicated or invalid.", SET_MANIFEST, 3)
        seen_terms.add(terminology)
        metadata = verify_licensed_index(directory / file_name)
        actual = _index_record(metadata)
        if record != actual:
            raise ContractError("INDEX_SET_INVALID", "An index does not match the set manifest.", file_name, 3)
        verified_records.append(actual)
        verified_digests[file_name] = metadata.index_sha256
    checksums = _parse_checksums(checksums_path)
    expected_files = {SET_MANIFEST, ENTITLEMENT, *(f"{term}.sqlite3" for term in seen_terms)}
    if set(checksums) != expected_files or {child.name for child in directory.iterdir()} != expected_files | {
        CHECKSUMS
    }:
        raise ContractError("INDEX_SET_INVALID", "The reference-set file inventory is not exact.", ".", 3)
    verified_digests[SET_MANIFEST] = sha256_bytes(manifest_path.read_bytes())
    verified_digests[ENTITLEMENT] = sha256_bytes((directory / ENTITLEMENT).read_bytes())
    for file_name, digest in checksums.items():
        if verified_digests[file_name] != digest:
            raise ContractError("HASH_MISMATCH", "A reference-set file hash does not match.", file_name, 3)
    expected_content = sha256_canonical(
        {
            "entitlement_assertion_sha256": assertion_sha,
            "indexes": verified_records,
            "set_content_schema_version": "coe-licensed-reference-set-v1",
        },
        domain=b"coe-licensed-reference-set-v1",
    )
    declared_content = check_sha256(
        require_string(manifest["set_content_sha256"], f"{SET_MANIFEST}.set_content_sha256"),
        f"{SET_MANIFEST}.set_content_sha256",
    )
    if expected_content != declared_content:
        raise ContractError("INDEX_SET_INVALID", "The reference-set content digest is invalid.", SET_MANIFEST, 3)
    return manifest
