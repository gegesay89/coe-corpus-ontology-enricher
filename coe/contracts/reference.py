"""Synthetic terminology release contract and validated in-memory catalog."""

from __future__ import annotations

import re
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import date
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

REFERENCE_MANIFEST = "terminology_release_manifest.json"
CODINGS = "codings.jsonl"
DESIGNATIONS = "designations.jsonl"
CHECKSUMS = "checksums.sha256"
CONTENT_HASH_SCHEMA = "coe-reference-content-v1"
MAX_REFERENCE_BYTES_CEILING = 50_000_000
MAX_ROWS_CEILING = 1_000_000
MAX_ALIASES_PER_CODE = 32


@dataclass(frozen=True, slots=True)
class Coding:
    code: str
    active: bool
    definition: str | None
    semantic_types: tuple[str, ...]
    properties: dict[str, JsonValue]


@dataclass(frozen=True, slots=True)
class Designation:
    code: str
    language: str
    kind: str
    value: str
    source: str


@dataclass(frozen=True, slots=True)
class ReferenceBundle:
    release_id: str
    system_uri: str
    system_name: str
    version: str
    effective_date: str
    language: str
    content_set_sha256: str
    manifest_sha256: str
    codings: tuple[Coding, ...]
    designations: tuple[Designation, ...]
    checked_files: int

    @property
    def code_catalog(self) -> frozenset[str]:
        return frozenset(coding.code for coding in self.codings)


def _parse_uuid(value: JsonValue, location: str) -> str:
    text = require_string(value, location)
    try:
        parsed = uuid.UUID(text)
    except ValueError as exc:
        raise ContractError("SCHEMA_INVALID", "Expected a canonical UUID.", location, 2) from exc
    if str(parsed) != text:
        raise ContractError("SCHEMA_INVALID", "Expected a lowercase canonical UUID.", location, 2)
    return text


def _parse_absolute_uri(value: JsonValue, location: str) -> str:
    text = require_string(value, location)
    parsed = urlparse(text)
    if not parsed.scheme or (parsed.scheme in {"http", "https"} and not parsed.netloc):
        raise ContractError("SCHEMA_INVALID", "Expected an absolute URI.", location, 2)
    return text


def _parse_date(value: JsonValue, location: str) -> date:
    text = require_string(value, location)
    try:
        return date.fromisoformat(text)
    except ValueError as exc:
        raise ContractError("SCHEMA_INVALID", "Expected an ISO 8601 calendar date.", location, 2) from exc


def _validate_root_layout(root: Path) -> None:
    if root.is_symlink():
        raise ContractError("SYMLINK", "The bundle root cannot be a symbolic link.", ".", 4)
    if not root.is_dir():
        raise ContractError("FILE_MISSING", "The reference bundle directory is missing.", ".", 3)
    allowed = {REFERENCE_MANIFEST, CODINGS, DESIGNATIONS, CHECKSUMS}
    actual: set[str] = set()
    for child in root.iterdir():
        if child.is_symlink():
            raise ContractError("SYMLINK", "Symbolic links are not permitted in bundles.", child.name, 4)
        if not child.is_file():
            raise ContractError("NONREGULAR", "Reference bundles contain regular files only.", child.name, 4)
        actual.add(child.name)
    missing = allowed - actual
    extra = actual - allowed
    if missing:
        raise ContractError("FILE_MISSING", "A required reference file is missing.", sorted(missing)[0], 3)
    if extra:
        raise ContractError("FILE_EXTRA", "The reference bundle contains an unexpected file.", sorted(extra)[0], 3)


def _parse_payload_descriptor(
    value: JsonValue, expected_path: str, expected_schema: str, location: str
) -> dict[str, JsonValue]:
    obj = require_object(value, location)
    require_exact_keys(obj, ("path", "sha256", "byte_count", "row_count", "schema_version"), (), location)
    path = normalized_relative_path(require_string(obj["path"], f"{location}.path"))
    if path != expected_path or obj["schema_version"] != expected_schema:
        raise ContractError("SCHEMA_INVALID", "Reference payload identity does not match the schema.", location, 2)
    return {
        "byte_count": require_int(obj["byte_count"], f"{location}.byte_count"),
        "path": path,
        "row_count": require_int(obj["row_count"], f"{location}.row_count"),
        "schema_version": expected_schema,
        "sha256": check_sha256(require_string(obj["sha256"], f"{location}.sha256"), f"{location}.sha256"),
    }


def _parse_checksums(raw: bytes) -> dict[str, str]:
    if raw.startswith(b"version https://git-lfs.github.com/spec/v1"):
        raise ContractError("LFS_POINTER", "A Git LFS pointer was supplied instead of content.", CHECKSUMS, 3)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError("UTF8_INVALID", "The checksum index is not valid UTF-8.", CHECKSUMS, 3) from exc
    if not raw.endswith(b"\n"):
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


def _require_scalar_properties(value: JsonValue, location: str) -> dict[str, JsonValue]:
    obj = require_object(value, location)
    for key, item in obj.items():
        if not key or isinstance(item, (dict, list, float)):
            raise ContractError("SCHEMA_INVALID", "Coding properties must be named JSON scalars.", location, 2)
    return obj


def inspect_reference_bundle(root: Path, environment: str = "synthetic") -> ReferenceBundle:
    _validate_root_layout(root)
    manifest_raw = read_stable_file(root / REFERENCE_MANIFEST, REFERENCE_MANIFEST, 5_000_000)
    manifest = require_object(load_json_bytes(manifest_raw, REFERENCE_MANIFEST), REFERENCE_MANIFEST)
    require_exact_keys(
        manifest,
        (
            "manifest_schema_version",
            "coding_schema_version",
            "designation_schema_version",
            "release_id",
            "system_uri",
            "system_name",
            "publisher",
            "version",
            "effective_date",
            "language",
            "source_uri",
            "content_set_sha256",
            "files",
            "code_format",
            "active_policy",
            "relationship_policy",
            "entitlement",
            "notices",
        ),
        (),
        REFERENCE_MANIFEST,
    )
    if (
        manifest["manifest_schema_version"] != "1.0.0"
        or manifest["coding_schema_version"] != "1.0.0"
        or manifest["designation_schema_version"] != "1.0.0"
    ):
        raise ContractError("SCHEMA_INVALID", "Unsupported reference schema version.", REFERENCE_MANIFEST, 2)
    release_id = _parse_uuid(manifest["release_id"], f"{REFERENCE_MANIFEST}.release_id")
    system_uri = _parse_absolute_uri(manifest["system_uri"], f"{REFERENCE_MANIFEST}.system_uri")
    if not system_uri.startswith("urn:coe:synthetic:"):
        raise ContractError(
            "ENTITLEMENT_INVALID", "v0 accepts synthetic terminology systems only.", REFERENCE_MANIFEST, 5
        )
    system_name = require_string(manifest["system_name"], f"{REFERENCE_MANIFEST}.system_name")
    require_string(manifest["publisher"], f"{REFERENCE_MANIFEST}.publisher")
    version = require_string(manifest["version"], f"{REFERENCE_MANIFEST}.version")
    effective_date = _parse_date(manifest["effective_date"], f"{REFERENCE_MANIFEST}.effective_date").isoformat()
    language = require_string(manifest["language"], f"{REFERENCE_MANIFEST}.language")
    _parse_absolute_uri(manifest["source_uri"], f"{REFERENCE_MANIFEST}.source_uri")
    expected_content_digest = check_sha256(
        require_string(manifest["content_set_sha256"], f"{REFERENCE_MANIFEST}.content_set_sha256"),
        f"{REFERENCE_MANIFEST}.content_set_sha256",
    )
    files = require_object(manifest["files"], f"{REFERENCE_MANIFEST}.files")
    require_exact_keys(files, ("codings", "designations"), (), f"{REFERENCE_MANIFEST}.files")
    coding_descriptor = _parse_payload_descriptor(
        files["codings"], CODINGS, "1.0.0", f"{REFERENCE_MANIFEST}.files.codings"
    )
    designation_descriptor = _parse_payload_descriptor(
        files["designations"], DESIGNATIONS, "1.0.0", f"{REFERENCE_MANIFEST}.files.designations"
    )
    if coding_descriptor["row_count"] > MAX_ROWS_CEILING or designation_descriptor["row_count"] > MAX_ROWS_CEILING:
        raise ContractError(
            "RESOURCE_LIMIT", "The reference release exceeds the v0 row ceiling.", REFERENCE_MANIFEST, 4
        )
    code_format = require_object(manifest["code_format"], f"{REFERENCE_MANIFEST}.code_format")
    require_exact_keys(code_format, ("pattern", "max_length"), (), f"{REFERENCE_MANIFEST}.code_format")
    pattern_text = require_string(code_format["pattern"], f"{REFERENCE_MANIFEST}.code_format.pattern")
    max_code_length = require_int(code_format["max_length"], f"{REFERENCE_MANIFEST}.code_format.max_length", minimum=1)
    if len(pattern_text) > 128 or max_code_length > 64:
        raise ContractError(
            "CODE_FORMAT_INVALID", "The code-format rule exceeds v0 safety limits.", REFERENCE_MANIFEST, 4
        )
    try:
        code_pattern = re.compile(pattern_text)
    except re.error as exc:
        raise ContractError(
            "CODE_FORMAT_INVALID", "The code-format regular expression is invalid.", REFERENCE_MANIFEST, 2
        ) from exc
    if manifest["active_policy"] != "include_active_and_inactive" or manifest["relationship_policy"] != "none":
        raise ContractError(
            "SCHEMA_INVALID", "v0 requires the explicit no-relationships reference policy.", REFERENCE_MANIFEST, 2
        )

    entitlement = require_object(manifest["entitlement"], f"{REFERENCE_MANIFEST}.entitlement")
    require_exact_keys(
        entitlement,
        (
            "owner_ref",
            "approval_ref",
            "analysis_use_permitted",
            "permitted_environments",
            "review_date",
            "allowed_derived_uses",
            "allowed_export_profiles",
        ),
        (),
        f"{REFERENCE_MANIFEST}.entitlement",
    )
    permitted = entitlement["permitted_environments"]
    derived = entitlement["allowed_derived_uses"]
    exports = entitlement["allowed_export_profiles"]
    entitlement_ok = (
        entitlement["owner_ref"] == "TEST-ONLY"
        and entitlement["approval_ref"] == "TEST-ONLY"
        and require_bool(
            entitlement["analysis_use_permitted"], f"{REFERENCE_MANIFEST}.entitlement.analysis_use_permitted"
        )
        and isinstance(permitted, list)
        and permitted == ["synthetic"]
        and environment in permitted
        and _parse_date(entitlement["review_date"], f"{REFERENCE_MANIFEST}.entitlement.review_date") >= date.today()
        and isinstance(derived, list)
        and derived == ["test"]
        and isinstance(exports, list)
        and exports == ["synthetic-internal"]
    )
    if not entitlement_ok:
        raise ContractError(
            "ENTITLEMENT_INVALID",
            "The synthetic analysis entitlement is missing, expired, or not permitted.",
            REFERENCE_MANIFEST,
            5,
        )
    notices = manifest["notices"]
    if not isinstance(notices, list) or not notices or not all(isinstance(item, str) and item for item in notices):
        raise ContractError(
            "ENTITLEMENT_INVALID", "At least one non-empty terminology notice is required.", REFERENCE_MANIFEST, 5
        )

    codings_raw = read_stable_file(root / CODINGS, CODINGS, MAX_REFERENCE_BYTES_CEILING)
    designations_raw = read_stable_file(root / DESIGNATIONS, DESIGNATIONS, MAX_REFERENCE_BYTES_CEILING)
    payloads = ((CODINGS, codings_raw, coding_descriptor), (DESIGNATIONS, designations_raw, designation_descriptor))
    for path, raw, descriptor in payloads:
        if raw.startswith(b"version https://git-lfs.github.com/spec/v1"):
            raise ContractError("LFS_POINTER", "A Git LFS pointer was supplied instead of content.", path, 3)
        if len(raw) != descriptor["byte_count"] or sha256_bytes(raw) != descriptor["sha256"]:
            raise ContractError("HASH_MISMATCH", "A reference payload does not match its manifest digest.", path, 3)
    coding_rows = load_jsonl_bytes(codings_raw, CODINGS)
    designation_rows = load_jsonl_bytes(designations_raw, DESIGNATIONS)
    if (
        len(coding_rows) != coding_descriptor["row_count"]
        or len(designation_rows) != designation_descriptor["row_count"]
    ):
        raise ContractError(
            "ROW_COUNT_MISMATCH", "A reference payload row count does not match its manifest.", REFERENCE_MANIFEST, 3
        )

    codings: list[Coding] = []
    codes: set[str] = set()
    for row_number, row in enumerate(coding_rows, start=1):
        location = f"{CODINGS}:{row_number}"
        require_exact_keys(row, ("code", "active", "definition", "semantic_types", "properties"), (), location)
        code = require_string(row["code"], f"{location}.code")
        if len(code) > max_code_length or code_pattern.fullmatch(code) is None:
            raise ContractError(
                "CODE_FORMAT_INVALID", "A coding does not satisfy the declared code format.", location, 3
            )
        if code in codes:
            raise ContractError("CODE_DUPLICATE", "The release contains a duplicate coding identity.", location, 3)
        codes.add(code)
        active = require_bool(row["active"], f"{location}.active")
        definition_value = row["definition"]
        if definition_value is not None and not isinstance(definition_value, str):
            raise ContractError("SCHEMA_INVALID", "Coding definitions must be strings or null.", location, 2)
        semantic_values = row["semantic_types"]
        if not isinstance(semantic_values, list) or not all(isinstance(item, str) and item for item in semantic_values):
            raise ContractError("SCHEMA_INVALID", "Semantic types must be a list of non-empty strings.", location, 2)
        if len(set(semantic_values)) != len(semantic_values):
            raise ContractError("SCHEMA_INVALID", "Semantic types cannot contain duplicates.", location, 2)
        properties = _require_scalar_properties(row["properties"], f"{location}.properties")
        codings.append(
            Coding(
                code=code,
                active=active,
                definition=definition_value,
                semantic_types=tuple(sorted(semantic_values)),
                properties=dict(sorted(properties.items())),
            )
        )

    designations: list[Designation] = []
    designation_keys: set[tuple[str, str, str, str, str]] = set()
    preferred_counts: Counter[tuple[str, str]] = Counter()
    alias_counts: Counter[str] = Counter()
    for row_number, row in enumerate(designation_rows, start=1):
        location = f"{DESIGNATIONS}:{row_number}"
        require_exact_keys(row, ("code", "language", "kind", "value", "source"), (), location)
        code = require_string(row["code"], f"{location}.code")
        row_language = require_string(row["language"], f"{location}.language")
        kind = require_string(row["kind"], f"{location}.kind")
        value = require_string(row["value"], f"{location}.value").strip()
        source = require_string(row["source"], f"{location}.source")
        if code not in codes:
            raise ContractError(
                "DESIGNATION_DANGLING", "A designation refers to a code absent from this release.", location, 3
            )
        if row_language != language or kind not in {"preferred", "alias"} or not value:
            raise ContractError(
                "SCHEMA_INVALID", "A designation has an unsupported language, kind, or empty value.", location, 2
            )
        key = (code, row_language, kind, value, source)
        if key in designation_keys:
            raise ContractError(
                "DESIGNATION_DUPLICATE", "The release contains a duplicate designation row.", location, 3
            )
        designation_keys.add(key)
        if kind == "preferred":
            preferred_counts[(code, row_language)] += 1
        else:
            alias_counts[code] += 1
            if alias_counts[code] > MAX_ALIASES_PER_CODE:
                raise ContractError("RESOURCE_LIMIT", "A coding exceeds the v0 alias ceiling.", location, 4)
        designations.append(Designation(code, row_language, kind, value, source))
    for code in codes:
        if preferred_counts[(code, language)] != 1:
            raise ContractError(
                "PREFERRED_LABEL_INVALID", "Each coding requires exactly one preferred designation.", DESIGNATIONS, 3
            )

    content_payload: dict[str, JsonValue] = {
        "content_hash_schema_version": CONTENT_HASH_SCHEMA,
        "payloads": sorted([coding_descriptor, designation_descriptor], key=lambda item: str(item["path"])),
    }
    actual_content_digest = sha256_canonical(content_payload)
    if actual_content_digest != expected_content_digest:
        raise ContractError(
            "CONTENT_DIGEST_MISMATCH", "The reference content-set digest is invalid.", REFERENCE_MANIFEST, 3
        )

    checksums_raw = read_stable_file(root / CHECKSUMS, CHECKSUMS, 5_000_000)
    checksums = _parse_checksums(checksums_raw)
    expected_checksum_paths = {REFERENCE_MANIFEST, CODINGS, DESIGNATIONS}
    if checksums.keys() != expected_checksum_paths:
        raise ContractError(
            "CHECKSUM_INDEX_INVALID", "The checksum index is not an exact file inventory.", CHECKSUMS, 3
        )
    actual_raw = {REFERENCE_MANIFEST: manifest_raw, CODINGS: codings_raw, DESIGNATIONS: designations_raw}
    for path, raw in actual_raw.items():
        if checksums[path] != sha256_bytes(raw):
            raise ContractError("HASH_MISMATCH", "A checksum index entry does not match its file.", path, 3)

    return ReferenceBundle(
        release_id=release_id,
        system_uri=system_uri,
        system_name=system_name,
        version=version,
        effective_date=effective_date,
        language=language,
        content_set_sha256=actual_content_digest,
        manifest_sha256=sha256_bytes(manifest_raw),
        codings=tuple(sorted(codings, key=lambda item: item.code)),
        designations=tuple(sorted(designations, key=lambda item: (item.code, item.kind, item.value, item.source))),
        checked_files=4,
    )


def validate_reference_bundle(root: Path, environment: str = "synthetic") -> PreflightReport:
    try:
        bundle = inspect_reference_bundle(root, environment=environment)
    except ContractError as exc:
        severity = "entitlement" if exc.exit_code == 5 else ("security" if exc.exit_code == 4 else "error")
        return PreflightReport(
            kind="reference",
            status="failed",
            issues=(
                Issue(
                    code=exc.code,
                    severity=severity,
                    check_id="reference_contract",
                    safe_message=exc.safe_message,
                    relative_location=exc.relative_location,
                ),
            ),
        )
    return PreflightReport(
        kind="reference",
        status="passed",
        subject_id=bundle.release_id,
        manifest_sha256=bundle.manifest_sha256,
        content_set_sha256=bundle.content_set_sha256,
        checked_files=bundle.checked_files,
        measurements={
            "coding_count": len(bundle.codings),
            "designation_count": len(bundle.designations),
            "system_uri": bundle.system_uri,
        },
    )
