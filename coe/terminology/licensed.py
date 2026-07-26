"""Immutable SQLite indexes for privately licensed terminology releases.

The source CSV is validated and hashed without loading it into memory.  The
resulting SQLite file is a derived, private cache: release identity is based on
the source digest and import profile rather than SQLite's non-portable bytes.
"""

from __future__ import annotations

import csv
import hashlib
import os
import re
import sqlite3
import stat
import sysconfig
import uuid
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from types import TracebackType
from typing import Iterator
from urllib.parse import urlparse

from coe.canonical import JsonValue, canonical_json_bytes, load_json, sha256_canonical
from coe.errors import ContractError
from coe.ingest.normalize import normalize_lexical
from coe.terminology.exact import DesignationHit

SCHEMA_VERSION = "1.0.0"
IMPORTER_VERSION = "1.0.0"
APPLICATION_ID = 0x434F4531  # COE1
USER_VERSION = 1
MAX_SOURCE_BYTES = 2_000_000_000
MAX_ROWS = 2_000_000
DEFAULT_SPECS_PATH = Path(__file__).resolve().parents[2] / "specs" / "licensed_terminologies.json"
_RELEASE_NAMESPACE = uuid.UUID("b814cd5d-6f3d-5b38-9d76-114f60de376e")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_METHOD_ORDER = {"exact_preferred": 0, "exact_alias": 1}
_VARIANT_ORDER = {"primary": 0, "casefold": 1}
_METADATA_KEYS = {
    "schema_version",
    "importer_version",
    "terminology",
    "system_label",
    "system_uri",
    "system_name",
    "publisher",
    "language",
    "version",
    "effective_date",
    "source_label",
    "source_uri",
    "source_sha256",
    "source_byte_count",
    "profile_sha256",
    "release_id",
    "code_count",
    "alias_count",
    "designation_count",
    "active_count",
    "inactive_count",
    "license_policy",
    "entitlement_ref",
    "notices_json",
    "content_set_sha256",
    "manifest_sha256",
}
_METADATA_TABLE_SQL = "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID"
_CODING_TABLE_SQL = """CREATE TABLE coding(
    code TEXT PRIMARY KEY,
    active INTEGER NOT NULL CHECK(active IN (0,1)),
    display TEXT NOT NULL,
    source_status TEXT NOT NULL,
    properties_json TEXT NOT NULL
) WITHOUT ROWID"""
_DESIGNATION_TABLE_SQL = """CREATE TABLE designation(
    designation_id TEXT PRIMARY KEY,
    code TEXT NOT NULL REFERENCES coding(code),
    kind TEXT NOT NULL CHECK(kind IN ('preferred','alias')),
    language TEXT NOT NULL,
    value TEXT NOT NULL,
    normalized_primary TEXT NOT NULL,
    normalized_folded TEXT NOT NULL,
    source TEXT NOT NULL,
    UNIQUE(code,kind,language,value,source)
) WITHOUT ROWID"""
_CODING_ACTIVE_INDEX_SQL = "CREATE INDEX coding_active ON coding(active,code)"
_DESIGNATION_PRIMARY_INDEX_SQL = "CREATE INDEX designation_primary ON designation(kind,normalized_primary,code)"
_DESIGNATION_FOLDED_INDEX_SQL = "CREATE INDEX designation_folded ON designation(kind,normalized_folded,code)"
_SQLITE_MASTER_INVENTORY: frozenset[tuple[str, str, str, str | None]] = frozenset(
    {
        ("table", "metadata", "metadata", _METADATA_TABLE_SQL),
        ("table", "coding", "coding", _CODING_TABLE_SQL),
        ("table", "designation", "designation", _DESIGNATION_TABLE_SQL),
        ("index", "coding_active", "coding", _CODING_ACTIVE_INDEX_SQL),
        ("index", "designation_primary", "designation", _DESIGNATION_PRIMARY_INDEX_SQL),
        ("index", "designation_folded", "designation", _DESIGNATION_FOLDED_INDEX_SQL),
        ("index", "sqlite_autoindex_designation_2", "designation", None),
    }
)


def _canonical_schema_sql(value: str | None) -> str | None:
    """Ignore SQLite's formatting preservation while retaining every schema token."""

    return None if value is None else " ".join(value.split())


_CANONICAL_SQLITE_MASTER_INVENTORY = frozenset(
    (kind, name, table, _canonical_schema_sql(sql)) for kind, name, table, sql in _SQLITE_MASTER_INVENTORY
)


@dataclass(frozen=True, slots=True)
class AliasSource:
    column: str
    delimiter: str


@dataclass(frozen=True, slots=True)
class StatusRule:
    mode: str
    basis: str
    column: str | None = None
    allowed_values: frozenset[str] = frozenset()
    active_values: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class TerminologySpec:
    key: str
    file_name: str
    system_label: str
    system_uri: str
    system_name: str
    publisher: str
    language: str
    version: str
    effective_date: str
    source_label: str
    source_uri: str
    normalized_sha256: str
    byte_count: int
    row_count: int
    alias_count: int
    columns: tuple[str, ...]
    alias_sources: tuple[AliasSource, ...]
    property_columns: tuple[str, ...]
    status_rule: StatusRule
    code_pattern: str
    max_code_length: int
    max_aliases_per_code: int
    max_designation_chars: int
    license_policy: str
    required_notices: tuple[str, ...]
    profile_sha256: str


@dataclass(frozen=True, slots=True)
class LicensedIndexMetadata:
    path: Path
    terminology: str
    system_label: str
    system_uri: str
    system_name: str
    version: str
    effective_date: str
    language: str
    release_id: str
    source_sha256: str
    profile_sha256: str
    content_set_sha256: str
    manifest_sha256: str
    index_sha256: str
    code_count: int
    alias_count: int
    designation_count: int
    active_count: int
    inactive_count: int


@dataclass(frozen=True, slots=True)
class LicensedLookupCandidate:
    system_uri: str
    release_id: str
    code: str
    best_method: str
    methods: tuple[str, ...]
    variants: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class LicensedLookupResult:
    system_uri: str
    release_id: str
    outcome: str
    candidates: tuple[LicensedLookupCandidate, ...]

    @property
    def ambiguous(self) -> bool:
        return self.outcome == "grounded_ambiguous"


@dataclass(frozen=True, slots=True)
class LicensedReferenceIdentity:
    release_id: str
    system_uri: str
    system_name: str
    version: str
    effective_date: str
    language: str
    content_set_sha256: str
    manifest_sha256: str
    code_catalog: "SQLiteCodeCatalog"


def _object(value: JsonValue, location: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise ContractError("SPEC_INVALID", "Expected an object in the terminology profile.", location, 2)
    return value


def _string(obj: dict[str, JsonValue], key: str, location: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value or any(ord(char) < 32 for char in value):
        raise ContractError("SPEC_INVALID", "Expected a non-empty profile string.", f"{location}.{key}", 2)
    return value


def _integer(obj: dict[str, JsonValue], key: str, location: str, minimum: int = 0) -> int:
    value = obj.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ContractError("SPEC_INVALID", "Expected a bounded profile integer.", f"{location}.{key}", 2)
    return value


def _strings(obj: dict[str, JsonValue], key: str, location: str, *, nonempty: bool = False) -> tuple[str, ...]:
    value = obj.get(key)
    if (
        not isinstance(value, list)
        or (nonempty and not value)
        or not all(isinstance(item, str) and item for item in value)
    ):
        raise ContractError("SPEC_INVALID", "Expected a list of profile strings.", f"{location}.{key}", 2)
    result = tuple(value)
    if len(set(result)) != len(result):
        raise ContractError("SPEC_INVALID", "Profile lists cannot contain duplicates.", f"{location}.{key}", 2)
    return result


def _parse_status(value: JsonValue, columns: tuple[str, ...], location: str) -> StatusRule:
    obj = _object(value, location)
    mode = _string(obj, "mode", location)
    if mode == "all_active":
        if set(obj) != {"mode", "basis"}:
            raise ContractError("SPEC_INVALID", "The all-active rule has invalid fields.", location, 2)
        return StatusRule(mode=mode, basis=_string(obj, "basis", location))
    if mode != "allowlist" or set(obj) != {"mode", "column", "allowed_values", "active_values"}:
        raise ContractError("SPEC_INVALID", "The status rule is unsupported.", location, 2)
    column = _string(obj, "column", location)
    allowed = frozenset(_strings(obj, "allowed_values", location, nonempty=True))
    active = frozenset(_strings(obj, "active_values", location, nonempty=True))
    if column not in columns or not active <= allowed:
        raise ContractError("SPEC_INVALID", "The status rule is inconsistent with its columns.", location, 2)
    return StatusRule(
        mode=mode, basis=f"{column} allowlist", column=column, allowed_values=allowed, active_values=active
    )


def _resolve_specs_path(path: Path | None) -> Path:
    if path is not None:
        return path
    configured = os.environ.get("COE_LICENSED_TERMINOLOGY_SPECS")
    candidates = (
        Path(configured).expanduser() if configured else None,
        DEFAULT_SPECS_PATH,
        Path(sysconfig.get_path("data")) / "share" / "coe" / "specs" / "licensed_terminologies.json",
    )
    for candidate in candidates:
        if candidate is not None and candidate.is_file():
            return candidate
    raise ContractError(
        "SPEC_MISSING",
        "Licensed terminology profiles are unavailable; pass an explicit specs_path.",
        "licensed_terminologies.json",
        3,
    )


def load_terminology_specs(path: Path | None = None) -> dict[str, TerminologySpec]:
    """Load strict import profiles, keyed by their short terminology name."""

    spec_path = _resolve_specs_path(path)
    root = _object(load_json(spec_path, spec_path.name), spec_path.name)
    if set(root) != {"schema_version", "importer_version", "terminologies"}:
        raise ContractError("SPEC_INVALID", "The terminology specification has invalid fields.", spec_path.name, 2)
    if root["schema_version"] != SCHEMA_VERSION or root["importer_version"] != IMPORTER_VERSION:
        raise ContractError("SPEC_INVALID", "The terminology specification version is unsupported.", spec_path.name, 2)
    profiles = _object(root["terminologies"], f"{spec_path.name}.terminologies")
    result: dict[str, TerminologySpec] = {}
    expected_keys = {
        "file_name",
        "system_label",
        "system_uri",
        "system_name",
        "publisher",
        "language",
        "version",
        "effective_date",
        "source_label",
        "source_uri",
        "normalized_sha256",
        "byte_count",
        "row_count",
        "alias_count",
        "columns",
        "alias_sources",
        "property_columns",
        "status_rule",
        "code_pattern",
        "max_code_length",
        "max_aliases_per_code",
        "max_designation_chars",
        "license_policy",
        "required_notices",
    }
    for key, raw in profiles.items():
        location = f"{spec_path.name}.terminologies.{key}"
        if not isinstance(key, str) or not re.fullmatch(r"[a-z0-9]+", key):
            raise ContractError("SPEC_INVALID", "Terminology profile keys must be lowercase identifiers.", location, 2)
        obj = _object(raw, location)
        if set(obj) != expected_keys:
            raise ContractError("SPEC_INVALID", "A terminology profile has invalid fields.", location, 2)
        columns = _strings(obj, "columns", location, nonempty=True)
        mandatory = {"system", "code", "display", "source", "version", "effective_date"}
        if not mandatory <= set(columns):
            raise ContractError("SPEC_INVALID", "A terminology profile lacks mandatory columns.", location, 2)
        alias_raw = obj["alias_sources"]
        if not isinstance(alias_raw, list):
            raise ContractError("SPEC_INVALID", "Alias sources must be a list.", location, 2)
        aliases: list[AliasSource] = []
        for index, item in enumerate(alias_raw):
            alias_obj = _object(item, f"{location}.alias_sources[{index}]")
            if set(alias_obj) != {"column", "delimiter"}:
                raise ContractError("SPEC_INVALID", "An alias source has invalid fields.", location, 2)
            column = _string(alias_obj, "column", location)
            delimiter = _string(alias_obj, "delimiter", location)
            if column not in columns or len(delimiter) != 1:
                raise ContractError("SPEC_INVALID", "An alias source is inconsistent with the CSV schema.", location, 2)
            aliases.append(AliasSource(column, delimiter))
        properties = _strings(obj, "property_columns", location)
        if not set(properties) <= set(columns):
            raise ContractError("SPEC_INVALID", "A property column is absent from the CSV schema.", location, 2)
        system_uri = _string(obj, "system_uri", location)
        parsed_uri = urlparse(system_uri)
        if not parsed_uri.scheme or (parsed_uri.scheme in {"http", "https"} and not parsed_uri.netloc):
            raise ContractError("SPEC_INVALID", "A canonical system URI is invalid.", location, 2)
        effective_date = _string(obj, "effective_date", location)
        try:
            date.fromisoformat(effective_date)
        except ValueError as exc:
            raise ContractError("SPEC_INVALID", "An effective date is invalid.", location, 2) from exc
        digest = _string(obj, "normalized_sha256", location)
        if _SHA256.fullmatch(digest) is None:
            raise ContractError("SPEC_INVALID", "A normalized SHA-256 is invalid.", location, 2)
        pattern = _string(obj, "code_pattern", location)
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ContractError("SPEC_INVALID", "A code pattern is invalid.", location, 2) from exc
        notices = _strings(obj, "required_notices", location, nonempty=True)
        file_name = _string(obj, "file_name", location)
        if Path(file_name).name != file_name:
            raise ContractError("SPEC_INVALID", "A terminology file name must be a basename.", location, 2)
        result[key] = TerminologySpec(
            key=key,
            file_name=file_name,
            system_label=_string(obj, "system_label", location),
            system_uri=system_uri,
            system_name=_string(obj, "system_name", location),
            publisher=_string(obj, "publisher", location),
            language=_string(obj, "language", location),
            version=_string(obj, "version", location),
            effective_date=effective_date,
            source_label=_string(obj, "source_label", location),
            source_uri=_string(obj, "source_uri", location),
            normalized_sha256=digest,
            byte_count=_integer(obj, "byte_count", location, 1),
            row_count=_integer(obj, "row_count", location, 1),
            alias_count=_integer(obj, "alias_count", location),
            columns=columns,
            alias_sources=tuple(aliases),
            property_columns=properties,
            status_rule=_parse_status(obj["status_rule"], columns, f"{location}.status_rule"),
            code_pattern=pattern,
            max_code_length=_integer(obj, "max_code_length", location, 1),
            max_aliases_per_code=_integer(obj, "max_aliases_per_code", location, 1),
            max_designation_chars=_integer(obj, "max_designation_chars", location, 1),
            license_policy=_string(obj, "license_policy", location),
            required_notices=notices,
            profile_sha256=sha256_canonical(obj, domain=b"coe-licensed-profile-v1"),
        )
    if not result:
        raise ContractError("SPEC_INVALID", "At least one terminology profile is required.", spec_path.name, 2)
    return result


def _is_link_or_reparse(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    is_junction = getattr(path, "is_junction", lambda: False)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return path.is_symlink() or bool(is_junction()) or bool(getattr(info, "st_file_attributes", 0) & reparse_flag)


def _has_link_or_reparse_component(path: Path) -> bool:
    absolute = path.absolute()
    if os.name != "nt":
        return _is_link_or_reparse(absolute)
    return any(_is_link_or_reparse(candidate) for candidate in (absolute, *absolute.parents))


def _open_regular(path: Path) -> tuple[int, os.stat_result]:
    if _has_link_or_reparse_component(path):
        raise ContractError("SYMLINK", "Symbolic links are not accepted as terminology sources.", path.name, 4)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as exc:
        raise ContractError("FILE_MISSING", "The terminology source is missing.", path.name, 3) from exc
    except OSError as exc:
        raise ContractError("FILE_UNREADABLE", "The terminology source could not be opened.", path.name, 3) from exc
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode):
        os.close(descriptor)
        raise ContractError("NONREGULAR", "The terminology source must be a regular file.", path.name, 4)
    if info.st_size > MAX_SOURCE_BYTES:
        os.close(descriptor)
        raise ContractError("RESOURCE_LIMIT", "The terminology source exceeds the byte limit.", path.name, 4)
    return descriptor, info


def _hash_source(path: Path) -> tuple[str, int, tuple[int, int, int, int], bytes]:
    descriptor, before = _open_regular(path)
    digest = hashlib.sha256()
    prefix = b""
    try:
        while chunk := os.read(descriptor, 4 * 1024 * 1024):
            if not prefix:
                prefix = chunk[:128]
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ContractError("FILE_CHANGED", "The terminology source changed while it was read.", path.name, 4)
    return digest.hexdigest(), before.st_size, identity, prefix


def _release_id(spec: TerminologySpec) -> str:
    identity = "\0".join(
        (
            IMPORTER_VERSION,
            spec.system_uri,
            spec.version,
            spec.effective_date,
            spec.normalized_sha256,
            spec.profile_sha256,
        )
    )
    return str(uuid.uuid5(_RELEASE_NAMESPACE, identity))


def _release_id_from_values(values: dict[str, str]) -> str:
    identity = "\0".join(
        (
            values["importer_version"],
            values["system_uri"],
            values["version"],
            values["effective_date"],
            values["source_sha256"],
            values["profile_sha256"],
        )
    )
    return str(uuid.uuid5(_RELEASE_NAMESPACE, identity))


def _designation_id(release_id: str, code: str, kind: str, value: str, source: str) -> str:
    payload: dict[str, JsonValue] = {
        "code": code,
        "kind": kind,
        "release_id": release_id,
        "source": source,
        "value": value,
    }
    return sha256_canonical(payload, domain=b"coe-designation-v1")


def _schema(connection: sqlite3.Connection) -> None:
    connection.executescript(";\n".join((_METADATA_TABLE_SQL, _CODING_TABLE_SQL, _DESIGNATION_TABLE_SQL)) + ";\n")


def _active(spec: TerminologySpec, row: dict[str, str]) -> tuple[bool, str]:
    rule = spec.status_rule
    if rule.mode == "all_active":
        return True, rule.basis
    assert rule.column is not None
    value = row[rule.column]
    if value not in rule.allowed_values:
        raise ContractError(
            "STATUS_INVALID", "A terminology status is outside the declared release policy.", spec.file_name, 3
        )
    return value in rule.active_values, value


def _manifest_values(
    spec: TerminologySpec,
    entitlement_ref: str,
    release_id: str,
    code_count: int,
    alias_count: int,
    active_count: int,
) -> dict[str, str]:
    content_payload: dict[str, JsonValue] = {
        "active_count": active_count,
        "alias_count": alias_count,
        "code_count": code_count,
        "importer_version": IMPORTER_VERSION,
        "profile_sha256": spec.profile_sha256,
        "source_byte_count": spec.byte_count,
        "source_sha256": spec.normalized_sha256,
    }
    content_digest = sha256_canonical(content_payload, domain=b"coe-licensed-content-v1")
    values = {
        "schema_version": SCHEMA_VERSION,
        "importer_version": IMPORTER_VERSION,
        "terminology": spec.key,
        "system_label": spec.system_label,
        "system_uri": spec.system_uri,
        "system_name": spec.system_name,
        "publisher": spec.publisher,
        "language": spec.language,
        "version": spec.version,
        "effective_date": spec.effective_date,
        "source_label": spec.source_label,
        "source_uri": spec.source_uri,
        "source_sha256": spec.normalized_sha256,
        "source_byte_count": str(spec.byte_count),
        "profile_sha256": spec.profile_sha256,
        "release_id": release_id,
        "code_count": str(code_count),
        "alias_count": str(alias_count),
        "designation_count": str(code_count + alias_count),
        "active_count": str(active_count),
        "inactive_count": str(code_count - active_count),
        "license_policy": spec.license_policy,
        "entitlement_ref": entitlement_ref,
        "notices_json": canonical_json_bytes(list(spec.required_notices)).decode("utf-8"),
        "content_set_sha256": content_digest,
    }
    manifest_payload: dict[str, JsonValue] = {key: value for key, value in values.items()}
    values["manifest_sha256"] = sha256_canonical(manifest_payload, domain=b"coe-licensed-manifest-v1")
    return values


def _build_database(source: Path, target: Path, spec: TerminologySpec, entitlement_ref: str) -> None:
    release_id = _release_id(spec)
    connection = sqlite3.connect(target)
    try:
        connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
        connection.execute(f"PRAGMA user_version={USER_VERSION}")
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA temp_store=FILE")
        _schema(connection)
        connection.execute("BEGIN IMMEDIATE")
        # One aliases cell may legally hold max_aliases_per_code entries of
        # max_designation_chars each (plus delimiters), so size the parser cap
        # to the largest cell the profile itself allows.
        csv.field_size_limit(
            max(spec.max_aliases_per_code * (spec.max_designation_chars + 1), spec.max_designation_chars * 4, 131_072)
        )
        code_pattern = re.compile(spec.code_pattern)
        code_count = alias_count = active_count = 0
        seen_codes: set[str] = set()
        coding_buffer: list[tuple[str, int, str, str, str]] = []
        designation_buffer: list[tuple[str, str, str, str, str, str, str, str]] = []

        def flush() -> None:
            try:
                connection.executemany("INSERT INTO coding VALUES(?,?,?,?,?)", coding_buffer)
                connection.executemany("INSERT INTO designation VALUES(?,?,?,?,?,?,?,?)", designation_buffer)
            except sqlite3.IntegrityError as exc:
                raise ContractError(
                    "ROW_DUPLICATE", "The terminology source contains a duplicate identity.", source.name, 3
                ) from exc
            coding_buffer.clear()
            designation_buffer.clear()

        with source.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if tuple(reader.fieldnames or ()) != spec.columns:
                raise ContractError(
                    "CSV_SCHEMA_INVALID", "The terminology CSV header does not match its profile.", source.name, 2
                )
            try:
                for row_number, raw_row in enumerate(reader, start=2):
                    if code_count >= MAX_ROWS:
                        raise ContractError(
                            "RESOURCE_LIMIT",
                            "The terminology source exceeds the importer row ceiling.",
                            f"{source.name}:{row_number}",
                            4,
                        )
                    if None in raw_row or any(value is None for value in raw_row.values()):
                        raise ContractError(
                            "CSV_ROW_INVALID", "A terminology CSV row is malformed.", f"{source.name}:{row_number}", 3
                        )
                    row = {key: str(value) for key, value in raw_row.items()}
                    if (
                        row["system"] != spec.system_label
                        or row["version"] != spec.version
                        or row["effective_date"] != spec.effective_date
                        or row["source"] != spec.source_label
                    ):
                        raise ContractError(
                            "RELEASE_METADATA_MISMATCH",
                            "A row does not match its pinned release metadata.",
                            f"{source.name}:{row_number}",
                            3,
                        )
                    code = row["code"]
                    display = row["display"]
                    if (
                        not code
                        or code != code.strip()
                        or len(code) > spec.max_code_length
                        or code_pattern.fullmatch(code) is None
                    ):
                        raise ContractError(
                            "CODE_FORMAT_INVALID",
                            "A code does not match its terminology profile.",
                            f"{source.name}:{row_number}",
                            3,
                        )
                    if code in seen_codes:
                        raise ContractError(
                            "CODE_DUPLICATE",
                            "The terminology source contains a duplicate code.",
                            f"{source.name}:{row_number}",
                            3,
                        )
                    seen_codes.add(code)
                    if not display or len(display) > spec.max_designation_chars or "\0" in display:
                        raise ContractError(
                            "DESIGNATION_INVALID",
                            "A preferred display is empty or oversized.",
                            f"{source.name}:{row_number}",
                            3,
                        )
                    is_active, source_status = _active(spec, row)
                    properties = {"active_basis": spec.status_rule.basis}
                    properties.update({column: row[column] for column in spec.property_columns if row[column]})
                    coding_buffer.append(
                        (code, int(is_active), display, source_status, canonical_json_bytes(properties).decode("utf-8"))
                    )
                    lexical = normalize_lexical(display)
                    preferred_source = f"{spec.source_label}#display"
                    designation_buffer.append(
                        (
                            _designation_id(release_id, code, "preferred", display, preferred_source),
                            code,
                            "preferred",
                            spec.language,
                            display,
                            lexical.primary,
                            lexical.folded,
                            preferred_source,
                        )
                    )
                    aliases: dict[str, str] = {}
                    for alias_source in spec.alias_sources:
                        raw_aliases = row[alias_source.column]
                        for value in raw_aliases.split(alias_source.delimiter) if raw_aliases else ():
                            alias = value.strip()
                            if alias and alias != display:
                                aliases.setdefault(alias, alias_source.column)
                    if len(aliases) > spec.max_aliases_per_code:
                        raise ContractError(
                            "RESOURCE_LIMIT", "A code exceeds its alias limit.", f"{source.name}:{row_number}", 4
                        )
                    for alias, column in aliases.items():
                        if len(alias) > spec.max_designation_chars or "\0" in alias:
                            raise ContractError(
                                "DESIGNATION_INVALID",
                                "An alias is oversized or invalid.",
                                f"{source.name}:{row_number}",
                                3,
                            )
                        alias_source = f"{spec.source_label}#{column}"
                        lexical = normalize_lexical(alias)
                        designation_buffer.append(
                            (
                                _designation_id(release_id, code, "alias", alias, alias_source),
                                code,
                                "alias",
                                spec.language,
                                alias,
                                lexical.primary,
                                lexical.folded,
                                alias_source,
                            )
                        )
                    code_count += 1
                    alias_count += len(aliases)
                    active_count += is_active
                    if len(coding_buffer) >= 2_000:
                        flush()
            except (UnicodeDecodeError, csv.Error) as exc:
                raise ContractError(
                    "CSV_INVALID", "The terminology source is not valid UTF-8 CSV.", source.name, 3
                ) from exc
        flush()
        if code_count != spec.row_count or alias_count != spec.alias_count:
            raise ContractError(
                "ROW_COUNT_MISMATCH", "The terminology row or alias count differs from its profile.", source.name, 3
            )
        connection.executescript(
            ";\n".join(
                (
                    _DESIGNATION_PRIMARY_INDEX_SQL,
                    _DESIGNATION_FOLDED_INDEX_SQL,
                    _CODING_ACTIVE_INDEX_SQL,
                )
            )
            + ";\n"
        )
        values = _manifest_values(spec, entitlement_ref, release_id, code_count, alias_count, active_count)
        connection.executemany("INSERT INTO metadata(key,value) VALUES(?,?)", sorted(values.items()))
        connection.commit()
        connection.execute("VACUUM")
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _cleanup_sqlite(path: Path) -> None:
    for candidate in (path, Path(f"{path}-journal"), Path(f"{path}-wal"), Path(f"{path}-shm")):
        try:
            candidate.unlink()
        except FileNotFoundError:
            pass


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def build_licensed_index(
    csv_path: Path,
    output_path: Path,
    terminology: str,
    *,
    specs_path: Path | None = None,
    entitlement_ref: str,
    overwrite: bool = False,
) -> LicensedIndexMetadata:
    """Validate a normalized release and atomically publish its SQLite index."""

    if not entitlement_ref.strip() or len(entitlement_ref) > 256 or any(ord(char) < 32 for char in entitlement_ref):
        raise ContractError(
            "ENTITLEMENT_INVALID", "A non-secret entitlement reference is required.", "entitlement_ref", 5
        )
    specs = load_terminology_specs(specs_path)
    try:
        spec = specs[terminology]
    except KeyError as exc:
        raise ContractError(
            "SPEC_INVALID", "The requested terminology profile does not exist.", terminology, 2
        ) from exc
    if csv_path.name != spec.file_name:
        raise ContractError(
            "FILE_IDENTITY_MISMATCH", "The terminology file name does not match its profile.", csv_path.name, 3
        )
    digest, byte_count, identity, prefix = _hash_source(csv_path)
    if prefix.startswith(b"version https://git-lfs.github.com/spec/v1"):
        raise ContractError(
            "LFS_POINTER", "A Git LFS pointer was supplied instead of terminology content.", csv_path.name, 3
        )
    if digest != spec.normalized_sha256 or byte_count != spec.byte_count:
        raise ContractError(
            "HASH_MISMATCH", "The terminology source does not match its pinned digest.", csv_path.name, 3
        )
    try:
        same_target = csv_path.resolve(strict=True) == output_path.resolve(strict=False)
        if output_path.exists():
            same_target = same_target or os.path.samefile(csv_path, output_path)
    except OSError:
        same_target = False
    if same_target:
        raise ContractError(
            "OUTPUT_INVALID",
            "The terminology source and index output must be distinct files.",
            output_path.name,
            4,
        )
    if _has_link_or_reparse_component(output_path.parent):
        raise ContractError(
            "OUTPUT_INVALID", "The terminology index path crosses a link or reparse point.", output_path.name, 4
        )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if _is_link_or_reparse(output_path) or (output_path.exists() and not output_path.is_file()):
        raise ContractError(
            "OUTPUT_INVALID", "The terminology index target is not a regular file.", output_path.name, 4
        )
    if output_path.exists() and not overwrite:
        raise ContractError("OUTPUT_EXISTS", "The terminology index already exists.", output_path.name, 4)
    temporary = output_path.with_name(f".{output_path.name}.{uuid.uuid4().hex}.tmp")
    try:
        _build_database(csv_path, temporary, spec, entitlement_ref.strip())
        digest_after, bytes_after, identity_after, _ = _hash_source(csv_path)
        if (digest_after, bytes_after, identity_after) != (digest, byte_count, identity):
            raise ContractError("FILE_CHANGED", "The terminology source changed during import.", csv_path.name, 4)
        verify_licensed_index(temporary, expected_source_sha256=digest)
        os.replace(temporary, output_path)
        _fsync_directory(output_path.parent)
        return verify_licensed_index(output_path, expected_source_sha256=digest)
    finally:
        _cleanup_sqlite(temporary)


def _connect_read_only(path: Path) -> sqlite3.Connection:
    if _has_link_or_reparse_component(path) or not path.is_file():
        raise ContractError("INDEX_INVALID", "The terminology index is not a regular file.", path.name, 4)
    try:
        connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro&immutable=1", uri=True)
    except sqlite3.Error as exc:
        raise ContractError("INDEX_INVALID", "The terminology index could not be opened.", path.name, 3) from exc
    connection.row_factory = sqlite3.Row
    return connection


def _content_payload(values: dict[str, str]) -> dict[str, JsonValue]:
    return {
        "active_count": int(values["active_count"]),
        "alias_count": int(values["alias_count"]),
        "code_count": int(values["code_count"]),
        "importer_version": values["importer_version"],
        "profile_sha256": values["profile_sha256"],
        "source_byte_count": int(values["source_byte_count"]),
        "source_sha256": values["source_sha256"],
    }


def _metadata_from_values(path: Path, values: dict[str, str], index_sha256: str) -> LicensedIndexMetadata:
    return LicensedIndexMetadata(
        path=path,
        terminology=values["terminology"],
        system_label=values["system_label"],
        system_uri=values["system_uri"],
        system_name=values["system_name"],
        version=values["version"],
        effective_date=values["effective_date"],
        language=values["language"],
        release_id=values["release_id"],
        source_sha256=values["source_sha256"],
        profile_sha256=values["profile_sha256"],
        content_set_sha256=values["content_set_sha256"],
        manifest_sha256=values["manifest_sha256"],
        index_sha256=index_sha256,
        code_count=int(values["code_count"]),
        alias_count=int(values["alias_count"]),
        designation_count=int(values["designation_count"]),
        active_count=int(values["active_count"]),
        inactive_count=int(values["inactive_count"]),
    )


def verify_licensed_index(path: Path, expected_source_sha256: str | None = None) -> LicensedIndexMetadata:
    """Verify structural integrity, counts and semantic metadata of an index."""

    connection = _connect_read_only(path)
    try:
        if (
            connection.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID
            or connection.execute("PRAGMA user_version").fetchone()[0] != USER_VERSION
        ):
            raise ContractError("INDEX_INVALID", "The SQLite application identity is invalid.", path.name, 3)
        if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ContractError("INDEX_INVALID", "The SQLite integrity check failed.", path.name, 3)
        sqlite_master_inventory = frozenset(
            (str(row[0]), str(row[1]), str(row[2]), _canonical_schema_sql(None if row[3] is None else str(row[3])))
            for row in connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name")
        )
        if sqlite_master_inventory != _CANONICAL_SQLITE_MASTER_INVENTORY:
            raise ContractError(
                "INDEX_INVALID",
                "The SQLite schema inventory does not match the licensed-index application schema.",
                path.name,
                3,
            )
        values = {str(row["key"]): str(row["value"]) for row in connection.execute("SELECT key,value FROM metadata")}
        if set(values) != _METADATA_KEYS:
            raise ContractError("INDEX_INVALID", "The index metadata inventory is invalid.", path.name, 3)
        for key in ("source_sha256", "profile_sha256", "content_set_sha256", "manifest_sha256"):
            if _SHA256.fullmatch(values[key]) is None:
                raise ContractError("INDEX_INVALID", "An index digest is invalid.", path.name, 3)
        if expected_source_sha256 is not None and values["source_sha256"] != expected_source_sha256:
            raise ContractError("HASH_MISMATCH", "The index references an unexpected source digest.", path.name, 3)
        code_count = connection.execute("SELECT COUNT(*) FROM coding").fetchone()[0]
        designation_count = connection.execute("SELECT COUNT(*) FROM designation").fetchone()[0]
        active_count = connection.execute("SELECT COUNT(*) FROM coding WHERE active=1").fetchone()[0]
        if (
            code_count != int(values["code_count"])
            or designation_count != int(values["designation_count"])
            or active_count != int(values["active_count"])
            or int(values["inactive_count"]) != code_count - active_count
            or int(values["designation_count"]) != code_count + int(values["alias_count"])
        ):
            raise ContractError("INDEX_INVALID", "The index counts do not match its metadata.", path.name, 3)
        invalid_preferred = connection.execute(
            "SELECT COUNT(*) FROM ("
            "SELECT c.code FROM coding c LEFT JOIN designation d ON d.code=c.code "
            "GROUP BY c.code HAVING SUM(CASE WHEN d.kind='preferred' THEN 1 ELSE 0 END) != 1)"
        ).fetchone()[0]
        if invalid_preferred or connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise ContractError("INDEX_INVALID", "The index contains invalid designation grounding.", path.name, 3)
        content_digest = sha256_canonical(_content_payload(values), domain=b"coe-licensed-content-v1")
        if content_digest != values["content_set_sha256"]:
            raise ContractError("INDEX_INVALID", "The reference content digest is invalid.", path.name, 3)
        if _release_id_from_values(values) != values["release_id"]:
            raise ContractError("INDEX_INVALID", "The deterministic release identity is invalid.", path.name, 3)
        manifest_values = {key: value for key, value in values.items() if key != "manifest_sha256"}
        if sha256_canonical(manifest_values, domain=b"coe-licensed-manifest-v1") != values["manifest_sha256"]:
            raise ContractError("INDEX_INVALID", "The reference manifest digest is invalid.", path.name, 3)
    except (KeyError, ValueError, sqlite3.Error) as exc:
        if isinstance(exc, ContractError):
            raise
        raise ContractError("INDEX_INVALID", "The terminology index is malformed.", path.name, 3) from exc
    finally:
        connection.close()
    index_sha256, _, _, _ = _hash_source(path)
    return _metadata_from_values(path, values, index_sha256)


class SQLiteCodeCatalog:
    def __init__(self, owner: "SQLiteTerminologyIndex") -> None:
        self._owner = owner

    def __contains__(self, code: object) -> bool:
        return isinstance(code, str) and self._owner.contains_code(code)

    def __iter__(self) -> Iterator[str]:
        for row in self._owner._connection.execute("SELECT code FROM coding ORDER BY code"):
            yield str(row[0])

    def __len__(self) -> int:
        return self._owner.metadata.code_count


class SQLiteTerminologyIndex:
    """Read-only exact index with both COE ExactIndex and protected-runner APIs."""

    def __init__(self, path: Path, *, verify: bool = True) -> None:
        self.path = path
        self.metadata = verify_licensed_index(path) if verify else self._read_metadata(path)
        self._connection = _connect_read_only(path)
        catalog = SQLiteCodeCatalog(self)
        self.reference = LicensedReferenceIdentity(
            release_id=self.metadata.release_id,
            system_uri=self.metadata.system_uri,
            system_name=self.metadata.system_name,
            version=self.metadata.version,
            effective_date=self.metadata.effective_date,
            language=self.metadata.language,
            content_set_sha256=self.metadata.content_set_sha256,
            manifest_sha256=self.metadata.manifest_sha256,
            code_catalog=catalog,
        )
        self.releases = (self.metadata,)

    @staticmethod
    def _read_metadata(path: Path) -> LicensedIndexMetadata:
        connection = _connect_read_only(path)
        try:
            values = {str(row[0]): str(row[1]) for row in connection.execute("SELECT key,value FROM metadata")}
        finally:
            connection.close()
        if set(values) != _METADATA_KEYS:
            raise ContractError("INDEX_INVALID", "The index metadata inventory is invalid.", path.name, 3)
        return _metadata_from_values(path, values, "unverified")

    def __enter__(self) -> "SQLiteTerminologyIndex":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        if getattr(self, "_connection", None) is not None:
            self._connection.close()
            self._connection = None  # type: ignore[assignment]

    def contains_code(self, code: str) -> bool:
        if self._connection is None:
            raise ContractError("INDEX_CLOSED", "The terminology index is closed.", self.path.name, 3)
        return self._connection.execute("SELECT 1 FROM coding WHERE code=?", (code,)).fetchone() is not None

    def lookup(self, key: str, *, kind: str, variant: str) -> tuple[DesignationHit, ...]:
        if self._connection is None:
            raise ContractError("INDEX_CLOSED", "The terminology index is closed.", self.path.name, 3)
        if kind not in {"preferred", "alias"} or variant not in {"primary", "casefold"}:
            raise ContractError("LOOKUP_INVALID", "The exact lookup mode is invalid.", self.path.name, 2)
        column = "normalized_primary" if variant == "primary" else "normalized_folded"
        rows = self._connection.execute(
            f"SELECT DISTINCT d.code FROM designation d JOIN coding c ON c.code=d.code "
            f"WHERE c.active=1 AND d.kind=? AND d.{column}=? ORDER BY d.code",
            (kind, key),
        )
        method = "exact_preferred" if kind == "preferred" else "exact_alias"
        return tuple(DesignationHit(str(row[0]), method, variant) for row in rows)

    def lookup_all(self, primary: str, folded: str) -> LicensedLookupResult:
        evidence: dict[str, set[tuple[str, str]]] = {}
        for kind in ("preferred", "alias"):
            for key, variant in ((primary, "primary"), (folded, "casefold")):
                for hit in self.lookup(key, kind=kind, variant=variant):
                    evidence.setdefault(hit.code, set()).add((hit.method, hit.variant))
        candidates: list[LicensedLookupCandidate] = []
        for code, items in evidence.items():
            methods = tuple(sorted({item[0] for item in items}, key=lambda item: (_METHOD_ORDER[item], item)))
            variants = tuple(sorted({item[1] for item in items}, key=lambda item: (_VARIANT_ORDER[item], item)))
            candidates.append(
                LicensedLookupCandidate(
                    system_uri=self.metadata.system_uri,
                    release_id=self.metadata.release_id,
                    code=code,
                    best_method=methods[0],
                    methods=methods,
                    variants=variants,
                )
            )
        candidates.sort(key=lambda item: (_METHOD_ORDER[item.best_method], item.code))
        outcome = (
            "unmapped" if not candidates else ("grounded_unique" if len(candidates) == 1 else "grounded_ambiguous")
        )
        return LicensedLookupResult(self.metadata.system_uri, self.metadata.release_id, outcome, tuple(candidates))


def open_licensed_index(path: Path, *, verify: bool = True) -> SQLiteTerminologyIndex:
    """Open a read-only licensed terminology index."""

    return SQLiteTerminologyIndex(path, verify=verify)
