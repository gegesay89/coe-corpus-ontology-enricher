"""Canonical serialization and content hashing.

The contracts intentionally allow only the JSON subset used here: objects,
arrays, strings, integers, booleans, and null. Rejecting floating-point input
avoids implementation-dependent numeric spellings while remaining compatible
with RFC 8785 JCS for this subset.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import stat
import unicodedata
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from coe.errors import ContractError

JsonValue = None | bool | int | str | list["JsonValue"] | dict[str, "JsonValue"]


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(
                "DUPLICATE_JSON_KEY",
                "A JSON object contains a duplicate key.",
                exit_code=2,
            )
        result[key] = value
    return result


def _validate_json_subset(value: Any, location: str = "$") -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        return
    if isinstance(value, float):
        raise ContractError(
            "SCHEMA_INVALID",
            "Floating-point JSON values are not permitted in canonical contracts.",
            location,
            2,
        )
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_subset(item, f"{location}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ContractError("SCHEMA_INVALID", "JSON keys must be strings.", location, 2)
            _validate_json_subset(item, f"{location}.{key}")
        return
    raise ContractError("SCHEMA_INVALID", "Unsupported JSON value type.", location, 2)


def canonical_json_bytes(value: JsonValue) -> bytes:
    _validate_json_subset(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_json_line(value: JsonValue) -> bytes:
    return canonical_json_bytes(value) + b"\n"


def load_json_bytes(raw: bytes, location: str) -> JsonValue:
    if raw.startswith(b"version https://git-lfs.github.com/spec/v1"):
        raise ContractError("LFS_POINTER", "A Git LFS pointer was supplied instead of content.", location, 3)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError("UTF8_INVALID", "A contract file is not valid UTF-8.", location, 3) from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=lambda _: (_ for _ in ()).throw(
                ContractError("SCHEMA_INVALID", "Floating-point JSON values are not permitted.", location, 2)
            ),
        )
    except ContractError:
        raise
    except json.JSONDecodeError as exc:
        raise ContractError("SCHEMA_INVALID", "A JSON contract file is malformed.", location, 2) from exc
    _validate_json_subset(value)
    return value


def load_json(path: Path, relative_location: str) -> JsonValue:
    return load_json_bytes(read_stable_file(path, relative_location), relative_location)


def load_jsonl_bytes(raw: bytes, location: str) -> list[dict[str, JsonValue]]:
    if raw.startswith(b"version https://git-lfs.github.com/spec/v1"):
        raise ContractError("LFS_POINTER", "A Git LFS pointer was supplied instead of content.", location, 3)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError("UTF8_INVALID", "A JSONL contract file is not valid UTF-8.", location, 3) from exc
    rows: list[dict[str, JsonValue]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            raise ContractError("SCHEMA_INVALID", "Blank JSONL rows are not permitted.", f"{location}:{line_number}", 2)
        value = load_json_bytes(line.encode("utf-8"), f"{location}:{line_number}")
        if not isinstance(value, dict):
            raise ContractError("SCHEMA_INVALID", "Every JSONL row must be an object.", f"{location}:{line_number}", 2)
        rows.append(value)
    if raw and not raw.endswith(b"\n"):
        raise ContractError("SCHEMA_INVALID", "JSONL files must end with a newline.", location, 2)
    return rows


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_canonical(value: JsonValue, domain: bytes | None = None) -> str:
    payload = canonical_json_bytes(value)
    if domain is not None:
        payload = domain + b"\0" + payload
    return sha256_bytes(payload)


def read_stable_file(path: Path, relative_location: str, max_bytes: int | None = None) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as exc:
        raise ContractError("FILE_MISSING", "A required file is missing.", relative_location, 3) from exc
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ContractError(
                "SYMLINK", "Symbolic links are not permitted in bundles.", relative_location, 4
            ) from exc
        raise ContractError(
            "FILE_UNREADABLE", "A required bundle file could not be opened.", relative_location, 3
        ) from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ContractError("NONREGULAR", "Only regular files are permitted in bundles.", relative_location, 4)
        if max_bytes is not None and before.st_size > max_bytes:
            raise ContractError(
                "RESOURCE_LIMIT", "A bundle file exceeds the configured byte limit.", relative_location, 4
            )
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read()
        after = os.fstat(descriptor)
        try:
            path_after = os.stat(path, follow_symlinks=False)
        except FileNotFoundError as exc:
            raise ContractError(
                "FILE_CHANGED", "A bundle file changed while it was being read.", relative_location, 4
            ) from exc
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if identity_before != identity_after or (path_after.st_dev, path_after.st_ino) != (
            before.st_dev,
            before.st_ino,
        ):
            raise ContractError("FILE_CHANGED", "A bundle file changed while it was being read.", relative_location, 4)
    finally:
        os.close(descriptor)
    return raw


def normalized_relative_path(value: str) -> str:
    normalized = unicodedata.normalize("NFC", value)
    if normalized != value or "\\" in value:
        raise ContractError("PATH_INVALID", "Bundle paths must be NFC-normalized POSIX paths.", value, 4)
    path = PurePosixPath(value)
    if not value or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ContractError("PATH_INVALID", "A bundle contains an unsafe relative path.", value, 4)
    return path.as_posix()


def require_object(value: JsonValue, location: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise ContractError("SCHEMA_INVALID", "Expected a JSON object.", location, 2)
    return value


def require_exact_keys(
    value: dict[str, JsonValue], required: Iterable[str], optional: Iterable[str], location: str
) -> None:
    required_set = set(required)
    allowed = required_set | set(optional)
    missing = sorted(required_set - value.keys())
    extra = sorted(value.keys() - allowed)
    if missing or extra:
        raise ContractError(
            "SCHEMA_INVALID",
            "Contract fields do not match the declared schema.",
            location,
            2,
        )


def require_string(value: JsonValue, location: str, *, nonempty: bool = True) -> str:
    if not isinstance(value, str) or (nonempty and not value):
        raise ContractError("SCHEMA_INVALID", "Expected a string value.", location, 2)
    return value


def require_int(value: JsonValue, location: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ContractError("SCHEMA_INVALID", "Expected a bounded integer value.", location, 2)
    return value


def require_bool(value: JsonValue, location: str) -> bool:
    if not isinstance(value, bool):
        raise ContractError("SCHEMA_INVALID", "Expected a boolean value.", location, 2)
    return value


def check_sha256(value: str, location: str) -> str:
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ContractError("SCHEMA_INVALID", "Expected a lowercase SHA-256 digest.", location, 2)
    return value
