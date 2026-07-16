from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from coe.canonical import JsonValue, canonical_json_line, sha256_bytes


@dataclass(frozen=True, slots=True)
class ArtifactDigest:
    path: str
    media_type: str
    schema_version: str
    row_count: int
    byte_count: int
    sha256: str

    def as_dict(self) -> dict[str, JsonValue]:
        return {
            "byte_count": self.byte_count,
            "media_type": self.media_type,
            "path": self.path,
            "row_count": self.row_count,
            "schema_version": self.schema_version,
            "sha256": self.sha256,
        }


def _atomic_write(path: Path, raw: bytes) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{uuid.uuid4().hex}")
    try:
        with temporary.open("xb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_jsonl(
    directory: Path,
    filename: str,
    records: Iterable[dict[str, JsonValue]],
    *,
    schema_version: str = "1.0.0",
) -> ArtifactDigest:
    rows = tuple(records)
    raw = b"".join(canonical_json_line(row) for row in rows)
    path = directory / filename
    _atomic_write(path, raw)
    return ArtifactDigest(
        path=filename,
        media_type="application/x-ndjson",
        schema_version=schema_version,
        row_count=len(rows),
        byte_count=len(raw),
        sha256=sha256_bytes(raw),
    )


def write_json(
    directory: Path,
    filename: str,
    value: dict[str, JsonValue],
    *,
    schema_version: str = "1.0.0",
) -> ArtifactDigest:
    raw = canonical_json_line(value)
    path = directory / filename
    _atomic_write(path, raw)
    return ArtifactDigest(
        path=filename,
        media_type="application/json",
        schema_version=schema_version,
        row_count=1,
        byte_count=len(raw),
        sha256=sha256_bytes(raw),
    )
