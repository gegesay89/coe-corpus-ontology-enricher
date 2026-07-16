#!/usr/bin/env python3
"""Package a verified private reference set for controlled Windows transfer."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tempfile
import zipfile
from pathlib import Path

from coe import __version__
from coe.terminology.licensed_set import verify_licensed_index_set

_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
_README = """# Private COE terminology reference set

This archive contains licensed terminology-derived SQLite indexes for controlled
internal analysis. It contains no patient data, source CSVs, raw publisher
packages, credentials, access logs, cookies, or model files.

Do not publish or attach this archive to an issue. Extract it only on an
authorized encrypted host, verify `checksums.sha256`, and mount the `references`
directory read-only during analysis. Public redistribution was not asserted by
the project-owner authorization recorded in this bundle.
"""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )


def _zip_deterministic(source: Path, output: Path) -> None:
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for path in sorted(source.rglob("*"), key=lambda item: item.relative_to(source.parent).as_posix()):
            if path.is_symlink():
                raise ValueError("symbolic links are not permitted in a reference bundle")
            if not path.is_file():
                continue
            relative = path.relative_to(source.parent).as_posix()
            info = zipfile.ZipInfo(relative, date_time=_ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100600 << 16
            with path.open("rb") as source_stream, archive.open(info, "w", force_zip64=True) as destination_stream:
                shutil.copyfileobj(source_stream, destination_stream, length=4 * 1024 * 1024)


def build_reference_bundle(*, reference_set: Path, output: Path, overwrite: bool = False) -> dict[str, object]:
    if output.suffix.casefold() != ".zip" or output.is_symlink() or (output.exists() and not output.is_file()):
        raise ValueError("output must be a regular .zip file path")
    try:
        output.resolve(strict=False).relative_to(reference_set.resolve(strict=True))
    except ValueError:
        pass
    else:
        raise ValueError("output cannot be inside the reference set")
    manifest = verify_licensed_index_set(reference_set)
    if output.exists() and not overwrite:
        raise FileExistsError(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    content_sha256 = str(manifest["set_content_sha256"])
    temporary_output = output.with_name(f".{output.name}.tmp")
    with tempfile.TemporaryDirectory(prefix="coe-reference-transfer-", dir=output.parent) as temporary:
        root = Path(temporary) / f"coe-private-references-{content_sha256[:12]}"
        references = root / "references"
        references.mkdir(parents=True)
        for source in sorted(reference_set.iterdir(), key=lambda item: item.name):
            if source.is_symlink() or not source.is_file():
                raise ValueError("the verified reference set changed before packaging")
            shutil.copyfile(source, references / source.name)
        copied_manifest = verify_licensed_index_set(references)
        if copied_manifest != manifest:
            raise ValueError("the reference set changed while it was being packaged")
        (root / "README-PRIVATE.md").write_text(_README, encoding="utf-8", newline="\n")
        transfer = {
            "application_minimum_version": __version__,
            "patient_data_included": False,
            "public_redistribution_status": "not_asserted",
            "reference_set_content_sha256": content_sha256,
            "reference_set_manifest_sha256": _sha256(references / "reference_set_manifest.json"),
            "transfer_manifest_schema_version": "1.0.0",
            "usage_profile": "private-controlled-analysis",
        }
        (root / "transfer_manifest.json").write_bytes(_canonical(transfer))
        files = sorted(
            (path for path in root.rglob("*") if path.is_file()),
            key=lambda item: item.relative_to(root).as_posix(),
        )
        rows = [f"{_sha256(path)}  {path.relative_to(root).as_posix()}" for path in files]
        (root / "checksums.sha256").write_text("\n".join(rows) + "\n", encoding="utf-8", newline="\n")
        if temporary_output.exists():
            temporary_output.unlink()
        try:
            _zip_deterministic(root, temporary_output)
            temporary_output.replace(output)
        finally:
            if temporary_output.exists():
                temporary_output.unlink()
    return {
        "byte_count": output.stat().st_size,
        "path": output.name,
        "reference_set_content_sha256": content_sha256,
        "sha256": _sha256(output),
        "status": "created",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference-set", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    result = build_reference_bundle(
        reference_set=args.reference_set.resolve(),
        output=args.output.resolve(),
        overwrite=args.overwrite,
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
