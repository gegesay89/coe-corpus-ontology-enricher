#!/usr/bin/env python3
"""Build a deterministic, PHI-free Windows transfer archive from explicit inputs."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import re
import shutil
import stat
import tempfile
import zipfile
from email import policy
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

from coe import __version__

_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
_PROHIBITED_PARTS = {
    ".aws",
    ".env",
    ".git",
    ".ssh",
    "patientdata",
    "raw",
    "secrets",
}
_PROHIBITED_SUFFIXES = {".cookie", ".key", ".pem", ".rdp"}
_PROHIBITED_WHEEL_SUFFIXES = {".csv", ".db", ".parquet", ".sqlite", ".sqlite3", ".tsv"}
_PROHIBITED_CONTENT = (
    b"/Users/",
    b"/home/",
    b"Authorization: Bearer",
    b"Cookie:",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
)
_AWS_ACCESS_KEY = re.compile(rb"(?:AKIA|ASIA)[0-9A-Z]{16}")
_EXPECTED_DISTRIBUTION = "coe-corpus-ontology-enricher"
_EXPECTED_WHEEL_NAME = f"coe_corpus_ontology_enricher-{__version__}-py3-none-any.whl"
_MAX_WHEEL_BYTES = 100_000_000
_MAX_WHEEL_EXPANDED_BYTES = 250_000_000
_MAX_NON_WHEEL_MEMBER_BYTES = 5_000_000


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )


def _assert_safe_relative(path: Path) -> None:
    lowered = {part.casefold() for part in path.parts}
    if lowered & _PROHIBITED_PARTS or path.suffix.casefold() in _PROHIBITED_SUFFIXES:
        raise ValueError(f"prohibited bundle member: {path.as_posix()}")


def _normalize_distribution(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).casefold()


def _stream_has_prohibited_content(stream: object) -> bool:
    longest = max(*(len(marker) for marker in _PROHIBITED_CONTENT), 20)
    tail = b""
    while True:
        chunk = stream.read(1024 * 1024)  # type: ignore[attr-defined]
        if not chunk:
            return False
        sample = tail + chunk
        if any(marker in sample for marker in _PROHIBITED_CONTENT) or _AWS_ACCESS_KEY.search(sample):
            return True
        tail = sample[-(longest - 1) :]


def _assert_expected_wheel_member(path: PurePosixPath, *, is_directory: bool) -> None:
    dist_info = f"coe_corpus_ontology_enricher-{__version__}.dist-info"
    data_root = f"coe_corpus_ontology_enricher-{__version__}.data"
    if is_directory:
        if path.parts[0] not in {"coe", dist_info, data_root}:
            raise ValueError("wheel contains an unexpected directory")
        return
    if path.parts[0] == "coe":
        if len(path.parts) < 2 or path.suffix != ".py" or "__pycache__" in path.parts:
            raise ValueError("wheel contains an unexpected application member")
        return
    if path.parts[0] == dist_info:
        allowed = {"METADATA", "RECORD", "WHEEL", "entry_points.txt", "top_level.txt"}
        if len(path.parts) != 2 or path.name not in allowed:
            raise ValueError("wheel contains an unexpected distribution member")
        return
    if path.parts[0] == data_root:
        if (
            len(path.parts) < 5
            or path.parts[1:4] != ("data", "share", "coe")
            or path.suffix.casefold() not in {".json", ".md"}
        ):
            raise ValueError("wheel contains an unexpected packaged-data member")
        return
    raise ValueError("wheel contains an unexpected top-level member")


def _verify_wheel_record(archive: zipfile.ZipFile, names: list[str]) -> None:
    record_name = f"coe_corpus_ontology_enricher-{__version__}.dist-info/RECORD"
    try:
        rows = list(csv.reader(io.StringIO(archive.read(record_name).decode("utf-8", errors="strict"))))
    except (KeyError, UnicodeDecodeError, csv.Error) as exc:
        raise ValueError("wheel RECORD is missing or malformed") from exc
    declared: dict[str, tuple[str, str]] = {}
    for row in rows:
        if len(row) != 3 or row[0] in declared:
            raise ValueError("wheel RECORD contains an invalid row")
        declared[row[0]] = (row[1], row[2])
    actual = {name for name in names if not name.endswith("/")}
    if set(declared) != actual:
        raise ValueError("wheel RECORD inventory does not match the archive")
    for name in sorted(actual):
        digest, size = declared[name]
        payload = archive.read(name)
        if name == record_name:
            if digest or size:
                raise ValueError("wheel RECORD must leave its own hash and size empty")
            continue
        expected_digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode("ascii")
        if digest != f"sha256={expected_digest}" or size != str(len(payload)):
            raise ValueError("wheel RECORD hash or size does not match a member")


def _inspect_wheel(path: Path) -> dict[str, str]:
    try:
        path_stat = path.lstat()
    except OSError as exc:
        raise ValueError("wheel must be an existing regular file") from exc
    if path.is_symlink() or not stat.S_ISREG(path_stat.st_mode) or path_stat.st_nlink != 1:
        raise ValueError("wheel must be a single-link regular file")
    if path.name != _EXPECTED_WHEEL_NAME:
        raise ValueError(f"wheel must be the exact {_EXPECTED_WHEEL_NAME} release artifact")
    if path_stat.st_size < 1 or path_stat.st_size > _MAX_WHEEL_BYTES:
        raise ValueError("wheel size is outside the release boundary")

    expected_metadata = f"coe_corpus_ontology_enricher-{__version__}.dist-info/METADATA"
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            names = [member.filename for member in members]
            if len(names) != len(set(names)) or len(names) != len({name.casefold() for name in names}):
                raise ValueError("wheel contains duplicate members")
            dist_info = f"coe_corpus_ontology_enricher-{__version__}.dist-info"
            required_members = {
                f"{dist_info}/METADATA",
                f"{dist_info}/RECORD",
                f"{dist_info}/WHEEL",
                f"{dist_info}/entry_points.txt",
                f"{dist_info}/top_level.txt",
            }
            if not required_members <= set(names):
                raise ValueError("wheel is missing a required release metadata member")
            expanded_bytes = 0
            for member in members:
                name = member.filename
                pure = PurePosixPath(name)
                if (
                    not name
                    or "\\" in name
                    or pure.is_absolute()
                    or any(part in {"", ".", ".."} for part in pure.parts)
                ):
                    raise ValueError("wheel contains an unsafe member path")
                relative = Path(*pure.parts)
                _assert_safe_relative(relative)
                _assert_expected_wheel_member(pure, is_directory=member.is_dir())
                if relative.suffix.casefold() in _PROHIBITED_WHEEL_SUFFIXES:
                    raise ValueError("wheel contains a controlled data payload")
                unix_mode = member.external_attr >> 16
                if stat.S_ISLNK(unix_mode):
                    raise ValueError("wheel contains a symbolic link")
                expanded_bytes += member.file_size
                if expanded_bytes > _MAX_WHEEL_EXPANDED_BYTES:
                    raise ValueError("wheel expanded size is outside the release boundary")
                if not member.is_dir():
                    with archive.open(member) as member_stream:
                        if _stream_has_prohibited_content(member_stream):
                            raise ValueError("wheel contains prohibited workstation or credential material")
            _verify_wheel_record(archive, names)
            wheel_metadata = archive.read(f"{dist_info}/WHEEL")
            if b"Root-Is-Purelib: true" not in wheel_metadata or b"Tag: py3-none-any" not in wheel_metadata:
                raise ValueError("wheel is not the expected platform-independent release")
            metadata_members = [name for name in names if name.endswith(".dist-info/METADATA")]
            if metadata_members != [expected_metadata]:
                raise ValueError("wheel metadata location does not match the release identity")
            metadata = BytesParser(policy=policy.default).parsebytes(archive.read(expected_metadata))
    except zipfile.BadZipFile as exc:
        raise ValueError("wheel is not a valid ZIP archive") from exc

    distribution = str(metadata.get("Name", ""))
    version = str(metadata.get("Version", ""))
    if _normalize_distribution(distribution) != _EXPECTED_DISTRIBUTION or version != __version__:
        raise ValueError("wheel metadata does not match the release identity")
    return {
        "distribution": _EXPECTED_DISTRIBUTION,
        "file_name": path.name,
        "sha256": _sha256(path),
        "version": version,
    }


def _copy_tree(source: Path, destination: Path) -> None:
    for path in sorted(source.rglob("*"), key=lambda item: item.relative_to(source).as_posix()):
        relative = path.relative_to(source)
        _assert_safe_relative(relative)
        path_stat = path.lstat()
        if path.is_symlink():
            raise ValueError(f"symbolic links are not permitted: {relative.as_posix()}")
        if path.is_dir():
            continue
        if not stat.S_ISREG(path_stat.st_mode) or path_stat.st_nlink != 1:
            raise ValueError(f"nonregular or hard-linked deployment member: {relative.as_posix()}")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)


def _scan_staged_root(root: Path) -> None:
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.casefold() == ".whl":
            continue
        if path.stat().st_size > _MAX_NON_WHEEL_MEMBER_BYTES:
            raise ValueError("a non-wheel bundle member is too large for the release scan")
        payload = path.read_bytes()
        if any(marker in payload for marker in _PROHIBITED_CONTENT) or _AWS_ACCESS_KEY.search(payload):
            raise ValueError("bundle contains prohibited workstation or credential material")


def _write_inventory(root: Path, wheel_details: dict[str, str]) -> None:
    wheel_name = wheel_details["file_name"]
    wheel = root / "app" / wheel_name
    manifest = {
        "application_version": __version__,
        "bundle_profile": "windows-native-with-conditional-wsl2",
        "exact_matching_device": "cpu",
        "patient_data_included": False,
        "runtime_manifest_schema_version": "1.0.0",
        "terminology_payload_included": False,
        "wheel": {
            "distribution": wheel_details["distribution"],
            "path": f"app/{wheel_name}",
            "sha256": wheel_details["sha256"],
            "version": wheel_details["version"],
        },
    }
    (root / "runtime_manifest.json").write_bytes(_canonical_json(manifest))
    sbom = {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "hashes": [{"alg": "SHA-256", "content": _sha256(wheel)}],
                "name": "coe-corpus-ontology-enricher",
                "type": "application",
                "version": __version__,
            }
        ],
        "metadata": {"component": {"name": "COE Windows transfer bundle", "type": "application"}},
        "specVersion": "1.5",
        "version": 1,
    }
    (root / "sbom.cdx.json").write_bytes(_canonical_json(sbom))
    members = sorted(
        (path for path in root.rglob("*") if path.is_file() and path.name != "checksums.sha256"),
        key=lambda item: item.relative_to(root).as_posix(),
    )
    rows = [f"{_sha256(path)}  {path.relative_to(root).as_posix()}" for path in members]
    (root / "checksums.sha256").write_text("\n".join(rows) + "\n", encoding="utf-8", newline="\n")


def _zip_deterministic(source: Path, output: Path) -> None:
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(source.rglob("*"), key=lambda item: item.relative_to(source.parent).as_posix()):
            if not path.is_file():
                continue
            relative = path.relative_to(source.parent).as_posix()
            info = zipfile.ZipInfo(relative, date_time=_ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def build_windows_bundle(
    *, project_root: Path, wheel: Path, output: Path, overwrite: bool = False
) -> dict[str, object]:
    if output.suffix.casefold() != ".zip" or output.is_symlink() or (output.exists() and not output.is_file()):
        raise ValueError("output must be a regular .zip file path")
    if output.exists() and not overwrite:
        raise FileExistsError(output)
    wheel_details = _inspect_wheel(wheel)
    deployment = project_root / "deploy" / "windows"
    spec = project_root / "specs" / "licensed_terminologies.json"
    entitlement = project_root / "governance" / "terminology_entitlement_assertion.json"
    required = (
        deployment,
        spec,
        entitlement,
        project_root / "SECURITY.md",
        project_root / "docs" / "CONTROLLED_DEPLOYMENT.md",
    )
    if any(not path.exists() for path in required):
        raise ValueError("required deployment source is missing")
    try:
        output.resolve(strict=False).relative_to(deployment.resolve(strict=True))
    except ValueError:
        pass
    else:
        raise ValueError("output cannot be inside the deployment source")

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_output = output.with_name(f".{output.name}.tmp")
    with tempfile.TemporaryDirectory(prefix="coe-windows-bundle-", dir=output.parent) as temporary:
        root = Path(temporary) / f"coe-windows-{__version__}"
        root.mkdir()
        _copy_tree(deployment, root)
        (root / "app").mkdir()
        copied_wheel = root / "app" / wheel.name
        shutil.copyfile(wheel, copied_wheel)
        copied_details = _inspect_wheel(copied_wheel)
        if copied_details != wheel_details:
            raise ValueError("wheel changed while the transfer bundle was being built")
        (root / "wheelhouse").mkdir()
        (root / "wheelhouse" / "README.txt").write_text(
            "Place only pre-reviewed, hash-pinned offline dependency wheels in this directory.\n",
            encoding="utf-8",
            newline="\n",
        )
        (root / "config").mkdir(exist_ok=True)
        shutil.copyfile(spec, root / "config" / spec.name)
        shutil.copyfile(entitlement, root / "config" / entitlement.name)
        shutil.copyfile(project_root / "SECURITY.md", root / "SECURITY.md")
        shutil.copyfile(project_root / "docs" / "CONTROLLED_DEPLOYMENT.md", root / "CONTROLLED_DEPLOYMENT.md")
        _scan_staged_root(root)
        _write_inventory(root, wheel_details)
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
        "sha256": _sha256(output),
        "status": "created",
        "version": __version__,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    result = build_windows_bundle(
        project_root=args.project_root.resolve(),
        wheel=args.wheel.resolve(),
        output=args.output.resolve(),
        overwrite=args.overwrite,
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
