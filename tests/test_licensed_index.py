from __future__ import annotations

import csv
import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from coe.errors import ContractError
from coe.terminology.licensed import (
    SQLiteTerminologyIndex,
    build_licensed_index,
    load_terminology_specs,
    open_licensed_index,
    verify_licensed_index,
)

HEADER = [
    "system",
    "code",
    "display",
    "aliases",
    "source",
    "version",
    "effective_date",
    "status",
    "related_names",
]
ROWS = [
    [
        "TEST",
        "U1",
        "Alpha finding",
        "shared|Alpha",
        "Private release",
        "1.0",
        "2026-01-01",
        "ACTIVE",
        "broad alpha term",
    ],
    ["TEST", "U2", "Beta finding", "shared", "Private release", "1.0", "2026-01-01", "ACTIVE", "broad beta term"],
    ["TEST", "U3", "Inactive finding", "old alias", "Private release", "1.0", "2026-01-01", "INACTIVE", "legacy term"],
]


def _fixture(
    root: Path,
    rows: list[list[str]] | None = None,
    *,
    alias_columns: tuple[str, ...] = ("aliases",),
) -> tuple[Path, Path]:
    selected_rows = rows or ROWS
    source = root / "test.csv"
    with source.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(HEADER)
        writer.writerows(selected_rows)
    raw = source.read_bytes()
    alias_count = 0
    for values in selected_rows:
        row = dict(zip(HEADER, values, strict=True))
        aliases: set[str] = set()
        for column in alias_columns:
            aliases.update(value.strip() for value in row[column].split("|") if value.strip())
        aliases.discard(row["display"])
        alias_count += len(aliases)
    profile = {
        "schema_version": "1.0.0",
        "importer_version": "1.0.0",
        "terminologies": {
            "test": {
                "file_name": "test.csv",
                "system_label": "TEST",
                "system_uri": "urn:example:test-codes",
                "system_name": "Private test codes",
                "publisher": "Test publisher",
                "language": "en",
                "version": "1.0",
                "effective_date": "2026-01-01",
                "source_label": "Private release",
                "source_uri": "urn:example:test-source",
                "normalized_sha256": hashlib.sha256(raw).hexdigest(),
                "byte_count": len(raw),
                "row_count": len(selected_rows),
                "alias_count": alias_count,
                "columns": HEADER,
                "alias_sources": [{"column": column, "delimiter": "|"} for column in alias_columns],
                "property_columns": ["status", "related_names"],
                "status_rule": {
                    "mode": "allowlist",
                    "column": "status",
                    "allowed_values": ["ACTIVE", "INACTIVE"],
                    "active_values": ["ACTIVE"],
                },
                "code_pattern": "^U[0-9]+$",
                "max_code_length": 8,
                "max_aliases_per_code": 8,
                "max_designation_chars": 256,
                "license_policy": "private-local-analysis",
                "required_notices": ["Private test content."],
            }
        },
    }
    specs = root / "specs.json"
    specs.write_text(json.dumps(profile), encoding="utf-8")
    return source, specs


def test_build_verify_and_exact_lookup(tmp_path: Path) -> None:
    source, specs = _fixture(tmp_path)
    first = tmp_path / "first.sqlite3"
    second = tmp_path / "second.sqlite3"
    metadata = build_licensed_index(source, first, "test", specs_path=specs, entitlement_ref="TEST-LICENSE-1")
    metadata_again = build_licensed_index(source, second, "test", specs_path=specs, entitlement_ref="TEST-LICENSE-1")
    assert metadata.release_id == metadata_again.release_id
    assert metadata.content_set_sha256 == metadata_again.content_set_sha256
    assert (metadata.code_count, metadata.alias_count, metadata.designation_count) == (3, 4, 7)
    assert (metadata.active_count, metadata.inactive_count) == (2, 1)
    assert verify_licensed_index(first, expected_source_sha256=metadata.source_sha256) == metadata

    with open_licensed_index(first) as index:
        assert len(index.releases) == 1
        assert "U3" in index.reference.code_catalog
        assert [hit.code for hit in index.lookup("Alpha finding", kind="preferred", variant="primary")] == ["U1"]
        assert index.lookup("old alias", kind="alias", variant="primary") == ()
        result = index.lookup_all("shared", "shared")
        assert result.ambiguous
        assert result.outcome == "grounded_ambiguous"
        assert [candidate.code for candidate in result.candidates] == ["U1", "U2"]
        assert all(not hasattr(candidate, "display") for candidate in result.candidates)
        assert index.lookup_all("missing", "missing").outcome == "unmapped"
        # related_names is preserved as metadata, not promoted to an exact alias.
        assert index.lookup_all("broad alpha term", "broad alpha term").outcome == "unmapped"

    connection = sqlite3.connect(first)
    try:
        properties = json.loads(connection.execute("SELECT properties_json FROM coding WHERE code='U1'").fetchone()[0])
    finally:
        connection.close()
    assert properties["related_names"] == "broad alpha term"


def test_alias_profile_can_explicitly_enable_an_extra_column(tmp_path: Path) -> None:
    source, specs = _fixture(tmp_path, alias_columns=("aliases", "related_names"))
    target = tmp_path / "extra-alias.sqlite3"
    build_licensed_index(source, target, "test", specs_path=specs, entitlement_ref="TEST-LICENSE-2")
    with SQLiteTerminologyIndex(target) as index:
        result = index.lookup_all("broad alpha term", "broad alpha term")
        assert result.outcome == "grounded_unique"
        assert result.candidates[0].code == "U1"


def test_hash_mismatch_is_fail_closed_and_preserves_existing_output(tmp_path: Path) -> None:
    source, specs = _fixture(tmp_path)
    target = tmp_path / "existing.sqlite3"
    target.write_bytes(b"prior-output")
    source.write_text(source.read_text(encoding="utf-8") + "changed", encoding="utf-8")
    with pytest.raises(ContractError, match="HASH_MISMATCH"):
        build_licensed_index(
            source,
            target,
            "test",
            specs_path=specs,
            entitlement_ref="TEST-LICENSE-3",
            overwrite=True,
        )
    assert target.read_bytes() == b"prior-output"


def test_duplicate_code_and_release_metadata_are_rejected(tmp_path: Path) -> None:
    duplicate = [ROWS[0], [*ROWS[0]]]
    source, specs = _fixture(tmp_path, duplicate)
    with pytest.raises(ContractError, match="CODE_DUPLICATE"):
        build_licensed_index(
            source, tmp_path / "duplicate.sqlite3", "test", specs_path=specs, entitlement_ref="TEST-LICENSE-4"
        )

    mismatch_root = tmp_path / "mismatch"
    mismatch_root.mkdir()
    bad_row = [row[:] for row in ROWS]
    bad_row[1][5] = "2.0"
    source, specs = _fixture(mismatch_root, bad_row)
    with pytest.raises(ContractError, match="RELEASE_METADATA_MISMATCH"):
        build_licensed_index(
            source, mismatch_root / "bad.sqlite3", "test", specs_path=specs, entitlement_ref="TEST-LICENSE-5"
        )


def test_output_entitlement_and_lookup_modes_are_fail_closed(tmp_path: Path) -> None:
    source, specs = _fixture(tmp_path)
    target = tmp_path / "index.sqlite3"
    with pytest.raises(ContractError, match="ENTITLEMENT_INVALID"):
        build_licensed_index(source, target, "test", specs_path=specs, entitlement_ref="")
    build_licensed_index(source, target, "test", specs_path=specs, entitlement_ref="TEST-LICENSE-6")
    with pytest.raises(ContractError, match="OUTPUT_EXISTS"):
        build_licensed_index(source, target, "test", specs_path=specs, entitlement_ref="TEST-LICENSE-6")
    index = SQLiteTerminologyIndex(target, verify=False)
    with pytest.raises(ContractError, match="LOOKUP_INVALID"):
        index.lookup("x", kind="broader", variant="primary")
    index.close()
    with pytest.raises(ContractError, match="INDEX_CLOSED"):
        index.contains_code("U1")


def test_verification_rejects_tampered_metadata(tmp_path: Path) -> None:
    source, specs = _fixture(tmp_path)
    target = tmp_path / "tampered.sqlite3"
    build_licensed_index(source, target, "test", specs_path=specs, entitlement_ref="TEST-LICENSE-7")
    connection = sqlite3.connect(target)
    try:
        connection.execute("UPDATE metadata SET value='4' WHERE key='code_count'")
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(ContractError, match="INDEX_INVALID"):
        verify_licensed_index(target)


@pytest.mark.parametrize(
    "tamper_sql",
    (
        "CREATE TABLE unexpected(value TEXT)",
        "CREATE VIEW unexpected_view AS SELECT code FROM coding",
        "CREATE TRIGGER unexpected_trigger AFTER INSERT ON coding BEGIN SELECT 1; END",
        "CREATE INDEX unexpected_index ON coding(display)",
        "ALTER TABLE coding ADD COLUMN unexpected TEXT",
        "DROP INDEX coding_active",
    ),
)
def test_verification_rejects_sqlite_schema_inventory_tampering(tmp_path: Path, tamper_sql: str) -> None:
    source, specs = _fixture(tmp_path)
    target = tmp_path / "schema-tampered.sqlite3"
    build_licensed_index(source, target, "test", specs_path=specs, entitlement_ref="TEST-LICENSE-SCHEMA")
    connection = sqlite3.connect(target)
    try:
        connection.executescript(tamper_sql)
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(ContractError, match="schema inventory"):
        verify_licensed_index(target)


def test_profile_inventory_and_spec_errors(tmp_path: Path) -> None:
    specs = load_terminology_specs()
    assert set(specs) == {"cpt", "hcpcs", "icd10cm", "icd10pcs", "loinc", "rxnorm", "snomed"}
    assert specs["loinc"].alias_count == 160181
    assert [source.column for source in specs["loinc"].alias_sources] == ["aliases"]
    assert "related_names" in specs["loinc"].property_columns

    source, custom = _fixture(tmp_path)
    raw = json.loads(custom.read_text(encoding="utf-8"))
    raw["terminologies"]["test"]["code_pattern"] = "["
    custom.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ContractError, match="SPEC_INVALID"):
        build_licensed_index(
            source, tmp_path / "invalid.sqlite3", "test", specs_path=custom, entitlement_ref="TEST-LICENSE-8"
        )


def test_lfs_pointer_and_symlink_sources_are_rejected(tmp_path: Path) -> None:
    source, specs = _fixture(tmp_path)
    pointer = "version https://git-lfs.github.com/spec/v1\noid sha256:" + "0" * 64 + "\nsize 123\n"
    source.write_text(pointer, encoding="utf-8")
    profile = json.loads(specs.read_text(encoding="utf-8"))
    profile["terminologies"]["test"]["normalized_sha256"] = hashlib.sha256(pointer.encode()).hexdigest()
    profile["terminologies"]["test"]["byte_count"] = len(pointer.encode())
    specs.write_text(json.dumps(profile), encoding="utf-8")
    with pytest.raises(ContractError, match="LFS_POINTER"):
        build_licensed_index(
            source, tmp_path / "lfs.sqlite3", "test", specs_path=specs, entitlement_ref="TEST-LICENSE-9"
        )

    if hasattr(Path, "symlink_to"):
        real_root = tmp_path / "real"
        real_root.mkdir()
        real_source, real_specs = _fixture(real_root)
        linked = real_root / "linked.csv"
        linked.symlink_to(real_source)
        profile = json.loads(real_specs.read_text(encoding="utf-8"))
        profile["terminologies"]["test"]["file_name"] = "linked.csv"
        real_specs.write_text(json.dumps(profile), encoding="utf-8")
        with pytest.raises(ContractError, match="SYMLINK"):
            build_licensed_index(
                linked,
                real_root / "linked.sqlite3",
                "test",
                specs_path=real_specs,
                entitlement_ref="TEST-LICENSE-10",
            )
