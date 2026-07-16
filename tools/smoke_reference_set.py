#!/usr/bin/env python3
"""Run support-safe real-index lookups without printing terminology labels."""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

from coe.terminology.licensed import SQLiteTerminologyIndex
from coe.terminology.licensed_set import verify_licensed_index_set


def _connection(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro&immutable=1", uri=True)


def smoke(reference_set: Path) -> dict[str, object]:
    manifest = verify_licensed_index_set(reference_set)
    results: list[dict[str, object]] = []
    for record in manifest["indexes"]:
        assert isinstance(record, dict)
        path = reference_set / str(record["file_name"])
        database = _connection(path)
        try:
            sample = database.execute(
                "SELECT d.normalized_primary,d.normalized_folded,d.code "
                "FROM designation d JOIN coding c ON c.code=d.code "
                "WHERE c.active=1 AND d.kind='preferred' LIMIT 1"
            ).fetchone()
        finally:
            database.close()
        if sample is None:
            raise RuntimeError("an active terminology has no preferred designation")
        with SQLiteTerminologyIndex(path, verify=False) as index:
            lookup = index.lookup_all(str(sample[0]), str(sample[1]))
            codes = {candidate.code for candidate in lookup.candidates}
            if str(sample[2]) not in codes:
                raise RuntimeError("a real exact lookup failed grounding")
            results.append(
                {
                    "candidate_count": len(codes),
                    "outcome": lookup.outcome,
                    "terminology": record["terminology"],
                }
            )

    loinc = reference_set / "loinc.sqlite3"
    database = _connection(loinc)
    try:
        inactive = database.execute(
            "SELECT d.normalized_primary,d.normalized_folded FROM designation d "
            "JOIN coding c ON c.code=d.code WHERE c.active=0 AND d.kind='preferred' "
            "AND NOT EXISTS (SELECT 1 FROM designation d2 JOIN coding c2 ON c2.code=d2.code "
            "WHERE c2.active=1 AND d2.normalized_primary=d.normalized_primary) LIMIT 1"
        ).fetchone()
    finally:
        database.close()
    if inactive is None:
        raise RuntimeError("no non-colliding inactive LOINC fixture was available")
    with SQLiteTerminologyIndex(loinc, verify=False) as index:
        if index.lookup_all(str(inactive[0]), str(inactive[1])).outcome != "unmapped":
            raise RuntimeError("inactive LOINC content entered automatic matching")
    return {
        "inactive_loinc_excluded": True,
        "lookup_smokes": results,
        "reference_set_content_sha256": manifest["set_content_sha256"],
        "status": "passed",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("reference_set", type=Path)
    args = parser.parse_args()
    print(json.dumps(smoke(args.reference_set), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
