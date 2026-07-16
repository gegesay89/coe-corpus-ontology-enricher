#!/usr/bin/env python3
"""Fail-closed validation of the aggregate-only protected-run attestation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


class AttestationError(ValueError):
    """Safe attestation validation failure."""


def _load_object(path: Path) -> dict[str, Any]:
    def no_duplicates(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise AttestationError("The protected-data attestation contains a duplicate key.")
            result[key] = value
        return result

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AttestationError("The protected-data attestation is unreadable or malformed.") from exc
    if not isinstance(value, dict):
        raise AttestationError("The protected-data attestation must be an object.")
    return value


def _approval_reference(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 256
        or any(ord(character) < 32 for character in value)
        or value.upper().startswith(("TEST-ONLY", "REPLACE-WITH"))
    ):
        raise AttestationError("The protected-data attestation contains an invalid approval reference.")
    return value


def validate(attestation: dict[str, Any]) -> dict[str, Any]:
    required = {
        "attestation_schema_version",
        "profile",
        "approved",
        "approval_refs",
        "retention_policy_id",
        "output_classification",
    }
    if set(attestation) != required:
        raise AttestationError("The protected-data attestation fields do not match its schema.")
    if (
        attestation["attestation_schema_version"] != "1.0.0"
        or attestation["profile"] != "protected_phi_local"
        or attestation["approved"] is not True
        or attestation["output_classification"] != "protected_aggregate"
    ):
        raise AttestationError("The protected-data attestation is not explicitly approved for this run.")
    approval_refs = attestation["approval_refs"]
    if not isinstance(approval_refs, dict):
        raise AttestationError("The protected-data attestation approval references are invalid.")
    if not {"data_owner", "privacy"} <= set(approval_refs) or not set(approval_refs) <= {
        "data_owner",
        "privacy",
        "security",
    }:
        raise AttestationError("The protected-data attestation approval references are incomplete or invalid.")
    for value in approval_refs.values():
        _approval_reference(value)
    _approval_reference(attestation["retention_policy_id"])
    return {
        "protected_attestation_check_schema_version": "1.0.0",
        "status": "passed",
        "profile": "protected_phi_local",
        "output_classification": "protected_aggregate",
        "approval_ref_count": len(approval_refs),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attestation", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = validate(_load_object(args.attestation))
    except AttestationError as exc:
        print(json.dumps({"status": "failed", "safe_error": str(exc)}, separators=(",", ":")), file=sys.stderr)
        return 4
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
