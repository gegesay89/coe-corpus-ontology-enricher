from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


def test_terminology_entitlement_assertion_is_complete_and_internal_only() -> None:
    root = Path(__file__).resolve().parents[1]
    assertion = json.loads((root / "governance/terminology_entitlement_assertion.json").read_text(encoding="utf-8"))
    schema = json.loads(
        (root / "schemas/governance/1.0.0/terminology_entitlement_assertion.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(assertion)
    assert assertion["public_redistribution_status"] == "not_asserted"
    assert date.fromisoformat(assertion["review_due_on"]) > date.fromisoformat(assertion["asserted_on"])
