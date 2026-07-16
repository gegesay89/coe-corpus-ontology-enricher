from __future__ import annotations

import json
from pathlib import Path

import pytest

from coe.errors import ContractError
from coe.governance import inspect_terminology_entitlement


def _assertion(root: Path) -> dict[str, object]:
    return json.loads((root / "governance/terminology_entitlement_assertion.json").read_text(encoding="utf-8"))


def test_entitlement_is_hash_bound_and_authorizes_each_index() -> None:
    root = Path(__file__).resolve().parents[1]
    path = root / "governance/terminology_entitlement_assertion.json"
    assertion = inspect_terminology_entitlement(path, terminology="snomed")
    assert assertion.binding_ref.startswith("project-owner-terminology-license-assertion-2026-07-16#sha256=")
    assert len(assertion.assertion_sha256) == 64


def test_entitlement_fails_closed_when_a_controlled_use_is_removed(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    value = _assertion(root)
    value["controlled_uses"]["analysis_use_permitted"] = False  # type: ignore[index]
    path = tmp_path / "entitlement.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ContractError, match="not authorized") as captured:
        inspect_terminology_entitlement(path, terminology="loinc")
    assert captured.value.exit_code == 5


def test_entitlement_fails_closed_when_inventory_is_incomplete(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    value = _assertion(root)
    value["terminologies"] = [item for item in value["terminologies"] if item != "cpt"]  # type: ignore[union-attr]
    path = tmp_path / "entitlement.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ContractError, match="inventory is incomplete"):
        inspect_terminology_entitlement(path)
