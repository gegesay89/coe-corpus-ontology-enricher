"""Machine-readable governance gates used by controlled-reference operations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from pathlib import Path

from coe.canonical import (
    JsonValue,
    load_json,
    require_bool,
    require_exact_keys,
    require_object,
    require_string,
    sha256_canonical,
)
from coe.errors import ContractError

_TERMINOLOGIES = frozenset({"cpt", "hcpcs", "icd10cm", "icd10pcs", "loinc", "rxnorm", "snomed"})


@dataclass(frozen=True, slots=True)
class TerminologyEntitlementAssertion:
    assertion_ref: str
    assertion_sha256: str
    asserted_on: str
    review_due_on: str
    terminologies: frozenset[str]

    @property
    def binding_ref(self) -> str:
        return f"{self.assertion_ref}#sha256={self.assertion_sha256}"


def _parse_date(value: JsonValue, location: str) -> date:
    text = require_string(value, location)
    try:
        return date.fromisoformat(text)
    except ValueError as exc:
        raise ContractError("ENTITLEMENT_INVALID", "An entitlement date is invalid.", location, 5) from exc


def inspect_terminology_entitlement(path: Path, *, terminology: str | None = None) -> TerminologyEntitlementAssertion:
    value = require_object(load_json(path, path.name), path.name)
    require_exact_keys(
        value,
        (
            "schema_version",
            "asserted_by_role",
            "asserted_on",
            "assertion_ref",
            "controlled_uses",
            "license_evidence_status",
            "public_redistribution_status",
            "review_due_on",
            "terminologies",
        ),
        (),
        path.name,
    )
    if value["schema_version"] != "1.0.0" or value["asserted_by_role"] != "project_owner":
        raise ContractError("ENTITLEMENT_INVALID", "The entitlement assertion identity is invalid.", path.name, 5)
    controlled = require_object(value["controlled_uses"], f"{path.name}.controlled_uses")
    require_exact_keys(
        controlled,
        (
            "analysis_use_permitted",
            "copy_derived_indexes_to_authorized_project_hosts",
            "create_private_derived_indexes",
        ),
        (),
        f"{path.name}.controlled_uses",
    )
    if not all(require_bool(controlled[key], f"{path.name}.controlled_uses.{key}") for key in controlled):
        raise ContractError("ENTITLEMENT_INVALID", "The controlled terminology uses are not authorized.", path.name, 5)
    if (
        value["license_evidence_status"] != "not_attached_to_portable_bundle"
        or value["public_redistribution_status"] != "not_asserted"
    ):
        raise ContractError("ENTITLEMENT_INVALID", "The entitlement export boundary is invalid.", path.name, 5)
    terms = value["terminologies"]
    if (
        not isinstance(terms, list)
        or not all(isinstance(item, str) for item in terms)
        or len(terms) != len(set(terms))
        or frozenset(terms) != _TERMINOLOGIES
    ):
        raise ContractError("ENTITLEMENT_INVALID", "The entitlement terminology inventory is incomplete.", path.name, 5)
    if terminology is not None and terminology not in terms:
        raise ContractError("ENTITLEMENT_INVALID", "The requested terminology is not authorized.", path.name, 5)
    asserted_on = _parse_date(value["asserted_on"], f"{path.name}.asserted_on")
    review_due = _parse_date(value["review_due_on"], f"{path.name}.review_due_on")
    today = date.today()
    if asserted_on > today or review_due < today or review_due <= asserted_on:
        raise ContractError("ENTITLEMENT_INVALID", "The entitlement assertion is not currently valid.", path.name, 5)
    assertion_ref = require_string(value["assertion_ref"], f"{path.name}.assertion_ref")
    if len(assertion_ref) > 160 or any(ord(char) < 32 for char in assertion_ref):
        raise ContractError("ENTITLEMENT_INVALID", "The entitlement reference is invalid.", path.name, 5)
    digest = sha256_canonical(value, domain=b"coe-terminology-entitlement-v1")
    return TerminologyEntitlementAssertion(
        assertion_ref=assertion_ref,
        assertion_sha256=digest,
        asserted_on=asserted_on.isoformat(),
        review_due_on=review_due.isoformat(),
        terminologies=frozenset(terms),
    )
