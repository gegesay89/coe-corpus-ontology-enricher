"""Deterministic, grounding-safe lexical variants for exact terminology lookup.

Every variant is a pure string transformation of the mined phrase; matching
still resolves only against designations already present in a pinned release,
so the grounding invariant is unchanged. Variants can only add dictionary
lookups, never fabricate codes.
"""

from __future__ import annotations

import re
from typing import Protocol

_COMPACT_STRIP = re.compile(r"[^0-9a-zÀ-ɏ ]+")
_WHITESPACE = re.compile(r"\s+")

VARIANT_METHOD_PRIORITY: dict[str, int] = {
    "exact_preferred": 0,
    "exact_alias": 1,
    "variant_compact": 2,
    "variant_abbreviation": 3,
    "variant_singular": 4,
}

# Curated, deliberately unambiguous clinical abbreviations. Keys are folded
# whole-phrase forms; values are the expansions submitted to exact lookup.
# An expansion that is absent from a release simply fails to match.
CLINICAL_ABBREVIATIONS: dict[str, str] = {
    "afib": "atrial fibrillation",
    "a fib": "atrial fibrillation",
    "bph": "benign prostatic hyperplasia",
    "cabg": "coronary artery bypass graft",
    "cad": "coronary artery disease",
    "chf": "congestive heart failure",
    "ckd": "chronic kidney disease",
    "copd": "chronic obstructive pulmonary disease",
    "cva": "cerebrovascular accident",
    "dm": "diabetes mellitus",
    "dvt": "deep venous thrombosis",
    "esrd": "end stage renal disease",
    "fx": "fracture",
    "gerd": "gastroesophageal reflux disease",
    "hld": "hyperlipidemia",
    "htn": "hypertension",
    "mi": "myocardial infarction",
    "osa": "obstructive sleep apnea",
    "sob": "shortness of breath",
    "t2dm": "type 2 diabetes mellitus",
    "tha": "total hip arthroplasty",
    "tia": "transient ischemic attack",
    "tka": "total knee arthroplasty",
    "uti": "urinary tract infection",
}

_PLURAL_KEEP_SUFFIXES = ("ss", "us", "is", "es")


def compact_form(folded: str) -> str:
    return _WHITESPACE.sub(" ", _COMPACT_STRIP.sub(" ", folded)).strip()


def singular_form(folded: str) -> str:
    tokens = folded.split(" ")
    last = tokens[-1]
    if len(last) > 4 and last.endswith("ies"):
        tokens[-1] = last[:-3] + "y"
    elif len(last) > 3 and last.endswith("s") and not last.endswith(_PLURAL_KEEP_SUFFIXES):
        tokens[-1] = last[:-1]
    else:
        return folded
    return " ".join(tokens)


def expand_variants(folded: str) -> tuple[tuple[str, str], ...]:
    """Return ordered (method, folded_key) variant lookups for a folded phrase.

    Order encodes confidence: compact before abbreviation before singular.
    Keys equal to the original folded phrase are omitted because the exact
    passes already cover them.
    """

    variants: list[tuple[str, str]] = []
    seen = {folded}
    compact = compact_form(folded)
    if compact and compact not in seen:
        variants.append(("variant_compact", compact))
        seen.add(compact)
    for base in (folded, compact):
        expansion = CLINICAL_ABBREVIATIONS.get(base)
        if expansion and expansion not in seen:
            variants.append(("variant_abbreviation", expansion))
            seen.add(expansion)
    for base in tuple(key for _, key in variants) + (folded,):
        singular = singular_form(base)
        if singular and singular not in seen:
            variants.append(("variant_singular", singular))
            seen.add(singular)
    return tuple(variants)


class _Hit(Protocol):
    code: str


class _ExactIndex(Protocol):
    def lookup(self, key: str, *, kind: str, variant: str) -> tuple[_Hit, ...]: ...


def grounded_lookup(
    index: _ExactIndex,
    primary: str,
    folded: str,
) -> dict[str, set[tuple[str, str]]]:
    """Collect exact + variant designation hits as {code: {(method, variant)}}.

    Exact passes query both stored columns; variant passes query the folded
    column with transformed keys, so every returned code is backed by a stored
    designation.
    """

    evidence: dict[str, set[tuple[str, str]]] = {}
    for kind in ("preferred", "alias"):
        for variant, key in (("primary", primary), ("casefold", folded)):
            for hit in index.lookup(key, kind=kind, variant=variant):
                method = "exact_preferred" if kind == "preferred" else "exact_alias"
                evidence.setdefault(hit.code, set()).add((method, variant))
        for method, key in expand_variants(folded):
            for hit in index.lookup(key, kind=kind, variant="casefold"):
                evidence.setdefault(hit.code, set()).add((method, method.removeprefix("variant_")))
    return evidence
