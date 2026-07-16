from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Protocol

from coe.contracts.reference import ReferenceBundle
from coe.ingest.normalize import normalize_lexical
from coe.mining.ngrams import PhraseAggregate

_METHOD_PRIORITY = {"exact_preferred": 0, "exact_alias": 1}


@dataclass(frozen=True, slots=True)
class DesignationHit:
    code: str
    method: str
    variant: str


class ExactIndex(Protocol):
    reference: ReferenceBundle

    def lookup(self, key: str, *, kind: str, variant: str) -> tuple[DesignationHit, ...]: ...


class InMemoryExactIndex:
    """Fixture-only index kept behind a replaceable interface."""

    def __init__(self, reference: ReferenceBundle) -> None:
        self.reference = reference
        active_codes = {coding.code for coding in reference.codings if coding.active}
        mutable: dict[tuple[str, str, str], set[str]] = defaultdict(set)
        for designation in reference.designations:
            if designation.code not in active_codes:
                continue
            lexical = normalize_lexical(designation.value)
            mutable[(designation.kind, "primary", lexical.primary)].add(designation.code)
            mutable[(designation.kind, "casefold", lexical.folded)].add(designation.code)
        self._index = {key: tuple(sorted(codes)) for key, codes in mutable.items()}

    def lookup(self, key: str, *, kind: str, variant: str) -> tuple[DesignationHit, ...]:
        method = "exact_preferred" if kind == "preferred" else "exact_alias"
        return tuple(
            DesignationHit(code=code, method=method, variant=variant)
            for code in self._index.get((kind, variant, key), ())
        )


def build_exact_indexes(references: tuple[ReferenceBundle, ...]) -> tuple[InMemoryExactIndex, ...]:
    return tuple(InMemoryExactIndex(reference) for reference in references)


def match_phrase(
    phrase: PhraseAggregate,
    index: ExactIndex,
    max_candidates: int,
) -> dict[str, object]:
    evidence: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for kind in ("preferred", "alias"):
        for hit in index.lookup(phrase.primary, kind=kind, variant="primary"):
            evidence[hit.code].add((hit.method, hit.variant))
        for hit in index.lookup(phrase.folded, kind=kind, variant="casefold"):
            evidence[hit.code].add((hit.method, hit.variant))
    if len(evidence) > max_candidates:
        from coe.errors import ContractError

        raise ContractError(
            "RESOURCE_LIMIT",
            "An exact collision exceeds the configured candidate limit; ambiguity was not truncated.",
            "analysis",
            4,
        )
    candidates: list[dict[str, object]] = []
    for code, items in evidence.items():
        methods = sorted({method for method, _ in items}, key=lambda item: (_METHOD_PRIORITY[item], item))
        variants = sorted({variant for _, variant in items}, key=lambda item: (item != "primary", item))
        candidates.append(
            {
                "best_method": methods[0],
                "code": code,
                "methods": methods,
                "release_id": index.reference.release_id,
                "variants": variants,
            }
        )
    candidates.sort(key=lambda item: (_METHOD_PRIORITY[str(item["best_method"])], str(item["code"])))
    previous_priority: int | None = None
    rank = 0
    for candidate in candidates:
        priority = _METHOD_PRIORITY[str(candidate["best_method"])]
        if priority != previous_priority:
            rank += 1
            previous_priority = priority
        candidate["rank"] = rank
    outcome = "unmapped" if not candidates else ("grounded_unique" if len(candidates) == 1 else "grounded_ambiguous")
    return {
        "acceptance_state": None if outcome == "unmapped" else "pending",
        "algorithmic_outcome": outcome,
        "candidate_set_schema_version": "1.0.0",
        "candidates": candidates,
        "document_frequency": phrase.document_frequency,
        "language": phrase.language,
        "note_type_counts": {key: value for key, value in phrase.note_type_counts},
        "occurrence_count": phrase.occurrence_count,
        "primary_normalized_form": phrase.primary,
        "release_id": index.reference.release_id,
        "system_uri": index.reference.system_uri,
        "token_count": phrase.token_count,
    }


def validate_grounding(rows: tuple[dict[str, object], ...], references: tuple[ReferenceBundle, ...]) -> int:
    catalogs = {(reference.system_uri, reference.release_id): reference.code_catalog for reference in references}
    checked = 0
    for row in rows:
        identity = (str(row["system_uri"]), str(row["release_id"]))
        catalog = catalogs.get(identity)
        if catalog is None:
            from coe.errors import ContractError

            raise ContractError("GROUNDING_FAILED", "A candidate set refers to an unvalidated release.", "analysis", 3)
        for candidate in row["candidates"]:  # type: ignore[union-attr]
            checked += 1
            if str(candidate["code"]) not in catalog:  # type: ignore[index]
                from coe.errors import ContractError

                raise ContractError(
                    "GROUNDING_FAILED", "An emitted code is absent from the pinned release.", "analysis", 3
                )
    return checked
