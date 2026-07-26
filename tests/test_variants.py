from __future__ import annotations

from coe.terminology.variants import (
    CLINICAL_ABBREVIATIONS,
    compact_form,
    expand_variants,
    singular_form,
)


def test_compact_form_strips_punctuation_and_collapses_whitespace() -> None:
    assert compact_form("diabetes mellitus, type 2") == "diabetes mellitus type 2"
    assert compact_form("copd/asthma") == "copd asthma"
    assert compact_form("hypertension") == "hypertension"
    assert compact_form("...") == ""


def test_singular_form_is_conservative() -> None:
    assert singular_form("medications") == "medication"
    assert singular_form("fevers") == "fever"
    assert singular_form("allergies") == "allergy"
    # Clinical false-plural traps must not be singularized.
    assert singular_form("diabetes") == "diabetes"
    assert singular_form("pertussis") == "pertussis"
    assert singular_form("lupus") == "lupus"
    assert singular_form("abscess") == "abscess"
    # Only the last token changes.
    assert singular_form("knee replacements") == "knee replacement"


def test_expand_variants_orders_by_confidence_and_deduplicates() -> None:
    variants = expand_variants("htn")
    assert ("variant_abbreviation", "hypertension") in variants
    # The compact form equals the input, so it is omitted.
    assert all(kind != "variant_compact" for kind, _ in variants)

    variants = expand_variants("copd/asthma")
    kinds = [kind for kind, _ in variants]
    assert kinds.index("variant_compact") < len(kinds)
    assert ("variant_compact", "copd asthma") in variants

    # No duplicate keys are produced.
    keys = [key for _, key in expand_variants("fevers,")]
    assert len(keys) == len(set(keys))


def test_abbreviation_map_is_folded_and_expansions_are_lowercase() -> None:
    for key, expansion in CLINICAL_ABBREVIATIONS.items():
        assert key == key.casefold()
        assert expansion == expansion.casefold()
