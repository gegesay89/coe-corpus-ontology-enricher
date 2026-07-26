from __future__ import annotations

import pytest

from coe.context import (
    CONTEXT_CURRENT_CLINICAL,
    CONTEXT_HISTORICAL,
    CONTEXT_NEGATED,
    CONTEXT_NON_PATIENT,
    document_context,
)
from coe.mining.ngrams import sentence_spans


def _classify(text: str, phrase: str) -> str:
    contexts = document_context(text, sentence_spans(text))
    start = text.index(phrase)
    return contexts.classify(start, start + len(phrase))


@pytest.mark.parametrize(
    ("text", "phrase"),
    [
        ("Patient reports fever and cough.", "fever"),
        ("Fever documented at triage.", "Fever"),
        ("Assessment: acute sinusitis today.", "acute sinusitis"),
    ],
)
def test_affirmed_patient_current_mentions(text: str, phrase: str) -> None:
    assert _classify(text, phrase) == CONTEXT_CURRENT_CLINICAL


@pytest.mark.parametrize(
    ("text", "phrase"),
    [
        ("No evidence of fever today.", "fever"),
        ("Denies chest pain.", "chest pain"),
        ("Patient without diabetes mellitus.", "diabetes mellitus"),
        ("Negative for atrial fibrillation.", "atrial fibrillation"),
        ("Rule out pulmonary embolism.", "pulmonary embolism"),
        ("No signs of infection noted.", "infection"),
        ("Chest pain is absent.", "Chest pain"),
        ("Sepsis was ruled out.", "Sepsis"),
    ],
)
def test_negated_mentions(text: str, phrase: str) -> None:
    assert _classify(text, phrase) == CONTEXT_NEGATED


@pytest.mark.parametrize(
    ("text", "phrase"),
    [
        ("Family history of diabetes mellitus.", "diabetes mellitus"),
        ("Mother had breast cancer.", "breast cancer"),
        ("Paternal grandfather with hypertension.", "hypertension"),
        ("His brother has asthma.", "asthma"),
    ],
)
def test_non_patient_mentions(text: str, phrase: str) -> None:
    assert _classify(text, phrase) == CONTEXT_NON_PATIENT


@pytest.mark.parametrize(
    ("text", "phrase"),
    [
        ("History of myocardial infarction.", "myocardial infarction"),
        ("Status post total knee arthroplasty.", "total knee arthroplasty"),
        ("Prior cholecystectomy noted.", "cholecystectomy"),
        ("Pneumonia in the past.", "Pneumonia"),
        ("h/o seizures.", "seizures"),
    ],
)
def test_historical_mentions(text: str, phrase: str) -> None:
    assert _classify(text, phrase) == CONTEXT_HISTORICAL


def test_scope_break_stops_negation() -> None:
    text = "No fever but reports cough."
    assert _classify(text, "fever") == CONTEXT_NEGATED
    assert _classify(text, "cough") == CONTEXT_CURRENT_CLINICAL


def test_negation_does_not_cross_sentences() -> None:
    text = "Denies chest pain. Fever documented."
    assert _classify(text, "chest pain") == CONTEXT_NEGATED
    assert _classify(text, "Fever") == CONTEXT_CURRENT_CLINICAL


def test_negation_outranks_family_and_history() -> None:
    assert _classify("Family history of no diabetes mellitus.", "diabetes mellitus") == CONTEXT_NEGATED
    assert _classify("No history of asthma.", "asthma") == CONTEXT_NEGATED


def test_family_outranks_history() -> None:
    assert _classify("Family history of prior stroke.", "stroke") == CONTEXT_NON_PATIENT


def test_section_headers_scope_and_reset() -> None:
    note = (
        "Family History:\n"
        "diabetes mellitus\n"
        "hypertension\n"
        "\n"
        "Past Medical History:\n"
        "asthma\n"
        "\n"
        "Assessment:\n"
        "acute sinusitis\n"
    )
    assert _classify(note, "diabetes mellitus") == CONTEXT_NON_PATIENT
    assert _classify(note, "hypertension") == CONTEXT_NON_PATIENT
    assert _classify(note, "asthma") == CONTEXT_HISTORICAL
    assert _classify(note, "acute sinusitis") == CONTEXT_CURRENT_CLINICAL


def test_distant_trigger_does_not_reach_the_phrase() -> None:
    # The negation window is bounded, so a far-away "no" must not negate.
    text = "No acute distress on arrival and the vitals remained stable, then fever developed"
    assert _classify(text, "fever") == CONTEXT_CURRENT_CLINICAL


def test_unknown_section_header_does_not_scope() -> None:
    note = "Random Header:\nfever today\n"
    assert _classify(note, "fever") == CONTEXT_CURRENT_CLINICAL


def test_sentence_ending_in_a_number_terminates_the_scope() -> None:
    # Regression: a period preceded by a digit must still end the sentence, or
    # a trigger leaks into the next one ("... in 2019. Heart attack today").
    text = "History of myocardial infarction in 2019. Chest pain today."
    assert _classify(text, "myocardial infarction") == CONTEXT_HISTORICAL
    assert _classify(text, "Chest pain") == CONTEXT_CURRENT_CLINICAL

    dose = "Denies use of warfarin 2.5 mg daily."
    assert _classify(dose, "warfarin") == CONTEXT_NEGATED
