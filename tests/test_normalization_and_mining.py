from __future__ import annotations

from pathlib import Path

from coe.contracts.config import inspect_analysis_config
from coe.contracts.snapshot import Document
from coe.ingest.normalize import normalize_lexical
from coe.mining.ngrams import mine_document


def test_normalization_is_reversible_and_idempotent() -> None:
    original = "  Cafe\u0301\t5.0 mg/mL  "
    first = normalize_lexical(original)
    second = normalize_lexical(first.primary)
    assert first.restore() == original
    assert first.primary == "Café 5.0 mg/mL"
    assert second.primary == first.primary
    assert first.folded == "café 5.0 mg/ml"


def test_ngrams_do_not_cross_sentence_boundaries(demo_root: Path) -> None:
    config = inspect_analysis_config(demo_root / "coe_config.json")
    text = "Alpha beta. Gamma delta."
    document = Document(
        doc_id="00000000-0000-4000-8000-000000000010",
        path="documents/00000000-0000-4000-8000-000000000010.txt",
        sha256="0" * 64,
        byte_count=len(text),
        character_count=len(text),
        note_type="synthetic_note",
        language="en",
        extraction_method="synthetic_fixture",
        text=text,
    )
    phrases = {item.primary for item in mine_document(document, config)}
    assert "Alpha beta" in phrases
    assert "Gamma delta" in phrases
    assert "beta Gamma" not in phrases
