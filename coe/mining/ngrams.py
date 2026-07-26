from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from decimal import ROUND_HALF_EVEN, Decimal

from coe.context import CONTEXT_CURRENT_CLINICAL, document_context
from coe.contracts.config import AnalysisConfig
from coe.contracts.snapshot import Document
from coe.errors import ContractError
from coe.ingest.normalize import normalize_lexical

# A single newline is soft (hard-wrapped clinical text keeps its phrases);
# a blank line, terminal punctuation, or a bullet/numbered line start splits.
# A period followed by a digit is a decimal ("5.0") and never a boundary; a
# period *preceded* by a digit still ends a sentence, because clinical notes
# routinely close one with a year or a value ("... in 2019. Next ...").
_SENTENCE_BOUNDARY = re.compile(r"(?:[ \t]*\r?\n){2,}[ \t]*|[!?;]+|\.(?!\d)|\r?\n(?=[ \t]*(?:[-*•]|\d+[.)])[ \t])")
_TOKEN = re.compile(r"[^\W_]+(?:[./+-][^\W_]+)*\+?", re.UNICODE)


@dataclass(frozen=True, slots=True)
class PhraseOccurrence:
    doc_id: str
    note_type: str
    language: str
    primary: str
    folded: str
    surface: str
    token_count: int
    context: str = CONTEXT_CURRENT_CLINICAL


@dataclass(frozen=True, slots=True)
class PhraseAggregate:
    language: str
    primary: str
    folded: str
    display: str
    token_count: int
    occurrence_count: int
    document_frequency: int
    note_type_counts: tuple[tuple[str, int], ...]
    max_sublinear_tf_idf: str

    def as_dict(self) -> dict[str, object]:
        return {
            "display": self.display,
            "document_frequency": self.document_frequency,
            "language": self.language,
            "max_sublinear_tf_idf": self.max_sublinear_tf_idf,
            "note_type_counts": {key: value for key, value in self.note_type_counts},
            "occurrence_count": self.occurrence_count,
            "phrase_schema_version": "1.0.0",
            "primary_normalized_form": self.primary,
            "token_count": self.token_count,
        }


def sentence_spans(text: str) -> tuple[tuple[int, int], ...]:
    spans: list[tuple[int, int]] = []
    cursor = 0
    for match in _SENTENCE_BOUNDARY.finditer(text):
        if cursor < match.start():
            spans.append((cursor, match.start()))
        cursor = match.end()
    if cursor < len(text):
        spans.append((cursor, len(text)))
    return tuple(spans)


def mine_document(
    document: Document,
    config: AnalysisConfig,
    *,
    qualify_context: bool = False,
) -> tuple[PhraseOccurrence, ...]:
    spans = sentence_spans(document.text)
    contexts = document_context(document.text, spans) if qualify_context else None
    sentence_tokens: list[list[tuple[int, int]]] = []
    token_total = 0
    ngram_total = 0
    for sentence_start, sentence_end in spans:
        tokens = [
            (sentence_start + match.start(), sentence_start + match.end())
            for match in _TOKEN.finditer(document.text[sentence_start:sentence_end])
        ]
        token_total += len(tokens)
        for n in range(config.mining.min_ngram_tokens, config.mining.max_ngram_tokens + 1):
            ngram_total += max(0, len(tokens) - n + 1)
        sentence_tokens.append(tokens)
    if token_total > config.resource_limits.max_tokens_per_document:
        raise ContractError("RESOURCE_LIMIT", "A document exceeds the configured token limit.", "document", 4)
    if ngram_total > config.resource_limits.max_ngrams_per_document:
        raise ContractError("RESOURCE_LIMIT", "A document exceeds the configured n-gram limit.", "document", 4)

    occurrences: list[PhraseOccurrence] = []
    for tokens in sentence_tokens:
        for n in range(config.mining.min_ngram_tokens, config.mining.max_ngram_tokens + 1):
            for index in range(0, len(tokens) - n + 1):
                start = tokens[index][0]
                end = tokens[index + n - 1][1]
                surface = document.text[start:end]
                lexical = normalize_lexical(surface)
                if lexical.primary:
                    occurrences.append(
                        PhraseOccurrence(
                            doc_id=document.doc_id,
                            note_type=document.note_type,
                            language=document.language,
                            primary=lexical.primary,
                            folded=lexical.folded,
                            surface=surface,
                            token_count=n,
                            context=(
                                contexts.classify(start, end) if contexts is not None else CONTEXT_CURRENT_CLINICAL
                            ),
                        )
                    )
    return tuple(occurrences)


def aggregate_phrases(documents: tuple[Document, ...], config: AnalysisConfig) -> tuple[PhraseAggregate, ...]:
    grouped: dict[tuple[str, str, int], list[PhraseOccurrence]] = defaultdict(list)
    for document in documents:
        for occurrence in mine_document(document, config):
            grouped[(occurrence.language, occurrence.primary, occurrence.token_count)].append(occurrence)
            if len(grouped) > config.mining.max_unique_phrases:
                raise ContractError(
                    "RESOURCE_LIMIT", "The run exceeds the configured unique-phrase limit.", "analysis", 4
                )

    document_count = len(documents)
    aggregates: list[PhraseAggregate] = []
    for (language, primary, token_count), occurrences in grouped.items():
        by_document: Counter[str] = Counter(item.doc_id for item in occurrences)
        document_frequency = len(by_document)
        if document_frequency < config.mining.min_document_frequency:
            continue
        surface_counts: Counter[str] = Counter(item.surface for item in occurrences)
        display = min(
            (surface for surface, count in surface_counts.items() if count == max(surface_counts.values())),
            key=lambda item: item,
        )
        note_types = Counter(item.note_type for item in occurrences)
        tf = max(Decimal(1) + Decimal(count).ln() for count in by_document.values())
        idf = (Decimal(document_count + 1) / Decimal(document_frequency + 1)).ln() + Decimal(1)
        score = (tf * idf).quantize(Decimal("0.000001"), rounding=ROUND_HALF_EVEN)
        aggregates.append(
            PhraseAggregate(
                language=language,
                primary=primary,
                folded=normalize_lexical(primary).folded,
                display=display,
                token_count=token_count,
                occurrence_count=len(occurrences),
                document_frequency=document_frequency,
                note_type_counts=tuple(sorted(note_types.items())),
                max_sublinear_tf_idf=format(score, "f"),
            )
        )
    return tuple(sorted(aggregates, key=lambda item: (item.language, item.primary, item.token_count)))
