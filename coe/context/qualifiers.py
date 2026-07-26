"""Deterministic assertion, experiencer, and temporality qualification.

Every mention of a phrase is assigned exactly one context label so counts
partition cleanly and never double-count:

- ``negated``       — the sentence asserts the concept is absent
- ``non_patient``   — the mention is about a family member or other person
- ``historical``    — the mention is about the patient's past, not the present
- ``current_clinical`` — an affirmed, patient, current mention

Precedence is negated > non_patient > historical > current_clinical: a negated
family-history mention is still, first and foremost, not an assertion that the
patient has the concept.

The rules are lexical, offline, and case-insensitive: trigger phrases scoped by
word distance, scope-breaking conjunctions, and EHR section headers. This is a
conservative screen, not a parser — it cannot resolve nested or long-range
scope, so ``current_clinical`` remains lexical evidence rather than a clinical
finding.
"""

from __future__ import annotations

import re
from bisect import bisect_left, bisect_right
from dataclasses import dataclass, field

CONTEXT_NEGATED = "negated"
CONTEXT_NON_PATIENT = "non_patient"
CONTEXT_HISTORICAL = "historical"
CONTEXT_CURRENT_CLINICAL = "current_clinical"

# Ordered by precedence; also the canonical emit order for reports.
CONTEXT_LABELS = (
    CONTEXT_CURRENT_CLINICAL,
    CONTEXT_HISTORICAL,
    CONTEXT_NEGATED,
    CONTEXT_NON_PATIENT,
)

_PRE_WINDOW_WORDS = 6
_POST_WINDOW_WORDS = 4
_EXPERIENCER_WINDOW_WORDS = 12

_NEGATION_PRE = (
    "no evidence of",
    "no evidence for",
    "no signs of",
    "no sign of",
    "no symptoms of",
    "no complaints of",
    "no history of",
    "not have",
    "not had",
    "no",
    "not",
    "without",
    "denies",
    "denied",
    "negative for",
    "negative",
    "rule out",
    "ruled out",
    "r/o",
    "free of",
    "absent",
    "unremarkable for",
    "declines",
    "never had",
    "no longer",
)
_NEGATION_POST = (
    "is absent",
    "was absent",
    "is negative",
    "was negative",
    "not present",
    "was ruled out",
    "is ruled out",
    "has been ruled out",
    "is not present",
)
# Tokens that end a negation scope: "no fever but reports cough".
_SCOPE_BREAK = (
    "but",
    "however",
    "although",
    "though",
    "except",
    "aside from",
    "apart from",
    "otherwise",
    "positive for",
    "reports",
    "complains of",
    "admits",
    "presents with",
)
_EXPERIENCER = (
    "family history",
    "familial history",
    "fh",
    "mother",
    "mothers",
    "father",
    "fathers",
    "parent",
    "parents",
    "sister",
    "sisters",
    "brother",
    "brothers",
    "sibling",
    "siblings",
    "son",
    "daughter",
    "aunt",
    "uncle",
    "grandmother",
    "grandfather",
    "grandparent",
    "cousin",
    "maternal",
    "paternal",
    "wife",
    "husband",
    "spouse",
    "partner",
)
_TEMPORALITY_PRE = (
    "history of",
    "hx of",
    "h/o",
    "past medical history",
    "past surgical history",
    "previously",
    "previous",
    "prior",
    "status post",
    "s/p",
    "in the past",
    "years ago",
    "months ago",
    "former",
    "formerly",
    "childhood",
    "as a child",
    "remote",
    "resolved",
    "healed",
)
_TEMPORALITY_POST = (
    "years ago",
    "months ago",
    "in the past",
    "has resolved",
    "resolved",
)

_SECTION_HEADERS: tuple[tuple[str, str], ...] = (
    ("family history", CONTEXT_NON_PATIENT),
    ("family hx", CONTEXT_NON_PATIENT),
    ("fh", CONTEXT_NON_PATIENT),
    ("social and family history", CONTEXT_NON_PATIENT),
    ("past medical history", CONTEXT_HISTORICAL),
    ("past surgical history", CONTEXT_HISTORICAL),
    ("past history", CONTEXT_HISTORICAL),
    ("medical history", CONTEXT_HISTORICAL),
    ("surgical history", CONTEXT_HISTORICAL),
    ("pmh", CONTEXT_HISTORICAL),
    ("psh", CONTEXT_HISTORICAL),
    ("prior surgeries", CONTEXT_HISTORICAL),
)
# Headers that return the note to present-tense patient content.
_RESET_HEADERS = (
    "history of present illness",
    "hpi",
    "chief complaint",
    "cc",
    "assessment",
    "assessment and plan",
    "plan",
    "physical examination",
    "physical exam",
    "exam",
    "review of systems",
    "ros",
    "impression",
    "medications",
    "current medications",
    "allergies",
    "vitals",
    "vital signs",
    "labs",
    "subjective",
    "objective",
    "social history",
)

_WORD = re.compile(r"[^\W_]+", re.UNICODE)
_HEADER_LINE = re.compile(r"^[ \t]*([A-Za-z][A-Za-z /&']{0,48})[ \t]*:", re.MULTILINE)


def _phrase_pattern(phrases: tuple[str, ...]) -> re.Pattern[str]:
    # Longest-first so "no evidence of" wins over the bare "no".
    ordered = sorted(set(phrases), key=lambda item: (-len(item), item))
    alternatives = "|".join(re.escape(phrase).replace(r"\ ", r"[ \t]+") for phrase in ordered)
    return re.compile(rf"(?<![^\W_])(?:{alternatives})(?![^\W_])", re.IGNORECASE)


_NEGATION_PRE_RE = _phrase_pattern(_NEGATION_PRE)
_NEGATION_POST_RE = _phrase_pattern(_NEGATION_POST)
_SCOPE_BREAK_RE = _phrase_pattern(_SCOPE_BREAK)
_EXPERIENCER_RE = _phrase_pattern(_EXPERIENCER)
_TEMPORALITY_PRE_RE = _phrase_pattern(_TEMPORALITY_PRE)
_TEMPORALITY_POST_RE = _phrase_pattern(_TEMPORALITY_POST)


@dataclass(frozen=True, slots=True)
class _SentenceContext:
    """Precomputed trigger offsets for one sentence."""

    start: int
    end: int
    word_starts: tuple[int, ...]
    negation_pre: tuple[tuple[int, int], ...]
    negation_post: tuple[tuple[int, int], ...]
    scope_breaks: tuple[int, ...]
    experiencer: tuple[tuple[int, int], ...]
    temporality_pre: tuple[tuple[int, int], ...]
    temporality_post: tuple[tuple[int, int], ...]

    def words_between(self, from_offset: int, to_offset: int) -> int:
        if to_offset <= from_offset:
            return 0
        left = bisect_right(self.word_starts, from_offset)
        right = bisect_left(self.word_starts, to_offset)
        return max(0, right - left)


@dataclass(frozen=True, slots=True)
class DocumentContext:
    """Context classifier bound to one document's text."""

    sections: tuple[tuple[int, int, str], ...] = field(repr=False)
    sentences: tuple[_SentenceContext, ...] = field(repr=False)

    def section_label(self, offset: int) -> str | None:
        for start, end, label in self.sections:
            if start <= offset < end:
                return label
        return None

    def _sentence(self, offset: int) -> _SentenceContext | None:
        for sentence in self.sentences:
            if sentence.start <= offset < sentence.end:
                return sentence
        return None

    def classify(self, phrase_start: int, phrase_end: int) -> str:
        sentence = self._sentence(phrase_start)
        section = self.section_label(phrase_start)
        if sentence is None:
            return section or CONTEXT_CURRENT_CLINICAL

        # A scope break between a trigger and the phrase cancels that trigger.
        def unbroken(trigger_end: int) -> bool:
            return not any(trigger_end <= position < phrase_start for position in sentence.scope_breaks)

        negated = any(
            unbroken(end) and sentence.words_between(end, phrase_start) <= _PRE_WINDOW_WORDS
            for _, end in sentence.negation_pre
            if end <= phrase_start
        ) or any(
            sentence.words_between(phrase_end, start) <= _POST_WINDOW_WORDS
            for start, _ in sentence.negation_post
            if start >= phrase_end
        )
        if negated:
            return CONTEXT_NEGATED

        if section == CONTEXT_NON_PATIENT:
            return CONTEXT_NON_PATIENT
        if any(
            sentence.words_between(end, phrase_start) <= _EXPERIENCER_WINDOW_WORDS
            for _, end in sentence.experiencer
            if end <= phrase_start
        ):
            return CONTEXT_NON_PATIENT

        if section == CONTEXT_HISTORICAL:
            return CONTEXT_HISTORICAL
        historical = any(
            sentence.words_between(end, phrase_start) <= _PRE_WINDOW_WORDS
            for _, end in sentence.temporality_pre
            if end <= phrase_start
        ) or any(
            sentence.words_between(phrase_end, start) <= _POST_WINDOW_WORDS
            for start, _ in sentence.temporality_post
            if start >= phrase_end
        )
        if historical:
            return CONTEXT_HISTORICAL
        return CONTEXT_CURRENT_CLINICAL


def _sections(text: str) -> tuple[tuple[int, int, str], ...]:
    labels: dict[str, str] = {header: label for header, label in _SECTION_HEADERS}
    resets = set(_RESET_HEADERS)
    spans: list[tuple[int, int, str]] = []
    open_start: int | None = None
    open_label: str | None = None
    for match in _HEADER_LINE.finditer(text):
        heading = " ".join(match.group(1).split()).casefold()
        label = labels.get(heading)
        is_reset = heading in resets
        if label is None and not is_reset:
            continue
        if open_start is not None and open_label is not None:
            spans.append((open_start, match.start(), open_label))
            open_start = None
            open_label = None
        if label is not None:
            open_start = match.end()
            open_label = label
    if open_start is not None and open_label is not None:
        spans.append((open_start, len(text), open_label))
    return tuple(spans)


def _sentence_context(text: str, start: int, end: int) -> _SentenceContext:
    fragment = text[start:end]

    def spans(pattern: re.Pattern[str]) -> tuple[tuple[int, int], ...]:
        return tuple((start + match.start(), start + match.end()) for match in pattern.finditer(fragment))

    return _SentenceContext(
        start=start,
        end=end,
        word_starts=tuple(start + match.start() for match in _WORD.finditer(fragment)),
        negation_pre=spans(_NEGATION_PRE_RE),
        negation_post=spans(_NEGATION_POST_RE),
        scope_breaks=tuple(begin for begin, _ in spans(_SCOPE_BREAK_RE)),
        experiencer=spans(_EXPERIENCER_RE),
        temporality_pre=spans(_TEMPORALITY_PRE_RE),
        temporality_post=spans(_TEMPORALITY_POST_RE),
    )


def document_context(text: str, sentence_spans: tuple[tuple[int, int], ...]) -> DocumentContext:
    """Precompute section and per-sentence trigger offsets for one document."""

    return DocumentContext(
        sections=_sections(text),
        sentences=tuple(_sentence_context(text, start, end) for start, end in sentence_spans),
    )
