"""Protected-local plaintext analysis with aggregate-only artifacts.

This runner is deliberately separate from the synthetic v0 pipeline. It reads
approved plaintext in place, retains lexical material only in process memory,
and emits no document identity, path, or snippet. Lexical surface forms and
unmapped candidate terms are emitted only when the data-use attestation
explicitly approves lexical output, and every emitted row is subject to a
small-cell document floor and a deterministic scrub filter.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import tempfile
import uuid
from collections import Counter
from collections.abc import Collection
from dataclasses import dataclass, field
from decimal import ROUND_HALF_EVEN, Decimal
from pathlib import Path
from typing import Protocol
from urllib.parse import urlparse

from coe.canonical import (
    JsonValue,
    load_json_bytes,
    read_stable_file,
    require_bool,
    require_exact_keys,
    require_object,
    require_string,
    sha256_bytes,
    sha256_canonical,
)
from coe.context import CONTEXT_CURRENT_CLINICAL, CONTEXT_LABELS
from coe.contracts.config import AnalysisConfig, MiningConfig, ResourceLimits
from coe.contracts.snapshot import Document
from coe.errors import ContractError, OutputExistsError
from coe.export.jsonl import ArtifactDigest, write_json, write_jsonl
from coe.identity import protected_implementation_identity
from coe.mining.ngrams import mine_document
from coe.runtime.doctor import probe_host
from coe.terminology.variants import VARIANT_METHOD_PRIORITY, grounded_lookup

ATTESTATION_SCHEMA_VERSION = "1.1.0"
OUTPUT_CLASSIFICATION = "protected_aggregate"
PROTECTED_ROW_SCHEMA_VERSION = "1.2.0"
RUN_REPORT_SCHEMA_VERSION = "protected-local-1.2.0"
SEMANTIC_AGGREGATE_SCHEMA = "coe-protected-aggregate-v3"
FINGERPRINT_DOMAIN = b"coe.protected-run.v3"
MAX_ATTESTATION_BYTES = 65_536
_ATTESTATION_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}")
_PLACEHOLDER_PREFIXES = ("TEST-ONLY", "REPLACE-WITH")
PROTECTED_LIMITATIONS = (
    "aggregate protected output; not de-identified or approved for public release",
    "exact and deterministic-variant n-gram evidence is lexically scoped and not overlap-resolved",
    "coding counts are lexical evidence across every mention context and not clinical prevalence",
    "context qualification is a conservative lexical screen and not a parser",
    "rows below the small-cell document floor are suppressed and reported only as counts",
    "candidate terms are unreviewed corpus text approved for restricted curation only",
    "association rows are document co-mention statistics and not clinical relationships",
)
PROTECTED_ARTIFACT_FILES = (
    "ambiguity_counts.jsonl",
    "associations.jsonl",
    "candidate_terms.jsonl",
    "coding_counts.jsonl",
    "context_counts.jsonl",
    "lexical_forms.jsonl",
)

_HARD_MAX_FILES = 10_000
_HARD_MAX_WALK_ENTRIES = 50_000
_HARD_MAX_FILE_BYTES = 10_000_000
_HARD_MAX_TOTAL_BYTES = 100_000_000
_HARD_MAX_TOKENS_PER_FILE = 250_000
_HARD_MAX_TOTAL_TOKENS = 5_000_000
_HARD_MAX_NGRAMS_PER_FILE = 1_000_000
_HARD_MAX_TOTAL_NGRAMS = 10_000_000
_HARD_MAX_UNIQUE_PHRASES = 1_000_000
_HARD_MAX_CANDIDATES = 100
_HARD_MAX_CELL_FLOOR = 1_000
_HARD_MAX_CANDIDATE_TERMS = 100_000
_HARD_MAX_ASSOCIATION_CODES = 500
_HARD_MAX_ASSOCIATION_PAIRS = 5_000_000

# Deterministic scrub filters for any lexical text that leaves the process.
_SCRUB_DIGIT_RUN = re.compile(r"\d{4,}")
_SCRUB_CONTACT = re.compile(r"[@#]")
_MAX_EMITTED_FORM_CHARS = 80
_MIN_ALPHA_CHARS = 3
_CANDIDATE_STOPWORDS = frozenset(
    """a an and are as at be but by for from had has have he her his if in is it its no not of on or
    she that the their they this to was were will with patient patients denies reports history noted
    normal stable left right daily follow up plan continue review""".split()
)


class _ReferenceView(Protocol):
    system_uri: str
    release_id: str
    code_catalog: Collection[str]


class _LookupHit(Protocol):
    code: str


class ProtectedExactIndex(Protocol):
    """Small interface shared by in-memory and licensed SQLite indexes."""

    reference: _ReferenceView

    def lookup(self, key: str, *, kind: str, variant: str) -> tuple[_LookupHit, ...]: ...


@dataclass(frozen=True, slots=True)
class ProtectedLimits:
    max_files: int = 10_000
    max_walk_entries: int = 50_000
    max_file_bytes: int = 10_000_000
    max_total_bytes: int = 100_000_000
    max_tokens_per_file: int = 250_000
    max_total_tokens: int = 5_000_000
    max_ngrams_per_file: int = 1_000_000
    max_total_ngrams: int = 10_000_000
    max_unique_phrases: int = 1_000_000
    max_candidates_per_phrase_system: int = 100
    max_ngram_tokens: int = 4
    min_cell_document_count: int = 3
    max_candidate_terms: int = 5_000
    max_association_codes_per_document: int = 150
    max_association_pairs: int = 1_000_000

    def __post_init__(self) -> None:
        fields = (
            ("max_files", self.max_files, _HARD_MAX_FILES),
            ("max_walk_entries", self.max_walk_entries, _HARD_MAX_WALK_ENTRIES),
            ("max_file_bytes", self.max_file_bytes, _HARD_MAX_FILE_BYTES),
            ("max_total_bytes", self.max_total_bytes, _HARD_MAX_TOTAL_BYTES),
            ("max_tokens_per_file", self.max_tokens_per_file, _HARD_MAX_TOKENS_PER_FILE),
            ("max_total_tokens", self.max_total_tokens, _HARD_MAX_TOTAL_TOKENS),
            ("max_ngrams_per_file", self.max_ngrams_per_file, _HARD_MAX_NGRAMS_PER_FILE),
            ("max_total_ngrams", self.max_total_ngrams, _HARD_MAX_TOTAL_NGRAMS),
            ("max_unique_phrases", self.max_unique_phrases, _HARD_MAX_UNIQUE_PHRASES),
            (
                "max_candidates_per_phrase_system",
                self.max_candidates_per_phrase_system,
                _HARD_MAX_CANDIDATES,
            ),
            ("max_ngram_tokens", self.max_ngram_tokens, 8),
            ("min_cell_document_count", self.min_cell_document_count, _HARD_MAX_CELL_FLOOR),
            ("max_candidate_terms", self.max_candidate_terms, _HARD_MAX_CANDIDATE_TERMS),
            (
                "max_association_codes_per_document",
                self.max_association_codes_per_document,
                _HARD_MAX_ASSOCIATION_CODES,
            ),
            ("max_association_pairs", self.max_association_pairs, _HARD_MAX_ASSOCIATION_PAIRS),
        )
        for name, value, maximum in fields:
            if not isinstance(value, int) or isinstance(value, bool) or value < 1 or value > maximum:
                raise ContractError(
                    "RESOURCE_LIMIT",
                    "A protected-local resource limit is outside its safety boundary.",
                    name,
                    4,
                )
        if self.max_file_bytes > self.max_total_bytes:
            raise ContractError("RESOURCE_LIMIT", "The per-file byte limit exceeds the total limit.", "limits", 4)
        if self.max_tokens_per_file > self.max_total_tokens:
            raise ContractError("RESOURCE_LIMIT", "The per-file token limit exceeds the total limit.", "limits", 4)
        if self.max_ngrams_per_file > self.max_total_ngrams:
            raise ContractError("RESOURCE_LIMIT", "The per-file n-gram limit exceeds the total limit.", "limits", 4)

    def as_dict(self) -> dict[str, JsonValue]:
        return {
            "max_association_codes_per_document": self.max_association_codes_per_document,
            "max_association_pairs": self.max_association_pairs,
            "max_candidate_terms": self.max_candidate_terms,
            "max_candidates_per_phrase_system": self.max_candidates_per_phrase_system,
            "max_file_bytes": self.max_file_bytes,
            "max_files": self.max_files,
            "max_ngram_tokens": self.max_ngram_tokens,
            "max_ngrams_per_file": self.max_ngrams_per_file,
            "max_tokens_per_file": self.max_tokens_per_file,
            "max_total_bytes": self.max_total_bytes,
            "max_total_ngrams": self.max_total_ngrams,
            "max_total_tokens": self.max_total_tokens,
            "max_unique_phrases": self.max_unique_phrases,
            "max_walk_entries": self.max_walk_entries,
            "min_cell_document_count": self.min_cell_document_count,
        }


@dataclass(frozen=True, slots=True)
class ProtectedAttestation:
    profile: str
    retention_policy_id: str
    output_classification: str
    approval_ref_count: int
    attestation_sha256: str
    lexical_output_approved: bool


@dataclass(slots=True)
class _PhraseStats:
    folded: str
    token_count: int
    occurrence_count: int = 0
    documents: Counter[int] = field(default_factory=Counter)
    # Mention context partitions occurrences: label -> document -> count.
    context_documents: dict[str, Counter[int]] = field(default_factory=dict)

    def observe(self, document_number: int, context: str) -> None:
        self.occurrence_count += 1
        self.documents[document_number] += 1
        self.context_documents.setdefault(context, Counter())[document_number] += 1


@dataclass(slots=True)
class _CodingStats:
    occurrence_count: int = 0
    documents: set[int] = field(default_factory=set)
    lexical_form_count: int = 0
    context_documents: dict[str, set[int]] = field(default_factory=dict)
    context_occurrences: Counter[str] = field(default_factory=Counter)

    def merge(self, phrase: _PhraseStats) -> None:
        self.occurrence_count += phrase.occurrence_count
        self.documents.update(phrase.documents)
        self.lexical_form_count += 1
        for label, documents in phrase.context_documents.items():
            self.context_documents.setdefault(label, set()).update(documents)
            self.context_occurrences[label] += sum(documents.values())


@dataclass(slots=True)
class _AmbiguityStats:
    occurrence_count: int = 0
    documents: set[int] = field(default_factory=set)
    lexical_form_count: int = 0


@dataclass(frozen=True, slots=True)
class _CorpusStats:
    file_count: int
    content_set_sha256: str
    total_bytes: int
    total_characters: int
    total_tokens: int
    total_ngrams: int
    phrases: dict[str, _PhraseStats] = field(repr=False)


@dataclass(frozen=True, slots=True)
class _AggregateResult:
    coding_rows: tuple[dict[str, JsonValue], ...]
    ambiguity_rows: tuple[dict[str, JsonValue], ...]
    context_rows: tuple[dict[str, JsonValue], ...]
    lexical_rows: tuple[dict[str, JsonValue], ...]
    candidate_rows: tuple[dict[str, JsonValue], ...]
    association_rows: tuple[dict[str, JsonValue], ...]
    grounded_candidates_checked: int
    privacy: dict[str, JsonValue]


def _bounded_text(value: JsonValue, location: str, maximum: int = 256) -> str:
    text = require_string(value, location)
    if len(text) > maximum or _ATTESTATION_IDENTIFIER.fullmatch(text) is None:
        raise ContractError("ATTESTATION_INVALID", "An attestation identifier is invalid.", location, 4)
    if text.upper().startswith(_PLACEHOLDER_PREFIXES):
        raise ContractError(
            "ATTESTATION_INVALID",
            "An attestation identifier is an unapproved placeholder.",
            location,
            4,
        )
    return text


def inspect_protected_attestation(path: Path) -> ProtectedAttestation:
    raw = read_stable_file(path, "data_use_attestation.json", MAX_ATTESTATION_BYTES)
    value = require_object(load_json_bytes(raw, "data_use_attestation.json"), "data_use_attestation.json")
    require_exact_keys(
        value,
        (
            "attestation_schema_version",
            "profile",
            "approved",
            "approval_refs",
            "retention_policy_id",
            "output_classification",
            "lexical_output_approved",
        ),
        (),
        "data_use_attestation.json",
    )
    if value["attestation_schema_version"] != ATTESTATION_SCHEMA_VERSION:
        raise ContractError("ATTESTATION_INVALID", "The attestation schema version is unsupported.", "attestation", 4)
    profile = require_string(value["profile"], "attestation.profile")
    if profile != "protected_phi_local":
        raise ContractError("UNSAFE_PROFILE", "The protected-local profile was not attested.", "attestation", 4)
    if not require_bool(value["approved"], "attestation.approved"):
        raise ContractError("ATTESTATION_INVALID", "Protected-local processing was not approved.", "attestation", 4)
    approval_refs = require_object(value["approval_refs"], "attestation.approval_refs")
    require_exact_keys(approval_refs, ("data_owner", "privacy"), ("security",), "attestation.approval_refs")
    for name, approval_ref in approval_refs.items():
        _bounded_text(approval_ref, f"attestation.approval_refs.{name}")
    retention_policy_id = _bounded_text(value["retention_policy_id"], "attestation.retention_policy_id")
    output_classification = require_string(value["output_classification"], "attestation.output_classification")
    if output_classification != OUTPUT_CLASSIFICATION:
        raise ContractError(
            "ATTESTATION_INVALID",
            "The output classification is not approved for aggregate-only protected output.",
            "attestation",
            4,
        )
    lexical_output_approved = require_bool(value["lexical_output_approved"], "attestation.lexical_output_approved")
    return ProtectedAttestation(
        profile=profile,
        retention_policy_id=retention_policy_id,
        output_classification=output_classification,
        approval_ref_count=len(approval_refs),
        attestation_sha256=sha256_bytes(raw),
        lexical_output_approved=lexical_output_approved,
    )


def _is_reparse_or_link(path: Path, path_stat: os.stat_result | None = None) -> bool:
    try:
        info = path_stat if path_stat is not None else path.lstat()
        if stat.S_ISLNK(info.st_mode):
            return True
        is_junction = getattr(path, "is_junction", None)
        if callable(is_junction) and is_junction():
            return True
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        return bool(getattr(info, "st_file_attributes", 0) & reparse_flag)
    except OSError:
        raise ContractError("FILE_UNREADABLE", "A corpus entry could not be safely inspected.", "corpus", 3) from None


def _collect_text_files(root: Path, limits: ProtectedLimits) -> tuple[Path, ...]:
    try:
        root_stat = root.lstat()
    except OSError:
        raise ContractError("FILE_MISSING", "The protected corpus directory is unavailable.", "corpus", 3) from None
    if _is_reparse_or_link(root, root_stat):
        raise ContractError("REPARSE_POINT", "Links, junctions, and reparse points are forbidden.", "corpus", 4)
    if not stat.S_ISDIR(root_stat.st_mode):
        raise ContractError("FILE_MISSING", "The protected corpus path is not a directory.", "corpus", 3)

    paths: list[Path] = []
    seen_files: set[tuple[int, int]] = set()
    total_bytes = 0
    walked_entries = 0

    def walk_error(_: OSError) -> None:
        raise ContractError("FILE_UNREADABLE", "The protected corpus could not be traversed.", "corpus", 3)

    def count_entry() -> None:
        nonlocal walked_entries
        walked_entries += 1
        if walked_entries > limits.max_walk_entries:
            raise ContractError("RESOURCE_LIMIT", "The corpus traversal exceeds its entry limit.", "corpus", 4)

    for current, directory_names, file_names in os.walk(root, topdown=True, onerror=walk_error, followlinks=False):
        directory_names.sort()
        file_names.sort()
        current_path = Path(current)
        for name in directory_names:
            count_entry()
            child = current_path / name
            try:
                child_stat = child.lstat()
            except OSError:
                raise ContractError(
                    "FILE_UNREADABLE", "A corpus entry could not be safely inspected.", "corpus", 3
                ) from None
            if _is_reparse_or_link(child, child_stat):
                raise ContractError("REPARSE_POINT", "Links, junctions, and reparse points are forbidden.", "corpus", 4)
            if not stat.S_ISDIR(child_stat.st_mode):
                raise ContractError("NONREGULAR", "A corpus entry has an unsupported type.", "corpus", 4)
        for name in file_names:
            count_entry()
            child = current_path / name
            try:
                child_stat = child.lstat()
            except OSError:
                raise ContractError(
                    "FILE_UNREADABLE", "A corpus entry could not be safely inspected.", "corpus", 3
                ) from None
            if _is_reparse_or_link(child, child_stat):
                raise ContractError("REPARSE_POINT", "Links, junctions, and reparse points are forbidden.", "corpus", 4)
            if not stat.S_ISREG(child_stat.st_mode):
                raise ContractError("NONREGULAR", "A corpus entry has an unsupported type.", "corpus", 4)
            if child_stat.st_nlink != 1:
                raise ContractError("HARDLINK", "Hard-linked corpus files are forbidden.", "corpus", 4)
            if child.suffix.casefold() != ".txt":
                continue
            identity = (child_stat.st_dev, child_stat.st_ino)
            if identity in seen_files:
                raise ContractError("HARDLINK", "A protected corpus file is reachable more than once.", "corpus", 4)
            seen_files.add(identity)
            if child_stat.st_size > limits.max_file_bytes:
                raise ContractError("RESOURCE_LIMIT", "A corpus file exceeds the configured byte limit.", "corpus", 4)
            paths.append(child)
            total_bytes += child_stat.st_size
            if len(paths) > limits.max_files or total_bytes > limits.max_total_bytes:
                raise ContractError("RESOURCE_LIMIT", "The protected corpus exceeds configured limits.", "corpus", 4)
    if not paths:
        raise ContractError("FILE_MISSING", "The protected corpus contains no plaintext files.", "corpus", 3)
    return tuple(paths)


def _mining_config(limits: ProtectedLimits) -> AnalysisConfig:
    return AnalysisConfig(
        config_id="protected-local-internal",
        note_types=("protected_plaintext",),
        languages=("en",),
        terminologies=(),
        mining=MiningConfig(
            min_ngram_tokens=1,
            max_ngram_tokens=limits.max_ngram_tokens,
            min_document_frequency=1,
            max_unique_phrases=limits.max_unique_phrases,
        ),
        resource_limits=ResourceLimits(
            max_documents=limits.max_files,
            max_snapshot_bytes=limits.max_total_bytes,
            max_document_bytes=limits.max_file_bytes,
            max_tokens_per_document=limits.max_tokens_per_file,
            max_ngrams_per_document=limits.max_ngrams_per_file,
            max_output_records=limits.max_unique_phrases,
            max_candidates_per_phrase_system=limits.max_candidates_per_phrase_system,
        ),
        algorithms={},
        canonical_value={},
        semantic_sha256="",
    )


def _read_corpus(root: Path, limits: ProtectedLimits) -> _CorpusStats:
    paths = _collect_text_files(root, limits)
    config = _mining_config(limits)
    phrases: dict[str, _PhraseStats] = {}
    total_bytes = 0
    total_characters = 0
    total_tokens = 0
    total_ngrams = 0
    content_descriptors: list[dict[str, JsonValue]] = []
    for document_number, path in enumerate(paths):
        raw = read_stable_file(path, "corpus file", limits.max_file_bytes)
        content_descriptors.append({"byte_count": len(raw), "sha256": sha256_bytes(raw)})
        total_bytes += len(raw)
        if total_bytes > limits.max_total_bytes:
            raise ContractError("RESOURCE_LIMIT", "The protected corpus exceeds its byte limit.", "corpus", 4)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise ContractError("UTF8_INVALID", "A protected corpus file is not valid UTF-8.", "corpus", 3) from None
        total_characters += len(text)
        document = Document(
            doc_id=str(document_number),
            path="",
            sha256="",
            byte_count=len(raw),
            character_count=len(text),
            note_type="protected_plaintext",
            language="en",
            extraction_method="protected_local_plaintext",
            text=text,
        )
        occurrences = mine_document(document, config, qualify_context=True)
        file_tokens = sum(1 for occurrence in occurrences if occurrence.token_count == 1)
        total_tokens += file_tokens
        total_ngrams += len(occurrences)
        if total_tokens > limits.max_total_tokens or total_ngrams > limits.max_total_ngrams:
            raise ContractError("RESOURCE_LIMIT", "The protected corpus exceeds processing limits.", "corpus", 4)
        for occurrence in occurrences:
            stats = phrases.get(occurrence.primary)
            if stats is None:
                if len(phrases) >= limits.max_unique_phrases:
                    raise ContractError("RESOURCE_LIMIT", "The unique-form limit was exceeded.", "corpus", 4)
                stats = _PhraseStats(folded=occurrence.folded, token_count=occurrence.token_count)
                phrases[occurrence.primary] = stats
            elif stats.folded != occurrence.folded:
                raise ContractError("NORMALIZATION_FAILED", "Lexical normalization was inconsistent.", "analysis", 3)
            stats.observe(document_number, occurrence.context)
    return _CorpusStats(
        file_count=len(paths),
        content_set_sha256=sha256_canonical(
            {
                "files": sorted(content_descriptors, key=lambda item: (str(item["sha256"]), int(item["byte_count"]))),
                "schema_version": "coe-protected-path-free-content-v1",
            },
            domain=b"coe.protected-content-set.v1",
        ),
        total_bytes=total_bytes,
        total_characters=total_characters,
        total_tokens=total_tokens,
        total_ngrams=total_ngrams,
        phrases=phrases,
    )


def _safe_export_identifier(value: object, kind: str, maximum: int = 2_048) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or any(ord(char) < 32 for char in value):
        raise ContractError("TERMINOLOGY_INVALID", "Terminology identity metadata is unsafe.", kind, 3)
    return value


def _index_identity(index: ProtectedExactIndex) -> tuple[str, str]:
    try:
        system_uri = _safe_export_identifier(index.reference.system_uri, "terminology")
        release_id = _safe_export_identifier(index.reference.release_id, "terminology")
        catalog = index.reference.code_catalog
    except (AttributeError, TypeError):
        raise ContractError(
            "TERMINOLOGY_INVALID", "The exact index metadata is incomplete.", "terminology", 3
        ) from None
    parsed = urlparse(system_uri)
    if not parsed.scheme or (parsed.scheme in {"http", "https"} and not parsed.netloc):
        raise ContractError("TERMINOLOGY_INVALID", "The terminology system identity is invalid.", "terminology", 3)
    if not isinstance(catalog, Collection) or isinstance(catalog, (str, bytes)):
        raise ContractError("TERMINOLOGY_INVALID", "The exact index has no code catalog.", "terminology", 3)
    return system_uri, release_id


def _ordered_indexes(indexes: tuple[ProtectedExactIndex, ...]) -> tuple[ProtectedExactIndex, ...]:
    if not indexes:
        raise ContractError(
            "TERMINOLOGY_INVALID", "At least one exact terminology index is required.", "terminology", 3
        )
    identities: dict[tuple[str, str], ProtectedExactIndex] = {}
    for index in indexes:
        identity = _index_identity(index)
        if identity in identities:
            raise ContractError("TERMINOLOGY_INVALID", "A terminology release was supplied twice.", "terminology", 3)
        identities[identity] = index
    return tuple(identities[key] for key in sorted(identities))


def scrub_allows_form(form: str) -> bool:
    """Deterministic filter for lexical text that may leave the process."""

    if len(form) > _MAX_EMITTED_FORM_CHARS:
        return False
    if _SCRUB_DIGIT_RUN.search(form) or _SCRUB_CONTACT.search(form):
        return False
    alpha = sum(1 for character in form if character.isalpha())
    return alpha >= _MIN_ALPHA_CHARS


def _candidate_is_reportable(primary: str, folded: str) -> bool:
    if not scrub_allows_form(primary):
        return False
    tokens = folded.split(" ")
    return any(token not in _CANDIDATE_STOPWORDS for token in tokens)


def _lookup_evidence(
    index: ProtectedExactIndex,
    primary: str,
    folded: str,
    max_candidates: int,
) -> dict[str, str]:
    """Return {code: best_method} for one phrase against one index."""

    try:
        evidence = grounded_lookup(index, primary, folded)
    except ContractError:
        raise ContractError("TERMINOLOGY_LOOKUP_FAILED", "Exact terminology lookup failed.", "terminology", 3) from None
    except Exception:
        raise ContractError("TERMINOLOGY_LOOKUP_FAILED", "Exact terminology lookup failed.", "terminology", 3) from None
    if len(evidence) > max_candidates:
        raise ContractError(
            "RESOURCE_LIMIT",
            "An exact collision exceeds the protected-local candidate limit.",
            "analysis",
            4,
        )
    best: dict[str, str] = {}
    catalog = index.reference.code_catalog
    for code, items in evidence.items():
        safe_code = _safe_export_identifier(code, "terminology code", 128)
        if safe_code not in catalog:
            raise ContractError(
                "GROUNDING_FAILED", "An exact lookup returned a code outside its release.", "analysis", 3
            )
        best[safe_code] = min(
            (method for method, _ in items),
            key=lambda item: (VARIANT_METHOD_PRIORITY[item], item),
        )
    return best


def _quantize(value: Decimal) -> str:
    return format(value.quantize(Decimal("0.000001"), rounding=ROUND_HALF_EVEN), "f")


def _phrase_salience(stats: _PhraseStats, document_count: int) -> str:
    tf = max(Decimal(1) + Decimal(count).ln() for count in stats.documents.values())
    idf = (Decimal(document_count + 1) / Decimal(len(stats.documents) + 1)).ln() + Decimal(1)
    return _quantize(tf * idf)


def _association_rows(
    doc_codes: dict[int, set[tuple[str, str, str]]],
    code_documents: dict[tuple[str, str, str], set[int]],
    corpus: _CorpusStats,
    limits: ProtectedLimits,
) -> tuple[tuple[dict[str, JsonValue], ...], int, int]:
    pair_documents: Counter[tuple[tuple[str, str, str], tuple[str, str, str]]] = Counter()
    documents_skipped = 0
    for _, codes in sorted(doc_codes.items()):
        if len(codes) > limits.max_association_codes_per_document:
            documents_skipped += 1
            continue
        ordered = sorted(codes)
        for first_position, first in enumerate(ordered):
            for second in ordered[first_position + 1 :]:
                pair_documents[(first, second)] += 1
                if len(pair_documents) > limits.max_association_pairs:
                    raise ContractError(
                        "RESOURCE_LIMIT", "The association pair count exceeds its limit.", "analysis", 4
                    )
    rows: list[dict[str, JsonValue]] = []
    suppressed = 0
    total_documents = Decimal(corpus.file_count)
    for (first, second), together in sorted(pair_documents.items()):
        if together < limits.min_cell_document_count:
            suppressed += 1
            continue
        probability_together = Decimal(together) / total_documents
        probability_first = Decimal(len(code_documents[first])) / total_documents
        probability_second = Decimal(len(code_documents[second])) / total_documents
        if probability_together == 1:
            npmi = Decimal(1)
        else:
            npmi = (probability_together / (probability_first * probability_second)).ln() / (-probability_together.ln())
        rows.append(
            {
                "association_schema_version": PROTECTED_ROW_SCHEMA_VERSION,
                "code_a": first[2],
                "code_b": second[2],
                "cooccurrence_document_count": together,
                "document_count_a": len(code_documents[first]),
                "document_count_b": len(code_documents[second]),
                "npmi": _quantize(npmi),
                "release_id_a": first[1],
                "release_id_b": second[1],
                "system_uri_a": first[0],
                "system_uri_b": second[0],
            }
        )
    return tuple(rows), suppressed, documents_skipped


def _aggregate_matches(
    corpus: _CorpusStats,
    indexes: tuple[ProtectedExactIndex, ...],
    limits: ProtectedLimits,
    lexical_output_approved: bool,
) -> _AggregateResult:
    coding: dict[tuple[str, str, str], _CodingStats] = {}
    ambiguity: dict[tuple[str, str], _AmbiguityStats] = {_index_identity(index): _AmbiguityStats() for index in indexes}
    lexical: list[tuple[str, str, str, str, str, _PhraseStats]] = []
    unmapped: list[tuple[str, _PhraseStats]] = []
    doc_codes: dict[int, set[tuple[str, str, str]]] = {}
    grounded_candidates_checked = 0
    floor = limits.min_cell_document_count
    for primary in sorted(corpus.phrases):
        phrase = corpus.phrases[primary]
        matched_anywhere = False
        for index in indexes:
            system_uri, release_id = _index_identity(index)
            evidence = _lookup_evidence(index, primary, phrase.folded, limits.max_candidates_per_phrase_system)
            grounded_candidates_checked += len(evidence)
            if evidence:
                matched_anywhere = True
            if len(evidence) == 1:
                code, method = next(iter(evidence.items()))
                key = (system_uri, release_id, code)
                stats = coding.setdefault(key, _CodingStats())
                stats.merge(phrase)
                lexical.append((system_uri, release_id, code, primary, method, phrase))
                # Associations are built from current-clinical mentions only:
                # co-occurring negations or family history are not findings.
                for document_number in phrase.context_documents.get(CONTEXT_CURRENT_CLINICAL, ()):
                    doc_codes.setdefault(document_number, set()).add(key)
            elif len(evidence) > 1:
                ambiguous = ambiguity[(system_uri, release_id)]
                ambiguous.occurrence_count += phrase.occurrence_count
                ambiguous.documents.update(phrase.documents)
                ambiguous.lexical_form_count += 1
        if not matched_anywhere:
            unmapped.append((primary, phrase))

    suppressed_coding = 0
    coding_rows: list[dict[str, JsonValue]] = []
    for (system_uri, release_id, code), stats in sorted(coding.items()):
        if len(stats.documents) < floor:
            suppressed_coding += 1
            continue
        coding_rows.append(
            {
                "coding_count_schema_version": PROTECTED_ROW_SCHEMA_VERSION,
                "code": code,
                "distinct_matched_form_count": stats.lexical_form_count,
                "exact_match_document_count": len(stats.documents),
                "exact_match_occurrence_count": stats.occurrence_count,
                "release_id": release_id,
                "system_uri": system_uri,
            }
        )
    ambiguity_rows = tuple(
        {
            "ambiguity_count_schema_version": PROTECTED_ROW_SCHEMA_VERSION,
            "ambiguous_document_count": len(stats.documents),
            "ambiguous_form_count": stats.lexical_form_count,
            "ambiguous_occurrence_count": stats.occurrence_count,
            "release_id": release_id,
            "system_uri": system_uri,
        }
        for (system_uri, release_id), stats in sorted(ambiguity.items())
    )

    # Mention-context breakdown per code. Coding counts remain lexical
    # evidence across every context; these rows say how much of that evidence
    # is affirmed, patient, and current.
    suppressed_context = 0
    context_rows: list[dict[str, JsonValue]] = []
    for (system_uri, release_id, code), stats in sorted(coding.items()):
        if len(stats.documents) < floor:
            continue
        for label in CONTEXT_LABELS:
            documents = stats.context_documents.get(label)
            if not documents:
                continue
            if len(documents) < floor:
                suppressed_context += 1
                continue
            context_rows.append(
                {
                    "code": code,
                    "context": label,
                    "context_count_schema_version": PROTECTED_ROW_SCHEMA_VERSION,
                    "document_count": len(documents),
                    "occurrence_count": stats.context_occurrences[label],
                    "release_id": release_id,
                    "system_uri": system_uri,
                }
            )

    suppressed_lexical = 0
    scrubbed_lexical = 0
    lexical_rows: list[dict[str, JsonValue]] = []
    if lexical_output_approved:
        for system_uri, release_id, code, primary, method, phrase in sorted(
            lexical, key=lambda item: (item[0], item[1], item[2], item[3])
        ):
            if not scrub_allows_form(primary):
                scrubbed_lexical += 1
                continue
            # One row per context so a synonym's trustworthiness is visible:
            # forty affirmed mentions differ from forty negated ones.
            for label in CONTEXT_LABELS:
                documents = phrase.context_documents.get(label)
                if not documents:
                    continue
                if len(documents) < floor:
                    suppressed_lexical += 1
                    continue
                lexical_rows.append(
                    {
                        "code": code,
                        "context": label,
                        "document_count": len(documents),
                        "form": primary,
                        "lexical_form_schema_version": PROTECTED_ROW_SCHEMA_VERSION,
                        "match_method": method,
                        "occurrence_count": sum(documents.values()),
                        "release_id": release_id,
                        "system_uri": system_uri,
                    }
                )

    suppressed_candidates = 0
    scrubbed_candidates = 0
    candidate_rows: list[dict[str, JsonValue]] = []
    candidates_truncated = False
    if lexical_output_approved:
        reportable: list[tuple[int, int, str, _PhraseStats]] = []
        for primary, phrase in unmapped:
            if len(phrase.documents) < floor:
                suppressed_candidates += 1
                continue
            if not _candidate_is_reportable(primary, phrase.folded):
                scrubbed_candidates += 1
                continue
            reportable.append((len(phrase.documents), phrase.occurrence_count, primary, phrase))
        reportable.sort(key=lambda item: (-item[0], -item[1], item[2]))
        if len(reportable) > limits.max_candidate_terms:
            candidates_truncated = True
            reportable = reportable[: limits.max_candidate_terms]
        for rank, (document_count, occurrence_count, primary, phrase) in enumerate(reportable, start=1):
            current = phrase.context_documents.get(CONTEXT_CURRENT_CLINICAL, {})
            candidate_rows.append(
                {
                    "candidate_term_schema_version": PROTECTED_ROW_SCHEMA_VERSION,
                    # How much of this candidate's evidence is affirmed,
                    # patient, and current — a curator's first question.
                    "current_clinical_document_count": len(current),
                    "document_count": document_count,
                    "form": primary,
                    "occurrence_count": occurrence_count,
                    "rank": rank,
                    "salience": _phrase_salience(phrase, corpus.file_count),
                    "token_count": phrase.token_count,
                }
            )

    code_documents = {
        key: stats.context_documents.get(CONTEXT_CURRENT_CLINICAL, set()) for key, stats in coding.items()
    }
    association_rows, suppressed_associations, association_documents_skipped = _association_rows(
        doc_codes, code_documents, corpus, limits
    )

    privacy: dict[str, JsonValue] = {
        "association_documents_skipped": association_documents_skipped,
        "candidate_terms_truncated": candidates_truncated,
        "lexical_output_approved": lexical_output_approved,
        "min_cell_document_count": floor,
        "scrubbed_candidate_term_count": scrubbed_candidates,
        "scrubbed_lexical_form_count": scrubbed_lexical,
        "suppressed_association_row_count": suppressed_associations,
        "suppressed_candidate_term_count": suppressed_candidates,
        "suppressed_coding_row_count": suppressed_coding,
        "suppressed_context_row_count": suppressed_context,
        "suppressed_lexical_form_count": suppressed_lexical,
    }
    return _AggregateResult(
        coding_rows=tuple(coding_rows),
        ambiguity_rows=ambiguity_rows,
        context_rows=tuple(context_rows),
        lexical_rows=tuple(lexical_rows),
        candidate_rows=tuple(candidate_rows),
        association_rows=tuple(association_rows),
        grounded_candidates_checked=grounded_candidates_checked,
        privacy=privacy,
    )


def _artifact_rows(artifacts: tuple[ArtifactDigest, ...]) -> list[dict[str, JsonValue]]:
    return [artifact.as_dict() for artifact in sorted(artifacts, key=lambda item: item.path)]


def _materialize_output(
    directory: Path,
    attestation: ProtectedAttestation,
    limits: ProtectedLimits,
    corpus: _CorpusStats,
    indexes: tuple[ProtectedExactIndex, ...],
    aggregates: _AggregateResult,
    require_nvidia: bool,
) -> dict[str, JsonValue]:
    implementation = protected_implementation_identity()
    artifact_map = {
        "ambiguity_counts.jsonl": aggregates.ambiguity_rows,
        "associations.jsonl": aggregates.association_rows,
        "candidate_terms.jsonl": aggregates.candidate_rows,
        "coding_counts.jsonl": aggregates.coding_rows,
        "context_counts.jsonl": aggregates.context_rows,
        "lexical_forms.jsonl": aggregates.lexical_rows,
    }
    artifacts = tuple(
        write_jsonl(directory, name, rows, schema_version=PROTECTED_ROW_SCHEMA_VERSION)
        for name, rows in sorted(artifact_map.items())
    )
    semantic_output_sha256 = sha256_canonical(
        {
            "ambiguity_counts": list(aggregates.ambiguity_rows),
            "associations": list(aggregates.association_rows),
            "candidate_terms": list(aggregates.candidate_rows),
            "coding_counts": list(aggregates.coding_rows),
            "context_counts": list(aggregates.context_rows),
            "lexical_forms": list(aggregates.lexical_rows),
            "schema_version": SEMANTIC_AGGREGATE_SCHEMA,
        },
        domain=b"coe.protected-aggregate.v3",
    )
    run_fingerprint = sha256_canonical(
        {
            "attestation": {
                "attestation_sha256": attestation.attestation_sha256,
                "lexical_output_approved": attestation.lexical_output_approved,
                "output_classification": attestation.output_classification,
                "profile": attestation.profile,
                "retention_policy_id": attestation.retention_policy_id,
            },
            "corpus_content_set_sha256": corpus.content_set_sha256,
            "implementation": implementation,
            "limits": limits.as_dict(),
            "semantic_output_sha256": semantic_output_sha256,
            "terminologies": [
                {"release_id": release_id, "system_uri": system_uri}
                for system_uri, release_id in (_index_identity(index) for index in indexes)
            ],
        },
        domain=FINGERPRINT_DOMAIN,
    )
    report: dict[str, JsonValue] = {
        "attestation": {
            "approval_ref_count": attestation.approval_ref_count,
            "approved": True,
            "attestation_sha256": attestation.attestation_sha256,
            "lexical_output_approved": attestation.lexical_output_approved,
            "output_classification": attestation.output_classification,
            "profile": attestation.profile,
            "retention_policy_id": attestation.retention_policy_id,
        },
        "artifacts": _artifact_rows(artifacts),
        "execution_profile": "protected_phi_local",
        "grounding": {
            "candidate_count_checked": aggregates.grounded_candidates_checked,
            "status": "passed",
        },
        "implementation": implementation,
        "limitations": list(PROTECTED_LIMITATIONS),
        "matching": {
            "context_default": CONTEXT_CURRENT_CLINICAL,
            "context_labels": list(CONTEXT_LABELS),
            "device": "cpu",
            "method": "exact_and_deterministic_variants",
            "nvidia_preflight": "passed" if require_nvidia else "not_required",
            "variant_methods": sorted(VARIANT_METHOD_PRIORITY, key=lambda item: VARIANT_METHOD_PRIORITY[item]),
        },
        "privacy": aggregates.privacy,
        "processing_totals": {
            "corpus_content_set_sha256": corpus.content_set_sha256,
            "file_count": corpus.file_count,
            "total_bytes": corpus.total_bytes,
            "total_characters": corpus.total_characters,
            "total_ngrams": corpus.total_ngrams,
            "total_tokens": corpus.total_tokens,
            "unique_form_count": len(corpus.phrases),
        },
        "resource_limits": limits.as_dict(),
        "run_fingerprint": run_fingerprint,
        "run_report_schema_version": RUN_REPORT_SCHEMA_VERSION,
        "semantic_output_sha256": semantic_output_sha256,
        "status": "succeeded",
        "terminologies": [
            {"release_id": release_id, "system_uri": system_uri}
            for system_uri, release_id in (_index_identity(index) for index in indexes)
        ],
        "totals": {
            "ambiguity_row_count": len(aggregates.ambiguity_rows),
            "association_row_count": len(aggregates.association_rows),
            "candidate_term_row_count": len(aggregates.candidate_rows),
            "coding_count_row_count": len(aggregates.coding_rows),
            "context_count_row_count": len(aggregates.context_rows),
            "lexical_form_row_count": len(aggregates.lexical_rows),
        },
    }
    write_json(directory, "run_report.json", report, schema_version=RUN_REPORT_SCHEMA_VERSION)
    return {
        "ambiguity_row_count": len(aggregates.ambiguity_rows),
        "association_row_count": len(aggregates.association_rows),
        "candidate_term_row_count": len(aggregates.candidate_rows),
        "coding_count_row_count": len(aggregates.coding_rows),
        "context_count_row_count": len(aggregates.context_rows),
        "lexical_form_row_count": len(aggregates.lexical_rows),
        "run_fingerprint": run_fingerprint,
        "semantic_output_sha256": semantic_output_sha256,
        "status": "succeeded",
    }


def _paths_overlap(first: Path, second: Path) -> bool:
    try:
        first_resolved = first.resolve(strict=False)
        second_resolved = second.resolve(strict=False)
    except OSError:
        raise ContractError("PATH_INVALID", "A protected-run path could not be resolved safely.", "output", 4) from None
    try:
        first_resolved.relative_to(second_resolved)
        return True
    except ValueError:
        pass
    try:
        second_resolved.relative_to(first_resolved)
        return True
    except ValueError:
        return False


def _index_storage_path(index: ProtectedExactIndex) -> Path | None:
    metadata = getattr(index, "metadata", None)
    value = getattr(metadata, "path", None)
    return value if isinstance(value, Path) else None


def run_protected_local(
    *,
    corpus_path: Path,
    attestation_path: Path,
    indexes: tuple[ProtectedExactIndex, ...],
    output_path: Path,
    limits: ProtectedLimits | None = None,
    require_nvidia: bool = False,
    overwrite: bool = False,
) -> dict[str, JsonValue]:
    """Analyze an approved local plaintext tree and atomically emit aggregates."""

    selected_limits = limits or ProtectedLimits()
    if output_path.exists() or output_path.is_symlink():
        if _is_reparse_or_link(output_path):
            raise ContractError("REPARSE_POINT", "The output path cannot be a link or reparse point.", "output", 4)
        if not overwrite:
            raise OutputExistsError()
        if not output_path.is_dir():
            raise ContractError("NONREGULAR", "The output path must be a directory.", "output", 4)
    protected_inputs = [("corpus", corpus_path), ("attestation", attestation_path)]
    protected_inputs.extend(
        ("terminology index", storage_path)
        for index in indexes
        if (storage_path := _index_storage_path(index)) is not None
    )
    if any(_paths_overlap(output_path, input_path) for _, input_path in protected_inputs):
        raise ContractError(
            "PATH_INVALID",
            "Protected output and every input must be bidirectionally disjoint.",
            "output",
            4,
        )

    attestation = inspect_protected_attestation(attestation_path)
    ordered_indexes = _ordered_indexes(indexes)
    if require_nvidia:
        probe_host(require_nvidia=True)
    corpus = _read_corpus(corpus_path, selected_limits)
    aggregates = _aggregate_matches(corpus, ordered_indexes, selected_limits, attestation.lexical_output_approved)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output_path.name}.tmp-", dir=output_path.parent))
    backup: Path | None = None
    try:
        summary = _materialize_output(
            temporary,
            attestation,
            selected_limits,
            corpus,
            ordered_indexes,
            aggregates,
            require_nvidia,
        )
        if output_path.exists():
            backup = output_path.parent / f".{output_path.name}.backup-{uuid.uuid4().hex}"
            os.replace(output_path, backup)
        try:
            os.replace(temporary, output_path)
        except Exception:
            if backup is not None and backup.exists() and not output_path.exists():
                os.replace(backup, output_path)
            raise
        if backup is not None:
            shutil.rmtree(backup)
        return summary
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
