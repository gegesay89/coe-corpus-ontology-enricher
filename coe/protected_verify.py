"""Fail-closed verification for protected-local aggregate output.

The verifier intentionally emits only path-free summary data and uses fixed,
sanitized errors. It establishes structural and cryptographic integrity, exact
release binding, code grounding, small-cell-floor compliance, and scrub-rule
compliance; it does not claim source-data provenance or cryptographic
authenticity.
"""

from __future__ import annotations

import errno
import hashlib
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Protocol

from coe.canonical import (
    JsonValue,
    canonical_json_line,
    load_json_bytes,
    require_exact_keys,
    sha256_canonical,
)
from coe.context import CONTEXT_CURRENT_CLINICAL, CONTEXT_LABELS
from coe.errors import ContractError
from coe.ingest.normalize import normalize_lexical
from coe.protected import (
    FINGERPRINT_DOMAIN,
    PROTECTED_ARTIFACT_FILES,
    PROTECTED_LIMITATIONS,
    PROTECTED_ROW_SCHEMA_VERSION,
    RUN_REPORT_SCHEMA_VERSION,
    ProtectedExactIndex,
    ProtectedLimits,
    _index_identity,
    _ordered_indexes,
    scrub_allows_form,
)
from coe.terminology.variants import VARIANT_METHOD_PRIORITY, grounded_lookup

_EXPECTED_FILES = frozenset(PROTECTED_ARTIFACT_FILES) | {"run_report.json"}
_MAX_TERMINOLOGY_COUNT = 7
_MAX_REPORT_BYTES = 1_048_576
_MAX_JSONL_BYTES = 8_000_000_000
_MAX_JSONL_LINE_BYTES = 16_384
_MAX_CODING_ROWS = 7_000_000
_SHA256_LENGTH = 64
_ATTESTATION_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}")
_SCORE_PATTERN = re.compile(r"^-?[0-9]+\.[0-9]{6}$")

_REPORT_KEYS = (
    "attestation",
    "artifacts",
    "execution_profile",
    "grounding",
    "implementation",
    "limitations",
    "matching",
    "privacy",
    "processing_totals",
    "resource_limits",
    "run_fingerprint",
    "run_report_schema_version",
    "semantic_output_sha256",
    "status",
    "terminologies",
    "totals",
)
_ATTESTATION_KEYS = (
    "approval_ref_count",
    "approved",
    "attestation_sha256",
    "lexical_output_approved",
    "output_classification",
    "profile",
    "retention_policy_id",
)
_ARTIFACT_KEYS = ("byte_count", "media_type", "path", "row_count", "schema_version", "sha256")
_IDENTITY_KEYS = ("release_id", "system_uri")
_GROUNDING_KEYS = ("candidate_count_checked", "status")
_MATCHING_KEYS = ("context_default", "context_labels", "device", "method", "nvidia_preflight", "variant_methods")
_IMPLEMENTATION_KEYS = ("algorithms", "coe_version", "source_sha256")
_ALGORITHM_KEYS = ("association", "context", "matching", "mining")
_PRIVACY_KEYS = (
    "association_documents_skipped",
    "candidate_terms_truncated",
    "lexical_output_approved",
    "min_cell_document_count",
    "scrubbed_candidate_term_count",
    "scrubbed_lexical_form_count",
    "suppressed_association_row_count",
    "suppressed_candidate_term_count",
    "suppressed_coding_row_count",
    "suppressed_context_row_count",
    "suppressed_lexical_form_count",
)
_PROCESSING_KEYS = (
    "corpus_content_set_sha256",
    "file_count",
    "total_bytes",
    "total_characters",
    "total_ngrams",
    "total_tokens",
    "unique_form_count",
)
_LIMIT_KEYS = (
    "max_association_codes_per_document",
    "max_association_pairs",
    "max_candidate_terms",
    "max_candidates_per_phrase_system",
    "max_file_bytes",
    "max_files",
    "max_ngram_tokens",
    "max_ngrams_per_file",
    "max_tokens_per_file",
    "max_total_bytes",
    "max_total_ngrams",
    "max_total_tokens",
    "max_unique_phrases",
    "max_walk_entries",
    "min_cell_document_count",
)
_TOTAL_KEYS = (
    "ambiguity_row_count",
    "association_row_count",
    "candidate_term_row_count",
    "coding_count_row_count",
    "context_count_row_count",
    "lexical_form_row_count",
)
_CODING_KEYS = (
    "coding_count_schema_version",
    "code",
    "distinct_matched_form_count",
    "exact_match_document_count",
    "exact_match_occurrence_count",
    "release_id",
    "system_uri",
)
_AMBIGUITY_KEYS = (
    "ambiguity_count_schema_version",
    "ambiguous_document_count",
    "ambiguous_form_count",
    "ambiguous_occurrence_count",
    "release_id",
    "system_uri",
)
_CONTEXT_KEYS = (
    "code",
    "context",
    "context_count_schema_version",
    "document_count",
    "occurrence_count",
    "release_id",
    "system_uri",
)
_LEXICAL_KEYS = (
    "code",
    "context",
    "document_count",
    "form",
    "lexical_form_schema_version",
    "match_method",
    "occurrence_count",
    "release_id",
    "system_uri",
)
_CANDIDATE_KEYS = (
    "candidate_term_schema_version",
    "current_clinical_document_count",
    "document_count",
    "form",
    "occurrence_count",
    "rank",
    "salience",
    "token_count",
)
_ASSOCIATION_KEYS = (
    "association_schema_version",
    "code_a",
    "code_b",
    "cooccurrence_document_count",
    "document_count_a",
    "document_count_b",
    "npmi",
    "release_id_a",
    "release_id_b",
    "system_uri_a",
    "system_uri_b",
)


@dataclass(frozen=True, slots=True)
class _FileIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int
    links: int


@dataclass(frozen=True, slots=True)
class _ArtifactRead:
    row_count: int
    byte_count: int
    sha256: str


class _Digest(Protocol):
    def update(self, value: bytes) -> None: ...

    def hexdigest(self) -> str: ...


def _fail(code: str, message: str, *, security: bool = False) -> ContractError:
    return ContractError(code, message, "protected_output", 4 if security else 3)


def _is_reparse_or_link(path: Path, info: os.stat_result) -> bool:
    if stat.S_ISLNK(info.st_mode):
        return True
    try:
        is_junction = getattr(path, "is_junction", None)
        if callable(is_junction) and is_junction():
            return True
    except OSError:
        raise _fail("FILE_UNREADABLE", "The protected output could not be safely inspected.", security=True) from None
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(info, "st_file_attributes", 0) & reparse_flag)


def _identity(info: os.stat_result) -> _FileIdentity:
    return _FileIdentity(info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_nlink)


def _inventory(root: Path) -> tuple[_FileIdentity, dict[str, _FileIdentity]]:
    try:
        root_info = root.lstat()
    except OSError:
        raise _fail("FILE_MISSING", "The protected output directory is unavailable.") from None
    if _is_reparse_or_link(root, root_info):
        raise _fail("REPARSE_POINT", "Links, junctions, and reparse points are forbidden.", security=True)
    if not stat.S_ISDIR(root_info.st_mode):
        raise _fail("NONREGULAR", "The protected output must be a directory.", security=True)
    try:
        with os.scandir(root) as iterator:
            entries = list(iterator)
    except OSError:
        raise _fail("FILE_UNREADABLE", "The protected output could not be safely inspected.") from None
    names = {entry.name for entry in entries}
    if len(entries) != len(names) or names != _EXPECTED_FILES:
        raise _fail("INVENTORY_INVALID", "The protected output inventory is not exact.", security=True)
    result: dict[str, _FileIdentity] = {}
    for entry in entries:
        path = root / entry.name
        try:
            info = path.lstat()
        except OSError:
            raise _fail("FILE_UNREADABLE", "A protected output artifact could not be inspected.") from None
        if _is_reparse_or_link(path, info):
            raise _fail("REPARSE_POINT", "Links, junctions, and reparse points are forbidden.", security=True)
        if not stat.S_ISREG(info.st_mode):
            raise _fail("NONREGULAR", "Protected output artifacts must be regular files.", security=True)
        if info.st_nlink != 1:
            raise _fail("HARDLINK", "Hard-linked protected output artifacts are forbidden.", security=True)
        result[entry.name] = _identity(info)
    return _identity(root_info), result


def _open_regular(path: Path, maximum: int) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise _fail("REPARSE_POINT", "Links, junctions, and reparse points are forbidden.", security=True) from None
        raise _fail("FILE_UNREADABLE", "A protected output artifact could not be opened.") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise _fail("NONREGULAR", "Protected output artifacts must be regular files.", security=True)
        if info.st_nlink != 1:
            raise _fail("HARDLINK", "Hard-linked protected output artifacts are forbidden.", security=True)
        if info.st_size > maximum:
            raise _fail("RESOURCE_LIMIT", "A protected output artifact exceeds its verification limit.", security=True)
        return descriptor, info
    except Exception:
        os.close(descriptor)
        raise


def _confirm_stable(path: Path, descriptor: int, before: os.stat_result) -> None:
    try:
        after = os.fstat(descriptor)
        path_after = path.lstat()
    except OSError:
        raise _fail("FILE_CHANGED", "A protected output artifact changed during verification.", security=True) from None
    if (
        _is_reparse_or_link(path, path_after)
        or _identity(before) != _identity(after)
        or (
            path_after.st_dev,
            path_after.st_ino,
        )
        != (before.st_dev, before.st_ino)
    ):
        raise _fail("FILE_CHANGED", "A protected output artifact changed during verification.", security=True)


def _load_json_safely(raw: bytes) -> JsonValue:
    try:
        return load_json_bytes(raw, "protected_output")
    except ContractError:
        raise
    except Exception:
        raise _fail("SCHEMA_INVALID", "A protected output JSON value is malformed.") from None


def _read_report(path: Path) -> dict[str, JsonValue]:
    descriptor, before = _open_regular(path, _MAX_REPORT_BYTES)
    try:
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(_MAX_REPORT_BYTES + 1)
        if len(raw) > _MAX_REPORT_BYTES:
            raise _fail("RESOURCE_LIMIT", "The protected run report exceeds its verification limit.", security=True)
        _confirm_stable(path, descriptor, before)
    finally:
        os.close(descriptor)
    value = _load_json_safely(raw)
    if not isinstance(value, dict):
        raise _fail("SCHEMA_INVALID", "The protected run report must be an object.")
    try:
        canonical = canonical_json_line(value)
    except Exception:
        raise _fail("SCHEMA_INVALID", "The protected run report contains an invalid JSON value.") from None
    if raw != canonical:
        raise _fail("CANONICALIZATION_FAILED", "The protected run report is not canonically encoded.")
    return value


def _read_jsonl(
    path: Path,
    *,
    maximum_rows: int,
    validator: _RowValidator,
    semantic_digest: _Digest,
) -> _ArtifactRead:
    descriptor, before = _open_regular(path, _MAX_JSONL_BYTES)
    digest = hashlib.sha256()
    try:
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            row_count, byte_count = _consume_jsonl(
                handle,
                digest,
                semantic_digest,
                validator,
                maximum_rows,
            )
        _confirm_stable(path, descriptor, before)
    finally:
        os.close(descriptor)
    return _ArtifactRead(row_count, byte_count, digest.hexdigest())


class _RowValidator(Protocol):
    def accept(self, value: dict[str, JsonValue]) -> None: ...


def _consume_jsonl(
    handle: BinaryIO,
    digest: _Digest,
    semantic_digest: _Digest,
    validator: _RowValidator,
    maximum_rows: int,
) -> tuple[int, int]:
    row_count = 0
    byte_count = 0
    while True:
        raw = handle.readline(_MAX_JSONL_LINE_BYTES + 1)
        if not raw:
            return row_count, byte_count
        if len(raw) > _MAX_JSONL_LINE_BYTES:
            raise _fail("RESOURCE_LIMIT", "A protected output row exceeds its verification limit.", security=True)
        if not raw.endswith(b"\n"):
            raise _fail("SCHEMA_INVALID", "Every protected output row must end with a newline.")
        if row_count >= maximum_rows:
            raise _fail("RESOURCE_LIMIT", "A protected output artifact exceeds its row limit.", security=True)
        value = _load_json_safely(raw[:-1])
        if not isinstance(value, dict):
            raise _fail("SCHEMA_INVALID", "Every protected output row must be an object.")
        try:
            canonical = canonical_json_line(value)
        except Exception:
            raise _fail("SCHEMA_INVALID", "A protected output row contains an invalid JSON value.") from None
        if raw != canonical:
            raise _fail("CANONICALIZATION_FAILED", "A protected output row is not canonically encoded.")
        validator.accept(value)
        digest.update(raw)
        if row_count:
            semantic_digest.update(b",")
        semantic_digest.update(raw[:-1])
        row_count += 1
        byte_count += len(raw)


def _object(value: JsonValue, keys: tuple[str, ...]) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise _fail("SCHEMA_INVALID", "A protected output object has an invalid type.")
    require_exact_keys(value, keys, (), "protected_output")
    return value


def _array(value: JsonValue, *, length: int | None = None) -> list[JsonValue]:
    if not isinstance(value, list) or (length is not None and len(value) != length):
        raise _fail("SCHEMA_INVALID", "A protected output array has an invalid shape.")
    return value


def _string(value: JsonValue, *, maximum: int, expected: str | None = None) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
        or (expected is not None and value != expected)
    ):
        raise _fail("SCHEMA_INVALID", "A protected output string is invalid.")
    return value


def _integer(value: JsonValue, *, minimum: int = 0, maximum: int | None = None) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or (maximum is not None and value > maximum)
    ):
        raise _fail("SCHEMA_INVALID", "A protected output integer is outside its allowed range.")
    return value


def _boolean(value: JsonValue) -> bool:
    if not isinstance(value, bool):
        raise _fail("SCHEMA_INVALID", "A protected output boolean is invalid.")
    return value


def _score(value: JsonValue) -> str:
    text = _string(value, maximum=32)
    if _SCORE_PATTERN.fullmatch(text) is None:
        raise _fail("SCHEMA_INVALID", "A protected output score is not a fixed-precision decimal.")
    return text


def _digest_value(value: JsonValue) -> str:
    digest = _string(value, maximum=_SHA256_LENGTH)
    if len(digest) != _SHA256_LENGTH or any(character not in "0123456789abcdef" for character in digest):
        raise _fail("SCHEMA_INVALID", "A protected output digest is invalid.")
    return digest


def _identity_object(value: JsonValue) -> tuple[str, str]:
    item = _object(value, _IDENTITY_KEYS)
    system_uri = _string(item["system_uri"], maximum=2_048)
    release_id = _string(item["release_id"], maximum=2_048)
    return system_uri, release_id


def _validate_report(
    report: dict[str, JsonValue], expected_identities: tuple[tuple[str, str], ...]
) -> tuple[ProtectedLimits, dict[str, JsonValue], dict[str, JsonValue], dict[str, JsonValue]]:
    require_exact_keys(report, _REPORT_KEYS, (), "protected_output")
    _string(report["run_report_schema_version"], maximum=64, expected=RUN_REPORT_SCHEMA_VERSION)
    _string(report["status"], maximum=16, expected="succeeded")
    _string(report["execution_profile"], maximum=64, expected="protected_phi_local")
    _digest_value(report["run_fingerprint"])
    _digest_value(report["semantic_output_sha256"])

    attestation = _object(report["attestation"], _ATTESTATION_KEYS)
    if attestation["approved"] is not True:
        raise _fail("SCHEMA_INVALID", "The protected output approval state is invalid.")
    _integer(attestation["approval_ref_count"], minimum=2, maximum=3)
    _digest_value(attestation["attestation_sha256"])
    lexical_output_approved = _boolean(attestation["lexical_output_approved"])
    _string(attestation["output_classification"], maximum=64, expected="protected_aggregate")
    _string(attestation["profile"], maximum=64, expected="protected_phi_local")
    retention_policy_id = _string(attestation["retention_policy_id"], maximum=256)
    if _ATTESTATION_IDENTIFIER.fullmatch(retention_policy_id) is None:
        raise _fail("SCHEMA_INVALID", "The protected output retention-policy identifier is invalid.")

    terminology_values = _array(report["terminologies"])
    if len(terminology_values) != len(expected_identities):
        raise _fail("TERMINOLOGY_MISMATCH", "The protected output is not bound to the supplied releases.")
    identities = tuple(_identity_object(item) for item in terminology_values)
    if identities != expected_identities:
        raise _fail("TERMINOLOGY_MISMATCH", "The protected output is not bound to the supplied releases.")

    limitations = _array(report["limitations"], length=len(PROTECTED_LIMITATIONS))
    if tuple(limitations) != PROTECTED_LIMITATIONS:
        raise _fail("SCHEMA_INVALID", "The protected output limitations are not the required exact statements.")

    implementation = _object(report["implementation"], _IMPLEMENTATION_KEYS)
    _string(implementation["coe_version"], maximum=64)
    _digest_value(implementation["source_sha256"])
    algorithms = _object(implementation["algorithms"], _ALGORITHM_KEYS)
    for key in _ALGORITHM_KEYS:
        _string(algorithms[key], maximum=128)

    matching = _object(report["matching"], _MATCHING_KEYS)
    _string(matching["device"], maximum=16, expected="cpu")
    _string(matching["method"], maximum=64, expected="exact_and_deterministic_variants")
    nvidia = _string(matching["nvidia_preflight"], maximum=32)
    if nvidia not in {"not_required", "passed"}:
        raise _fail("SCHEMA_INVALID", "The protected output hardware preflight state is invalid.")
    expected_methods = sorted(VARIANT_METHOD_PRIORITY, key=lambda item: VARIANT_METHOD_PRIORITY[item])
    if matching["variant_methods"] != expected_methods:
        raise _fail("SCHEMA_INVALID", "The protected output variant-method list is invalid.")
    _string(matching["context_default"], maximum=64, expected=CONTEXT_CURRENT_CLINICAL)
    if matching["context_labels"] != list(CONTEXT_LABELS):
        raise _fail("SCHEMA_INVALID", "The protected output context-label list is invalid.")

    limit_values = _object(report["resource_limits"], _LIMIT_KEYS)
    try:
        limits = ProtectedLimits(**{key: _integer(limit_values[key], minimum=1) for key in _LIMIT_KEYS})
    except TypeError:
        raise _fail("SCHEMA_INVALID", "The protected output resource limits are invalid.") from None

    privacy = _object(report["privacy"], _PRIVACY_KEYS)
    if _boolean(privacy["lexical_output_approved"]) != lexical_output_approved:
        raise _fail("SCHEMA_INVALID", "The protected output lexical approval states disagree.")
    if _integer(privacy["min_cell_document_count"], minimum=1) != limits.min_cell_document_count:
        raise _fail("SCHEMA_INVALID", "The protected output small-cell floors disagree.")
    _boolean(privacy["candidate_terms_truncated"])
    for key in (
        "association_documents_skipped",
        "scrubbed_candidate_term_count",
        "scrubbed_lexical_form_count",
        "suppressed_association_row_count",
        "suppressed_candidate_term_count",
        "suppressed_coding_row_count",
        "suppressed_context_row_count",
        "suppressed_lexical_form_count",
    ):
        _integer(privacy[key])

    processing = _object(report["processing_totals"], _PROCESSING_KEYS)
    _digest_value(processing["corpus_content_set_sha256"])
    _integer(processing["file_count"], minimum=1, maximum=limits.max_files)
    total_bytes = _integer(processing["total_bytes"], maximum=limits.max_total_bytes)
    _integer(processing["total_characters"], maximum=total_bytes)
    total_tokens = _integer(processing["total_tokens"], maximum=limits.max_total_tokens)
    total_ngrams = _integer(processing["total_ngrams"], maximum=limits.max_total_ngrams)
    unique_forms = _integer(processing["unique_form_count"], maximum=limits.max_unique_phrases)
    if total_tokens > total_ngrams or unique_forms > total_ngrams:
        raise _fail("TOTALS_INVALID", "The protected output processing totals are inconsistent.")

    grounding = _object(report["grounding"], _GROUNDING_KEYS)
    _string(grounding["status"], maximum=16, expected="passed")
    _integer(
        grounding["candidate_count_checked"],
        maximum=unique_forms * len(expected_identities) * limits.max_candidates_per_phrase_system,
    )

    totals = _object(report["totals"], _TOTAL_KEYS)
    _integer(totals["ambiguity_row_count"], maximum=len(expected_identities))
    _integer(totals["coding_count_row_count"], maximum=min(_MAX_CODING_ROWS, unique_forms * 7))
    _integer(
        totals["lexical_form_row_count"],
        maximum=unique_forms * len(expected_identities) * len(CONTEXT_LABELS),
    )
    _integer(
        totals["context_count_row_count"],
        maximum=min(_MAX_CODING_ROWS, unique_forms * 7) * len(CONTEXT_LABELS),
    )
    _integer(totals["candidate_term_row_count"], maximum=min(limits.max_candidate_terms, unique_forms))
    _integer(totals["association_row_count"], maximum=limits.max_association_pairs)
    if not lexical_output_approved and (
        totals["lexical_form_row_count"] != 0 or totals["candidate_term_row_count"] != 0
    ):
        raise _fail("SCHEMA_INVALID", "Lexical rows are present without lexical output approval.")

    artifacts = _array(report["artifacts"], length=len(PROTECTED_ARTIFACT_FILES))
    parsed_artifacts: dict[str, dict[str, JsonValue]] = {}
    for value in artifacts:
        artifact = _object(value, _ARTIFACT_KEYS)
        path = _string(artifact["path"], maximum=64)
        if path not in PROTECTED_ARTIFACT_FILES or path in parsed_artifacts:
            raise _fail("SCHEMA_INVALID", "The protected output artifact manifest is invalid.")
        _string(artifact["media_type"], maximum=64, expected="application/x-ndjson")
        _string(artifact["schema_version"], maximum=16, expected=PROTECTED_ROW_SCHEMA_VERSION)
        _integer(artifact["byte_count"], maximum=_MAX_JSONL_BYTES)
        _integer(artifact["row_count"], maximum=_MAX_CODING_ROWS)
        _digest_value(artifact["sha256"])
        parsed_artifacts[path] = artifact
    if [str(_object(item, _ARTIFACT_KEYS)["path"]) for item in artifacts] != list(PROTECTED_ARTIFACT_FILES):
        raise _fail("SCHEMA_INVALID", "The protected output artifact manifest order is invalid.")
    return limits, processing, parsed_artifacts, privacy


@dataclass(slots=True)
class _CodingValidator:
    identity_indexes: dict[tuple[str, str], ProtectedExactIndex]
    file_count: int
    total_ngrams: int
    unique_forms: int
    floor: int
    previous: tuple[str, str, str] | None = None
    form_count: int = 0
    documents: dict[tuple[str, str, str], int] = field(default_factory=dict)

    def accept(self, value: dict[str, JsonValue]) -> None:
        row = _object(value, _CODING_KEYS)
        _string(row["coding_count_schema_version"], maximum=16, expected=PROTECTED_ROW_SCHEMA_VERSION)
        identity = _identity_object({"release_id": row["release_id"], "system_uri": row["system_uri"]})
        code = _string(row["code"], maximum=128)
        key = (*identity, code)
        if identity not in self.identity_indexes or (self.previous is not None and key <= self.previous):
            raise _fail("GROUNDING_FAILED", "A protected coding row has invalid release grounding or order.")
        form_count = _integer(row["distinct_matched_form_count"], minimum=1, maximum=self.unique_forms)
        document_count = _integer(row["exact_match_document_count"], minimum=self.floor, maximum=self.file_count)
        occurrence_count = _integer(row["exact_match_occurrence_count"], minimum=1, maximum=self.total_ngrams)
        if form_count > occurrence_count or document_count > occurrence_count:
            raise _fail("TOTALS_INVALID", "A protected coding row contains inconsistent counts.")
        try:
            grounded = code in self.identity_indexes[identity].reference.code_catalog
        except Exception:
            raise _fail("GROUNDING_FAILED", "A protected coding row could not be grounded.") from None
        if not grounded:
            raise _fail("GROUNDING_FAILED", "A protected coding row is outside the supplied release.")
        self.form_count += form_count
        self.documents[key] = document_count
        self.previous = key


@dataclass(slots=True)
class _AmbiguityValidator:
    expected_identities: tuple[tuple[str, str], ...]
    file_count: int
    total_ngrams: int
    unique_forms: int
    identities: list[tuple[str, str]] = field(default_factory=list)
    form_count: int = 0

    def accept(self, value: dict[str, JsonValue]) -> None:
        row = _object(value, _AMBIGUITY_KEYS)
        _string(row["ambiguity_count_schema_version"], maximum=16, expected=PROTECTED_ROW_SCHEMA_VERSION)
        identity = _identity_object({"release_id": row["release_id"], "system_uri": row["system_uri"]})
        self.identities.append(identity)
        form_count = _integer(row["ambiguous_form_count"], maximum=self.unique_forms)
        document_count = _integer(row["ambiguous_document_count"], maximum=self.file_count)
        occurrence_count = _integer(row["ambiguous_occurrence_count"], maximum=self.total_ngrams)
        if (form_count == 0) != (document_count == 0) or (form_count == 0) != (occurrence_count == 0):
            raise _fail("TOTALS_INVALID", "A protected ambiguity row contains inconsistent zero counts.")
        if form_count > occurrence_count or document_count > occurrence_count:
            raise _fail("TOTALS_INVALID", "A protected ambiguity row contains inconsistent counts.")
        self.form_count += form_count

    def finish(self) -> None:
        if tuple(self.identities) != self.expected_identities:
            raise _fail("GROUNDING_FAILED", "Protected ambiguity rows do not match the supplied releases.")


@dataclass(slots=True)
class _ContextValidator:
    """Verify the mention-context breakdown against the coding rows."""

    identity_indexes: dict[tuple[str, str], ProtectedExactIndex]
    file_count: int
    total_ngrams: int
    floor: int
    previous: tuple[str, str, str, str] | None = None
    documents: dict[tuple[str, str, str], int] = field(default_factory=dict)
    occurrences: dict[tuple[str, str, str], int] = field(default_factory=dict)
    current_documents: dict[tuple[str, str, str], int] = field(default_factory=dict)

    def accept(self, value: dict[str, JsonValue]) -> None:
        row = _object(value, _CONTEXT_KEYS)
        _string(row["context_count_schema_version"], maximum=16, expected=PROTECTED_ROW_SCHEMA_VERSION)
        identity = _identity_object({"release_id": row["release_id"], "system_uri": row["system_uri"]})
        code = _string(row["code"], maximum=128)
        label = _string(row["context"], maximum=32)
        if label not in CONTEXT_LABELS:
            raise _fail("SCHEMA_INVALID", "A protected context row has an unknown context label.")
        key = (*identity, code, label)
        if identity not in self.identity_indexes or (self.previous is not None and key <= self.previous):
            raise _fail("GROUNDING_FAILED", "A protected context row has invalid release grounding or order.")
        document_count = _integer(row["document_count"], minimum=self.floor, maximum=self.file_count)
        occurrence_count = _integer(row["occurrence_count"], minimum=1, maximum=self.total_ngrams)
        if document_count > occurrence_count:
            raise _fail("TOTALS_INVALID", "A protected context row contains inconsistent counts.")
        try:
            grounded = code in self.identity_indexes[identity].reference.code_catalog
        except Exception:
            raise _fail("GROUNDING_FAILED", "A protected context row could not be grounded.") from None
        if not grounded:
            raise _fail("GROUNDING_FAILED", "A protected context row is outside the supplied release.")
        code_key = (*identity, code)
        self.documents[code_key] = max(self.documents.get(code_key, 0), document_count)
        self.occurrences[code_key] = self.occurrences.get(code_key, 0) + occurrence_count
        if label == CONTEXT_CURRENT_CLINICAL:
            self.current_documents[code_key] = document_count
        self.previous = key

    def reconcile(self, coding_documents: dict[tuple[str, str, str], int]) -> None:
        # Contexts partition a code's occurrences, so each context count is
        # bounded by the code's totals and the per-code sum cannot exceed them.
        for code_key, document_count in self.documents.items():
            total = coding_documents.get(code_key)
            if total is None:
                raise _fail("TOTALS_INVALID", "A protected context row references a missing coding row.")
            if document_count > total:
                raise _fail("TOTALS_INVALID", "A protected context row exceeds its coding document count.")


@dataclass(slots=True)
class _LexicalValidator:
    identity_indexes: dict[tuple[str, str], ProtectedExactIndex]
    file_count: int
    total_ngrams: int
    floor: int
    approved: bool
    previous: tuple[str, str, str, str, str] | None = None

    def accept(self, value: dict[str, JsonValue]) -> None:
        if not self.approved:
            raise _fail("SCHEMA_INVALID", "Lexical rows are present without lexical output approval.")
        row = _object(value, _LEXICAL_KEYS)
        _string(row["lexical_form_schema_version"], maximum=16, expected=PROTECTED_ROW_SCHEMA_VERSION)
        identity = _identity_object({"release_id": row["release_id"], "system_uri": row["system_uri"]})
        code = _string(row["code"], maximum=128)
        form = _string(row["form"], maximum=256)
        if not scrub_allows_form(form):
            raise _fail("PRIVACY_INVALID", "A protected lexical form violates the scrub rules.", security=True)
        method = _string(row["match_method"], maximum=64)
        if method not in VARIANT_METHOD_PRIORITY:
            raise _fail("SCHEMA_INVALID", "A protected lexical row has an unknown match method.")
        label = _string(row["context"], maximum=32)
        if label not in CONTEXT_LABELS:
            raise _fail("SCHEMA_INVALID", "A protected lexical row has an unknown context label.")
        key = (*identity, code, form, label)
        if identity not in self.identity_indexes or (self.previous is not None and key <= self.previous):
            raise _fail("GROUNDING_FAILED", "A protected lexical row has invalid release grounding or order.")
        document_count = _integer(row["document_count"], minimum=self.floor, maximum=self.file_count)
        occurrence_count = _integer(row["occurrence_count"], minimum=1, maximum=self.total_ngrams)
        if document_count > occurrence_count:
            raise _fail("TOTALS_INVALID", "A protected lexical row contains inconsistent counts.")
        try:
            grounded = code in self.identity_indexes[identity].reference.code_catalog
        except Exception:
            raise _fail("GROUNDING_FAILED", "A protected lexical row could not be grounded.") from None
        if not grounded:
            raise _fail("GROUNDING_FAILED", "A protected lexical row is outside the supplied release.")
        self.previous = key


@dataclass(slots=True)
class _CandidateValidator:
    indexes: tuple[ProtectedExactIndex, ...]
    file_count: int
    total_ngrams: int
    floor: int
    approved: bool
    max_ngram_tokens: int
    previous_rank: int = 0

    def accept(self, value: dict[str, JsonValue]) -> None:
        if not self.approved:
            raise _fail("SCHEMA_INVALID", "Candidate rows are present without lexical output approval.")
        row = _object(value, _CANDIDATE_KEYS)
        _string(row["candidate_term_schema_version"], maximum=16, expected=PROTECTED_ROW_SCHEMA_VERSION)
        form = _string(row["form"], maximum=256)
        if not scrub_allows_form(form):
            raise _fail("PRIVACY_INVALID", "A protected candidate term violates the scrub rules.", security=True)
        rank = _integer(row["rank"], minimum=1)
        if rank != self.previous_rank + 1:
            raise _fail("SCHEMA_INVALID", "Protected candidate ranks must be dense and increasing.")
        document_count = _integer(row["document_count"], minimum=self.floor, maximum=self.file_count)
        occurrence_count = _integer(row["occurrence_count"], minimum=1, maximum=self.total_ngrams)
        if document_count > occurrence_count:
            raise _fail("TOTALS_INVALID", "A protected candidate row contains inconsistent counts.")
        _integer(row["current_clinical_document_count"], maximum=document_count)
        _integer(row["token_count"], minimum=1, maximum=self.max_ngram_tokens)
        _score(row["salience"])
        folded = normalize_lexical(form).folded
        for index in self.indexes:
            try:
                if grounded_lookup(index, form, folded):
                    raise _fail(
                        "GROUNDING_FAILED",
                        "A protected candidate term is grounded and must not be a candidate.",
                    )
            except ContractError:
                raise
            except Exception:
                raise _fail("GROUNDING_FAILED", "A protected candidate term could not be checked.") from None
        self.previous_rank = rank


@dataclass(slots=True)
class _AssociationValidator:
    identity_indexes: dict[tuple[str, str], ProtectedExactIndex]
    file_count: int
    floor: int
    coding_documents: dict[tuple[str, str, str], int]
    previous: tuple[str, str, str, str, str, str] | None = None

    def accept(self, value: dict[str, JsonValue]) -> None:
        row = _object(value, _ASSOCIATION_KEYS)
        _string(row["association_schema_version"], maximum=16, expected=PROTECTED_ROW_SCHEMA_VERSION)
        first = (
            _string(row["system_uri_a"], maximum=2_048),
            _string(row["release_id_a"], maximum=2_048),
            _string(row["code_a"], maximum=128),
        )
        second = (
            _string(row["system_uri_b"], maximum=2_048),
            _string(row["release_id_b"], maximum=2_048),
            _string(row["code_b"], maximum=128),
        )
        if first >= second:
            raise _fail("SCHEMA_INVALID", "A protected association row is not canonically ordered.")
        key = first + second
        if self.previous is not None and key <= self.previous:
            raise _fail("SCHEMA_INVALID", "Protected association rows are not canonically sorted.")
        together = _integer(row["cooccurrence_document_count"], minimum=self.floor, maximum=self.file_count)
        count_a = _integer(row["document_count_a"], minimum=together, maximum=self.file_count)
        count_b = _integer(row["document_count_b"], minimum=together, maximum=self.file_count)
        _score(row["npmi"])
        for identity_code, document_count in ((first, count_a), (second, count_b)):
            identity = (identity_code[0], identity_code[1])
            index = self.identity_indexes.get(identity)
            if index is None:
                raise _fail("GROUNDING_FAILED", "A protected association row names an unknown release.")
            try:
                grounded = identity_code[2] in index.reference.code_catalog
            except Exception:
                raise _fail("GROUNDING_FAILED", "A protected association row could not be grounded.") from None
            if not grounded:
                raise _fail("GROUNDING_FAILED", "A protected association row is outside the supplied release.")
            known = self.coding_documents.get(identity_code)
            if known is not None and document_count > known:
                raise _fail("TOTALS_INVALID", "A protected association row exceeds its coding document count.")
        self.previous = key


def _verify_artifact_metadata(
    artifacts: dict[str, dict[str, JsonValue]],
    name: str,
    actual: _ArtifactRead,
) -> None:
    claimed = artifacts[name]
    if (
        claimed["row_count"] != actual.row_count
        or claimed["byte_count"] != actual.byte_count
        or claimed["sha256"] != actual.sha256
    ):
        raise _fail("ARTIFACT_INTEGRITY_FAILED", "A protected output artifact does not match its manifest.")


def verify_protected_output(
    *,
    output_path: Path,
    indexes: tuple[ProtectedExactIndex, ...],
) -> dict[str, JsonValue]:
    """Verify one protected-local output directory against its index releases."""

    ordered_indexes = _ordered_indexes(indexes)
    if not 1 <= len(ordered_indexes) <= _MAX_TERMINOLOGY_COUNT:
        raise _fail("TERMINOLOGY_MISMATCH", "Between one and seven distinct terminology releases are required.")
    expected_identities = tuple(_index_identity(index) for index in ordered_indexes)
    identity_indexes = {identity: index for identity, index in zip(expected_identities, ordered_indexes, strict=True)}

    root_before, inventory_before = _inventory(output_path)
    report = _read_report(output_path / "run_report.json")
    limits, processing, artifacts, privacy = _validate_report(report, expected_identities)
    file_count = int(processing["file_count"])
    total_ngrams = int(processing["total_ngrams"])
    unique_forms = int(processing["unique_form_count"])
    floor = limits.min_cell_document_count
    approved = bool(privacy["lexical_output_approved"])

    semantic_digest = hashlib.sha256()
    semantic_digest.update(b'coe.protected-aggregate.v3\0{"ambiguity_counts":[')
    ambiguity_validator = _AmbiguityValidator(
        expected_identities=expected_identities,
        file_count=file_count,
        total_ngrams=total_ngrams,
        unique_forms=unique_forms,
    )
    ambiguity = _read_jsonl(
        output_path / "ambiguity_counts.jsonl",
        maximum_rows=len(expected_identities),
        validator=ambiguity_validator,
        semantic_digest=semantic_digest,
    )
    ambiguity_validator.finish()

    coding_documents: dict[tuple[str, str, str], int] = {}
    semantic_digest.update(b'],"associations":[')
    association_validator = _AssociationValidator(
        identity_indexes=identity_indexes,
        file_count=file_count,
        floor=floor,
        coding_documents=coding_documents,
    )
    # Association rows are structurally validated during streaming; the
    # coding-document cross-check runs after coding rows are read below,
    # using this compact record of each row's identity/count fields.
    association_rows: list[tuple[tuple[str, str, str], int, tuple[str, str, str], int, int]] = []

    class _AssociationCollector:
        def accept(self, value: dict[str, JsonValue]) -> None:
            association_validator.accept(value)
            association_rows.append(
                (
                    (str(value["system_uri_a"]), str(value["release_id_a"]), str(value["code_a"])),
                    int(value["document_count_a"]),  # type: ignore[arg-type]
                    (str(value["system_uri_b"]), str(value["release_id_b"]), str(value["code_b"])),
                    int(value["document_count_b"]),  # type: ignore[arg-type]
                    int(value["cooccurrence_document_count"]),  # type: ignore[arg-type]
                )
            )

    association = _read_jsonl(
        output_path / "associations.jsonl",
        maximum_rows=limits.max_association_pairs,
        validator=_AssociationCollector(),
        semantic_digest=semantic_digest,
    )

    semantic_digest.update(b'],"candidate_terms":[')
    candidate_validator = _CandidateValidator(
        indexes=ordered_indexes,
        file_count=file_count,
        total_ngrams=total_ngrams,
        floor=floor,
        approved=approved,
        max_ngram_tokens=limits.max_ngram_tokens,
    )
    candidate = _read_jsonl(
        output_path / "candidate_terms.jsonl",
        maximum_rows=min(limits.max_candidate_terms, max(unique_forms, 1)),
        validator=candidate_validator,
        semantic_digest=semantic_digest,
    )

    semantic_digest.update(b'],"coding_counts":[')
    coding_maximum = min(_MAX_CODING_ROWS, unique_forms * 7)
    coding_validator = _CodingValidator(
        identity_indexes=identity_indexes,
        file_count=file_count,
        total_ngrams=total_ngrams,
        unique_forms=unique_forms,
        floor=floor,
    )
    coding = _read_jsonl(
        output_path / "coding_counts.jsonl",
        maximum_rows=coding_maximum,
        validator=coding_validator,
        semantic_digest=semantic_digest,
    )
    coding_documents.update(coding_validator.documents)

    semantic_digest.update(b'],"context_counts":[')
    context_validator = _ContextValidator(
        identity_indexes=identity_indexes,
        file_count=file_count,
        total_ngrams=total_ngrams,
        floor=floor,
    )
    context = _read_jsonl(
        output_path / "context_counts.jsonl",
        maximum_rows=coding_maximum * len(CONTEXT_LABELS),
        validator=context_validator,
        semantic_digest=semantic_digest,
    )
    context_validator.reconcile(coding_documents)

    semantic_digest.update(b'],"lexical_forms":[')
    lexical_validator = _LexicalValidator(
        identity_indexes=identity_indexes,
        file_count=file_count,
        total_ngrams=total_ngrams,
        floor=floor,
        approved=approved,
    )
    lexical = _read_jsonl(
        output_path / "lexical_forms.jsonl",
        maximum_rows=unique_forms * len(expected_identities) * len(CONTEXT_LABELS) if unique_forms else 1,
        validator=lexical_validator,
        semantic_digest=semantic_digest,
    )
    semantic_digest.update(b'],"schema_version":"coe-protected-aggregate-v3"}')

    for name, actual in (
        ("ambiguity_counts.jsonl", ambiguity),
        ("associations.jsonl", association),
        ("candidate_terms.jsonl", candidate),
        ("coding_counts.jsonl", coding),
        ("context_counts.jsonl", context),
        ("lexical_forms.jsonl", lexical),
    ):
        _verify_artifact_metadata(artifacts, name, actual)

    for first, count_a, second, count_b, _together in association_rows:
        for identity_code, claimed in ((first, count_a), (second, count_b)):
            known = coding_documents.get(identity_code)
            if known is not None and claimed > known:
                raise _fail("TOTALS_INVALID", "A protected association row exceeds its coding document count.")
            if known is None and claimed >= floor:
                # A code may appear in associations without a coding row only
                # when its own document count sits below the small-cell floor.
                raise _fail("TOTALS_INVALID", "A protected association row references a missing coding row.")
            # Associations are current-clinical only, so a claimed count must
            # agree with the current-clinical context row when one exists.
            current = context_validator.current_documents.get(identity_code)
            if current is not None and claimed != current:
                raise _fail("TOTALS_INVALID", "A protected association row disagrees with its context counts.")

    totals = _object(report["totals"], _TOTAL_KEYS)
    if totals != {
        "ambiguity_row_count": ambiguity.row_count,
        "association_row_count": association.row_count,
        "candidate_term_row_count": candidate.row_count,
        "coding_count_row_count": coding.row_count,
        "context_count_row_count": context.row_count,
        "lexical_form_row_count": lexical.row_count,
    }:
        raise _fail("TOTALS_INVALID", "The protected output report row totals are inconsistent.")

    exact_forms = coding_validator.form_count
    ambiguous_forms = ambiguity_validator.form_count
    grounding = _object(report["grounding"], _GROUNDING_KEYS)
    candidates_checked = int(grounding["candidate_count_checked"])
    # Suppressed coding rows still contributed grounded candidates at run
    # time, so the exact interval only holds when nothing was suppressed.
    if int(privacy["suppressed_coding_row_count"]) == 0:
        minimum_candidates = exact_forms + (2 * ambiguous_forms)
        maximum_candidates = exact_forms + (limits.max_candidates_per_phrase_system * ambiguous_forms)
        if not minimum_candidates <= candidates_checked <= maximum_candidates:
            raise _fail("TOTALS_INVALID", "The protected output grounding total is inconsistent.")

    semantic_output_sha256 = semantic_digest.hexdigest()
    if report["semantic_output_sha256"] != semantic_output_sha256:
        raise _fail("SEMANTIC_INTEGRITY_FAILED", "The protected semantic output digest is invalid.")

    attestation = _object(report["attestation"], _ATTESTATION_KEYS)
    run_fingerprint = sha256_canonical(
        {
            "attestation": {
                "attestation_sha256": attestation["attestation_sha256"],
                "lexical_output_approved": attestation["lexical_output_approved"],
                "output_classification": attestation["output_classification"],
                "profile": attestation["profile"],
                "retention_policy_id": attestation["retention_policy_id"],
            },
            "corpus_content_set_sha256": processing["corpus_content_set_sha256"],
            "implementation": report["implementation"],
            "limits": limits.as_dict(),
            "semantic_output_sha256": semantic_output_sha256,
            "terminologies": [
                {"release_id": release_id, "system_uri": system_uri} for system_uri, release_id in expected_identities
            ],
        },
        domain=FINGERPRINT_DOMAIN,
    )
    if report["run_fingerprint"] != run_fingerprint:
        raise _fail("RUN_INTEGRITY_FAILED", "The protected run fingerprint is invalid.")

    root_after, inventory_after = _inventory(output_path)
    if root_before != root_after or inventory_before != inventory_after:
        raise _fail("FILE_CHANGED", "The protected output changed during verification.", security=True)

    return {
        "ambiguity_row_count": ambiguity.row_count,
        "association_row_count": association.row_count,
        "candidate_term_row_count": candidate.row_count,
        "coding_count_row_count": coding.row_count,
        "context_count_row_count": context.row_count,
        "lexical_form_row_count": lexical.row_count,
        "run_fingerprint": run_fingerprint,
        "semantic_output_sha256": semantic_output_sha256,
        "status": "passed",
        "terminology_count": len(expected_identities),
        "verification_schema_version": "protected-output-verification-1.2.0",
    }
