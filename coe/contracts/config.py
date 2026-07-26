"""Semantic v0 analysis configuration and cross-contract validation."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from coe.canonical import (
    JsonValue,
    check_sha256,
    load_json,
    require_bool,
    require_exact_keys,
    require_int,
    require_object,
    require_string,
    sha256_canonical,
)
from coe.contracts.reference import ReferenceBundle
from coe.contracts.report import Issue, PreflightReport
from coe.contracts.snapshot import SnapshotBundle
from coe.errors import ContractError

MAX_DOCUMENTS = 10_000
MAX_SNAPSHOT_BYTES = 100_000_000
MAX_DOCUMENT_BYTES = 10_000_000
MAX_TOKENS_PER_DOCUMENT = 250_000
MAX_NGRAMS_PER_DOCUMENT = 1_000_000
MAX_UNIQUE_PHRASES = 1_000_000
MAX_OUTPUT_RECORDS = 2_000_000
MAX_EXACT_CANDIDATES = 100


@dataclass(frozen=True, slots=True)
class TerminologySelection:
    system_uri: str
    release_id: str
    manifest_sha256: str
    candidate_priority: int


@dataclass(frozen=True, slots=True)
class MiningConfig:
    min_ngram_tokens: int
    max_ngram_tokens: int
    min_document_frequency: int
    max_unique_phrases: int


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    max_documents: int
    max_snapshot_bytes: int
    max_document_bytes: int
    max_tokens_per_document: int
    max_ngrams_per_document: int
    max_output_records: int
    max_candidates_per_phrase_system: int


@dataclass(frozen=True, slots=True)
class AnalysisConfig:
    config_id: str
    note_types: tuple[str, ...]
    languages: tuple[str, ...]
    terminologies: tuple[TerminologySelection, ...]
    mining: MiningConfig
    resource_limits: ResourceLimits
    algorithms: dict[str, str]
    canonical_value: dict[str, JsonValue]
    semantic_sha256: str


def _string_list(value: JsonValue, location: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ContractError("CFG_SCHEMA_INVALID", "Expected a non-empty list of strings.", location, 2)
    items: list[str] = []
    for index, item in enumerate(value):
        items.append(require_string(item, f"{location}[{index}]"))
    if len(set(items)) != len(items):
        raise ContractError("CFG_SCHEMA_INVALID", "Configuration lists cannot contain duplicates.", location, 2)
    return tuple(items)


def _bounded_int(value: JsonValue, location: str, maximum: int, minimum: int = 1) -> int:
    result = require_int(value, location, minimum=minimum)
    if result > maximum:
        raise ContractError("RESOURCE_LIMIT", "A configured resource limit exceeds the v0 safety ceiling.", location, 4)
    return result


def inspect_analysis_config(
    path: Path,
    snapshot: SnapshotBundle | None = None,
    references: tuple[ReferenceBundle, ...] = (),
) -> AnalysisConfig:
    value = require_object(load_json(path, "coe_config.json"), "coe_config.json")
    require_exact_keys(
        value,
        (
            "config_schema_version",
            "config_id",
            "execution_profile",
            "note_types",
            "languages",
            "terminologies",
            "normalization",
            "mining",
            "matching",
            "privacy",
            "resource_limits",
            "algorithms",
            "random_seed",
        ),
        (),
        "coe_config.json",
    )
    if value["config_schema_version"] != "1.1.0" or value["execution_profile"] != "offline_synthetic_v0":
        raise ContractError(
            "UNSAFE_PROFILE", "Only the offline_synthetic_v0 execution profile is supported.", "coe_config.json", 4
        )
    config_id = require_string(value["config_id"], "coe_config.json.config_id")
    note_types = _string_list(value["note_types"], "coe_config.json.note_types")
    languages = _string_list(value["languages"], "coe_config.json.languages")

    terminology_values = value["terminologies"]
    if not isinstance(terminology_values, list) or not terminology_values:
        raise ContractError(
            "CFG_SCHEMA_INVALID", "At least one terminology selection is required.", "coe_config.json.terminologies", 2
        )
    selections: list[TerminologySelection] = []
    priorities: set[int] = set()
    identities: set[tuple[str, str]] = set()
    canonical_selections: list[dict[str, JsonValue]] = []
    for index, selection_value in enumerate(terminology_values):
        location = f"coe_config.json.terminologies[{index}]"
        selection = require_object(selection_value, location)
        require_exact_keys(
            selection,
            ("system_uri", "release_id", "manifest_sha256", "candidate_priority"),
            (),
            location,
        )
        system_uri = require_string(selection["system_uri"], f"{location}.system_uri")
        parsed_uri = urlparse(system_uri)
        if not parsed_uri.scheme or (parsed_uri.scheme in {"http", "https"} and not parsed_uri.netloc):
            raise ContractError(
                "CFG_SCHEMA_INVALID",
                "Terminology system identity must be an absolute URI.",
                f"{location}.system_uri",
                2,
            )
        release_id = require_string(selection["release_id"], f"{location}.release_id")
        try:
            if str(uuid.UUID(release_id)) != release_id:
                raise ValueError
        except ValueError as exc:
            raise ContractError(
                "CFG_SCHEMA_INVALID",
                "Terminology release identity must be a canonical UUID.",
                f"{location}.release_id",
                2,
            ) from exc
        manifest_sha256 = check_sha256(
            require_string(selection["manifest_sha256"], f"{location}.manifest_sha256"),
            f"{location}.manifest_sha256",
        )
        priority = require_int(selection["candidate_priority"], f"{location}.candidate_priority", minimum=1)
        if priority in priorities:
            raise ContractError("DUPLICATE_PRIORITY", "Terminology candidate priorities must be unique.", location, 6)
        if (system_uri, release_id) in identities:
            raise ContractError("CFG_SCHEMA_INVALID", "Terminology selections cannot repeat a release.", location, 2)
        priorities.add(priority)
        identities.add((system_uri, release_id))
        selections.append(TerminologySelection(system_uri, release_id, manifest_sha256, priority))
        canonical_selections.append(
            {
                "candidate_priority": priority,
                "manifest_sha256": manifest_sha256,
                "release_id": release_id,
                "system_uri": system_uri,
            }
        )

    normalization = require_object(value["normalization"], "coe_config.json.normalization")
    require_exact_keys(
        normalization,
        ("profile_id", "version", "unicode_form", "collapse_whitespace", "primary", "casefold_variant"),
        (),
        "coe_config.json.normalization",
    )
    normalization_ok = (
        normalization["profile_id"] == "coe-conservative"
        and normalization["version"] == "1.0.0"
        and normalization["unicode_form"] == "NFC"
        and require_bool(normalization["collapse_whitespace"], "coe_config.json.normalization.collapse_whitespace")
        and normalization["primary"] == "case-sensitive"
        and normalization["casefold_variant"] == "unicode-casefold"
    )
    if not normalization_ok:
        raise ContractError(
            "NORMALIZER_INCOMPATIBLE",
            "The configuration requests an unsupported normalizer.",
            "coe_config.json.normalization",
            6,
        )

    mining_value = require_object(value["mining"], "coe_config.json.mining")
    require_exact_keys(
        mining_value,
        ("method", "min_ngram_tokens", "max_ngram_tokens", "min_document_frequency", "max_unique_phrases"),
        (),
        "coe_config.json.mining",
    )
    if mining_value["method"] != "sentence_bounded_token_ngrams":
        raise ContractError(
            "CFG_SCHEMA_INVALID", "v0 supports sentence-bounded token n-grams only.", "coe_config.json.mining.method", 2
        )
    min_ngram = _bounded_int(mining_value["min_ngram_tokens"], "coe_config.json.mining.min_ngram_tokens", 8)
    max_ngram = _bounded_int(mining_value["max_ngram_tokens"], "coe_config.json.mining.max_ngram_tokens", 8)
    if min_ngram > max_ngram:
        raise ContractError(
            "CFG_SCHEMA_INVALID", "Minimum n-gram length cannot exceed maximum length.", "coe_config.json.mining", 2
        )
    mining = MiningConfig(
        min_ngram_tokens=min_ngram,
        max_ngram_tokens=max_ngram,
        min_document_frequency=_bounded_int(
            mining_value["min_document_frequency"], "coe_config.json.mining.min_document_frequency", MAX_DOCUMENTS
        ),
        max_unique_phrases=_bounded_int(
            mining_value["max_unique_phrases"], "coe_config.json.mining.max_unique_phrases", MAX_UNIQUE_PHRASES
        ),
    )

    matching = require_object(value["matching"], "coe_config.json.matching")
    require_exact_keys(
        matching,
        (
            "layers",
            "active_only",
            "ambiguity_policy",
            "auto_acceptance_policy_id",
            "canonical_target_policy",
            "max_candidates_per_phrase_system",
        ),
        (),
        "coe_config.json.matching",
    )
    matching_ok = (
        matching["layers"]
        == [
            "exact_preferred",
            "exact_alias",
            "variant_compact",
            "variant_abbreviation",
            "variant_singular",
        ]
        and require_bool(matching["active_only"], "coe_config.json.matching.active_only")
        and matching["ambiguity_policy"] == "preserve"
        and matching["auto_acceptance_policy_id"] == "disabled-v0"
        and matching["canonical_target_policy"] == "none-review-required"
    )
    if not matching_ok:
        raise ContractError(
            "UNSUPPORTED_LAYER", "v0 supports ambiguity-preserving exact matching only.", "coe_config.json.matching", 6
        )
    max_candidates = _bounded_int(
        matching["max_candidates_per_phrase_system"],
        "coe_config.json.matching.max_candidates_per_phrase_system",
        MAX_EXACT_CANDIDATES,
    )

    privacy = require_object(value["privacy"], "coe_config.json.privacy")
    require_exact_keys(
        privacy, ("profile_id", "version", "canary_set_version", "fail_closed"), (), "coe_config.json.privacy"
    )
    privacy_ok = (
        privacy["profile_id"] == "synthetic-canary-only"
        and privacy["version"] == "1.0.0"
        and privacy["canary_set_version"] == "1.0.0"
        and require_bool(privacy["fail_closed"], "coe_config.json.privacy.fail_closed")
    )
    if not privacy_ok:
        raise ContractError(
            "UNSAFE_PROFILE", "The fail-closed synthetic privacy profile is mandatory.", "coe_config.json.privacy", 4
        )

    limits_value = require_object(value["resource_limits"], "coe_config.json.resource_limits")
    require_exact_keys(
        limits_value,
        (
            "max_documents",
            "max_snapshot_bytes",
            "max_document_bytes",
            "max_tokens_per_document",
            "max_ngrams_per_document",
            "max_output_records",
        ),
        (),
        "coe_config.json.resource_limits",
    )
    limits = ResourceLimits(
        max_documents=_bounded_int(
            limits_value["max_documents"], "coe_config.json.resource_limits.max_documents", MAX_DOCUMENTS
        ),
        max_snapshot_bytes=_bounded_int(
            limits_value["max_snapshot_bytes"], "coe_config.json.resource_limits.max_snapshot_bytes", MAX_SNAPSHOT_BYTES
        ),
        max_document_bytes=_bounded_int(
            limits_value["max_document_bytes"], "coe_config.json.resource_limits.max_document_bytes", MAX_DOCUMENT_BYTES
        ),
        max_tokens_per_document=_bounded_int(
            limits_value["max_tokens_per_document"],
            "coe_config.json.resource_limits.max_tokens_per_document",
            MAX_TOKENS_PER_DOCUMENT,
        ),
        max_ngrams_per_document=_bounded_int(
            limits_value["max_ngrams_per_document"],
            "coe_config.json.resource_limits.max_ngrams_per_document",
            MAX_NGRAMS_PER_DOCUMENT,
        ),
        max_output_records=_bounded_int(
            limits_value["max_output_records"], "coe_config.json.resource_limits.max_output_records", MAX_OUTPUT_RECORDS
        ),
        max_candidates_per_phrase_system=max_candidates,
    )

    algorithms_value = require_object(value["algorithms"], "coe_config.json.algorithms")
    require_exact_keys(
        algorithms_value,
        ("tokenizer", "normalizer", "span_matcher", "index_schema", "mining", "variant_matcher"),
        (),
        "coe_config.json.algorithms",
    )
    algorithms = {
        key: require_string(item, f"coe_config.json.algorithms.{key}") for key, item in algorithms_value.items()
    }
    if algorithms != {
        "tokenizer": "coe-regex-tokenizer/1.0.0",
        "normalizer": "coe-conservative/1.0.0",
        "span_matcher": "coe-exact-span/1.1.0",
        "index_schema": "coe-in-memory-exact/1.0.0-synthetic-only",
        "mining": "coe-sentence-bounded-token-ngrams/1.1.0",
        "variant_matcher": "coe-exact-and-deterministic-variants/1.0.0",
    }:
        raise ContractError(
            "NORMALIZER_INCOMPATIBLE",
            "Algorithm identities do not match this v0 implementation.",
            "coe_config.json.algorithms",
            6,
        )
    if value["random_seed"] != 0:
        raise ContractError(
            "CFG_SCHEMA_INVALID", "v0 requires the deterministic random seed 0.", "coe_config.json.random_seed", 2
        )

    canonical_value: dict[str, JsonValue] = dict(value)
    canonical_value["note_types"] = sorted(note_types)
    canonical_value["languages"] = sorted(languages)
    canonical_value["terminologies"] = sorted(
        canonical_selections,
        key=lambda item: (int(item["candidate_priority"]), str(item["system_uri"]), str(item["release_id"])),
    )

    if snapshot is not None:
        if not set(snapshot.note_types).issubset(note_types):
            raise ContractError(
                "NOTE_TYPE_INCOMPATIBLE",
                "The snapshot contains a note type not enabled by the config.",
                "coe_config.json.note_types",
                6,
            )
        if not set(snapshot.languages).issubset(languages):
            raise ContractError(
                "LANGUAGE_INCOMPATIBLE",
                "The snapshot contains a language not enabled by the config.",
                "coe_config.json.languages",
                6,
            )
        if len(snapshot.documents) > limits.max_documents:
            raise ContractError(
                "RESOURCE_LIMIT",
                "The snapshot exceeds the configured document limit.",
                "coe_config.json.resource_limits",
                4,
            )
        if sum(document.byte_count for document in snapshot.documents) > limits.max_snapshot_bytes:
            raise ContractError(
                "RESOURCE_LIMIT",
                "The snapshot exceeds the configured snapshot byte limit.",
                "coe_config.json.resource_limits",
                4,
            )
        if any(document.byte_count > limits.max_document_bytes for document in snapshot.documents):
            raise ContractError(
                "RESOURCE_LIMIT", "A document exceeds the configured byte limit.", "coe_config.json.resource_limits", 4
            )

    if references:
        reference_by_identity = {(reference.system_uri, reference.release_id): reference for reference in references}
        if set(reference_by_identity) != identities:
            raise ContractError(
                "REFERENCE_NOT_VALIDATED",
                "The supplied reference releases do not exactly match the config.",
                "coe_config.json.terminologies",
                6,
            )
        for selection in selections:
            reference = reference_by_identity[(selection.system_uri, selection.release_id)]
            if reference.manifest_sha256 != selection.manifest_sha256:
                raise ContractError(
                    "REFERENCE_HASH_MISMATCH",
                    "A selected terminology manifest hash does not match.",
                    "coe_config.json.terminologies",
                    6,
                )
            if reference.language not in languages:
                raise ContractError(
                    "LANGUAGE_INCOMPATIBLE",
                    "A reference language is not enabled by the config.",
                    "coe_config.json.languages",
                    6,
                )

    return AnalysisConfig(
        config_id=config_id,
        note_types=tuple(sorted(note_types)),
        languages=tuple(sorted(languages)),
        terminologies=tuple(
            sorted(selections, key=lambda item: (item.candidate_priority, item.system_uri, item.release_id))
        ),
        mining=mining,
        resource_limits=limits,
        algorithms=dict(sorted(algorithms.items())),
        canonical_value=canonical_value,
        semantic_sha256=sha256_canonical(canonical_value),
    )


def validate_analysis_config(
    path: Path,
    snapshot: SnapshotBundle | None = None,
    references: tuple[ReferenceBundle, ...] = (),
) -> PreflightReport:
    try:
        config = inspect_analysis_config(path, snapshot=snapshot, references=references)
    except ContractError as exc:
        severity = "security" if exc.exit_code == 4 else ("cross_contract" if exc.exit_code == 6 else "error")
        return PreflightReport(
            kind="config",
            status="failed",
            issues=(
                Issue(
                    code=exc.code,
                    severity=severity,
                    check_id="config_contract",
                    safe_message=exc.safe_message,
                    relative_location=exc.relative_location,
                ),
            ),
        )
    return PreflightReport(
        kind="config",
        status="passed",
        subject_id=config.config_id,
        content_set_sha256=config.semantic_sha256,
        checked_files=1,
        measurements={"terminology_count": len(config.terminologies)},
    )
