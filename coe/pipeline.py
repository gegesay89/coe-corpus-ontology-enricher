"""Offline, synthetic-only v0 orchestration."""

from __future__ import annotations

import os
import platform
import shutil
import tempfile
import unicodedata
import uuid
from collections import Counter
from decimal import getcontext
from pathlib import Path

from coe import __version__
from coe.canonical import JsonValue, sha256_bytes, sha256_canonical
from coe.contracts.config import AnalysisConfig, inspect_analysis_config
from coe.contracts.reference import ReferenceBundle, inspect_reference_bundle
from coe.contracts.snapshot import SnapshotBundle, inspect_snapshot_bundle
from coe.errors import ContractError, OutputExistsError
from coe.export.jsonl import ArtifactDigest, write_json, write_jsonl
from coe.mining.ngrams import PhraseAggregate, aggregate_phrases
from coe.terminology.exact import build_exact_indexes, match_phrase, validate_grounding

GENESIS_CURATION_ID = "genesis-v0"
GENESIS_CURATION_SHA256 = sha256_canonical(
    {
        "curation_snapshot_schema_version": "1.0.0",
        "decision_count": 0,
        "id": GENESIS_CURATION_ID,
        "scope": "offline-synthetic-v0",
    },
    domain=b"coe.curation-snapshot.v0",
)


def _implementation_sha256() -> str:
    package_root = Path(__file__).parent
    descriptors: list[dict[str, JsonValue]] = []
    for path in sorted(package_root.rglob("*.py"), key=lambda item: item.relative_to(package_root).as_posix()):
        raw = path.read_bytes()
        descriptors.append(
            {
                "byte_count": len(raw),
                "path": path.relative_to(package_root).as_posix(),
                "sha256": sha256_bytes(raw),
            }
        )
    return sha256_canonical(
        {"implementation_hash_schema_version": "coe-python-package-v1", "sources": descriptors},
        domain=b"coe.implementation.v0",
    )


def _implementation_identity() -> dict[str, JsonValue]:
    return {
        "coe_version": __version__,
        "decimal_context_precision": getcontext().prec,
        "python_version": platform.python_version(),
        "source_sha256": _implementation_sha256(),
        "unicode_data_version": unicodedata.unidata_version,
    }


def _fingerprint_payload(
    snapshot: SnapshotBundle,
    references: tuple[ReferenceBundle, ...],
    config: AnalysisConfig,
    implementation: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    return {
        "algorithm_versions": dict(config.algorithms),
        "config_sha256": config.semantic_sha256,
        "curation_snapshot": {
            "id": GENESIS_CURATION_ID,
            "sha256": GENESIS_CURATION_SHA256,
        },
        "fingerprint_schema_version": "coe-run-fingerprint-v1",
        "implementation": implementation,
        "references": sorted(
            [
                {
                    "content_set_sha256": reference.content_set_sha256,
                    "manifest_sha256": reference.manifest_sha256,
                    "release_id": reference.release_id,
                    "system_uri": reference.system_uri,
                    "version": reference.version,
                }
                for reference in references
            ],
            key=lambda item: (str(item["system_uri"]), str(item["release_id"])),
        ),
        "snapshot_content_set_sha256": snapshot.content_set_sha256,
    }


def _as_json_records(rows: tuple[dict[str, object], ...]) -> tuple[dict[str, JsonValue], ...]:
    return tuple(row for row in rows)  # type: ignore[return-value]


def _artifact_map(artifacts: tuple[ArtifactDigest, ...]) -> list[dict[str, JsonValue]]:
    return [artifact.as_dict() for artifact in sorted(artifacts, key=lambda item: item.path)]


def _materialize(
    directory: Path,
    snapshot: SnapshotBundle,
    references: tuple[ReferenceBundle, ...],
    config: AnalysisConfig,
    phrases: tuple[PhraseAggregate, ...],
    candidate_rows: tuple[dict[str, object], ...],
    grounding_count: int,
    fingerprint: str,
    implementation: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    run_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"urn:coe:run:{fingerprint}"))
    phrase_records = tuple(phrase.as_dict() for phrase in phrases)
    matches = tuple(row for row in candidate_rows if row["algorithmic_outcome"] != "unmapped")
    unmapped = tuple(row for row in candidate_rows if row["algorithmic_outcome"] == "unmapped")
    artifacts: list[ArtifactDigest] = []
    artifacts.append(write_jsonl(directory, "phrase_aggregates.jsonl", _as_json_records(phrase_records)))
    artifacts.append(write_jsonl(directory, "candidate_sets.jsonl", _as_json_records(candidate_rows)))
    artifacts.append(write_jsonl(directory, "matches.jsonl", _as_json_records(matches)))
    artifacts.append(write_jsonl(directory, "unmapped.jsonl", _as_json_records(unmapped)))

    run_manifest: dict[str, JsonValue] = {
        "config": {"config_id": config.config_id, "semantic_sha256": config.semantic_sha256},
        "curation_snapshot": {"id": GENESIS_CURATION_ID, "sha256": GENESIS_CURATION_SHA256},
        "implementation": implementation,
        "references": [
            {
                "content_set_sha256": reference.content_set_sha256,
                "manifest_sha256": reference.manifest_sha256,
                "release_id": reference.release_id,
                "system_uri": reference.system_uri,
                "version": reference.version,
            }
            for reference in references
        ],
        "run_fingerprint": fingerprint,
        "run_id": run_id,
        "run_manifest_schema_version": "1.0.0",
        "snapshot": {
            "content_set_sha256": snapshot.content_set_sha256,
            "snapshot_id": snapshot.snapshot_id,
            "snapshot_iri": snapshot.snapshot_iri,
        },
        "source_profile": "synthetic-only",
        "status": "succeeded",
    }
    run_manifest_artifact = write_json(directory, "run_manifest.json", run_manifest)
    artifacts.append(run_manifest_artifact)

    outcome_counts = Counter(str(row["algorithmic_outcome"]) for row in candidate_rows)
    by_system: dict[str, Counter[str]] = {}
    for row in candidate_rows:
        system_uri = str(row["system_uri"])
        by_system.setdefault(system_uri, Counter())[str(row["algorithmic_outcome"])] += 1
    run_report: dict[str, JsonValue] = {
        "algorithm_versions": dict(config.algorithms),
        "artifacts": _artifact_map(tuple(artifacts)),
        "grounding": {
            "candidate_count_checked": grounding_count,
            "invariant": "every emitted coding exists in its pinned release",
            "status": "passed",
        },
        "limitations": [
            "offline synthetic alpha only",
            "candidate grounding is not acceptance",
            "all acceptance states remain pending",
            "no context, fuzzy matching, embeddings, associations, curation, database, or publication",
            "the in-memory exact index is fixture-only and not a production backend decision",
            "the synthetic privacy canary scanner is not a de-identification method",
        ],
        "outcomes": {key: outcome_counts[key] for key in sorted(outcome_counts)},
        "outcomes_by_system": {
            system_uri: {key: counter[key] for key in sorted(counter)}
            for system_uri, counter in sorted(by_system.items())
        },
        "preflight": {"config": "passed", "references": "passed", "snapshot": "passed"},
        "resource_limits": {
            "max_candidates_per_phrase_system": config.resource_limits.max_candidates_per_phrase_system,
            "max_document_bytes": config.resource_limits.max_document_bytes,
            "max_documents": config.resource_limits.max_documents,
            "max_ngrams_per_document": config.resource_limits.max_ngrams_per_document,
            "max_output_records": config.resource_limits.max_output_records,
            "max_snapshot_bytes": config.resource_limits.max_snapshot_bytes,
            "max_tokens_per_document": config.resource_limits.max_tokens_per_document,
            "max_unique_phrases": config.mining.max_unique_phrases,
        },
        "run_fingerprint": fingerprint,
        "run_id": run_id,
        "run_report_schema_version": "1.0.0",
        "status": "succeeded",
        "totals": {
            "candidate_set_count": len(candidate_rows),
            "document_count": len(snapshot.documents),
            "mapped_candidate_set_count": len(matches),
            "phrase_count": len(phrases),
            "unmapped_candidate_set_count": len(unmapped),
        },
    }
    run_report_artifact = write_json(directory, "run_report.json", run_report)
    semantic_artifacts = tuple(artifacts) + (run_report_artifact,)
    artifact_payload: dict[str, JsonValue] = {
        "artifact_manifest_schema_version": "1.0.0",
        "files": _artifact_map(semantic_artifacts),
        "run_fingerprint": fingerprint,
    }
    artifact_payload["semantic_content_sha256"] = sha256_canonical(
        {
            "digest_schema_version": "coe-v0-semantic-artifacts-v1",
            "files": artifact_payload["files"],
            "run_fingerprint": fingerprint,
        },
        domain=b"coe.semantic-artifacts.v0",
    )
    write_json(directory, "artifact_manifest.json", artifact_payload)
    return {
        "artifact_manifest": "artifact_manifest.json",
        "candidate_set_count": len(candidate_rows),
        "output_status": "created",
        "run_fingerprint": fingerprint,
        "run_id": run_id,
        "semantic_content_sha256": artifact_payload["semantic_content_sha256"],
        "status": "succeeded",
    }


def run_v0(
    *,
    snapshot_path: Path,
    reference_paths: tuple[Path, ...],
    config_path: Path,
    curation_snapshot: str,
    output_path: Path,
    overwrite: bool = False,
) -> dict[str, JsonValue]:
    if curation_snapshot != GENESIS_CURATION_ID:
        raise ContractError(
            "CURATION_SNAPSHOT_UNSUPPORTED",
            "v0 requires the explicit immutable genesis-v0 curation snapshot.",
            "curation_snapshot",
            6,
        )
    if output_path.exists() and not overwrite:
        raise OutputExistsError()

    snapshot = inspect_snapshot_bundle(snapshot_path)
    references_unordered = tuple(inspect_reference_bundle(path, environment="synthetic") for path in reference_paths)
    config = inspect_analysis_config(config_path, snapshot=snapshot, references=references_unordered)
    references_by_identity = {(item.system_uri, item.release_id): item for item in references_unordered}
    references = tuple(
        references_by_identity[(selection.system_uri, selection.release_id)] for selection in config.terminologies
    )

    phrases = aggregate_phrases(snapshot.documents, config)
    indexes = build_exact_indexes(references)
    rows: list[dict[str, object]] = []
    for phrase in phrases:
        for index in indexes:
            rows.append(
                match_phrase(
                    phrase,
                    index,
                    max_candidates=config.resource_limits.max_candidates_per_phrase_system,
                )
            )
            if len(rows) > config.resource_limits.max_output_records:
                raise ContractError(
                    "RESOURCE_LIMIT", "The run exceeds the configured output-record limit.", "analysis", 4
                )
    candidate_rows = tuple(
        sorted(
            rows,
            key=lambda row: (
                str(row["language"]),
                str(row["primary_normalized_form"]),
                str(row["system_uri"]),
                str(row["release_id"]),
            ),
        )
    )
    grounding_count = validate_grounding(candidate_rows, references)
    implementation = _implementation_identity()
    fingerprint = sha256_canonical(
        _fingerprint_payload(snapshot, references, config, implementation),
        domain=b"coe.run-fingerprint.v0",
    )

    parent = output_path.parent
    parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output_path.name}.tmp-", dir=parent))
    backup: Path | None = None
    try:
        summary = _materialize(
            temporary,
            snapshot,
            references,
            config,
            phrases,
            candidate_rows,
            grounding_count,
            fingerprint,
            implementation,
        )
        if output_path.exists():
            backup = parent / f".{output_path.name}.backup-{uuid.uuid4().hex}"
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
