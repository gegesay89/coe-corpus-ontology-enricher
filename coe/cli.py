from __future__ import annotations

import argparse
import sys
from contextlib import ExitStack
from pathlib import Path
from typing import Sequence

from coe import __version__
from coe.benchmark import benchmark_reference
from coe.canonical import JsonValue, canonical_json_bytes
from coe.contracts.config import inspect_analysis_config, validate_analysis_config
from coe.contracts.reference import inspect_reference_bundle, validate_reference_bundle
from coe.contracts.report import PreflightReport
from coe.contracts.snapshot import inspect_snapshot_bundle, validate_snapshot_bundle
from coe.curation import append_decision, write_snapshot
from coe.demo import create_demo
from coe.errors import CoeError
from coe.export.skos import DEFAULT_BASE_IRI, export_skos
from coe.export.tabular import export_csv
from coe.governance import inspect_terminology_entitlement
from coe.pipeline import run_v0
from coe.protected import ProtectedLimits, run_protected_local
from coe.protected_verify import verify_protected_output
from coe.runtime.doctor import probe_host
from coe.terminology.licensed import (
    LicensedIndexMetadata,
    SQLiteTerminologyIndex,
    build_licensed_index,
    verify_licensed_index,
)
from coe.terminology.licensed_set import build_licensed_index_set, verify_licensed_index_set


def _emit(value: dict[str, JsonValue]) -> None:
    sys.stdout.buffer.write(canonical_json_bytes(value) + b"\n")


def _report_exit(report: PreflightReport) -> int:
    if report.passed:
        return 0
    issue = report.issues[0]
    if issue.severity == "security":
        return 4
    if issue.severity == "entitlement":
        return 5
    if issue.severity == "cross_contract":
        return 6
    if issue.code in {"SCHEMA_INVALID", "CFG_SCHEMA_INVALID", "DUPLICATE_JSON_KEY"}:
        return 2
    return 3


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="coe", description="COE deterministic terminology analysis")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    demo = commands.add_parser("demo", help="manage deterministic synthetic inputs")
    demo_commands = demo.add_subparsers(dest="demo_command", required=True)
    demo_create = demo_commands.add_parser("create", help="create a synthetic snapshot, reference, and config")
    demo_create.add_argument("path", type=Path)
    demo_create.add_argument("--overwrite", action="store_true")

    preflight = commands.add_parser("preflight", help="validate input contracts without analysis")
    preflight_commands = preflight.add_subparsers(dest="preflight_kind", required=True)
    snapshot = preflight_commands.add_parser("snapshot")
    snapshot.add_argument("path", type=Path)
    reference = preflight_commands.add_parser("reference")
    reference.add_argument("path", type=Path)
    reference.add_argument("--environment", default="synthetic", choices=("synthetic",))
    config = preflight_commands.add_parser("config")
    config.add_argument("path", type=Path)
    all_inputs = preflight_commands.add_parser("all")
    all_inputs.add_argument("--snapshot", type=Path, required=True)
    all_inputs.add_argument("--reference", type=Path, action="append", required=True)
    all_inputs.add_argument("--config", type=Path, required=True)

    run = commands.add_parser("run", help="run the synthetic deterministic vertical slice")
    run.add_argument("--snapshot", type=Path, required=True)
    run.add_argument("--reference", type=Path, action="append", required=True)
    run.add_argument("--config", type=Path, required=True)
    run.add_argument("--curation-snapshot", required=True)
    run.add_argument("--curation-decisions", type=Path)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--overwrite", action="store_true")

    curation = commands.add_parser("curation", help="record and snapshot hash-chained curation decisions")
    curation_commands = curation.add_subparsers(dest="curation_command", required=True)
    curation_decide = curation_commands.add_parser("decide", help="append one accept/reject decision")
    curation_decide.add_argument("--decisions", type=Path, required=True)
    curation_decide.add_argument("--form", required=True)
    curation_decide.add_argument("--system", required=True)
    curation_decide.add_argument("--release", required=True)
    curation_decide.add_argument("--code", required=True)
    curation_decide.add_argument("--decision", required=True, choices=("accepted", "rejected"))
    curation_decide.add_argument("--curator", required=True)
    curation_decide.add_argument("--note")
    curation_snapshot = curation_commands.add_parser("snapshot", help="pin the decision chain as a snapshot")
    curation_snapshot.add_argument("--decisions", type=Path, required=True)
    curation_snapshot.add_argument("--id", dest="snapshot_id", required=True)
    curation_snapshot.add_argument("--scope", required=True)
    curation_snapshot.add_argument("--output", type=Path, required=True)

    export = commands.add_parser("export", help="project run output into interchange formats")
    export_commands = export.add_subparsers(dest="export_kind", required=True)
    export_csv_parser = export_commands.add_parser("csv", help="flatten run artifacts to CSV")
    export_csv_parser.add_argument("--run", type=Path, required=True)
    export_csv_parser.add_argument("--output", type=Path, required=True)
    export_skos_parser = export_commands.add_parser("skos", help="emit a SKOS Turtle concept scheme")
    export_skos_parser.add_argument("--run", type=Path, required=True)
    export_skos_parser.add_argument("--output", type=Path, required=True)
    export_skos_parser.add_argument("--base-iri", default=DEFAULT_BASE_IRI)

    benchmark = commands.add_parser("benchmark", help="run bounded, non-semantic performance checks")
    benchmark_commands = benchmark.add_subparsers(dest="benchmark_kind", required=True)
    benchmark_reference_parser = benchmark_commands.add_parser("reference")
    benchmark_reference_parser.add_argument("path", type=Path)
    benchmark_reference_parser.add_argument("--lookups", type=int, default=10000)

    licensed_reference = commands.add_parser("reference", help="manage private licensed SQLite reference indexes")
    licensed_commands = licensed_reference.add_subparsers(dest="licensed_command", required=True)
    licensed_build = licensed_commands.add_parser("build-index", help="build one pinned terminology index")
    licensed_build.add_argument("--terminology", required=True)
    licensed_build.add_argument("--csv", type=Path, required=True)
    licensed_build.add_argument("--spec", type=Path)
    licensed_build.add_argument("--entitlement", type=Path, required=True)
    licensed_build.add_argument("--output", type=Path, required=True)
    licensed_build.add_argument("--overwrite", action="store_true")
    licensed_verify = licensed_commands.add_parser("verify-index", help="verify one immutable terminology index")
    licensed_verify.add_argument("path", type=Path)
    licensed_build_set = licensed_commands.add_parser("build-set", help="atomically build every pinned terminology")
    licensed_build_set.add_argument("--source-dir", type=Path, required=True)
    licensed_build_set.add_argument("--spec", type=Path)
    licensed_build_set.add_argument("--entitlement", type=Path, required=True)
    licensed_build_set.add_argument("--output", type=Path, required=True)
    licensed_build_set.add_argument("--overwrite", action="store_true")
    licensed_verify_set = licensed_commands.add_parser("verify-set", help="verify a complete reference index set")
    licensed_verify_set.add_argument("path", type=Path)

    protected = commands.add_parser("protected", help="run aggregate-only analysis on approved local plaintext")
    protected_commands = protected.add_subparsers(dest="protected_command", required=True)
    protected_run = protected_commands.add_parser("run")
    protected_run.add_argument("--corpus", type=Path, required=True)
    protected_run.add_argument("--attestation", type=Path, required=True)
    protected_run.add_argument("--index", type=Path, action="append", required=True)
    protected_run.add_argument("--output", type=Path, required=True)
    protected_run.add_argument("--require-nvidia", action="store_true")
    protected_run.add_argument("--overwrite", action="store_true")
    limit_defaults = ProtectedLimits()
    protected_run.add_argument("--max-files", type=int, default=limit_defaults.max_files)
    protected_run.add_argument("--max-walk-entries", type=int, default=limit_defaults.max_walk_entries)
    protected_run.add_argument("--max-file-bytes", type=int, default=limit_defaults.max_file_bytes)
    protected_run.add_argument("--max-total-bytes", type=int, default=limit_defaults.max_total_bytes)
    protected_run.add_argument("--max-tokens-per-file", type=int, default=limit_defaults.max_tokens_per_file)
    protected_run.add_argument("--max-total-tokens", type=int, default=limit_defaults.max_total_tokens)
    protected_run.add_argument("--max-ngrams-per-file", type=int, default=limit_defaults.max_ngrams_per_file)
    protected_run.add_argument("--max-total-ngrams", type=int, default=limit_defaults.max_total_ngrams)
    protected_run.add_argument("--max-unique-phrases", type=int, default=limit_defaults.max_unique_phrases)
    protected_run.add_argument(
        "--max-candidates-per-phrase-system",
        type=int,
        default=limit_defaults.max_candidates_per_phrase_system,
    )
    protected_run.add_argument("--max-ngram-tokens", type=int, default=limit_defaults.max_ngram_tokens)
    protected_run.add_argument("--min-cell-document-count", type=int, default=limit_defaults.min_cell_document_count)
    protected_run.add_argument("--max-candidate-terms", type=int, default=limit_defaults.max_candidate_terms)
    protected_run.add_argument(
        "--max-association-codes-per-document",
        type=int,
        default=limit_defaults.max_association_codes_per_document,
    )
    protected_run.add_argument("--max-association-pairs", type=int, default=limit_defaults.max_association_pairs)
    protected_verify = protected_commands.add_parser(
        "verify", help="verify aggregate output against its terminology releases"
    )
    protected_verify.add_argument("--output", type=Path, required=True)
    protected_verify.add_argument("--index", type=Path, action="append", required=True)

    hardware = commands.add_parser("hardware", help="emit a sanitized runtime capability report")
    hardware_commands = hardware.add_subparsers(dest="hardware_command", required=True)
    hardware_probe = hardware_commands.add_parser("probe")
    hardware_probe.add_argument("--require-nvidia", action="store_true")
    return parser


def _handle_preflight(args: argparse.Namespace) -> int:
    if args.preflight_kind == "snapshot":
        report = validate_snapshot_bundle(args.path)
        _emit(report.as_dict())
        return _report_exit(report)
    if args.preflight_kind == "reference":
        report = validate_reference_bundle(args.path, environment=args.environment)
        _emit(report.as_dict())
        return _report_exit(report)
    if args.preflight_kind == "config":
        report = validate_analysis_config(args.path)
        _emit(report.as_dict())
        return _report_exit(report)
    snapshot = inspect_snapshot_bundle(args.snapshot)
    references = tuple(inspect_reference_bundle(path, environment="synthetic") for path in args.reference)
    config = inspect_analysis_config(args.config, snapshot=snapshot, references=references)
    _emit(
        {
            "config_sha256": config.semantic_sha256,
            "preflight_report_schema_version": "1.0.0",
            "reference_count": len(references),
            "snapshot_content_set_sha256": snapshot.content_set_sha256,
            "status": "passed",
        }
    )
    return 0


def _licensed_metadata(metadata: LicensedIndexMetadata) -> dict[str, JsonValue]:
    return {
        "active_count": metadata.active_count,
        "alias_count": metadata.alias_count,
        "code_count": metadata.code_count,
        "content_set_sha256": metadata.content_set_sha256,
        "designation_count": metadata.designation_count,
        "effective_date": metadata.effective_date,
        "inactive_count": metadata.inactive_count,
        "index_sha256": metadata.index_sha256,
        "manifest_sha256": metadata.manifest_sha256,
        "profile_sha256": metadata.profile_sha256,
        "release_id": metadata.release_id,
        "source_sha256": metadata.source_sha256,
        "status": "passed",
        "system_name": metadata.system_name,
        "system_uri": metadata.system_uri,
        "terminology": metadata.terminology,
        "version": metadata.version,
    }


def _handle_licensed_reference(args: argparse.Namespace) -> int:
    if args.licensed_command == "verify-index":
        _emit(_licensed_metadata(verify_licensed_index(args.path)))
        return 0
    if args.licensed_command == "verify-set":
        _emit(verify_licensed_index_set(args.path))
        return 0
    if args.licensed_command == "build-set":
        _emit(
            build_licensed_index_set(
                source_dir=args.source_dir,
                output_dir=args.output,
                entitlement_path=args.entitlement,
                specs_path=args.spec,
                overwrite=args.overwrite,
            )
        )
        return 0
    assertion = inspect_terminology_entitlement(args.entitlement, terminology=args.terminology)
    metadata = build_licensed_index(
        args.csv,
        args.output,
        args.terminology,
        specs_path=args.spec,
        entitlement_ref=assertion.binding_ref,
        overwrite=args.overwrite,
    )
    _emit(_licensed_metadata(metadata))
    return 0


def _handle_protected(args: argparse.Namespace) -> int:
    if args.protected_command == "verify":
        with ExitStack() as stack:
            indexes = tuple(stack.enter_context(SQLiteTerminologyIndex(path)) for path in args.index)
            result = verify_protected_output(output_path=args.output, indexes=indexes)
        _emit(result)
        return 0
    limits = ProtectedLimits(
        max_files=args.max_files,
        max_walk_entries=args.max_walk_entries,
        max_file_bytes=args.max_file_bytes,
        max_total_bytes=args.max_total_bytes,
        max_tokens_per_file=args.max_tokens_per_file,
        max_total_tokens=args.max_total_tokens,
        max_ngrams_per_file=args.max_ngrams_per_file,
        max_total_ngrams=args.max_total_ngrams,
        max_unique_phrases=args.max_unique_phrases,
        max_candidates_per_phrase_system=args.max_candidates_per_phrase_system,
        max_ngram_tokens=args.max_ngram_tokens,
        min_cell_document_count=args.min_cell_document_count,
        max_candidate_terms=args.max_candidate_terms,
        max_association_codes_per_document=args.max_association_codes_per_document,
        max_association_pairs=args.max_association_pairs,
    )
    with ExitStack() as stack:
        indexes = tuple(stack.enter_context(SQLiteTerminologyIndex(path)) for path in args.index)
        result = run_protected_local(
            corpus_path=args.corpus,
            attestation_path=args.attestation,
            indexes=indexes,
            output_path=args.output,
            limits=limits,
            require_nvidia=args.require_nvidia,
            overwrite=args.overwrite,
        )
    _emit(result)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "demo":
            _emit(create_demo(args.path, overwrite=args.overwrite))
            return 0
        if args.command == "preflight":
            return _handle_preflight(args)
        if args.command == "run":
            _emit(
                run_v0(
                    snapshot_path=args.snapshot,
                    reference_paths=tuple(args.reference),
                    config_path=args.config,
                    curation_snapshot=args.curation_snapshot,
                    output_path=args.output,
                    curation_decisions=args.curation_decisions,
                    overwrite=args.overwrite,
                )
            )
            return 0
        if args.command == "curation":
            if args.curation_command == "decide":
                decision = append_decision(
                    args.decisions,
                    primary_normalized_form=args.form,
                    system_uri=args.system,
                    release_id=args.release,
                    code=args.code,
                    decision=args.decision,
                    curator=args.curator,
                    note=args.note,
                )
                _emit(
                    {
                        "code": decision.code,
                        "decision": decision.decision,
                        "sequence": decision.sequence,
                        "status": "recorded",
                    }
                )
                return 0
            snapshot_value = write_snapshot(args.output, args.decisions, snapshot_id=args.snapshot_id, scope=args.scope)
            _emit({**snapshot_value, "status": "created"})
            return 0
        if args.command == "export":
            if args.export_kind == "csv":
                _emit(export_csv(args.run, args.output))
                return 0
            _emit(export_skos(args.run, args.output, base_iri=args.base_iri))
            return 0
        if args.command == "benchmark" and args.benchmark_kind == "reference":
            _emit(benchmark_reference(args.path, lookup_count=args.lookups))
            return 0
        if args.command == "hardware" and args.hardware_command == "probe":
            _emit(probe_host(require_nvidia=args.require_nvidia))
            return 0
        if args.command == "reference":
            return _handle_licensed_reference(args)
        if args.command == "protected":
            return _handle_protected(args)
        parser.error("unknown command")
    except CoeError as exc:
        _emit(
            {
                "error": {
                    "code": exc.code,
                    "relative_location": exc.relative_location,
                    "safe_message": exc.safe_message,
                },
                "status": "failed",
            }
        )
        return exc.exit_code
    except Exception:
        _emit(
            {
                "error": {
                    "code": "INTERNAL_ERROR",
                    "safe_message": "An unexpected internal error occurred; no diagnostic content was exported.",
                },
                "status": "failed",
            }
        )
        return 70
    return 70
