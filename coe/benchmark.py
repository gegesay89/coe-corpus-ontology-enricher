"""Non-semantic performance harness for the fixture-only exact index."""

from __future__ import annotations

import time
import tracemalloc
from pathlib import Path

from coe.canonical import JsonValue
from coe.contracts.reference import inspect_reference_bundle
from coe.errors import ContractError
from coe.ingest.normalize import normalize_lexical
from coe.terminology.exact import InMemoryExactIndex

MAX_LOOKUPS = 1_000_000


def benchmark_reference(path: Path, lookup_count: int = 10_000) -> dict[str, JsonValue]:
    if lookup_count < 1 or lookup_count > MAX_LOOKUPS:
        raise ContractError(
            "RESOURCE_LIMIT",
            "Benchmark lookups must be between 1 and 1,000,000.",
            "lookups",
            4,
        )
    validation_start = time.perf_counter_ns()
    reference = inspect_reference_bundle(path, environment="synthetic")
    validation_elapsed_ns = time.perf_counter_ns() - validation_start

    tracemalloc.start()
    build_start = time.perf_counter_ns()
    index = InMemoryExactIndex(reference)
    build_elapsed_ns = time.perf_counter_ns() - build_start
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    queries = tuple(
        (
            designation.kind,
            normalize_lexical(designation.value).primary,
        )
        for designation in reference.designations
    )
    hit_count = 0
    lookup_start = time.perf_counter_ns()
    for number in range(lookup_count):
        kind, key = queries[number % len(queries)]
        hit_count += len(index.lookup(key, kind=kind, variant="primary"))
    lookup_elapsed_ns = time.perf_counter_ns() - lookup_start
    return {
        "benchmark_schema_version": "1.0.0",
        "coding_count": len(reference.codings),
        "designation_count": len(reference.designations),
        "fixture_only": True,
        "index_build_elapsed_microseconds": build_elapsed_ns // 1_000,
        "index_build_peak_bytes": peak_bytes,
        "lookup_average_nanoseconds": lookup_elapsed_ns // lookup_count,
        "lookup_count": lookup_count,
        "lookup_hit_count": hit_count,
        "lookup_total_microseconds": lookup_elapsed_ns // 1_000,
        "release_id": reference.release_id,
        "status": "completed",
        "system_uri": reference.system_uri,
        "validation_elapsed_microseconds": validation_elapsed_ns // 1_000,
        "warning": "Results characterize only the synthetic in-memory fixture index; they do not select a production backend.",
    }
