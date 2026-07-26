"""Shared software-identity descriptors for run reports and fingerprints."""

from __future__ import annotations

import platform
import unicodedata
from decimal import getcontext
from pathlib import Path

from coe import __version__
from coe.canonical import JsonValue, sha256_bytes, sha256_canonical

MINING_ALGORITHM_VERSION = "coe-sentence-bounded-token-ngrams/1.2.0"
MATCHING_ALGORITHM_VERSION = "coe-exact-and-deterministic-variants/1.0.0"
ASSOCIATION_ALGORITHM_VERSION = "coe-document-cooccurrence-npmi/1.0.0"
CONTEXT_ALGORITHM_VERSION = "coe-lexical-context-screen/1.0.0"


def implementation_sha256() -> str:
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


def implementation_identity() -> dict[str, JsonValue]:
    return {
        "coe_version": __version__,
        "decimal_context_precision": getcontext().prec,
        "python_version": platform.python_version(),
        "source_sha256": implementation_sha256(),
        "unicode_data_version": unicodedata.unidata_version,
    }


def protected_implementation_identity() -> dict[str, JsonValue]:
    """Host-independent identity stamped into protected reports and fingerprints.

    Deliberately excludes python/unicode/host details so a protected run's
    fingerprint is reproducible across verifying hosts while still binding the
    exact source tree and algorithm versions that produced the output.
    """

    return {
        "algorithms": {
            "association": ASSOCIATION_ALGORITHM_VERSION,
            "context": CONTEXT_ALGORITHM_VERSION,
            "matching": MATCHING_ALGORITHM_VERSION,
            "mining": MINING_ALGORITHM_VERSION,
        },
        "coe_version": __version__,
        "source_sha256": implementation_sha256(),
    }
