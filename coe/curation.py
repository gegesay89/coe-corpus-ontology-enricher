"""Hash-chained curation decisions and immutable curation snapshots.

Decisions are recorded as an append-only canonical JSONL chain: every row
carries a dense sequence number and the SHA-256 of the previous canonical row
(the genesis row points at a fixed zero digest). A curation snapshot pins the
decision file by content digest so a run can prove exactly which decisions it
applied. No timestamps are recorded; determinism and attribution come from the
chain itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from coe.canonical import (
    JsonValue,
    canonical_json_line,
    load_json_bytes,
    read_stable_file,
    require_exact_keys,
    require_int,
    require_object,
    require_string,
    sha256_bytes,
)
from coe.errors import ContractError

DECISION_SCHEMA_VERSION = "1.0.0"
SNAPSHOT_SCHEMA_VERSION = "1.0.0"
GENESIS_PREVIOUS_SHA256 = "0" * 64
MAX_DECISION_FILE_BYTES = 50_000_000
MAX_SNAPSHOT_BYTES = 65_536
_DECISION_KEYS = (
    "curation_decision_schema_version",
    "sequence",
    "previous_sha256",
    "primary_normalized_form",
    "system_uri",
    "release_id",
    "code",
    "decision",
    "curator",
)


@dataclass(frozen=True, slots=True)
class CurationDecision:
    sequence: int
    primary_normalized_form: str
    system_uri: str
    release_id: str
    code: str
    decision: str
    curator: str
    note: str | None


@dataclass(frozen=True, slots=True)
class CurationSnapshot:
    snapshot_id: str
    decision_count: int
    decisions_sha256: str
    scope: str
    snapshot_sha256: str
    decisions: tuple[CurationDecision, ...]


def _bounded(value: JsonValue, location: str, maximum: int) -> str:
    text = require_string(value, location)
    if not text or len(text) > maximum or any(ord(character) < 32 for character in text):
        raise ContractError("CURATION_INVALID", "A curation field is invalid.", location, 3)
    return text


def _parse_decision_row(
    raw_line: bytes,
    line_number: int,
    expected_previous: str,
) -> tuple[CurationDecision, str]:
    value = require_object(load_json_bytes(raw_line, "curation_decisions"), "curation_decisions")
    require_exact_keys(value, _DECISION_KEYS, ("note",), "curation_decisions")
    if canonical_json_line(value) != raw_line + b"\n":
        raise ContractError(
            "CANONICALIZATION_FAILED", "A curation decision row is not canonically encoded.", "curation_decisions", 3
        )
    if value["curation_decision_schema_version"] != DECISION_SCHEMA_VERSION:
        raise ContractError(
            "CURATION_INVALID", "The curation decision schema version is unsupported.", "curation_decisions", 3
        )
    sequence = require_int(value["sequence"], "curation_decisions.sequence", minimum=1)
    if sequence != line_number:
        raise ContractError(
            "CURATION_INVALID", "Curation decision sequence numbers must be dense.", "curation_decisions", 3
        )
    previous = _bounded(value["previous_sha256"], "curation_decisions.previous_sha256", 64)
    if previous != expected_previous:
        raise ContractError("CURATION_INVALID", "The curation decision chain is broken.", "curation_decisions", 3)
    decision = _bounded(value["decision"], "curation_decisions.decision", 16)
    if decision not in {"accepted", "rejected"}:
        raise ContractError("CURATION_INVALID", "A curation decision value is invalid.", "curation_decisions", 3)
    note_value = value.get("note")
    note = None if note_value is None else _bounded(note_value, "curation_decisions.note", 1_024)
    parsed = CurationDecision(
        sequence=sequence,
        primary_normalized_form=_bounded(
            value["primary_normalized_form"], "curation_decisions.primary_normalized_form", 256
        ),
        system_uri=_bounded(value["system_uri"], "curation_decisions.system_uri", 2_048),
        release_id=_bounded(value["release_id"], "curation_decisions.release_id", 2_048),
        code=_bounded(value["code"], "curation_decisions.code", 128),
        decision=decision,
        curator=_bounded(value["curator"], "curation_decisions.curator", 128),
        note=note,
    )
    return parsed, sha256_bytes(raw_line + b"\n")


def read_decisions(path: Path) -> tuple[tuple[CurationDecision, ...], str]:
    """Read and verify a decision chain; returns (decisions, content sha256)."""

    raw = read_stable_file(path, "curation_decisions.jsonl", MAX_DECISION_FILE_BYTES)
    decisions: list[CurationDecision] = []
    expected_previous = GENESIS_PREVIOUS_SHA256
    if raw:
        if not raw.endswith(b"\n"):
            raise ContractError(
                "CURATION_INVALID", "The curation decision file must end with a newline.", "curation_decisions", 3
            )
        for line_number, raw_line in enumerate(raw[:-1].split(b"\n"), start=1):
            decision, expected_previous = _parse_decision_row(raw_line, line_number, expected_previous)
            decisions.append(decision)
    return tuple(decisions), sha256_bytes(raw)


def append_decision(
    path: Path,
    *,
    primary_normalized_form: str,
    system_uri: str,
    release_id: str,
    code: str,
    decision: str,
    curator: str,
    note: str | None = None,
) -> CurationDecision:
    existing, _ = read_decisions(path) if path.exists() else ((), "")
    previous = GENESIS_PREVIOUS_SHA256
    if existing:
        raw = path.read_bytes()
        last_line = raw[:-1].split(b"\n")[-1]
        previous = sha256_bytes(last_line + b"\n")
    row: dict[str, JsonValue] = {
        "code": code,
        "curation_decision_schema_version": DECISION_SCHEMA_VERSION,
        "curator": curator,
        "decision": decision,
        "previous_sha256": previous,
        "primary_normalized_form": primary_normalized_form,
        "release_id": release_id,
        "sequence": len(existing) + 1,
        "system_uri": system_uri,
    }
    if note is not None:
        row["note"] = note
    encoded = canonical_json_line(row)
    parsed, _ = _parse_decision_row(encoded[:-1], len(existing) + 1, previous)
    with path.open("ab") as handle:
        handle.write(encoded)
    return parsed


def write_snapshot(snapshot_path: Path, decisions_path: Path, *, snapshot_id: str, scope: str) -> dict[str, JsonValue]:
    decisions, decisions_sha256 = read_decisions(decisions_path)
    value: dict[str, JsonValue] = {
        "curation_snapshot_schema_version": SNAPSHOT_SCHEMA_VERSION,
        "decision_count": len(decisions),
        "decisions_sha256": decisions_sha256,
        "id": _bounded(snapshot_id, "curation_snapshot.id", 128),
        "scope": _bounded(scope, "curation_snapshot.scope", 256),
    }
    snapshot_path.write_bytes(canonical_json_line(value))
    return value


def load_snapshot(snapshot_path: Path, decisions_path: Path | None) -> CurationSnapshot:
    raw = read_stable_file(snapshot_path, "curation_snapshot.json", MAX_SNAPSHOT_BYTES)
    value = require_object(load_json_bytes(raw, "curation_snapshot.json"), "curation_snapshot.json")
    require_exact_keys(
        value,
        ("curation_snapshot_schema_version", "decision_count", "decisions_sha256", "id", "scope"),
        (),
        "curation_snapshot.json",
    )
    if value["curation_snapshot_schema_version"] != SNAPSHOT_SCHEMA_VERSION:
        raise ContractError(
            "CURATION_INVALID", "The curation snapshot schema version is unsupported.", "curation_snapshot", 3
        )
    decision_count = require_int(value["decision_count"], "curation_snapshot.decision_count", minimum=0)
    decisions_sha256 = _bounded(value["decisions_sha256"], "curation_snapshot.decisions_sha256", 64)
    decisions: tuple[CurationDecision, ...] = ()
    if decision_count:
        if decisions_path is None:
            raise ContractError(
                "CURATION_INVALID",
                "A curation snapshot with decisions requires the decision file.",
                "curation_snapshot",
                3,
            )
        decisions, actual_sha256 = read_decisions(decisions_path)
        if len(decisions) != decision_count or actual_sha256 != decisions_sha256:
            raise ContractError(
                "CURATION_INVALID",
                "The curation snapshot does not match the decision file.",
                "curation_snapshot",
                3,
            )
    return CurationSnapshot(
        snapshot_id=_bounded(value["id"], "curation_snapshot.id", 128),
        decision_count=decision_count,
        decisions_sha256=decisions_sha256,
        scope=_bounded(value["scope"], "curation_snapshot.scope", 256),
        snapshot_sha256=sha256_bytes(raw),
        decisions=decisions,
    )


def decision_lookup(
    snapshot: CurationSnapshot,
) -> dict[tuple[str, str, str, str], str]:
    """Map (form, system, release, code) to its latest decision state."""

    resolved: dict[tuple[str, str, str, str], str] = {}
    for decision in snapshot.decisions:
        key = (
            decision.primary_normalized_form,
            decision.system_uri,
            decision.release_id,
            decision.code,
        )
        resolved[key] = "curator_accepted" if decision.decision == "accepted" else "curator_rejected"
    return resolved
