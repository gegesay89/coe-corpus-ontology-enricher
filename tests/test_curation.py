from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from coe.curation import append_decision, load_snapshot, read_decisions, write_snapshot
from coe.demo import create_demo
from coe.errors import ContractError
from coe.pipeline import run_v0


def _decide(path: Path, form: str, code: str, decision: str, sequence_curator: str = "curator-1") -> None:
    append_decision(
        path,
        primary_normalized_form=form,
        system_uri="urn:example:system",
        release_id="00000000-0000-4000-8000-000000000001",
        code=code,
        decision=decision,
        curator=sequence_curator,
    )


def test_decision_chain_is_hash_linked_and_tamper_evident(tmp_path: Path) -> None:
    decisions = tmp_path / "decisions.jsonl"
    _decide(decisions, "alpha finding", "U1", "accepted")
    _decide(decisions, "beta finding", "U2", "rejected")

    parsed, _ = read_decisions(decisions)
    assert [decision.sequence for decision in parsed] == [1, 2]
    assert parsed[0].decision == "accepted"
    assert parsed[1].decision == "rejected"

    # Tampering with the first row breaks the chain for the second.
    lines = decisions.read_bytes().split(b"\n")
    tampered = lines[0].replace(b"alpha finding", b"gamma finding")
    decisions.write_bytes(b"\n".join([tampered, *lines[1:]]))
    with pytest.raises(ContractError) as caught:
        read_decisions(decisions)
    assert caught.value.code == "CURATION_INVALID"


def test_snapshot_pins_decisions_and_detects_divergence(tmp_path: Path) -> None:
    decisions = tmp_path / "decisions.jsonl"
    _decide(decisions, "alpha finding", "U1", "accepted")
    snapshot_path = tmp_path / "snapshot.json"
    value = write_snapshot(snapshot_path, decisions, snapshot_id="review-1", scope="unit-test")
    assert value["decision_count"] == 1

    loaded = load_snapshot(snapshot_path, decisions)
    assert loaded.snapshot_id == "review-1"
    assert loaded.decisions[0].code == "U1"

    _decide(decisions, "beta finding", "U2", "rejected")
    with pytest.raises(ContractError) as caught:
        load_snapshot(snapshot_path, decisions)
    assert caught.value.code == "CURATION_INVALID"


def _demo_run(tmp_path: Path, curation_snapshot: str, decisions: Path | None, tag: str = "a") -> Path:
    demo = tmp_path / f"demo-{tag}"
    create_demo(demo)
    output = tmp_path / f"run-output-{tag}"
    run_v0(
        snapshot_path=demo / "snapshot",
        reference_paths=(demo / "reference",),
        config_path=demo / "coe_config.json",
        curation_snapshot=curation_snapshot,
        output_path=output,
        curation_decisions=decisions,
        overwrite=True,
    )
    return output


def test_run_applies_curation_decisions_to_candidate_sets(tmp_path: Path) -> None:
    baseline = _demo_run(tmp_path, "genesis-v0", None)
    rows = [json.loads(line) for line in (baseline / "candidate_sets.jsonl").read_text(encoding="utf-8").splitlines()]
    grounded = [row for row in rows if row["algorithmic_outcome"] == "grounded_unique"]
    assert grounded, "the demo must produce at least one grounded candidate set"
    target = grounded[0]

    decisions = tmp_path / "decisions.jsonl"
    append_decision(
        decisions,
        primary_normalized_form=target["primary_normalized_form"],
        system_uri=target["system_uri"],
        release_id=target["release_id"],
        code=target["candidates"][0]["code"],
        decision="accepted",
        curator="curator-1",
    )
    snapshot_path = tmp_path / "snapshot.json"
    write_snapshot(snapshot_path, decisions, snapshot_id="review-1", scope="demo")

    curated = _demo_run(tmp_path, str(snapshot_path), decisions, tag="b")
    curated_rows = [
        json.loads(line) for line in (curated / "candidate_sets.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    states = {(row["primary_normalized_form"], row["system_uri"]): row["acceptance_state"] for row in curated_rows}
    assert states[(target["primary_normalized_form"], target["system_uri"])] == "curator_accepted"

    manifest = json.loads((curated / "run_manifest.json").read_text(encoding="utf-8"))
    assert manifest["curation_snapshot"]["id"] == "review-1"

    baseline_manifest = json.loads((baseline / "run_manifest.json").read_text(encoding="utf-8"))
    assert manifest["run_fingerprint"] != baseline_manifest["run_fingerprint"]


def test_curation_cli_records_and_snapshots(tmp_path: Path) -> None:
    project = Path(__file__).resolve().parents[1]
    decisions = tmp_path / "decisions.jsonl"
    recorded = subprocess.run(
        [
            sys.executable,
            "-m",
            "coe",
            "curation",
            "decide",
            "--decisions",
            str(decisions),
            "--form",
            "alpha finding",
            "--system",
            "urn:example:system",
            "--release",
            "00000000-0000-4000-8000-000000000001",
            "--code",
            "U1",
            "--decision",
            "accepted",
            "--curator",
            "curator-1",
        ],
        cwd=project,
        check=False,
        capture_output=True,
        text=True,
    )
    assert recorded.returncode == 0, recorded.stdout
    assert json.loads(recorded.stdout)["status"] == "recorded"

    snapshot = subprocess.run(
        [
            sys.executable,
            "-m",
            "coe",
            "curation",
            "snapshot",
            "--decisions",
            str(decisions),
            "--id",
            "review-1",
            "--scope",
            "cli-test",
            "--output",
            str(tmp_path / "snapshot.json"),
        ],
        cwd=project,
        check=False,
        capture_output=True,
        text=True,
    )
    assert snapshot.returncode == 0, snapshot.stdout
    assert json.loads(snapshot.stdout)["decision_count"] == 1
