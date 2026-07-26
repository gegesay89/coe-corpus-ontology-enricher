from __future__ import annotations

from subprocess import CompletedProcess

import pytest

from coe.errors import ContractError
from coe.runtime import doctor


def test_probe_is_sanitized_when_no_gpu(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor.shutil, "which", lambda _: None)
    report = doctor.probe_host()
    assert report["exact_matching_device"] == "cpu"
    assert report["nvidia"]["device_count"] == 0  # type: ignore[index]
    serialized = repr(report).casefold()
    for prohibited in ("hostname", "username", "serial", "ip_address", "patient_path"):
        assert prohibited not in serialized


def test_probe_requires_gpu_without_silent_cpu_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor.shutil, "which", lambda _: None)
    with pytest.raises(ContractError, match="No usable NVIDIA GPU") as captured:
        doctor.probe_host(require_nvidia=True)
    assert captured.value.code == "NVIDIA_GPU_REQUIRED"


def test_probe_parses_nvidia_devices(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor.shutil, "which", lambda _: "nvidia-smi")
    monkeypatch.setattr(
        doctor.subprocess,
        "run",
        lambda *args, **kwargs: CompletedProcess(
            args=args,
            returncode=0,
            stdout="NVIDIA RTX 6000 Ada Generation, 49140, 576.12, 8.9\n",
            stderr="",
        ),
    )
    report = doctor.probe_host(require_nvidia=True)
    assert report["gpu_semantic_stage"] == "reserved_not_implemented"
    devices = report["nvidia"]["devices"]  # type: ignore[index]
    assert devices[0]["memory_total_mib"] == 49140  # type: ignore[index]
