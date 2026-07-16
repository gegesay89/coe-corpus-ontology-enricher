"""Cross-platform host checks that deliberately exclude machine identity and data paths."""

from __future__ import annotations

import platform
import shutil
import subprocess
from dataclasses import dataclass

from coe.canonical import JsonValue
from coe.errors import ContractError

_NVIDIA_QUERY = (
    "name,memory.total,driver_version,compute_cap",
    "name,memory.total,driver_version",
)


@dataclass(frozen=True, slots=True)
class NvidiaDevice:
    name: str
    memory_total_mib: int
    driver_version: str
    compute_capability: str | None = None

    def as_dict(self) -> dict[str, JsonValue]:
        return {
            "compute_capability": self.compute_capability,
            "driver_version": self.driver_version,
            "memory_total_mib": self.memory_total_mib,
            "name": self.name,
        }


def _query_nvidia() -> tuple[NvidiaDevice, ...]:
    executable = shutil.which("nvidia-smi")
    if executable is None:
        return ()
    for fields in _NVIDIA_QUERY:
        try:
            completed = subprocess.run(
                [
                    executable,
                    f"--query-gpu={fields}",
                    "--format=csv,noheader,nounits",
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        devices: list[NvidiaDevice] = []
        expected = 4 if "compute_cap" in fields else 3
        valid = True
        for row in completed.stdout.splitlines():
            parts = [part.strip() for part in row.split(",")]
            if len(parts) != expected:
                valid = False
                break
            try:
                memory = int(parts[1])
            except ValueError:
                valid = False
                break
            devices.append(
                NvidiaDevice(
                    name=parts[0],
                    memory_total_mib=memory,
                    driver_version=parts[2],
                    compute_capability=parts[3] if expected == 4 else None,
                )
            )
        if valid and devices:
            return tuple(devices)
    return ()


def probe_host(*, require_nvidia: bool = False) -> dict[str, JsonValue]:
    """Return a support-safe capability report without hostnames, users, serials, IPs, or paths."""

    devices = _query_nvidia()
    if require_nvidia and not devices:
        raise ContractError(
            "NVIDIA_GPU_REQUIRED",
            "No usable NVIDIA GPU was detected by nvidia-smi; GPU-required execution was not started.",
            "runtime",
            4,
        )
    return {
        "architecture": platform.machine(),
        "exact_matching_device": "cpu",
        "gpu_semantic_stage": "available" if devices else "unavailable",
        "nvidia": {
            "device_count": len(devices),
            "devices": [device.as_dict() for device in devices],
            "nvidia_smi_available": bool(devices),
        },
        "operating_system": platform.system(),
        "python_version": platform.python_version(),
        "runtime_probe_schema_version": "1.0.0",
        "status": "passed",
    }
