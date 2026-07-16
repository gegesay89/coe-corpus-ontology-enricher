from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class Issue:
    code: str
    severity: str
    check_id: str
    safe_message: str
    relative_location: str | None = None

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "check_id": self.check_id,
            "code": self.code,
            "safe_message": self.safe_message,
            "severity": self.severity,
        }
        if self.relative_location is not None:
            result["relative_location"] = self.relative_location
        return result


@dataclass(frozen=True, slots=True)
class PreflightReport:
    kind: str
    status: str
    subject_id: str | None = None
    manifest_sha256: str | None = None
    content_set_sha256: str | None = None
    checked_files: int = 0
    measurements: dict[str, int | str] = field(default_factory=dict)
    issues: tuple[Issue, ...] = ()
    report_schema_version: str = "1.0.0"

    @property
    def passed(self) -> bool:
        return self.status == "passed"

    def as_dict(self) -> dict[str, Any]:
        return {
            "checked_files": self.checked_files,
            "content_set_sha256": self.content_set_sha256,
            "issues": [issue.as_dict() for issue in self.issues],
            "kind": self.kind,
            "manifest_sha256": self.manifest_sha256,
            "measurements": dict(sorted(self.measurements.items())),
            "report_schema_version": self.report_schema_version,
            "status": self.status,
            "subject_id": self.subject_id,
        }
