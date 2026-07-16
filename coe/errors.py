"""Stable, sanitized errors used by contracts and the CLI."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class CoeError(Exception):
    code: str
    safe_message: str
    relative_location: str | None = None
    exit_code: int = 3

    def __str__(self) -> str:
        return f"{self.code}: {self.safe_message}"


class ContractError(CoeError):
    """An input failed a versioned contract or integrity check."""


class OutputExistsError(CoeError):
    def __init__(self) -> None:
        super().__init__(
            "OUTPUT_EXISTS",
            "The output directory already exists; pass --overwrite explicitly.",
            exit_code=4,
        )
