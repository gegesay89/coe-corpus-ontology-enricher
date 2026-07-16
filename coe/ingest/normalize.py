from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

_WHITESPACE = re.compile(r"\s+")


@dataclass(frozen=True, slots=True)
class ReversibleLexicalForm:
    primary: str
    folded: str
    transformations: tuple[str, ...]
    original: str = field(repr=False)

    def restore(self) -> str:
        return self.original


def normalize_lexical(text: str) -> ReversibleLexicalForm:
    primary = unicodedata.normalize("NFC", text)
    transformations: list[str] = []
    if primary != text:
        transformations.append("unicode_nfc")
    collapsed = _WHITESPACE.sub(" ", primary).strip()
    if collapsed != primary:
        transformations.append("collapse_whitespace")
    folded = unicodedata.normalize("NFC", collapsed.casefold())
    if folded != collapsed:
        transformations.append("unicode_casefold_variant")
    return ReversibleLexicalForm(
        original=text,
        primary=collapsed,
        folded=folded,
        transformations=tuple(transformations),
    )
