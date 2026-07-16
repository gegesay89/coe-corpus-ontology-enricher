from __future__ import annotations

import pytest

from coe.canonical import canonical_json_bytes, load_json_bytes, normalized_relative_path
from coe.errors import ContractError


def test_canonical_json_is_order_independent() -> None:
    assert canonical_json_bytes({"b": 2, "a": 1}) == b'{"a":1,"b":2}'


def test_duplicate_json_key_fails_closed() -> None:
    with pytest.raises(ContractError, match="DUPLICATE_JSON_KEY"):
        load_json_bytes(b'{"a":1,"a":2}', "fixture.json")


def test_floating_point_contract_value_is_rejected() -> None:
    with pytest.raises(ContractError, match="SCHEMA_INVALID"):
        load_json_bytes(b'{"score":0.5}', "fixture.json")


@pytest.mark.parametrize("path", ("../secret", "/absolute", "documents\\unsafe.txt"))
def test_unsafe_relative_paths_are_rejected(path: str) -> None:
    with pytest.raises(ContractError, match="PATH_INVALID"):
        normalized_relative_path(path)
