from __future__ import annotations

from pathlib import Path

import pytest

from coe.demo import create_demo


@pytest.fixture
def demo_root(tmp_path: Path) -> Path:
    root = tmp_path / "demo"
    create_demo(root)
    return root
