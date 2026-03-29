from __future__ import annotations

import shutil
import sys
import uuid
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture
def tmp_path() -> Path:
    base_dir = Path(__file__).resolve().parents[1] / ".tmp_test_runs"
    base_dir.mkdir(exist_ok=True)
    path = base_dir / f"pytest-{uuid.uuid4().hex}"
    path.mkdir()
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)
