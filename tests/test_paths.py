from __future__ import annotations

from pathlib import Path

import pytest

from miskzi_ciphers.common.paths import find_project_root, get_data_dir


def test_find_project_root_from_tests_dir() -> None:
    root = find_project_root(Path(__file__).resolve())
    assert root is not None
    assert (root / "pyproject.toml").exists()


def test_get_data_dir_from_explicit_cwd() -> None:
    data_dir = get_data_dir(Path(__file__).resolve().parents[1])
    assert data_dir.name == "data"
    assert (data_dir / "caesar" / "variants.json").exists()


def test_get_data_dir_from_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    env_data = tmp_path / "custom_data"
    env_data.mkdir()
    monkeypatch.setenv("MISKZI_DATA_DIR", str(env_data))
    assert get_data_dir() == env_data.resolve()


def test_get_data_dir_from_bad_env_raises(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    missing = tmp_path / "missing_data"
    monkeypatch.setenv("MISKZI_CIPHERS_DATA_DIR", str(missing))
    with pytest.raises(FileNotFoundError):
        get_data_dir()
