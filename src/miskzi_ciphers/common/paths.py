from __future__ import annotations

import os
from pathlib import Path

_ENV_KEYS = ("MISKZI_CIPHERS_DATA_DIR", "MISKZI_DATA_DIR", "MISkZI_CIPHERS_DATA_DIR", "MISkZI_DATA_DIR")
_MARKERS = ("pyproject.toml", ".git")


def find_project_root(start: Path) -> Path | None:
    current = start.resolve()
    if current.is_file():
        current = current.parent

    for candidate in (current, *current.parents):
        if any((candidate / marker).exists() for marker in _MARKERS):
            return candidate
    return None


def _data_from_env() -> Path | None:
    for key in _ENV_KEYS:
        value = os.getenv(key)
        if not value:
            continue
        path = Path(value).expanduser().resolve()
        if path.is_dir():
            return path
        raise FileNotFoundError(
            f"{key} is set to '{value}', but this path does not exist or is not a directory."
        )
    return None


def get_data_dir(cwd: Path | None = None) -> Path:
    env_path = _data_from_env()
    if env_path is not None:
        return env_path

    search_start = (cwd or Path.cwd()).resolve()
    root = find_project_root(search_start)
    if root is not None:
        data_dir = root / "data"
        if data_dir.is_dir():
            return data_dir

    package_root = find_project_root(Path(__file__).resolve())
    if package_root is not None:
        data_dir = package_root / "data"
        if data_dir.is_dir():
            return data_dir

    raise FileNotFoundError(
        "Cannot locate 'data' directory. Run from repository root, or set "
        "MISKZI_DATA_DIR=/path/to/data (or MISKZI_CIPHERS_DATA_DIR)."
    )
