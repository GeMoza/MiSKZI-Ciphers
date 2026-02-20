from __future__ import annotations
from typing import Any, Iterable

def reject_unknown_keys(raw: dict[str, Any], allowed: Iterable[str], *, cipher: str | None = None) -> None:
    allowed_set = set(allowed)
    extra = sorted(k for k in raw.keys() if k not in allowed_set)
    if extra:
        prefix = f"{cipher}: " if cipher else ""
        raise ValueError(f"{prefix}Unknown key(s): {', '.join(extra)}. Allowed: {', '.join(sorted(allowed_set))}")

def require(raw: dict[str, Any], name: str) -> Any:
    if name not in raw:
        raise ValueError(f"Missing key '{name}'.")
    return raw[name]

def optional(raw: dict[str, Any], name: str, default: Any) -> Any:
    return raw.get(name, default)

def as_int(v: Any, name: str) -> int:
    try:
        # JSON может дать int, CLI почти всегда str
        return int(v)
    except Exception:
        raise ValueError(f"Key '{name}' must be int, got {v!r}.")

def as_str(v: Any, name: str) -> str:
    if v is None:
        raise ValueError(f"Key '{name}' must be str, got None.")
    return str(v)

def as_bool(v: Any, name: str) -> bool:
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in ("1", "true", "yes", "y", "on"):
        return True
    if s in ("0", "false", "no", "n", "off"):
        return False
    raise ValueError(f"Key '{name}' must be bool, got {v!r}.")

def as_enum_str(v: Any, name: str, choices: set[str]) -> str:
    s = str(v).strip()
    if s not in choices:
        raise ValueError(f"Key '{name}' must be one of {sorted(choices)}, got {v!r}.")
    return s

def as_enum_int(v: Any, name: str, choices: set[int]) -> int:
    i = as_int(v, name)
    if i not in choices:
        raise ValueError(f"Key '{name}' must be one of {sorted(choices)}, got {v!r}.")
    return i

def as_char(v: Any, name: str) -> str:
    s = as_str(v, name)
    if len(s) != 1:
        raise ValueError(f"Key '{name}' must be a single character, got {v!r}.")
    return s
