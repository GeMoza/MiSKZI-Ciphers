from __future__ import annotations

from functools import lru_cache
from types import MappingProxyType
from typing import Callable

RU_33 = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"


@lru_cache(maxsize=32)
def _cached_index(alphabet: str) -> MappingProxyType[str, int]:
    """Build and cache symbol->index mapping for alphabets with unique characters."""
    index: dict[str, int] = {}
    for i, ch in enumerate(alphabet):
        if ch in index:
            raise ValueError(f"alphabet contains duplicate symbol: {ch!r}")
        index[ch] = i
    return MappingProxyType(index)


def build_index(alphabet: str) -> MappingProxyType[str, int]:
    """Return cached symbol->index mapping. Returned mapping must not be mutated."""
    return _cached_index(alphabet)


def normalize(text: str, *, to_upper: bool = True) -> str:
    """Normalize text case without removing any characters."""
    return text.upper() if to_upper else text


def shift_char(ch: str, *, alphabet: str, k: int) -> str | None:
    """Shift one symbol by k within alphabet, or return None if symbol is outside alphabet."""
    idx = _cached_index(alphabet).get(ch)
    if idx is None:
        return None
    return alphabet[(idx + k) % len(alphabet)]


def map_text(
    text: str,
    *,
    alphabet: str,
    fn: Callable[[str], str | None],
    keep_unknown: bool = True,
) -> str:
    """Map text symbol-by-symbol using fn; optionally keep original symbols for None results."""
    _ = alphabet  # reserved for future alphabet-aware adapters

    out: list[str] = []
    for ch in text:
        mapped = fn(ch)
        if mapped is None:
            if keep_unknown:
                out.append(ch)
            continue
        out.append(mapped)
    return "".join(out)
