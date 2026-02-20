from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from typing import Any, Iterable

from miskzi_ciphers.common.types import Cipher


@dataclass(frozen=True)
class CipherRef:
    """Ссылка на фабрику шифра."""
    name: str
    module: str  # e.g. "miskzi_ciphers.ciphers.caesar.cipher"


class CipherRegistry:
    def __init__(self, refs: Iterable[CipherRef]) -> None:
        self._refs: dict[str, CipherRef] = {r.name: r for r in refs}

    def list_names(self) -> list[str]:
        return sorted(self._refs.keys())

    def has(self, name: str) -> bool:
        return name in self._refs

    def load(self, name: str) -> Cipher:
        if name not in self._refs:
            known = ", ".join(self.list_names()) or "<none>"
            raise ValueError(f"Unknown cipher '{name}'. Known: {known}")

        ref = self._refs[name]
        mod = import_module(ref.module)

        if not hasattr(mod, "get_cipher"):
            raise ImportError(f"Module '{ref.module}' must export get_cipher().")

        obj = mod.get_cipher()
        self._validate_cipher(obj, expected_name=ref.name, module=ref.module)
        return obj  # type: ignore[return-value]

    @staticmethod
    def _validate_cipher(obj: Any, expected_name: str, module: str) -> None:
        missing: list[str] = []

        # обязательные атрибуты / методы
        if not hasattr(obj, "name"):
            missing.append("name")
        for m in ("encrypt", "decrypt", "describe", "parse_key"):
            if not hasattr(obj, m) or not callable(getattr(obj, m)):
                missing.append(m)

        if missing:
            raise TypeError(
                f"Cipher from '{module}' is missing required members: {', '.join(missing)}"
            )

        # проверка имени
        name = getattr(obj, "name", None)
        if not isinstance(name, str) or not name.strip():
            raise TypeError(f"Cipher from '{module}' has invalid 'name': {name!r}")

        if name != expected_name:
            raise TypeError(
                f"Cipher name mismatch for '{module}': expected '{expected_name}', got '{name}'"
            )

        # describe() должна возвращать dict-подобные
        info = obj.describe()
        if not isinstance(info, dict):
            raise TypeError(f"{expected_name}.describe() must return dict, got {type(info).__name__}")


# Статический реестр (ручной список). Позже можно заменить на автодискавери.
REGISTRY = CipherRegistry(
    refs=[
        CipherRef("book_cipher", "miskzi_ciphers.ciphers.book_cipher.cipher"),
        CipherRef("scytale", "miskzi_ciphers.ciphers.scytale.cipher"),
        CipherRef("polybius", "miskzi_ciphers.ciphers.polybius.cipher"),
        CipherRef("magic_square", "miskzi_ciphers.ciphers.magic_square.cipher"),
        CipherRef("caesar", "miskzi_ciphers.ciphers.caesar.cipher"),
        CipherRef("atbash", "miskzi_ciphers.ciphers.atbash.cipher"),
    ]
)


def load_cipher(name: str) -> Cipher:
    return REGISTRY.load(name)


def list_ciphers() -> list[str]:
    return REGISTRY.list_names()
