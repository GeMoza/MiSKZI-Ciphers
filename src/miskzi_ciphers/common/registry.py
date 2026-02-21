from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
import logging
import pkgutil
from typing import Any, Iterable

import miskzi_ciphers.ciphers as ciphers_pkg

from miskzi_ciphers.common.types import Cipher

logger = logging.getLogger(__name__)


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

        if hasattr(mod, "get_cipher") and callable(mod.get_cipher):
            obj = mod.get_cipher()
        elif hasattr(mod, "CIPHER"):
            obj = mod.CIPHER
        else:
            raise ImportError(f"Module '{ref.module}' must export get_cipher() or CIPHER.")
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


def discover_cipher_modules() -> list[str]:
    """Discover cipher implementation modules under miskzi_ciphers.ciphers.*."""
    modules: list[str] = []
    for item in sorted(pkgutil.iter_modules(ciphers_pkg.__path__), key=lambda x: x.name):
        if not item.ispkg:
            continue
        module_path = f"miskzi_ciphers.ciphers.{item.name}.cipher"
        try:
            mod = import_module(module_path)
        except Exception as exc:  # pragma: no cover - defensive discovery path
            logger.debug("Skipping %s: import failed (%s)", module_path, exc)
            continue

        has_factory = hasattr(mod, "get_cipher") and callable(mod.get_cipher)
        has_instance = hasattr(mod, "CIPHER")
        if has_factory or has_instance:
            modules.append(module_path)
            continue

        logger.debug("Skipping %s: no get_cipher() or CIPHER", module_path)
    return modules


def _build_registry() -> CipherRegistry:
    modules = discover_cipher_modules()
    if not modules:
        raise RuntimeError("No ciphers discovered in package 'miskzi_ciphers.ciphers'.")

    refs = [CipherRef(name=module.split(".")[-2], module=module) for module in modules]
    return CipherRegistry(refs=refs)


REGISTRY = _build_registry()


def load_cipher(name: str) -> Cipher:
    return REGISTRY.load(name)


def list_ciphers() -> list[str]:
    return REGISTRY.list_names()
