from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, TypedDict, Literal

Key = dict[str, Any]

class ParamSpec(TypedDict, total=False):
    name: str
    type: str            # "int" | "str" | "enum" | "bool" | "path" | ...
    required: bool
    default: Any
    choices: list[Any]
    help: str
    example: Any

class CipherInfo(TypedDict, total=False):
    name: str
    title: str
    family: str
    params: list[ParamSpec]
    notes: str

class Cipher(Protocol):
    name: str

    def describe(self) -> CipherInfo: ...
    def parse_key(self, raw_key: Key) -> Key: ...

    def encrypt(self, plaintext: str, key: Key) -> str: ...
    def decrypt(self, ciphertext: str, key: Key) -> str: ...

@dataclass(frozen=True)
class Variant:
    id: int
    mode: Literal["encrypt", "decrypt"]
    text: str
    key: Key
    expected: str | None = None
