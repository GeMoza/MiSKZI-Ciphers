from __future__ import annotations

from miskzi_ciphers.common.alphabet import RU_33
from miskzi_ciphers.common.keyparse import reject_unknown_keys
from miskzi_ciphers.common.types import CipherInfo, Key


RUS_UPPER = RU_33
RUS_LOWER = RUS_UPPER.lower()

MAP_UPPER = {a: b for a, b in zip(RUS_UPPER, reversed(RUS_UPPER))}
MAP_LOWER = {a: b for a, b in zip(RUS_LOWER, reversed(RUS_LOWER))}


class AtbashCipher:
    name = "atbash"

    def describe(self) -> CipherInfo:
        return {
            "name": self.name,
            "title": "Атбаш (русский алфавит)",
            "family": "substitution",
            "params": [],
            "notes": (
                "Атбаш: зеркальная замена букв русского алфавита "
                "(включая Ё). Небуквенные символы сохраняются."
            ),
        }

    def parse_key(self, raw_key: Key) -> Key:
        reject_unknown_keys(raw_key, allowed=[], cipher=self.name)
        return {}

    def encrypt(self, plaintext: str, key: Key) -> str:
        return self._xform(plaintext)

    def decrypt(self, ciphertext: str, key: Key) -> str:
        return self._xform(ciphertext)

    @staticmethod
    def _xform(text: str) -> str:
        out: list[str] = []
        for ch in text:
            if ch in MAP_UPPER:
                out.append(MAP_UPPER[ch])
            elif ch in MAP_LOWER:
                out.append(MAP_LOWER[ch])
            else:
                out.append(ch)
        return "".join(out)


def get_cipher() -> AtbashCipher:
    return AtbashCipher()
