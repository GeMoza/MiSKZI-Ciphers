from __future__ import annotations

from common.types import CipherInfo, Key
from common.keyparse import reject_unknown_keys, require, as_int

RUS = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"


class CaesarCipher:
    name = "caesar"

    def describe(self) -> CipherInfo:
        return {
            "name": self.name,
            "title": "Шифр Цезаря",
            "family": "substitution",
            "params": [
                {
                    "name": "k",
                    "type": "int",
                    "required": True,
                    "help": "Сдвиг по алфавиту",
                    "example": 3,
                },
            ],
        }

    def parse_key(self, raw_key: Key) -> Key:
        reject_unknown_keys(raw_key, allowed=["k"], cipher=self.name)
        k_raw = require(raw_key, "k")
        k = as_int(k_raw, "k") % len(RUS)
        return {"k": k}

    def encrypt(self, plaintext: str, key: Key) -> str:
        k = key["k"]
        return self._shift(plaintext, k)

    def decrypt(self, ciphertext: str, key: Key) -> str:
        k = key["k"]
        return self._shift(ciphertext, -k)

    def _shift(self, s: str, k: int) -> str:
        out = []
        for ch in s:
            up = ch.upper()
            if up in RUS:
                idx = RUS.index(up)
                new = RUS[(idx + k) % len(RUS)]
                out.append(new if ch.isupper() else new.lower())
            else:
                out.append(ch)
        return "".join(out)


def get_cipher() -> CaesarCipher:
    return CaesarCipher()
