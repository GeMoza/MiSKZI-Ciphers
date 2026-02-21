from __future__ import annotations

from miskzi_ciphers.common.keyparse import reject_unknown_keys
from miskzi_ciphers.common.types import CipherInfo, Key

# TODO: Verify/adjust pairs according to approved project table if it differs.
LITOREA_PAIRS = [
    ("Б", "Щ"),
    ("В", "Ш"),
    ("Г", "Ч"),
    ("Д", "Ц"),
    ("Ж", "Х"),
    ("З", "Ф"),
    ("К", "Т"),
    ("Л", "С"),
    ("М", "Р"),
    ("Н", "П"),
]

MAP_UPPER: dict[str, str] = {}
for a, b in LITOREA_PAIRS:
    MAP_UPPER[a] = b
    MAP_UPPER[b] = a

VOWELS = set("АЕЁИОУЫЭЮЯ")


class LitoreaCipher:
    name = "litorea"

    def describe(self) -> CipherInfo:
        return {
            "name": self.name,
            "title": "Простая литорея",
            "family": "substitution",
            "params": [],
            "notes": "Фиксированная таблица пар согласных; гласные и прочие символы не меняются.",
        }

    def parse_key(self, raw_key: Key) -> Key:
        reject_unknown_keys(raw_key, allowed=[], cipher=self.name)
        return {}

    def encrypt(self, plaintext: str, key: Key) -> str:
        return self._xform(plaintext)

    def decrypt(self, ciphertext: str, key: Key) -> str:
        return self._xform(ciphertext)

    def _xform(self, text: str) -> str:
        out: list[str] = []
        for ch in text:
            up = ch.upper()
            if up in VOWELS:
                out.append(ch)
                continue
            mapped = MAP_UPPER.get(up)
            if mapped is None:
                out.append(ch)
                continue
            out.append(mapped if ch.isupper() else mapped.lower())
        return "".join(out)


def get_cipher() -> LitoreaCipher:
    return LitoreaCipher()
