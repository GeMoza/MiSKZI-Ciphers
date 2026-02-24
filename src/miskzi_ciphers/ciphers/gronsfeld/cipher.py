from __future__ import annotations

from miskzi_ciphers.common.alphabet import RU_33, build_index
from miskzi_ciphers.common.keyparse import as_str, optional, reject_unknown_keys
from miskzi_ciphers.common.types import CipherInfo, Key


class GronsfeldCipher:
    name = "gronsfeld"

    def describe(self) -> CipherInfo:
        return {
            "name": self.name,
            "title": "Шифр Гронсфельда",
            "family": "polyalphabetic",
            "params": [
                {
                    "name": "digits",
                    "type": "str",
                    "required": True,
                    "help": "Числовой ключ (используются только цифры 0-9)",
                    "example": "15215",
                }
            ],
        }

    def parse_key(self, raw_key: Key) -> Key:
        reject_unknown_keys(raw_key, allowed=["digits"], cipher=self.name)
        digits_raw = as_str(optional(raw_key, "digits", ""), "digits")
        digits = [int(ch) for ch in digits_raw if ch.isdigit()]
        if not digits:
            raise ValueError("gronsfeld: digits must contain at least one decimal digit.")
        return {"digits": digits}

    def encrypt(self, plaintext: str, key: Key) -> str:
        return self._xform(plaintext, digits=key["digits"], decrypt=False)

    def decrypt(self, ciphertext: str, key: Key) -> str:
        return self._xform(ciphertext, digits=key["digits"], decrypt=True)

    def _xform(self, text: str, *, digits: list[int], decrypt: bool) -> str:
        idx = build_index(RU_33)
        m = len(RU_33)

        out: list[str] = []
        i = 0
        for ch in text:
            up = ch.upper()
            x = idx.get(up)
            if x is None:
                out.append(ch)
                continue

            shift = digits[i % len(digits)]
            y = (x - shift) % m if decrypt else (x + shift) % m
            mapped = RU_33[y]
            out.append(mapped if ch.isupper() else mapped.lower())
            i += 1
        return "".join(out)


def get_cipher() -> GronsfeldCipher:
    return GronsfeldCipher()
