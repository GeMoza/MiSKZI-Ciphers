from __future__ import annotations

from miskzi_ciphers.common.alphabet import RU_33, build_index
from miskzi_ciphers.common.keyparse import as_str, reject_unknown_keys, require
from miskzi_ciphers.common.types import CipherInfo, Key


class VigenereCipher:
    name = "vigenere"

    def describe(self) -> CipherInfo:
        return {
            "name": self.name,
            "title": "Шифр Виженера",
            "family": "polyalphabetic",
            "params": [
                {
                    "name": "keyword",
                    "type": "str",
                    "required": True,
                    "help": "Ключевое слово (используются только буквы RU_33)",
                    "example": "КЛЮЧ",
                }
            ],
        }

    def parse_key(self, raw_key: Key) -> Key:
        reject_unknown_keys(raw_key, allowed=["keyword"], cipher=self.name)
        keyword_raw = as_str(require(raw_key, "keyword"), "keyword")
        idx = build_index(RU_33)
        keyword = "".join(ch for ch in keyword_raw.upper() if ch in idx)
        if keyword == "":
            raise ValueError("vigenere: keyword must contain at least one RU_33 letter.")
        return {"keyword": keyword}

    def encrypt(self, plaintext: str, key: Key) -> str:
        return self._xform(plaintext, keyword=key["keyword"], decrypt=False)

    def decrypt(self, ciphertext: str, key: Key) -> str:
        return self._xform(ciphertext, keyword=key["keyword"], decrypt=True)

    def _xform(self, text: str, *, keyword: str, decrypt: bool) -> str:
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

            k = idx[keyword[i % len(keyword)]]
            y = (x - k) % m if decrypt else (x + k) % m
            mapped = RU_33[y]
            out.append(mapped if ch.isupper() else mapped.lower())
            i += 1
        return "".join(out)


def get_cipher() -> VigenereCipher:
    return VigenereCipher()
