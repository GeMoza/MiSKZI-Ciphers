from __future__ import annotations

from miskzi_ciphers.common.alphabet import RU_33, build_index
from miskzi_ciphers.common.keyparse import as_bool, as_str, optional, reject_unknown_keys, require
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
                },
                {
                    "name": "one_based",
                    "type": "bool",
                    "required": False,
                    "help": "Сдвиг по ключу как index+1 вместо index",
                    "example": False,
                }
            ],
        }

    def parse_key(self, raw_key: Key) -> Key:
        reject_unknown_keys(raw_key, allowed=["keyword", "one_based"], cipher=self.name)
        keyword_raw = as_str(require(raw_key, "keyword"), "keyword")
        one_based = as_bool(optional(raw_key, "one_based", False), "one_based")
        idx = build_index(RU_33)
        keyword = "".join(ch for ch in keyword_raw.upper() if ch in idx)
        if keyword == "":
            raise ValueError("vigenere: keyword must contain at least one RU_33 letter.")
        return {"keyword": keyword, "one_based": one_based}

    def encrypt(self, plaintext: str, key: Key) -> str:
        return self._xform(plaintext, keyword=key["keyword"], one_based=key.get("one_based", False), decrypt=False)

    def decrypt(self, ciphertext: str, key: Key) -> str:
        return self._xform(ciphertext, keyword=key["keyword"], one_based=key.get("one_based", False), decrypt=True)

    def _xform(self, text: str, *, keyword: str, one_based: bool, decrypt: bool) -> str:
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
            shift = (k + 1) % m if one_based else k
            y = (x - shift) % m if decrypt else (x + shift) % m
            mapped = RU_33[y]
            out.append(mapped if ch.isupper() else mapped.lower())
            i += 1
        return "".join(out)


def get_cipher() -> VigenereCipher:
    return VigenereCipher()
