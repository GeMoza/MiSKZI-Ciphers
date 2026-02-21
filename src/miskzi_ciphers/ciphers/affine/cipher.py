from __future__ import annotations

from miskzi_ciphers.common.alphabet import RU_33, build_index
from miskzi_ciphers.common.keyparse import as_int, reject_unknown_keys, require
from miskzi_ciphers.common.math_utils import gcd, modinv
from miskzi_ciphers.common.types import CipherInfo, Key


class AffineCipher:
    name = "affine"

    def describe(self) -> CipherInfo:
        return {
            "name": self.name,
            "title": "Аффинный шифр",
            "family": "substitution",
            "params": [
                {"name": "a", "type": "int", "required": True, "help": "Коэффициент a", "example": 5},
                {"name": "b", "type": "int", "required": True, "help": "Смещение b", "example": 3},
            ],
        }

    def parse_key(self, raw_key: Key) -> Key:
        reject_unknown_keys(raw_key, allowed=["a", "b"], cipher=self.name)
        m = len(RU_33)
        a = as_int(require(raw_key, "a"), "a") % m
        b = as_int(require(raw_key, "b"), "b") % m
        if gcd(a, m) != 1:
            raise ValueError(f"affine: key 'a' must be coprime with {m}, got a={a}.")
        return {"a": a, "b": b, "m": m, "a_inv": modinv(a, m)}

    def encrypt(self, plaintext: str, key: Key) -> str:
        return self._xform(plaintext, key=key, decrypt=False)

    def decrypt(self, ciphertext: str, key: Key) -> str:
        return self._xform(ciphertext, key=key, decrypt=True)

    def _xform(self, text: str, *, key: Key, decrypt: bool) -> str:
        idx = build_index(RU_33)
        a = key["a"]
        b = key["b"]
        a_inv = key["a_inv"]
        m = key["m"]

        out: list[str] = []
        for ch in text:
            up = ch.upper()
            x = idx.get(up)
            if x is None:
                out.append(ch)
                continue

            if decrypt:
                y = (a_inv * (x - b)) % m
            else:
                y = (a * x + b) % m
            mapped = RU_33[y]
            out.append(mapped if ch.isupper() else mapped.lower())
        return "".join(out)


def get_cipher() -> AffineCipher:
    return AffineCipher()
