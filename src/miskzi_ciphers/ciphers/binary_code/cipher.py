from __future__ import annotations

from miskzi_ciphers.common.alphabet import RU_33, build_index
from miskzi_ciphers.common.keyparse import reject_unknown_keys
from miskzi_ciphers.common.types import CipherInfo, Key


class BinaryCodeCipher:
    name = "binary_code"

    def describe(self) -> CipherInfo:
        return {
            "name": self.name,
            "title": "Двоичный код (номер буквы RU_33)",
            "family": "encoding",
            "params": [],
        }

    def parse_key(self, raw_key: Key) -> Key:
        reject_unknown_keys(raw_key, allowed=[], cipher=self.name)
        return {}

    def encrypt(self, plaintext: str, key: Key) -> str:
        idx = build_index(RU_33)
        groups: list[str] = []
        for ch in plaintext:
            if ch in (" ", "\t", "\n", "\r"):
                continue
            up = ch.upper()
            pos = idx.get(up)
            if pos is None:
                raise ValueError(f"binary_code: plaintext contains unsupported character: {ch!r}")
            groups.append(format(pos + 1, "08b"))
        return " ".join(groups)

    def decrypt(self, ciphertext: str, key: Key) -> str:
        if ciphertext.strip() == "":
            return ""

        out: list[str] = []
        for grp in ciphertext.split():
            if any(ch not in "01" for ch in grp):
                raise ValueError(f"binary_code: invalid bit group {grp!r}")
            if len(grp) > 8:
                raise ValueError(f"binary_code: bit group too long ({len(grp)} > 8): {grp!r}")
            padded = grp.rjust(8, "0")
            n = int(padded, 2)
            if not (1 <= n <= len(RU_33)):
                raise ValueError(f"binary_code: decoded value out of RU_33 range: {n}")
            out.append(RU_33[n - 1])
        return "".join(out)


def get_cipher() -> BinaryCodeCipher:
    return BinaryCodeCipher()
