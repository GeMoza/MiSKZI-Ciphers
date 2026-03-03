from __future__ import annotations

import re

from miskzi_ciphers.common.keyparse import reject_unknown_keys, require
from miskzi_ciphers.common.types import CipherInfo, Key


class RichelieuCipher:
    name = "richelieu"

    def describe(self) -> CipherInfo:
        return {
            "name": self.name,
            "title": "Шифр Ришелье",
            "family": "transposition",
            "params": [
                {"name": "key", "type": "str", "required": True, "help": "Нотация вида (4213)(51243)", "example": "(4213)"},
                {
                    "name": "permutations",
                    "type": "json",
                    "required": False,
                    "help": "Список перестановок, например [[4,2,1,3],[5,1,2,4,3]]",
                },
            ],
            "notes": "Перестановка задает порядок извлечения символов из блока: (4213) => 4-й,2-й,1-й,3-й.",
        }

    def parse_key(self, raw_key: Key) -> Key:
        reject_unknown_keys(raw_key, allowed=["key", "permutations"], cipher=self.name)
        perms_raw = raw_key.get("permutations")
        if "key" in raw_key:
            perms_raw = self._parse_notation(str(require(raw_key, "key")))
        if perms_raw is None:
            raise ValueError("richelieu: provide 'key' or 'permutations'.")

        if not isinstance(perms_raw, list):
            raise ValueError("richelieu: 'permutations' must be a list of integer lists.")

        perms: list[list[int]] = []
        for i, block in enumerate(perms_raw):
            if not isinstance(block, list):
                raise ValueError(f"richelieu: permutations[{i}] must be a list.")
            perm = [int(v) for v in block]
            self._validate_perm(perm)
            perms.append(perm)
        return {"permutations": perms}

    def encrypt(self, plaintext: str, key: Key) -> str:
        return self._transform(plaintext, key["permutations"], decrypt=False)

    def decrypt(self, ciphertext: str, key: Key) -> str:
        return self._transform(ciphertext, key["permutations"], decrypt=True)

    def _transform(self, text: str, perms: list[list[int]], *, decrypt: bool) -> str:
        expected = sum(len(p) for p in perms)
        if len(text) != expected:
            raise ValueError(f"richelieu: text length ({len(text)}) must equal sum of block sizes ({expected}).")

        pos = 0
        out: list[str] = []
        for perm in perms:
            block = text[pos : pos + len(perm)]
            pos += len(perm)
            if decrypt:
                out.append(self._apply_inverse(block, perm))
            else:
                out.append("".join(block[p - 1] for p in perm))
        return "".join(out)

    @staticmethod
    def _apply_inverse(block: str, perm: list[int]) -> str:
        restored = [""] * len(perm)
        for i, p in enumerate(perm):
            restored[p - 1] = block[i]
        return "".join(restored)

    @staticmethod
    def _parse_notation(value: str) -> list[list[int]]:
        groups = re.findall(r"\((\d+)\)", value.replace(" ", ""))
        if not groups:
            raise ValueError("richelieu: key must use notation like '(4213)(51243)'.")
        return [[int(ch) for ch in group] for group in groups]

    @staticmethod
    def _validate_perm(perm: list[int]) -> None:
        k = len(perm)
        if k < 2:
            raise ValueError("richelieu: each permutation must contain at least 2 items.")
        if sorted(perm) != list(range(1, k + 1)):
            raise ValueError(f"richelieu: invalid permutation {perm}; expected numbers 1..{k} without duplicates.")


def get_cipher() -> RichelieuCipher:
    return RichelieuCipher()
