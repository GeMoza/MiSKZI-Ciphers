from __future__ import annotations

from miskzi_ciphers.common.keyparse import reject_unknown_keys
from miskzi_ciphers.common.types import CipherInfo, Key


# Таблица 2 (фиксированный квадрат 4x4)
MS = [
    [16, 3, 2, 13],
    [5, 10, 11, 8],
    [9, 6, 7, 12],
    [4, 15, 14, 1],
]
N = 4
SIZE = 16

# число -> (r,c)
POS = {}
for r in range(N):
    for c in range(N):
        POS[MS[r][c]] = (r, c)


class MagicSquareCipher:
    name = "magic_square"

    def describe(self) -> CipherInfo:
        return {
            "name": self.name,
            "title": "Магический квадрат (табл. 2, 16 символов)",
            "family": "transposition",
            "params": [],
            "notes": (
                "По методичке: сообщение длины 16. "
                "Шифрование: буквы нумеруются 1..16 и вписываются в ячейки, где стоит их номер; "
                "шифрограмма читается по строкам. "
                "Дешифрование: шифрограмма вписывается по строкам; читается по возрастанию чисел."
            ),
        }

    def parse_key(self, raw_key: Key) -> Key:
        reject_unknown_keys(raw_key, allowed=[], cipher=self.name)
        return {}

    @staticmethod
    def _norm_text(s: str) -> str:
        # В PDF варианты иногда визуально с пробелом/переносом — убираем whitespace.
        return "".join(ch for ch in s if not ch.isspace())

    def encrypt(self, plaintext: str, key: Key) -> str:
        s = self._norm_text(plaintext)
        if len(s) != SIZE:
            raise ValueError(f"magic_square: plaintext must have length {SIZE}, got {len(s)}")
        grid = [[""] * N for _ in range(N)]
        for i, ch in enumerate(s, start=1):
            r, c = POS[i]
            grid[r][c] = ch
        return "".join("".join(row) for row in grid)

    def decrypt(self, ciphertext: str, key: Key) -> str:
        s = self._norm_text(ciphertext)
        if len(s) != SIZE:
            raise ValueError(f"magic_square: ciphertext must have length {SIZE}, got {len(s)}")
        # заполнение по строкам
        grid = [[None] * N for _ in range(N)]
        idx = 0
        for r in range(N):
            for c in range(N):
                grid[r][c] = s[idx]
                idx += 1
        # чтение по возрастанию чисел 1..16
        out = []
        for num in range(1, SIZE + 1):
            r, c = POS[num]
            out.append(grid[r][c])
        return "".join(out)


def get_cipher() -> MagicSquareCipher:
    return MagicSquareCipher()
