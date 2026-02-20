from __future__ import annotations

import math
from miskzi_ciphers.common.keyparse import reject_unknown_keys, require, as_int
from miskzi_ciphers.common.types import CipherInfo, Key


class ScytaleCipher:
    name = "scytale"

    def describe(self) -> CipherInfo:
        return {
            "name": self.name,
            "title": "Скитала (r = число граней)",
            "family": "transposition",
            "params": [
                {"name": "r", "type": "int", "required": True, "help": "Число граней (строк) r.", "example": 3}
            ],
            "notes": (
                "По методичке: текст записывается построчно в таблицу r×c (c=ceil(n/r)). "
                "Шифрограмма читается по столбцам снизу вверх слева направо. "
                "Пустые ячейки в последнем столбце игнорируются."
            ),
        }

    def parse_key(self, raw_key: Key) -> Key:
        reject_unknown_keys(raw_key, allowed=["r"], cipher=self.name)
        r = as_int(require(raw_key, "r"), "r")
        if r < 2:
            raise ValueError("scytale: key 'r' must be >= 2")
        return {"r": r}

    def encrypt(self, plaintext: str, key: Key) -> str:
        r = key["r"]
        n = len(plaintext)
        if n == 0:
            return ""

        c = math.ceil(n / r)

        grid: list[list[str | None]] = [[None] * c for _ in range(r)]
        idx = 0
        for i in range(r):
            for j in range(c):
                if idx < n:
                    grid[i][j] = plaintext[idx]
                    idx += 1

        out: list[str] = []
        for j in range(c):              # слева направо по столбцам
            for i in range(r - 1, -1, -1):  # снизу вверх
                ch = grid[i][j]
                if ch is not None:
                    out.append(ch)
        return "".join(out)

    def decrypt(self, ciphertext: str, key: Key) -> str:
        r = key["r"]
        n = len(ciphertext)
        if n == 0:
            return ""

        c = math.ceil(n / r)

        # При заполнении построчно пустые клетки (если есть) находятся в последней строке.
        # Значит:
        # - первые last_row_len столбцов имеют r заполненных клеток
        # - оставшиеся столбцы имеют r-1 заполненных клеток
        last_row_len = n - (r - 1) * c  # сколько символов попало в последнюю строку (1..c)
        if not (1 <= last_row_len <= c):
            raise ValueError("scytale: internal error computing last_row_len")

        col_lens = [r] * last_row_len + [r - 1] * (c - last_row_len)

        grid: list[list[str | None]] = [[None] * c for _ in range(r)]
        idx = 0

        # ciphertext читали: по столбцам слева направо, внутри столбца снизу вверх,
        # но в "коротких" столбцах (где нижняя ячейка была пустой) чтение начиналось с i=r-2.
        for j in range(c):
            filled = col_lens[j]

            # если столбец короткий (r-1), то нижняя строка (r-1) была None при шифровании
            start_i = (r - 1) if filled == r else (r - 2)

            for step in range(filled):
                i = start_i - step
                grid[i][j] = ciphertext[idx]
                idx += 1

        # восстановление plaintext: чтение таблицы построчно слева направо, пропуская None
        out: list[str] = []
        for i in range(r):
            for j in range(c):
                ch = grid[i][j]
                if ch is not None:
                    out.append(ch)
        return "".join(out)


def get_cipher() -> ScytaleCipher:
    return ScytaleCipher()
