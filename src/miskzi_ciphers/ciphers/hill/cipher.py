from __future__ import annotations

import json
from collections.abc import Mapping

from miskzi_ciphers.common.alphabet import RU_33, build_index
from miskzi_ciphers.common.keyparse import as_char, reject_unknown_keys, require
from miskzi_ciphers.common.math_utils import gcd, modinv
from miskzi_ciphers.common.types import CipherInfo, Key

MODULUS = 33


class HillCipher:
    name = "hill"

    def describe(self) -> CipherInfo:
        return {
            "name": self.name,
            "title": "???? ?????",
            "family": "polygraphic",
            "params": [
                {"name": "matrix", "type": "json", "required": True, "help": "?????????? ??????? n x n", "example": [[1, 2], [3, 5]]},
                {"name": "pad_char", "type": "str", "required": False, "help": "?????? RU_33 ??? ??????????"},
            ],
            "notes": "?????? ?? mod 33. ??? ????????????? ??????? ?????? ???? ?????????: gcd(det,33)=1.",
        }

    def parse_key(self, raw_key: Key) -> Key:
        reject_unknown_keys(raw_key, allowed=["matrix", "pad_char"], cipher=self.name)
        matrix_raw = require(raw_key, "matrix")
        if isinstance(matrix_raw, str):
            try:
                matrix_raw = json.loads(matrix_raw)
            except Exception as exc:
                raise ValueError("hill: matrix string must be valid JSON list.") from exc
        if not isinstance(matrix_raw, list) or not matrix_raw or not all(isinstance(row, list) for row in matrix_raw):
            raise ValueError("hill: 'matrix' must be a non-empty square list of lists.")

        try:
            matrix: list[list[int]] = [[int(x) for x in row] for row in matrix_raw]
        except (TypeError, ValueError) as exc:
            raise ValueError("hill: matrix elements must be integers.") from exc

        n = len(matrix)
        if n < 2 or any(len(row) != n for row in matrix):
            raise ValueError("hill: matrix must be square n x n with n >= 2.")

        pad_char = raw_key.get("pad_char")
        if pad_char is not None:
            pad_char = as_char(pad_char, "pad_char").upper()
            if pad_char not in build_index(RU_33):
                raise ValueError("hill: pad_char must be a RU_33 symbol.")

        return {"matrix": matrix, "pad_char": pad_char}

    def encrypt(self, plaintext: str, key: Key) -> str:
        matrix = key["matrix"]
        n = len(matrix)
        idx = build_index(RU_33)

        text = plaintext.upper()
        for ch in text:
            if ch not in idx:
                raise ValueError(f"hill: unsupported symbol {ch!r}; only RU_33 letters are allowed.")

        pad_char = key.get("pad_char")
        if len(text) % n != 0:
            if pad_char is None:
                raise ValueError(f"hill: plaintext length ({len(text)}) must be a multiple of matrix size {n}.")
            missing = (-len(text)) % n
            text += pad_char * missing

        return self._apply_matrix(text, matrix)

    def decrypt(self, ciphertext: str, key: Key) -> str:
        if not _is_invertible_mod(key["matrix"], MODULUS):
            raise ValueError("hill: matrix not invertible mod 33.")
        inv = _inverse_matrix_mod(key["matrix"], MODULUS)
        return self._apply_matrix(ciphertext.upper(), inv)

    @staticmethod
    def _apply_matrix(text: str, matrix: list[list[int]]) -> str:
        n = len(matrix)
        idx = build_index(RU_33)
        out: list[str] = []

        for offset in range(0, len(text), n):
            block = text[offset : offset + n]
            vec = [_char_to_hill_value(ch, idx) for ch in block]
            for row in matrix:
                total = sum(row[i] * vec[i] for i in range(n)) % MODULUS
                out.append(_hill_value_to_char(total))
        return "".join(out)


def _determinant(matrix: list[list[int]]) -> int:
    n = len(matrix)
    if n == 1:
        return matrix[0][0]
    if n == 2:
        return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]

    det = 0
    for j in range(n):
        minor = [row[:j] + row[j + 1 :] for row in matrix[1:]]
        det += ((-1) ** j) * matrix[0][j] * _determinant(minor)
    return det


def _inverse_matrix_mod(matrix: list[list[int]], mod: int) -> list[list[int]]:
    n = len(matrix)
    aug = [[matrix[r][c] % mod for c in range(n)] + [1 if r == c else 0 for c in range(n)] for r in range(n)]

    for col in range(n):
        pivot = None
        for row in range(col, n):
            if gcd(aug[row][col], mod) == 1:
                pivot = row
                break
        if pivot is None:
            raise ValueError("hill: matrix not invertible mod 33.")
        if pivot != col:
            aug[col], aug[pivot] = aug[pivot], aug[col]

        inv_pivot = modinv(aug[col][col], mod)
        aug[col] = [(v * inv_pivot) % mod for v in aug[col]]

        for row in range(n):
            if row == col:
                continue
            factor = aug[row][col] % mod
            if factor == 0:
                continue
            aug[row] = [(aug[row][k] - factor * aug[col][k]) % mod for k in range(2 * n)]

    return [row[n:] for row in aug]


def _is_invertible_mod(matrix: list[list[int]], mod: int) -> bool:
    return gcd(_determinant(matrix), mod) == 1


def _char_to_hill_value(ch: str, idx: Mapping[str, int]) -> int:
    return idx[ch] + 1


def _hill_value_to_char(value: int) -> str:
    normalized = value % MODULUS
    if normalized == 0:
        normalized = MODULUS
    return RU_33[normalized - 1]


def get_cipher() -> HillCipher:
    return HillCipher()
