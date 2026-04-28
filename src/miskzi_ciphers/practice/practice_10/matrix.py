from __future__ import annotations

from dataclasses import dataclass

from miskzi_ciphers.practice.common.models import PracticeTable


@dataclass
class KeyedMatrix:
    alphabet: str
    width: int
    rows: list[list[str]]
    positions: dict[str, tuple[int, int]]
    keyed_alphabet: str


def build_keyed_matrix(key: str, alphabet: str, width: int) -> KeyedMatrix:
    if width <= 0:
        raise ValueError("matrix width must be positive.")
    if len(alphabet) % width != 0:
        raise ValueError("alphabet length must be divisible by matrix width.")

    unique_chars: list[str] = []
    seen: set[str] = set()
    for char in key + alphabet:
        if char not in alphabet or char in seen:
            continue
        unique_chars.append(char)
        seen.add(char)

    rows = [unique_chars[start : start + width] for start in range(0, len(unique_chars), width)]
    positions = {
        char: (row_index, column_index)
        for row_index, row in enumerate(rows)
        for column_index, char in enumerate(row)
    }
    return KeyedMatrix(
        alphabet=alphabet,
        width=width,
        rows=rows,
        positions=positions,
        keyed_alphabet="".join(unique_chars),
    )


def matrix_to_practice_table(matrix: KeyedMatrix, title: str = "Playfair matrix") -> PracticeTable:
    return PracticeTable(
        title=title,
        columns=[f"c{column}" for column in range(1, matrix.width + 1)],
        rows=[
            {f"c{column + 1}": char for column, char in enumerate(row)}
            for row in matrix.rows
        ],
    )

