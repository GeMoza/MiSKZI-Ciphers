from __future__ import annotations

from miskzi_ciphers.common.alphabet import RU_33, normalize
from miskzi_ciphers.common.keyparse import as_char, as_enum_str, as_int, as_str, optional, reject_unknown_keys
from miskzi_ciphers.common.types import CipherInfo, Key

CARDANO_MASK_6: tuple[tuple[int, int], ...] = (
    (0, 0),
    (0, 1),
    (0, 2),
    (0, 3),
    (0, 4),
    (1, 1),
    (1, 2),
    (1, 3),
    (2, 2),
)


def _rotate(pos: tuple[int, int], size: int, rotation: str) -> tuple[int, int]:
    r, c = pos
    if rotation == "ccw":
        return size - 1 - c, r
    return c, size - 1 - r


class CardanoGrilleCipher:
    name = "cardano_grille"

    def describe(self) -> CipherInfo:
        return {
            "name": self.name,
            "title": "Решётка Кардано (6x6)",
            "family": "transposition",
            "params": [
                {
                    "name": "size",
                    "type": "int",
                    "required": False,
                    "default": 6,
                    "help": "Размер решётки (поддерживается только 6)",
                    "example": 6,
                },
                {
                    "name": "rotation",
                    "type": "str",
                    "required": False,
                    "default": "ccw",
                    "help": "Направление поворота на 90 градусов: ccw или cw",
                    "example": "ccw",
                },
                {
                    "name": "filler",
                    "type": "str",
                    "required": False,
                    "default": "X",
                    "help": "Символ заполнения для незаполненных ячеек",
                    "example": "А",
                },
                {
                    "name": "mask_id",
                    "type": "str",
                    "required": False,
                    "default": "fig12",
                    "help": "Идентификатор маски отверстий (текущая реализация: fig12)",
                    "example": "fig12",
                },
            ],
        }

    def parse_key(self, raw_key: Key) -> Key:
        reject_unknown_keys(raw_key, allowed=["size", "rotation", "filler", "mask_id"], cipher=self.name)
        size = as_int(optional(raw_key, "size", 6), "size")
        rotation = as_enum_str(optional(raw_key, "rotation", "ccw"), "rotation", {"ccw", "cw"})
        filler = as_char(optional(raw_key, "filler", "X"), "filler")
        mask_id = as_str(optional(raw_key, "mask_id", "fig12"), "mask_id")

        if size != 6:
            raise ValueError("cardano_grille: only size=6 is supported in this version.")
        if mask_id != "fig12":
            raise ValueError("cardano_grille: only mask_id='fig12' is supported.")

        return {"size": size, "rotation": rotation, "filler": filler, "mask_id": mask_id}

    def encrypt(self, plaintext: str, key: Key) -> str:
        size = key["size"]
        rotation = key["rotation"]
        filler = key["filler"]

        matrix: list[list[str]] = [[filler for _ in range(size)] for _ in range(size)]
        data = [ch for ch in normalize(plaintext) if ch in RU_33]
        cursor = 0

        holes = list(CARDANO_MASK_6)
        for _ in range(4):
            for r, c in holes:
                if cursor < len(data):
                    matrix[r][c] = data[cursor]
                    cursor += 1
                else:
                    matrix[r][c] = filler
            holes = [_rotate(pos, size, rotation) for pos in holes]

        return "".join("".join(row) for row in matrix)

    def decrypt(self, ciphertext: str, key: Key) -> str:
        size = key["size"]
        rotation = key["rotation"]

        clean = "".join(ch for ch in ciphertext if not ch.isspace())
        expected_len = size * size
        if len(clean) != expected_len:
            raise ValueError(
                f"cardano_grille: ciphertext length must be {expected_len} (without whitespace), got {len(clean)}."
            )

        matrix = [list(clean[i * size : (i + 1) * size]) for i in range(size)]

        out: list[str] = []
        holes = list(CARDANO_MASK_6)
        for _ in range(4):
            for r, c in holes:
                out.append(matrix[r][c])
            holes = [_rotate(pos, size, rotation) for pos in holes]
        return "".join(out)


def get_cipher() -> CardanoGrilleCipher:
    return CardanoGrilleCipher()
