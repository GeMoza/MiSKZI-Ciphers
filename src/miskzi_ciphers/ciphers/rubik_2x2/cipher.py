from __future__ import annotations

import json
from typing import Any

from miskzi_ciphers.common.alphabet import RU_33
from miskzi_ciphers.common.keyparse import as_int, as_str, reject_unknown_keys
from miskzi_ciphers.common.types import CipherInfo, Key

# PZ-05 uses a fixed unfolded 2x2 net with numbered faces:
#       1
#    2  3  4
#       5
#       6
#
# The implementation keeps this exact educational stencil:
# - plaintext letters are placed into the positions shown in figure 21
# - ciphertext is read from the positions visible in figure 24
# - moves are applied as explicit permutations over the unfolded net

FACE_IDS = {1, 2, 3, 4, 5, 6}
CELL_IDS = ("tl", "tr", "bl", "br")
ALL_POSITIONS = tuple(f"{face}_{cell}" for face in sorted(FACE_IDS) for cell in CELL_IDS)
TEXT_BLOCK_SIZE = 8

CONTROL_MOVES = [
    {"face": 1, "direction": "right", "turns": 1},
    {"face": 3, "direction": "right", "turns": 1},
    {"face": 4, "direction": "right", "turns": 2},
]

# Figure 21: placement of the source text "РТУ МИРЭА" on the unfolded net.
INPUT_STENCIL = (
    "1_tl",
    "1_br",
    "2_tr",
    "3_bl",
    "3_br",
    "4_br",
    "5_bl",
    "6_br",
)

# Figure 24: the same block read after the methodical sequence of turns.
OUTPUT_STENCIL = (
    "1_tl",
    "3_tl",
    "4_tl",
    "4_tr",
    "3_bl",
    "5_tl",
    "5_bl",
    "6_bl",
)

# Figure 22. "Face 1 right" from the methodical unfolded model.
FACE_1_RIGHT = {
    "1_tl": "1_br",
    "1_br": "1_tl",
    "2_tr": "6_bl",
    "6_bl": "2_tr",
    "5_bl": "5_tl",
    "5_tl": "5_bl",
    "6_br": "4_bl",
    "4_bl": "6_br",
}

# Figure 23. "Face 3 right" from the methodical unfolded model.
FACE_3_RIGHT = {
    "3_tl": "3_tr",
    "3_tr": "3_br",
    "3_br": "3_bl",
    "3_bl": "3_tl",
    "1_br": "4_bl",
    "4_bl": "5_tl",
    "5_tl": "5_bl",
    "5_bl": "1_br",
}

# Face rotations that are not independently illustrated in the PDF are kept as
# simple in-face clockwise rotations on the unfolded 2x2 stencil.
FACE_2_RIGHT = {
    "2_tl": "2_tr",
    "2_tr": "2_br",
    "2_br": "2_bl",
    "2_bl": "2_tl",
}
FACE_4_RIGHT = {
    "4_tl": "4_tr",
    "4_tr": "4_br",
    "4_br": "4_bl",
    "4_bl": "4_tl",
}
FACE_5_RIGHT = {
    "5_tl": "5_tr",
    "5_tr": "5_br",
    "5_br": "5_bl",
    "5_bl": "5_tl",
}
FACE_6_RIGHT = {
    "6_tl": "6_tr",
    "6_tr": "6_br",
    "6_br": "6_bl",
    "6_bl": "6_tl",
}

RIGHT_TURN_MAPS = {
    1: FACE_1_RIGHT,
    2: FACE_2_RIGHT,
    3: FACE_3_RIGHT,
    4: FACE_4_RIGHT,
    5: FACE_5_RIGHT,
    6: FACE_6_RIGHT,
}


def _complete_permutation(partial: dict[str, str]) -> dict[str, str]:
    permutation = {position: position for position in ALL_POSITIONS}
    permutation.update(partial)
    return permutation


COMPLETE_RIGHT_TURN_MAPS = {
    face: _complete_permutation(mapping) for face, mapping in RIGHT_TURN_MAPS.items()
}


class Rubik2x2Cipher:
    name = "rubik_2x2"

    def describe(self) -> CipherInfo:
        return {
            "name": self.name,
            "title": "Шифр Рубика 2x2 (ПЗ-05)",
            "family": "transposition",
            "params": [
                {
                    "name": "moves",
                    "type": "json",
                    "required": False,
                    "default": CONTROL_MOVES,
                    "help": "Последовательность ходов вида [{'face': 1, 'direction': 'right', 'turns': 1}, ...].",
                    "example": CONTROL_MOVES,
                }
            ],
            "notes": (
                "Используется учебная развёртка 2x2 из ПЗ-05. Блок имеет фиксированную вместимость 8 русских букв; "
                "пробелы во входе игнорируются. Текст размещается по трафарету рисунка 21, а шифртекст считывается "
                "по трафарету рисунка 24. Для методических вариантов 1-5 проект теперь поддерживает отдельный вход "
                "через layout-раскладку заполненных ячеек развёртки. Контрольный пример: 'РТУ МИРЭА' -> 'ТМРРИАЭУ'."
            ),
        }

    def parse_key(self, raw_key: Key) -> Key:
        reject_unknown_keys(raw_key, allowed=["moves"], cipher=self.name)

        raw_moves = raw_key.get("moves", CONTROL_MOVES)
        if isinstance(raw_moves, str):
            try:
                raw_moves = json.loads(raw_moves)
            except json.JSONDecodeError as exc:
                raise ValueError("rubik_2x2: moves string must be valid JSON.") from exc

        if not isinstance(raw_moves, list):
            raise ValueError("rubik_2x2: moves must be a list.")

        moves: list[dict[str, Any]] = []
        for index, item in enumerate(raw_moves):
            if not isinstance(item, dict):
                raise ValueError(f"rubik_2x2: moves[{index}] must be an object.")

            reject_unknown_keys(item, allowed=["face", "direction", "turns"], cipher=f"{self.name}.moves[{index}]")

            face = as_int(item.get("face"), f"moves[{index}].face")
            if face not in FACE_IDS:
                raise ValueError(f"rubik_2x2: moves[{index}].face must be in 1..6.")

            direction = as_str(item.get("direction"), f"moves[{index}].direction").strip().lower()
            if direction not in {"right", "left"}:
                raise ValueError(f"rubik_2x2: moves[{index}].direction must be 'right' or 'left'.")

            turns = as_int(item.get("turns"), f"moves[{index}].turns")
            if turns <= 0:
                raise ValueError(f"rubik_2x2: moves[{index}].turns must be positive.")
            normalized_turns = turns % 4
            if normalized_turns == 0:
                continue

            moves.append({"face": face, "direction": direction, "turns": normalized_turns})

        return {"moves": moves}

    def parse_layout(self, raw_layout: Any) -> dict[str, str]:
        if not isinstance(raw_layout, dict):
            raise ValueError("rubik_2x2: layout must be an object mapping positions to letters.")

        layout: dict[str, str] = {}
        for raw_position, raw_value in raw_layout.items():
            position = str(raw_position).strip()
            if position not in ALL_POSITIONS:
                raise ValueError(f"rubik_2x2: layout position {position!r} is unknown.")

            value = as_str(raw_value, f"layout[{position}]").strip().upper()
            if len(value) != 1 or value not in RU_33:
                raise ValueError(f"rubik_2x2: layout[{position}] must be one RU_33 letter.")
            layout[position] = value

        if len(layout) != TEXT_BLOCK_SIZE:
            raise ValueError("rubik_2x2: layout must contain exactly 8 occupied cells.")
        return layout

    def encrypt(self, plaintext: str, key: Key) -> str:
        letters = self._normalize_plaintext(plaintext)
        state = self._empty_state()
        for position, letter in zip(INPUT_STENCIL, letters):
            state[position] = letter

        transformed = self._apply_moves(state, key["moves"])
        return "".join(transformed[position] for position in OUTPUT_STENCIL)

    def encrypt_layout(self, layout: dict[str, str], key: Key) -> str:
        normalized_layout = self.parse_layout(layout)
        state = self._empty_state()
        state.update(normalized_layout)
        transformed = self._apply_moves(state, key["moves"])
        return "".join(transformed[position] for position in OUTPUT_STENCIL)

    def decrypt(self, ciphertext: str, key: Key) -> str:
        letters = self._normalize_ciphertext(ciphertext)
        state = self._empty_state()
        for position, letter in zip(OUTPUT_STENCIL, letters):
            state[position] = letter

        inverse_moves = self._invert_moves(key["moves"])
        transformed = self._apply_moves(state, inverse_moves)
        plaintext = "".join(transformed[position] for position in INPUT_STENCIL)
        return f"{plaintext[:3]} {plaintext[3:]}"

    @staticmethod
    def _empty_state() -> dict[str, str]:
        return {position: "" for position in ALL_POSITIONS}

    @staticmethod
    def _normalize_plaintext(text: str) -> str:
        normalized = text.replace(" ", "").upper()
        invalid = sorted({ch for ch in normalized if ch not in RU_33})
        if invalid:
            joined = ", ".join(repr(ch) for ch in invalid)
            raise ValueError(f"rubik_2x2: plaintext supports only RU_33 letters and spaces; invalid: {joined}.")
        if len(normalized) != len(INPUT_STENCIL):
            raise ValueError("rubik_2x2: plaintext must contain exactly 8 Russian letters (spaces are ignored).")
        return normalized

    @staticmethod
    def _normalize_ciphertext(text: str) -> str:
        normalized = text.replace(" ", "").upper()
        invalid = sorted({ch for ch in normalized if ch not in RU_33})
        if invalid:
            joined = ", ".join(repr(ch) for ch in invalid)
            raise ValueError(f"rubik_2x2: ciphertext supports only RU_33 letters; invalid: {joined}.")
        if len(normalized) != len(OUTPUT_STENCIL):
            raise ValueError("rubik_2x2: ciphertext must contain exactly 8 Russian letters.")
        return normalized

    @staticmethod
    def _apply_permutation(state: dict[str, str], permutation: dict[str, str]) -> dict[str, str]:
        next_state = {position: "" for position in ALL_POSITIONS}
        for source, destination in permutation.items():
            next_state[destination] = state[source]
        return next_state

    def _apply_moves(self, state: dict[str, str], moves: list[dict[str, Any]]) -> dict[str, str]:
        current = dict(state)
        for move in moves:
            face = int(move["face"])
            direction = str(move["direction"])
            turns = int(move["turns"])

            right_permutation = COMPLETE_RIGHT_TURN_MAPS[face]
            permutation = self._inverse_permutation(right_permutation) if direction == "left" else right_permutation
            for _ in range(turns):
                current = self._apply_permutation(current, permutation)
        return current

    @staticmethod
    def _inverse_permutation(permutation: dict[str, str]) -> dict[str, str]:
        return {destination: source for source, destination in permutation.items()}

    @staticmethod
    def _invert_moves(moves: list[dict[str, Any]]) -> list[dict[str, Any]]:
        inverted: list[dict[str, Any]] = []
        for move in reversed(moves):
            inverted.append(
                {
                    "face": move["face"],
                    "direction": "left" if move["direction"] == "right" else "right",
                    "turns": move["turns"],
                }
            )
        return inverted


def get_cipher() -> Rubik2x2Cipher:
    return Rubik2x2Cipher()
