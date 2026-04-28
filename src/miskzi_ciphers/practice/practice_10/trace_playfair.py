from __future__ import annotations

from dataclasses import dataclass

from miskzi_ciphers.practice.common.models import PracticeStep, PracticeTable
from miskzi_ciphers.practice.practice_10.bigram import (
    BigramItem,
    normalize_for_bigram,
    split_into_bigrams,
)
from miskzi_ciphers.practice.practice_10.matrix import build_keyed_matrix, matrix_to_practice_table

EN_PLAYFAIR_ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
RU_PLAYFAIR_ALPHABET = "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"


@dataclass(frozen=True)
class PlayfairPolicy:
    mode: str
    alphabet: str
    width: int
    filler: str
    replacements: dict[str, str]
    notes: list[str]


def trace_playfair(
    text: str,
    key: str,
    operation: str,
    alphabet_mode: str = "EN",
) -> tuple[str, str, list[PracticeStep], list[PracticeTable], list[str]]:
    _validate_operation(operation)
    policy = _get_policy(alphabet_mode)
    notes = list(policy.notes)

    normalized_text = normalize_for_bigram(
        text,
        policy.alphabet,
        replacements=policy.replacements,
    )
    normalized_key = normalize_for_bigram(
        key,
        policy.alphabet,
        replacements=policy.replacements,
    )
    notes.extend(normalized_text.notes)
    notes.extend(f"Text replacement: {item}" for item in normalized_text.replacements)
    notes.extend(f"Text removal: {item}" for item in normalized_text.removed)
    notes.extend(normalized_key.notes)
    notes.extend(f"Key replacement: {item}" for item in normalized_key.replacements)
    notes.extend(f"Key removal: {item}" for item in normalized_key.removed)

    matrix = build_keyed_matrix(normalized_key.text, policy.alphabet, policy.width)
    bigram_split = _build_operation_bigrams(normalized_text.text, policy.filler, operation)
    notes.extend(bigram_split.notes)

    output_parts: list[str] = []
    steps: list[PracticeStep] = []
    for bigram in bigram_split.bigrams:
        output_bigram, rule, result_positions = _transform_bigram(
            bigram,
            operation=operation,
            matrix_rows=matrix.rows,
            positions=matrix.positions,
        )
        output_parts.append(output_bigram)
        first_position = matrix.positions[bigram.first_char]
        second_position = matrix.positions[bigram.second_char]
        steps.append(
            PracticeStep(
                index=bigram.index,
                input_value=bigram.value,
                output_value=output_bigram,
                formula=rule,
                details={
                    "first_char": bigram.first_char,
                    "second_char": bigram.second_char,
                    "first_position": first_position,
                    "second_position": second_position,
                    "result_positions": result_positions,
                    "rule": rule,
                    "filler_inserted": bigram.filler_inserted,
                    "filler_reason": bigram.filler_reason,
                    "source_indexes": bigram.source_indexes,
                },
                comment=_comment_for_rule(rule, operation, bigram),
            )
        )

    tables = [
        matrix_to_practice_table(matrix),
        _bigrams_to_table(bigram_split.bigrams, steps),
    ]
    notes.append(
        "Playfair is implemented as a standard educational practice scenario; "
        "full compatibility with the historical .exe is not claimed."
    )
    return "".join(output_parts), normalized_text.text, steps, tables, notes


def _get_policy(alphabet_mode: str) -> PlayfairPolicy:
    mode = alphabet_mode.strip().upper()
    if mode == "EN":
        return PlayfairPolicy(
            mode="EN",
            alphabet=EN_PLAYFAIR_ALPHABET,
            width=5,
            filler="X",
            replacements={"J": "I"},
            notes=["EN Playfair uses a 5x5 matrix and replaces J with I."],
        )
    if mode == "RU":
        return PlayfairPolicy(
            mode="RU",
            alphabet=RU_PLAYFAIR_ALPHABET,
            width=8,
            filler="Х",
            replacements={"Ё": "Е"},
            notes=["RU Playfair uses a 4x8 educational matrix and replaces Ё with Е."],
        )
    raise ValueError("alphabet_mode must be either 'EN' or 'RU'.")


def _validate_operation(operation: str) -> None:
    if operation not in {"encrypt", "decrypt"}:
        raise ValueError("operation must be either 'encrypt' or 'decrypt'.")


def _build_operation_bigrams(text: str, filler: str, operation: str):
    if operation == "encrypt":
        return split_into_bigrams(text, filler)

    if len(text) % 2 == 0:
        return split_into_bigrams_without_inserting_fillers(text)

    return split_into_bigrams(text, filler)


def split_into_bigrams_without_inserting_fillers(text: str):
    from miskzi_ciphers.practice.practice_10.bigram import BigramSplit

    bigrams = [
        BigramItem(
            index=index + 1,
            value=text[start : start + 2],
            first_char=text[start],
            second_char=text[start + 1],
            source_indexes=[start, start + 1],
        )
        for index, start in enumerate(range(0, len(text), 2))
    ]
    return BigramSplit(bigrams=bigrams)


def _transform_bigram(
    bigram: BigramItem,
    operation: str,
    matrix_rows: list[list[str]],
    positions: dict[str, tuple[int, int]],
) -> tuple[str, str, list[tuple[int, int]]]:
    first_row, first_column = positions[bigram.first_char]
    second_row, second_column = positions[bigram.second_char]
    width = len(matrix_rows[0])
    height = len(matrix_rows)
    shift = 1 if operation == "encrypt" else -1

    if first_row == second_row:
        first_result = (first_row, (first_column + shift) % width)
        second_result = (second_row, (second_column + shift) % width)
        rule = "same row"
    elif first_column == second_column:
        first_result = ((first_row + shift) % height, first_column)
        second_result = ((second_row + shift) % height, second_column)
        rule = "same column"
    else:
        first_result = (first_row, second_column)
        second_result = (second_row, first_column)
        rule = "rectangle"

    output = matrix_rows[first_result[0]][first_result[1]] + matrix_rows[second_result[0]][
        second_result[1]
    ]
    return output, rule, [first_result, second_result]


def _comment_for_rule(rule: str, operation: str, bigram: BigramItem) -> str:
    if rule == "same row":
        action = "right" if operation == "encrypt" else "left"
        base = f"Characters are in one row; shift columns {action}."
    elif rule == "same column":
        action = "down" if operation == "encrypt" else "up"
        base = f"Characters are in one column; shift rows {action}."
    else:
        base = "Characters form a rectangle; swap columns."

    if bigram.filler_inserted:
        return f"{base} Filler was inserted because of {bigram.filler_reason}."
    return base


def _bigrams_to_table(bigrams: list[BigramItem], steps: list[PracticeStep]) -> PracticeTable:
    return PracticeTable(
        title="Playfair bigrams",
        columns=["index", "input_bigram", "rule", "output_bigram", "comment"],
        rows=[
            {
                "index": bigram.index,
                "input_bigram": bigram.value,
                "rule": step.details["rule"],
                "output_bigram": step.output_value,
                "comment": step.comment,
            }
            for bigram, step in zip(bigrams, steps, strict=True)
        ],
    )
