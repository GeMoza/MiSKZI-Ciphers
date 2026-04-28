from __future__ import annotations

from miskzi_ciphers.practice.common.models import PracticeStep


def trace_pair_swap(text: str, operation: str) -> tuple[str, str, list[PracticeStep], list[str]]:
    _validate_self_inverse_operation(operation)

    output_parts: list[str] = []
    steps: list[PracticeStep] = []
    pair_index = 1

    for offset in range(0, len(text), 2):
        pair = text[offset : offset + 2]
        if len(pair) == 2:
            result_pair = pair[1] + pair[0]
            comment = "Adjacent pair swapped."
        else:
            result_pair = pair
            comment = "Last unpaired character preserved because input length is odd."

        output_parts.append(result_pair)
        steps.append(
            PracticeStep(
                index=pair_index,
                input_value=pair,
                output_value=result_pair,
                formula="AB -> BA" if len(pair) == 2 else "A -> A",
                details={
                    "pair_position": pair_index,
                    "start_index": offset,
                    "end_index": offset + len(pair) - 1,
                    "is_unpaired_last_character": len(pair) == 1,
                },
                comment=comment,
            )
        )
        pair_index += 1

    notes = [
        "Pair swap is an educational simple permutation of adjacent characters; "
        "full compatibility with the historical .exe is not claimed."
    ]
    return "".join(output_parts), text, steps, notes


def _validate_self_inverse_operation(operation: str) -> None:
    if operation not in {"encrypt", "decrypt"}:
        raise ValueError("operation must be either 'encrypt' or 'decrypt'.")
