from __future__ import annotations

from miskzi_ciphers.practice.common.models import PracticeStep
from miskzi_ciphers.practice.common.normalization import (
    RUSSIAN_ALPHABET,
    normalize_russian,
    normalize_upper,
)


def trace_gronsfeld_russian(
    text: str,
    *,
    key_numbers: list[int],
    operation: str,
    alphabet: str = RUSSIAN_ALPHABET,
) -> tuple[str, str, list[PracticeStep], list[str]]:
    if operation not in {"encrypt", "decrypt"}:
        raise ValueError("operation must be 'encrypt' or 'decrypt'.")
    if not key_numbers:
        raise ValueError("gronsfeld: key_numbers must not be empty.")
    if not alphabet:
        raise ValueError("alphabet must not be empty.")

    normalized_upper = normalize_upper(text)
    normalized = normalize_russian(text)
    notes: list[str] = []
    if normalized != normalized_upper:
        notes.append("Input was normalized to Russian alphabet; unsupported symbols were excluded.")

    index = {ch: pos for pos, ch in enumerate(alphabet)}
    output: list[str] = []
    steps: list[PracticeStep] = []

    for pos, ch in enumerate(normalized, start=1):
        source_index = index[ch]
        key_number = int(key_numbers[(pos - 1) % len(key_numbers)])
        if operation == "encrypt":
            target_index = (source_index + key_number) % len(alphabet)
            formula = f"({source_index} + {key_number}) mod {len(alphabet)} = {target_index}"
        else:
            target_index = (source_index - key_number) % len(alphabet)
            formula = f"({source_index} - {key_number}) mod {len(alphabet)} = {target_index}"

        mapped = alphabet[target_index]
        output.append(mapped)
        steps.append(
            PracticeStep(
                index=pos,
                input_value=ch,
                output_value=mapped,
                formula=formula,
                details={
                    "char_index": source_index,
                    "key_number": key_number,
                    "result_index": target_index,
                },
                comment="Gronsfeld Russian alphabet",
            )
        )

    return "".join(output), normalized, steps, notes
