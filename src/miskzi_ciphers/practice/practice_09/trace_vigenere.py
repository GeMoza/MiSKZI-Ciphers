from __future__ import annotations

from string import ascii_uppercase

from miskzi_ciphers.practice.common.models import PracticeStep
from miskzi_ciphers.practice.common.normalization import normalize_latin, normalize_upper

ALPHABET = ascii_uppercase


def trace_vigenere_latin(
    text: str,
    *,
    key: str,
    operation: str,
) -> tuple[str, str, list[PracticeStep], list[str]]:
    if operation not in {"encrypt", "decrypt"}:
        raise ValueError("operation must be 'encrypt' or 'decrypt'.")

    keyword = normalize_latin(key)
    if not keyword:
        raise ValueError("vigenere: key must contain at least one Latin A-Z letter.")

    normalized_upper = normalize_upper(text)
    normalized = normalize_latin(text)
    notes: list[str] = []
    if normalized != normalized_upper:
        notes.append("Input was normalized to Latin A-Z; non-Latin symbols were excluded.")

    output: list[str] = []
    steps: list[PracticeStep] = []
    for pos, ch in enumerate(normalized, start=1):
        key_ch = keyword[(pos - 1) % len(keyword)]
        source_index = ALPHABET.index(ch)
        key_index = ALPHABET.index(key_ch)
        if operation == "encrypt":
            target_index = (source_index + key_index) % len(ALPHABET)
            formula = f"({source_index} + {key_index}) mod 26 = {target_index}"
        else:
            target_index = (source_index - key_index) % len(ALPHABET)
            formula = f"({source_index} - {key_index}) mod 26 = {target_index}"

        mapped = ALPHABET[target_index]
        output.append(mapped)
        steps.append(
            PracticeStep(
                index=pos,
                input_value=ch,
                output_value=mapped,
                formula=formula,
                details={
                    "char_index": source_index,
                    "key_char": key_ch,
                    "key_index": key_index,
                    "result_index": target_index,
                },
                comment="Vigenere A-Z",
            )
        )

    return "".join(output), normalized, steps, notes
