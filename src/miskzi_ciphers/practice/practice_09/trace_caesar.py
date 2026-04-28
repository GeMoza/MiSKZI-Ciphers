from __future__ import annotations

from miskzi_ciphers.practice.common.models import PracticeStep
from miskzi_ciphers.practice.common.normalization import RUSSIAN_ALPHABET, normalize_upper


def trace_caesar(
    text: str,
    *,
    shift: int,
    operation: str,
    alphabet: str = RUSSIAN_ALPHABET,
) -> tuple[str, str, list[PracticeStep], list[str]]:
    if operation not in {"encrypt", "decrypt"}:
        raise ValueError("operation must be 'encrypt' or 'decrypt'.")
    if not alphabet:
        raise ValueError("alphabet must not be empty.")

    normalized = normalize_upper(text)
    index = {ch: pos for pos, ch in enumerate(alphabet)}
    actual_shift = shift if operation == "encrypt" else -shift
    output: list[str] = []
    steps: list[PracticeStep] = []
    notes: list[str] = []

    for pos, ch in enumerate(normalized, start=1):
        source_index = index.get(ch)
        if source_index is None:
            output.append(ch)
            notes.append(f"Symbol {ch!r} at position {pos} is outside alphabet and was preserved.")
            steps.append(
                PracticeStep(
                    index=pos,
                    input_value=ch,
                    output_value=ch,
                    formula="outside alphabet",
                    details={"position": pos, "shift": shift},
                    comment="symbol preserved",
                )
            )
            continue

        target_index = (source_index + actual_shift) % len(alphabet)
        mapped = alphabet[target_index]
        output.append(mapped)
        sign = "+" if operation == "encrypt" else "-"
        formula = f"({source_index} {sign} {shift}) mod {len(alphabet)} = {target_index}"
        steps.append(
            PracticeStep(
                index=pos,
                input_value=ch,
                output_value=mapped,
                formula=formula,
                details={
                    "char_index": source_index,
                    "shift": shift,
                    "result_index": target_index,
                },
                comment="Caesar shift",
            )
        )

    return "".join(output), normalized, steps, notes
