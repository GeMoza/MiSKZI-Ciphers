from __future__ import annotations

import unicodedata

from miskzi_ciphers.practice.common.models import PracticeStep

WINDOWS_1251 = "cp1251"


def trace_invert_255(text: str, operation: str) -> tuple[str, str, list[PracticeStep], list[str]]:
    _validate_self_inverse_operation(operation)

    output_chars: list[str] = []
    steps: list[PracticeStep] = []
    notes: list[str] = []

    for position, char in enumerate(text, start=1):
        try:
            source_byte = char.encode(WINDOWS_1251)
        except UnicodeEncodeError:
            notes.append(
                f"Character {char!r} at position {position} is not encodable as Windows-1251 "
                "and was preserved without byte inversion."
            )
            output_chars.append(char)
            steps.append(
                PracticeStep(
                    index=position,
                    input_value=char,
                    output_value=char,
                    formula="not encodable as Windows-1251",
                    details={"encoding": WINDOWS_1251, "skipped": True},
                    comment="Character is outside Windows-1251; preserved.",
                )
            )
            continue

        source_value = source_byte[0]
        result_value = 255 - source_value
        result_byte = bytes([result_value])
        result_char, decode_comment = _decode_result_byte(result_byte)
        output_chars.append(result_char)

        comment_parts = ["Self-inverse byte-level Windows-1251 transformation."]
        if decode_comment:
            comment_parts.append(decode_comment)

        steps.append(
            PracticeStep(
                index=position,
                input_value=char,
                output_value=result_char,
                formula=f"255 - {source_value} = {result_value}",
                details={
                    "encoding": WINDOWS_1251,
                    "source_byte_decimal": source_value,
                    "source_byte_hex": f"0x{source_value:02X}",
                    "result_byte_decimal": result_value,
                    "result_byte_hex": f"0x{result_value:02X}",
                    "result_char": result_char,
                },
                comment=" ".join(comment_parts),
            )
        )

    notes.append(
        "Invert 255 is implemented as an educational byte-level transformation over Windows-1251; "
        "full compatibility with the historical .exe is not claimed."
    )
    return "".join(output_chars), text, steps, notes


def _validate_self_inverse_operation(operation: str) -> None:
    if operation not in {"encrypt", "decrypt"}:
        raise ValueError("operation must be either 'encrypt' or 'decrypt'.")


def _decode_result_byte(result_byte: bytes) -> tuple[str, str]:
    result_value = result_byte[0]
    try:
        result_char = result_byte.decode(WINDOWS_1251)
    except UnicodeDecodeError:
        placeholder = f"\\x{result_value:02X}"
        return (
            placeholder,
            "Result byte is not decodable as Windows-1251; escaped placeholder used.",
        )

    if unicodedata.category(result_char).startswith("C"):
        return result_char, "Result is a control or non-printable character."

    return result_char, ""
