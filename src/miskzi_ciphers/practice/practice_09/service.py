from __future__ import annotations

from typing import Any

from miskzi_ciphers.practice.common.histogram import compare_histograms
from miskzi_ciphers.practice.common.models import PracticeResult, PracticeTable
from miskzi_ciphers.practice.common.normalization import RUSSIAN_ALPHABET
from miskzi_ciphers.practice.practice_09.trace_caesar import trace_caesar
from miskzi_ciphers.practice.practice_09.trace_gronsfeld import trace_gronsfeld_russian
from miskzi_ciphers.practice.practice_09.trace_vigenere import trace_vigenere_latin

PRACTICE_ID = "practice_09"


def run_practice_09_algorithm(
    algorithm: str,
    operation: str,
    text: str,
    params: dict[str, Any] | None = None,
) -> PracticeResult:
    params = dict(params or {})
    algorithm_id = algorithm.strip().lower()

    if algorithm_id == "caesar":
        shift = int(params.get("shift", params.get("k", 0)))
        alphabet = str(params.get("alphabet", RUSSIAN_ALPHABET))
        output_text, normalized_text, steps, notes = trace_caesar(
            text,
            shift=shift,
            operation=operation,
            alphabet=alphabet,
        )
        parameters = {"shift": shift, "alphabet": alphabet}
    elif algorithm_id == "vigenere":
        key = str(params.get("key", params.get("keyword", "")))
        output_text, normalized_text, steps, notes = trace_vigenere_latin(
            text,
            key=key,
            operation=operation,
        )
        parameters = {"key": key, "alphabet": "A-Z"}
    elif algorithm_id == "gronsfeld":
        key_numbers = _parse_key_numbers(params.get("key_numbers", params.get("key", [])))
        output_text, normalized_text, steps, notes = trace_gronsfeld_russian(
            text,
            key_numbers=key_numbers,
            operation=operation,
        )
        parameters = {"key_numbers": key_numbers, "alphabet": RUSSIAN_ALPHABET}
    else:
        raise ValueError("algorithm must be one of: caesar, vigenere, gronsfeld.")

    input_histogram, output_histogram = compare_histograms(normalized_text, output_text)
    table = PracticeTable(
        title="Character trace",
        columns=["index", "input", "formula", "output", "comment"],
        rows=[
            {
                "index": step.index,
                "input": step.input_value,
                "formula": step.formula,
                "output": step.output_value,
                "comment": step.comment,
            }
            for step in steps
        ],
    )

    if normalized_text != text:
        notes = [*notes, "Input text differs from normalized text used by the practice scenario."]

    return PracticeResult(
        practice_id=PRACTICE_ID,
        algorithm_id=algorithm_id,
        operation=operation,
        input_text=text,
        output_text=output_text,
        normalized_text=normalized_text,
        parameters=parameters,
        steps=steps,
        tables=[table],
        histograms=[input_histogram, output_histogram],
        notes=notes,
    )


def _parse_key_numbers(value: Any) -> list[int]:
    if isinstance(value, (list, tuple)):
        return [int(item) for item in value]
    if isinstance(value, str):
        raw_parts = value.replace(",", " ").replace(";", " ").split()
        return [int(part) for part in raw_parts]
    raise ValueError("gronsfeld: key_numbers must be a list or a whitespace-separated string.")
