from __future__ import annotations

from typing import Any

from miskzi_ciphers.practice.common.models import PracticeResult
from miskzi_ciphers.practice.practice_10.trace_playfair import trace_playfair

PRACTICE_ID = "practice_10"


def run_practice_10_algorithm(
    algorithm: str,
    operation: str,
    text: str,
    params: dict[str, Any] | None = None,
) -> PracticeResult:
    params = dict(params or {})
    algorithm_id = algorithm.strip().lower()

    if algorithm_id != "playfair":
        raise ValueError("MVP-3 supports only the playfair practice scenario.")

    key = str(params.get("key", ""))
    alphabet_mode = str(params.get("alphabet_mode", params.get("alphabet", "EN"))).upper()
    output_text, normalized_text, steps, tables, notes = trace_playfair(
        text,
        key=key,
        operation=operation,
        alphabet_mode=alphabet_mode,
    )

    return PracticeResult(
        practice_id=PRACTICE_ID,
        algorithm_id=algorithm_id,
        operation=operation,
        input_text=text,
        output_text=output_text,
        normalized_text=normalized_text,
        parameters={"key": key, "alphabet_mode": alphabet_mode},
        steps=steps,
        tables=tables,
        notes=notes,
    )

