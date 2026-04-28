from __future__ import annotations

from dataclasses import asdict

import pytest

from miskzi_ciphers.common.types import Cipher
from miskzi_ciphers.practice.common.cipher_adapter import run_cipher
from miskzi_ciphers.practice.common.export import (
    practice_result_to_markdown,
    practice_result_to_text,
)
from miskzi_ciphers.practice.common.histogram import build_histogram, compare_histograms
from miskzi_ciphers.practice.common.models import PracticeResult, PracticeStep
from miskzi_ciphers.practice.practice_09.presets import PRACTICE_09_VARIANT_5
from miskzi_ciphers.practice.practice_09.service import run_practice_09_algorithm
from miskzi_ciphers.practice.practice_09.trace_caesar import trace_caesar
from miskzi_ciphers.practice.practice_09.trace_gronsfeld import trace_gronsfeld_russian
from miskzi_ciphers.practice.practice_09.trace_vigenere import trace_vigenere_latin


def test_practice_result_is_dataclass_serializable() -> None:
    result = PracticeResult(
        practice_id="practice_09",
        algorithm_id="caesar",
        operation="encrypt",
        input_text="АБ",
        output_text="БВ",
        normalized_text="АБ",
        parameters={"shift": 1},
        steps=[PracticeStep(index=1, input_value="А", output_value="Б", formula="0 + 1")],
    )

    serialized = asdict(result)

    assert serialized["practice_id"] == "practice_09"
    assert serialized["steps"][0]["input_value"] == "А"
    assert serialized["parameters"] == {"shift": 1}


def test_histogram_absolute_and_relative_frequencies() -> None:
    histogram = build_histogram("ААБ", title="sample")

    by_symbol = {entry.symbol: entry for entry in histogram.entries}

    assert histogram.total_count == 3
    assert by_symbol["А"].absolute_count == 2
    assert by_symbol["А"].relative_frequency == pytest.approx(2 / 3)
    assert by_symbol["Б"].absolute_count == 1
    assert by_symbol["Б"].relative_frequency == pytest.approx(1 / 3)


def test_compare_histograms_returns_input_and_output_histograms() -> None:
    input_histogram, output_histogram = compare_histograms("АА", "БББ")

    assert input_histogram.title == "Input text histogram"
    assert output_histogram.title == "Output text histogram"
    assert input_histogram.total_count == 2
    assert output_histogram.total_count == 3


def test_export_markdown_and_text_include_core_sections() -> None:
    result = run_practice_09_algorithm("caesar", "encrypt", "АБ", {"shift": 1})

    markdown = practice_result_to_markdown(result)
    text = practice_result_to_text(result)

    assert "# Practice result: practice_09" in markdown
    assert "## Parameters" in markdown
    assert "## Steps" in markdown
    assert "## Histograms" in markdown
    assert "Output:" in text
    assert "Histograms:" in text


def test_caesar_trace_encrypt_and_decrypt_simple_example() -> None:
    encrypted, normalized, enc_steps, _ = trace_caesar(
        "АБВ",
        shift=1,
        operation="encrypt",
        alphabet="АБВГ",
    )
    decrypted, _, dec_steps, _ = trace_caesar(
        encrypted,
        shift=1,
        operation="decrypt",
        alphabet="АБВГ",
    )

    assert normalized == "АБВ"
    assert encrypted == "БВГ"
    assert decrypted == "АБВ"
    assert enc_steps[0].details["char_index"] == 0
    assert enc_steps[0].details["shift"] == 1
    assert dec_steps[0].formula == "(1 - 1) mod 4 = 0"


def test_vigenere_decrypt_variant_5() -> None:
    preset = PRACTICE_09_VARIANT_5["vigenere"]

    decrypted, normalized, steps, notes = trace_vigenere_latin(
        preset["ciphertext"],
        key=preset["key"],
        operation="decrypt",
    )

    assert normalized == "YOIKYOJ"
    assert decrypted == "CARACAS"
    assert steps[0].details["key_char"] == "W"
    assert notes == []


def test_gronsfeld_decrypt_variant_5_uses_number_key() -> None:
    preset = PRACTICE_09_VARIANT_5["gronsfeld"]

    decrypted, normalized, steps, _ = trace_gronsfeld_russian(
        preset["ciphertext"],
        key_numbers=preset["key_numbers"],
        operation="decrypt",
    )

    assert normalized == "СЕПЩВЖРМ"
    assert decrypted == "КАГЖЫВДЪ"
    assert steps[0].details["key_number"] == 7
    assert steps[2].details["key_number"] == 13


@pytest.mark.parametrize(
    ("algorithm", "operation", "text", "params"),
    [
        ("caesar", "encrypt", "АБВ", {"shift": 1, "alphabet": "АБВГ"}),
        ("vigenere", "decrypt", "yoikyoj", {"key": "work"}),
        ("gronsfeld", "decrypt", "сепщвжрм", {"key_numbers": [7, 5, 13, 19]}),
    ],
)
def test_run_practice_09_algorithm_for_supported_algorithms(
    algorithm: str,
    operation: str,
    text: str,
    params: dict[str, object],
) -> None:
    result = run_practice_09_algorithm(algorithm, operation, text, params)

    assert result.practice_id == "practice_09"
    assert result.algorithm_id == algorithm
    assert result.operation == operation
    assert result.output_text
    assert result.steps
    assert len(result.histograms) == 2


def test_cipher_adapter_keeps_regular_cipher_contract_usage() -> None:
    assert run_cipher("caesar", "encrypt", "АБВ", {"k": 1}) == "БВГ"


def test_cipher_protocol_is_not_extended_with_practice_members() -> None:
    protocol_members = set(Cipher.__dict__)

    assert "encrypt" in protocol_members
    assert "decrypt" in protocol_members
    assert "parse_key" in protocol_members
    assert "describe" in protocol_members
    assert "trace" not in protocol_members
    assert "histogram" not in protocol_members
