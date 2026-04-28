from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

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
from miskzi_ciphers.practice.practice_09.trace_invert_255 import trace_invert_255
from miskzi_ciphers.practice.practice_09.trace_pair_swap import trace_pair_swap
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


def test_invert_255_is_self_inverse_over_windows_1251() -> None:
    encrypted, normalized, steps, notes = trace_invert_255("А", operation="encrypt")
    decrypted, _, decrypt_steps, _ = trace_invert_255(encrypted, operation="decrypt")

    assert normalized == "А"
    assert encrypted == "?"
    assert decrypted == "А"
    assert steps[0].details["encoding"] == "cp1251"
    assert steps[0].details["source_byte_decimal"] == 192
    assert steps[0].details["source_byte_hex"] == "0xC0"
    assert steps[0].details["result_byte_decimal"] == 63
    assert steps[0].details["result_byte_hex"] == "0x3F"
    assert decrypt_steps[0].formula == "255 - 63 = 192"
    assert "educational byte-level transformation" in notes[0]


def test_invert_255_preserves_unencodable_characters_in_trace() -> None:
    output, _, steps, notes = trace_invert_255("🙂", operation="encrypt")

    assert output == "🙂"
    assert steps[0].details["skipped"] is True
    assert "not encodable as Windows-1251" in notes[0]


def test_pair_swap_examples_and_self_inverse() -> None:
    encrypted_even, _, even_steps, _ = trace_pair_swap("ABCD", operation="encrypt")
    encrypted_odd, _, odd_steps, _ = trace_pair_swap("ABCDE", operation="encrypt")
    decrypted_odd, _, _, _ = trace_pair_swap(encrypted_odd, operation="decrypt")

    assert encrypted_even == "BADC"
    assert encrypted_odd == "BADCE"
    assert decrypted_odd == "ABCDE"
    assert even_steps[0].input_value == "AB"
    assert even_steps[0].output_value == "BA"
    assert odd_steps[-1].input_value == "E"
    assert odd_steps[-1].details["is_unpaired_last_character"] is True
    assert "preserved" in odd_steps[-1].comment


@pytest.mark.parametrize(
    ("algorithm", "operation", "text", "params"),
    [
        ("caesar", "encrypt", "АБВ", {"shift": 1, "alphabet": "АБВГ"}),
        ("vigenere", "decrypt", "yoikyoj", {"key": "work"}),
        ("gronsfeld", "decrypt", "сепщвжрм", {"key_numbers": [7, 5, 13, 19]}),
        ("invert_255", "encrypt", "А", {}),
        ("pair_swap", "encrypt", "ABCDE", {}),
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


def test_service_runs_mvp_2_algorithms_as_practice_results() -> None:
    invert_result = run_practice_09_algorithm("invert_255", "decrypt", "?", {})
    pair_swap_result = run_practice_09_algorithm("pair_swap", "encrypt", "ABCD", {})

    assert invert_result.output_text == "А"
    assert invert_result.parameters["encoding"] == "Windows-1251"
    assert invert_result.steps[0].details["result_byte_hex"] == "0xC0"
    assert pair_swap_result.output_text == "BADC"
    assert pair_swap_result.steps[0].details["pair_position"] == 1


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


def test_regular_cipher_modules_do_not_import_practice_layer() -> None:
    cipher_files = Path("src/miskzi_ciphers/ciphers").glob("*/cipher.py")

    for path in cipher_files:
        assert "miskzi_ciphers.practice" not in path.read_text(encoding="utf-8")
