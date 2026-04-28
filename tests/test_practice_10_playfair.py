from __future__ import annotations

from pathlib import Path

from miskzi_ciphers.common.types import Cipher
from miskzi_ciphers.practice.practice_10.bigram import normalize_for_bigram, split_into_bigrams
from miskzi_ciphers.practice.practice_10.matrix import build_keyed_matrix, matrix_to_practice_table
from miskzi_ciphers.practice.practice_10.service import run_practice_10_algorithm
from miskzi_ciphers.practice.practice_10.trace_playfair import (
    EN_PLAYFAIR_ALPHABET,
    RU_PLAYFAIR_ALPHABET,
    trace_playfair,
)


def test_build_keyed_matrix_en_removes_duplicate_key_characters() -> None:
    matrix = build_keyed_matrix("BALLOON", EN_PLAYFAIR_ALPHABET, width=5)

    assert matrix.keyed_alphabet.startswith("BALON")
    assert matrix.rows[0] == ["B", "A", "L", "O", "N"]
    assert matrix.positions["B"] == (0, 0)
    assert matrix.positions["N"] == (0, 4)


def test_matrix_can_be_exported_as_practice_table() -> None:
    matrix = build_keyed_matrix("KEY", EN_PLAYFAIR_ALPHABET, width=5)
    table = matrix_to_practice_table(matrix)

    assert table.title == "Playfair matrix"
    assert table.columns == ["c1", "c2", "c3", "c4", "c5"]
    assert table.rows[0]["c1"] == "K"


def test_normalize_for_bigram_applies_en_i_j_policy_and_removes_symbols() -> None:
    normalized = normalize_for_bigram(
        "Jig!",
        EN_PLAYFAIR_ALPHABET,
        replacements={"J": "I"},
    )

    assert normalized.text == "IIG"
    assert normalized.replacements == [{"index": 0, "source": "J", "replacement": "I"}]
    assert normalized.removed == [{"index": 3, "source": "!"}]
    assert normalized.notes


def test_split_bigrams_handles_repeats_odd_length_and_single_letter() -> None:
    repeated = split_into_bigrams("BALLOON", filler="X")
    odd = split_into_bigrams("ABC", filler="X")
    single = split_into_bigrams("A", filler="X")

    assert [item.value for item in repeated.bigrams] == ["BA", "LX", "LO", "ON"]
    assert repeated.bigrams[1].filler_reason == "repeated_character"
    assert [item.value for item in odd.bigrams] == ["AB", "CX"]
    assert odd.bigrams[-1].filler_reason == "odd_length"
    assert [item.value for item in single.bigrams] == ["AX"]
    assert single.bigrams[0].filler_inserted is True


def test_playfair_encrypt_decrypt_roundtrip_en_without_padding() -> None:
    encrypted, normalized, enc_steps, tables, notes = trace_playfair(
        "AB",
        key="KEYWORD",
        operation="encrypt",
        alphabet_mode="EN",
    )
    decrypted, decrypted_normalized, dec_steps, _, _ = trace_playfair(
        encrypted,
        key="KEYWORD",
        operation="decrypt",
        alphabet_mode="EN",
    )

    assert normalized == "AB"
    assert decrypted_normalized == encrypted
    assert decrypted == "AB"
    assert encrypted
    assert enc_steps[0].details["rule"] in {"same row", "same column", "rectangle"}
    assert dec_steps[0].details["result_positions"]
    assert any(table.title == "Playfair matrix" for table in tables)
    assert any("5x5" in note for note in notes)


def test_playfair_ru_uses_yo_to_e_policy_and_rectangular_matrix() -> None:
    encrypted, normalized, steps, tables, notes = trace_playfair(
        "ЁЖ",
        key="КЛЮЧ",
        operation="encrypt",
        alphabet_mode="RU",
    )

    matrix_table = tables[0]

    assert normalized == "ЕЖ"
    assert encrypted
    assert steps[0].input_value == "ЕЖ"
    assert len(RU_PLAYFAIR_ALPHABET) == 32
    assert matrix_table.columns == ["c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8"]
    assert any("4x8" in note for note in notes)
    assert any("Ё" in note for note in notes)


def test_practice_10_service_returns_playfair_practice_result() -> None:
    result = run_practice_10_algorithm(
        "playfair",
        "encrypt",
        "HELLO",
        {"key": "KEYWORD", "alphabet_mode": "EN"},
    )

    assert result.practice_id == "practice_10"
    assert result.algorithm_id == "playfair"
    assert result.operation == "encrypt"
    assert result.normalized_text == "HELLO"
    assert result.output_text
    assert result.steps
    assert any(step.details["filler_inserted"] for step in result.steps)
    assert [table.title for table in result.tables] == ["Playfair matrix", "Playfair bigrams"]


def test_cipher_protocol_is_not_extended_by_practice_10() -> None:
    protocol_members = set(Cipher.__dict__)

    assert "encrypt" in protocol_members
    assert "decrypt" in protocol_members
    assert "trace" not in protocol_members
    assert "matrix" not in protocol_members


def test_regular_cipher_modules_still_do_not_import_practice_layer() -> None:
    cipher_files = Path("src/miskzi_ciphers/ciphers").glob("*/cipher.py")

    for path in cipher_files:
        assert "miskzi_ciphers.practice" not in path.read_text(encoding="utf-8")
