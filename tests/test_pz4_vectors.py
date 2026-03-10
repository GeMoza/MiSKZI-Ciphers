from __future__ import annotations

import pytest

from miskzi_ciphers.common.registry import load_cipher


NON_INVERTIBLE_HILL_MATRIX = [[2, 5, 10], [12, 9, 11], [6, 18, 29]]


def test_richelieu_vector() -> None:
    cipher = load_cipher("richelieu")
    key = cipher.parse_key({"key": "(4213)"})
    assert cipher.encrypt("????", key) == "????"
    assert cipher.decrypt("????", key) == "????"


def test_morse_roundtrip_basic() -> None:
    cipher = load_cipher("morse")
    key = cipher.parse_key({})
    encoded = cipher.encrypt("???? ???", key)
    assert "/" in encoded
    assert cipher.decrypt(encoded, key) == "???? ???"


def test_vernam_roundtrip_with_dot_key() -> None:
    cipher = load_cipher("vernam")
    key = cipher.parse_key({"keyword": "...."})
    plaintext = "????"
    assert cipher.decrypt(cipher.encrypt(plaintext, key), key) == plaintext


def test_adfgvx_roundtrip() -> None:
    cipher = load_cipher("adfgvx")
    key = cipher.parse_key({"keyword": "DRIVE"})
    plaintext = "TEST123"
    assert cipher.decrypt(cipher.encrypt(plaintext, key), key) == plaintext


def test_hill_roundtrip() -> None:
    cipher = load_cipher("hill")
    key = cipher.parse_key({"matrix": [[1, 2], [3, 5]]})
    plaintext = "????"
    assert cipher.decrypt(cipher.encrypt(plaintext, key), key) == plaintext


def test_hill_requires_padding_or_exact_block() -> None:
    cipher = load_cipher("hill")
    key = cipher.parse_key({"matrix": [[1, 2], [3, 5]]})
    with pytest.raises(ValueError):
        cipher.encrypt("???", key)


def test_hill_matches_pz5_example() -> None:
    cipher = load_cipher("hill")
    key = cipher.parse_key({"matrix": [[14, 8, 3], [8, 5, 2], [3, 2, 1]]})
    assert cipher.encrypt("??????", key) == "??????"


def test_hill_allows_non_invertible_matrix_for_encrypt() -> None:
    cipher = load_cipher("hill")
    key = cipher.parse_key({"matrix": NON_INVERTIBLE_HILL_MATRIX})
    encrypted = cipher.encrypt("???", key)
    assert isinstance(encrypted, str)
    assert len(encrypted) == 3


def test_hill_decrypt_requires_invertible_matrix() -> None:
    cipher = load_cipher("hill")
    key = cipher.parse_key({"matrix": NON_INVERTIBLE_HILL_MATRIX})
    with pytest.raises(ValueError, match="hill: matrix not invertible mod 33\\."):
        cipher.decrypt("???", key)
