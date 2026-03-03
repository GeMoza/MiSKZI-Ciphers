from __future__ import annotations

import pytest

from miskzi_ciphers.common.registry import load_cipher


def test_richelieu_vector() -> None:
    cipher = load_cipher("richelieu")
    key = cipher.parse_key({"key": "(4213)"})
    assert cipher.encrypt("ТЕСТ", key) == "ТЕТС"
    assert cipher.decrypt("ТЕТС", key) == "ТЕСТ"


def test_morse_roundtrip_basic() -> None:
    cipher = load_cipher("morse")
    key = cipher.parse_key({})
    encoded = cipher.encrypt("ТЕСТ МИР", key)
    assert "/" in encoded
    assert cipher.decrypt(encoded, key) == "ТЕСТ МИР"


def test_vernam_roundtrip_with_dot_key() -> None:
    cipher = load_cipher("vernam")
    key = cipher.parse_key({"keyword": "...."})
    plaintext = "ТЕСТ"
    assert cipher.decrypt(cipher.encrypt(plaintext, key), key) == plaintext


def test_adfgvx_roundtrip() -> None:
    cipher = load_cipher("adfgvx")
    key = cipher.parse_key({"keyword": "DRIVE"})
    plaintext = "TEST123"
    assert cipher.decrypt(cipher.encrypt(plaintext, key), key) == plaintext


def test_hill_roundtrip() -> None:
    cipher = load_cipher("hill")
    key = cipher.parse_key({"matrix": [[1, 2], [3, 5]]})
    plaintext = "ТЕСТ"
    assert cipher.decrypt(cipher.encrypt(plaintext, key), key) == plaintext


def test_hill_requires_padding_or_exact_block() -> None:
    cipher = load_cipher("hill")
    key = cipher.parse_key({"matrix": [[1, 2], [3, 5]]})
    with pytest.raises(ValueError):
        cipher.encrypt("ТЕС", key)
