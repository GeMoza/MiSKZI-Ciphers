from __future__ import annotations

import json
from pathlib import Path

import pytest

from miskzi_ciphers.app import service
from miskzi_ciphers.common.paths import get_data_dir
from miskzi_ciphers.common.registry import REGISTRY, load_cipher


RSA_CONTROL_KEY = {"p": 17, "q": 23, "e": 3}
ELGAMAL_CONTROL_VARIANTS = [
    ({"p": 17, "g": 3, "x": 5, "k": 11}, "9", 5, "7,14"),
    ({"p": 19, "g": 2, "x": 7, "k": 5}, "11", 14, "13,15"),
    ({"p": 23, "g": 5, "x": 9, "k": 7}, "14", 11, "17,6"),
    ({"p": 29, "g": 2, "x": 11, "k": 9}, "17", 18, "19,24"),
    ({"p": 31, "g": 3, "x": 8, "k": 11}, "19", 20, "13,9"),
    ({"p": 37, "g": 2, "x": 13, "k": 5}, "21", 15, "32,23"),
    ({"p": 41, "g": 6, "x": 17, "k": 9}, "24", 26, "19,39"),
    ({"p": 43, "g": 3, "x": 14, "k": 5}, "26", 36, "28,27"),
    ({"p": 47, "g": 5, "x": 19, "k": 7}, "29", 10, "11,36"),
    ({"p": 53, "g": 2, "x": 21, "k": 11}, "31", 48, "34,16"),
]


def _variants(cipher_id: str) -> dict[str, object]:
    repo_root = Path(__file__).resolve().parents[1]
    data_dir = get_data_dir(cwd=repo_root)
    path = data_dir / cipher_id / "variants.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_rsa_is_discovered_by_registry() -> None:
    assert REGISTRY.has("rsa")
    assert "rsa" in REGISTRY.list_names()


def test_elgamal_is_discovered_by_registry() -> None:
    assert REGISTRY.has("elgamal")
    assert "elgamal" in REGISTRY.list_names()


def test_rsa_parse_key_computes_methodical_values() -> None:
    cipher = load_cipher("rsa")

    parsed = cipher.parse_key({"p": "17", "q": "23", "e": "3"})

    assert parsed == {"p": 17, "q": 23, "e": 3, "n": 391, "phi": 352, "d": 235}


@pytest.mark.parametrize(
    ("raw_key", "message"),
    [
        ({"p": 4, "q": 11, "e": 7}, "prime"),
        ({"p": 17, "q": 17, "e": 3}, "different primes"),
        ({"p": 17, "q": 23, "e": 352}, r"1 < e <"),
        ({"p": 5, "q": 11, "e": 10}, "coprime"),
        ({"extra": 1}, "Unknown key"),
    ],
)
def test_rsa_parse_key_rejects_invalid_input(raw_key: dict[str, object], message: str) -> None:
    cipher = load_cipher("rsa")

    with pytest.raises(ValueError, match=message):
        cipher.parse_key(raw_key)


def test_rsa_encrypt_and_decrypt_match_control_vector() -> None:
    cipher = load_cipher("rsa")
    key = cipher.parse_key(RSA_CONTROL_KEY)

    assert cipher.encrypt("42 123", key) == "189 98"
    assert cipher.decrypt("189 98", key) == "42 123"


def test_rsa_supports_multiple_decimal_tokens() -> None:
    cipher = load_cipher("rsa")
    key = cipher.parse_key({"p": 29, "q": 31, "e": 11})

    assert cipher.encrypt("42 123 314", key) == "613 371 190"
    assert cipher.decrypt("613 371 190", key) == "42 123 314"


def test_elgamal_parse_key_computes_y() -> None:
    cipher = load_cipher("elgamal")

    parsed = cipher.parse_key({"p": "17", "g": "3", "x": "5", "k": "11"})

    assert parsed == {"p": 17, "g": 3, "x": 5, "k": 11, "y": 5}


def test_elgamal_parse_key_accepts_primitive_root_generator() -> None:
    cipher = load_cipher("elgamal")

    parsed = cipher.parse_key({"p": 17, "g": 3, "x": 5, "k": 7})

    assert parsed["y"] == pow(3, 5, 17)


@pytest.mark.parametrize(
    ("raw_key", "message"),
    [
        ({"p": 12, "g": 2, "x": 9, "k": 7}, "prime"),
        ({"p": 11, "g": 11, "x": 9, "k": 7}, r"1 < g < p"),
        ({"p": 11, "g": 3, "x": 9, "k": 7}, "primitive root"),
        ({"p": 11, "g": 2, "x": 1, "k": 7}, r"1 < x < p"),
        ({"p": 11, "g": 2, "x": 9, "k": 10}, r"1 < k < p-1"),
        ({"p": 11, "g": 2, "x": 9, "k": 5}, "coprime"),
        ({"extra": 1}, "Unknown key"),
    ],
)
def test_elgamal_parse_key_rejects_invalid_input(raw_key: dict[str, object], message: str) -> None:
    cipher = load_cipher("elgamal")

    with pytest.raises(ValueError, match=message):
        cipher.parse_key(raw_key)


@pytest.mark.parametrize(("raw_key", "message", "expected_y", "expected_ciphertext"), ELGAMAL_CONTROL_VARIANTS)
def test_elgamal_project_control_variants_compute_y_encrypt_and_decrypt(
    raw_key: dict[str, int],
    message: str,
    expected_y: int,
    expected_ciphertext: str,
) -> None:
    cipher = load_cipher("elgamal")
    key = cipher.parse_key(raw_key)

    assert key["y"] == expected_y
    assert cipher.encrypt(message, key) == expected_ciphertext
    assert cipher.decrypt(expected_ciphertext, key) == message
    left, right = expected_ciphertext.split(",")
    assert cipher.decrypt(f"({left}, {right})", key) == message


def test_rsa_variants_file_passes_existing_validation_flow() -> None:
    variants = service.load_variants("rsa")

    assert service.validate_variants_obj(variants) == []
    assert service.validate_variants_for_cipher("rsa", variants) == []


def test_elgamal_variants_file_passes_existing_validation_flow() -> None:
    variants = service.load_variants("elgamal")

    assert service.validate_variants_obj(variants) == []
    assert service.validate_variants_for_cipher("elgamal", variants) == []


def test_rsa_variants_match_control_vectors() -> None:
    variants = _variants("rsa")
    items = {entry["id"]: entry for entry in variants["items"] if isinstance(entry, dict) and "id" in entry}

    assert items[1]["expected"] == "189 98"
    assert items[2]["expected"] == "42 123"
    assert items[3]["expected"] == "613 371 190"
    assert items[4]["expected"] == "42 123 314"


def test_elgamal_variants_match_project_control_vectors() -> None:
    variants = _variants("elgamal")
    items = {entry["id"]: entry for entry in variants["items"] if isinstance(entry, dict) and "id" in entry}

    assert len(items) == 20
    for offset, (raw_key, message, expected_y, expected_ciphertext) in enumerate(ELGAMAL_CONTROL_VARIANTS):
        encrypt_item = items[offset * 2 + 1]
        decrypt_item = items[offset * 2 + 2]

        assert encrypt_item["key"] == raw_key
        assert encrypt_item["text"] == message
        assert encrypt_item["expected"] == expected_ciphertext

        assert decrypt_item["key"] == raw_key
        assert decrypt_item["text"] == expected_ciphertext
        assert decrypt_item["expected"] == message
        assert pow(raw_key["g"], raw_key["x"], raw_key["p"]) == expected_y
