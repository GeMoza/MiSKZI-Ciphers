from __future__ import annotations

import json
from pathlib import Path

import pytest

from miskzi_ciphers.app import service
from miskzi_ciphers.common.paths import get_data_dir
from miskzi_ciphers.common.registry import REGISTRY, load_cipher


RSA_CONTROL_KEY = {"p": 17, "q": 23, "e": 3}
ELGAMAL_CONTROL_KEY = {"p": 11, "g": 2, "x": 9, "k": 7}


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

    parsed = cipher.parse_key({"p": "11", "g": "2", "x": "9", "k": "7"})

    assert parsed == {"p": 11, "g": 2, "x": 9, "k": 7, "y": 6}


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
        ({"p": 11, "g": 2, "x": 9, "k": 5}, "coprime"),
        ({"extra": 1}, "Unknown key"),
    ],
)
def test_elgamal_parse_key_rejects_invalid_input(raw_key: dict[str, object], message: str) -> None:
    cipher = load_cipher("elgamal")

    with pytest.raises(ValueError, match=message):
        cipher.parse_key(raw_key)


def test_elgamal_matches_methodical_example_and_verifies_decryption() -> None:
    cipher = load_cipher("elgamal")
    key = cipher.parse_key(ELGAMAL_CONTROL_KEY)

    assert key["y"] == 6
    assert cipher.encrypt("4", key) == "7,10"
    assert cipher.decrypt("7,10", key) == "4"
    assert cipher.decrypt("(7, 10)", key) == "4"


def test_elgamal_matches_methodical_variant_1() -> None:
    cipher = load_cipher("elgamal")
    key = cipher.parse_key({"p": 17, "g": 7, "x": 11, "k": 13})

    assert key["y"] == 14
    assert cipher.encrypt("10", key) == "6,16"
    assert cipher.decrypt("6,16", key) == "10"


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


def test_elgamal_variants_match_methodics_vectors() -> None:
    variants = _variants("elgamal")
    items = {entry["id"]: entry for entry in variants["items"] if isinstance(entry, dict) and "id" in entry}

    assert items[1]["expected"] == "7,10"
    assert items[2]["expected"] == "4"
    assert items[3]["expected"] == "6,16"
    assert items[4]["expected"] == "10"
    assert items[5]["expected"] == "4,9"
    assert items[6]["expected"] == "13"
