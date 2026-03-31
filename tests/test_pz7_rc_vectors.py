from __future__ import annotations

import json
from pathlib import Path

import pytest

from miskzi_ciphers.app import service
from miskzi_ciphers.common.paths import get_data_dir
from miskzi_ciphers.common.registry import REGISTRY, load_cipher
from miskzi_ciphers.ciphers.rc5.cipher import methodics_display as rc5_display
from miskzi_ciphers.ciphers.rc6.cipher import methodics_display as rc6_display


def _variants(cipher_id: str) -> dict[str, object]:
    repo_root = Path(__file__).resolve().parents[1]
    data_dir = get_data_dir(cwd=repo_root)
    path = data_dir / cipher_id / "variants.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_rc5_is_discovered_by_registry() -> None:
    assert REGISTRY.has("rc5")
    assert "rc5" in REGISTRY.list_names()


def test_rc6_is_discovered_by_registry() -> None:
    assert REGISTRY.has("rc6")
    assert "rc6" in REGISTRY.list_names()


def test_rc5_matches_pz7_example_and_methodical_display() -> None:
    cipher = load_cipher("rc5")
    key = cipher.parse_key({"keyword": "КНИГА"})

    ciphertext = cipher.encrypt("ЛЕТО", key)

    assert ciphertext == "82 4A 91 4F"
    assert rc5_display(ciphertext) == "БЙРО"
    assert cipher.decrypt(ciphertext, key) == "ЛЕТО"


@pytest.mark.parametrize(
    ("raw_key", "message"),
    [
        ({"keyword": "КНИГ"}, "exactly 5"),
        ({"keyword": "КНИГАЁ"}, "without 'Ё'"),
    ],
)
def test_rc5_parse_key_rejects_invalid_input(raw_key: dict[str, object], message: str) -> None:
    cipher = load_cipher("rc5")

    with pytest.raises(ValueError, match=message):
        cipher.parse_key(raw_key)


def test_rc5_variants_file_passes_existing_validation_flow() -> None:
    variants = service.load_variants("rc5")

    assert service.validate_variants_obj(variants) == []
    assert service.validate_variants_for_cipher("rc5", variants) == []


def test_rc5_variants_match_example_vector() -> None:
    variants = _variants("rc5")
    items = {entry["id"]: entry for entry in variants["items"] if isinstance(entry, dict) and "id" in entry}

    assert items[1]["expected"] == "82 4A 91 4F"
    assert items[2]["expected"] == "ЛЕТО"


def test_rc6_matches_pz7_example_and_methodical_display() -> None:
    cipher = load_cipher("rc6")
    key = cipher.parse_key({"keyword": "КНИГА", "shift": 1})

    ciphertext = cipher.encrypt("ЛЕТО", key)

    assert ciphertext == "12 0E 1F D4"
    assert rc6_display(ciphertext) == "РМЭТ"
    assert cipher.decrypt(ciphertext, key) == "ЛЕТО"


@pytest.mark.parametrize(
    ("plaintext", "keyword", "shift", "expected"),
    [
        ("СВЕТ", "ЛАМПА", 1, "10 9C 15 5A"),
        ("ЗИМА", "ОСЕНЬ", 2, "1A D3 14 4C"),
        ("КТСО", "УЧЁБА", 2, "29 B5 29 B3"),
        ("КУРС", "ХАКЕР", 1, "2C 15 14 13"),
    ],
)
def test_rc6_matches_pz7_variants(plaintext: str, keyword: str, shift: int, expected: str) -> None:
    cipher = load_cipher("rc6")
    key = cipher.parse_key({"keyword": keyword, "shift": shift})

    assert cipher.encrypt(plaintext, key) == expected
    assert cipher.decrypt(expected, key) == plaintext


@pytest.mark.parametrize(
    ("raw_key", "message"),
    [
        ({"keyword": "КНИГ", "shift": 1}, "exactly 5"),
        ({"keyword": "КНИГА", "shift": -1}, "shift"),
    ],
)
def test_rc6_parse_key_rejects_invalid_input(raw_key: dict[str, object], message: str) -> None:
    cipher = load_cipher("rc6")

    with pytest.raises(ValueError, match=message):
        cipher.parse_key(raw_key)


def test_rc6_variants_file_passes_existing_validation_flow() -> None:
    variants = service.load_variants("rc6")

    assert service.validate_variants_obj(variants) == []
    assert service.validate_variants_for_cipher("rc6", variants) == []


def test_rc6_variants_match_control_vectors() -> None:
    variants = _variants("rc6")
    items = {entry["id"]: entry for entry in variants["items"] if isinstance(entry, dict) and "id" in entry}

    assert items[1]["expected"] == "12 0E 1F D4"
    assert items[3]["expected"] == "10 9C 15 5A"
    assert items[4]["expected"] == "1A D3 14 4C"
    assert items[6]["expected"] == "29 B5 29 B3"
    assert items[12]["expected"] == "2C 15 14 13"
