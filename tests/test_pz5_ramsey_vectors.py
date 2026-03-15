from __future__ import annotations

import json
from pathlib import Path

import pytest

from miskzi_ciphers.app import service
from miskzi_ciphers.common.paths import get_data_dir
from miskzi_ciphers.common.registry import REGISTRY, load_cipher


def _ramsey_variants() -> dict[str, object]:
    repo_root = Path(__file__).resolve().parents[1]
    data_dir = get_data_dir(cwd=repo_root)
    path = data_dir / "ramsey" / "variants.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_ramsey_is_discovered_by_registry() -> None:
    assert REGISTRY.has("ramsey")
    assert "ramsey" in REGISTRY.list_names()


def test_ramsey_parse_key_canonicalizes_valid_input() -> None:
    cipher = load_cipher("ramsey")

    parsed = cipher.parse_key({"keyword": "Letter", "anagram": "spare", "group_size": "7"})

    assert parsed == {
        "keyword": "LETR",
        "anagram": "SPARE",
        "group_size": 7,
    }


@pytest.mark.parametrize(
    ("raw_key", "message"),
    [
        ({}, "Missing key 'keyword'."),
        ({"keyword": "ORBIT"}, "Missing key 'anagram'."),
        ({"keyword": "ORBIT", "anagram": "LEVEL"}, "duplicate letters"),
        ({"keyword": "ORB1T", "anagram": "SPARE"}, "Latin letters A-Z"),
        ({"keyword": "ORBIT", "anagram": "SPARE", "group_size": 0}, "positive integer"),
        ({"keyword": "ORBIT", "anagram": "SPARE", "extra": 1}, "Unknown key"),
    ],
)
def test_ramsey_parse_key_rejects_invalid_input(raw_key: dict[str, object], message: str) -> None:
    cipher = load_cipher("ramsey")

    with pytest.raises(ValueError, match=message):
        cipher.parse_key(raw_key)


def test_ramsey_encrypt_matches_control_vector() -> None:
    cipher = load_cipher("ramsey")
    variants = _ramsey_variants()
    item = next(entry for entry in variants["items"] if isinstance(entry, dict) and entry.get("id") == 1)

    key = cipher.parse_key(item["key"])

    assert cipher.encrypt(str(item["text"]), key) == item["expected"]


def test_ramsey_decrypt_matches_control_vector() -> None:
    cipher = load_cipher("ramsey")
    variants = _ramsey_variants()
    item = next(entry for entry in variants["items"] if isinstance(entry, dict) and entry.get("id") == 2)

    key = cipher.parse_key(item["key"])

    assert cipher.decrypt(str(item["text"]), key) == item["expected"]


def test_ramsey_decrypt_accepts_grouped_and_ungrouped_ciphertext() -> None:
    cipher = load_cipher("ramsey")
    key = cipher.parse_key({"keyword": "ORBIT", "anagram": "SPARE", "group_size": 5})
    grouped = "19393 91119 15281 52827 1611"
    ungrouped = "193939111915281528271611"

    assert cipher.decrypt(grouped, key) == "MEET AT NOON"
    assert cipher.decrypt(ungrouped, key) == "MEET AT NOON"


def test_ramsey_roundtrip_additional_example() -> None:
    cipher = load_cipher("ramsey")
    key = cipher.parse_key({"keyword": "PLANET", "anagram": "BOARD", "group_size": 4})
    plaintext = "HELLO WORLD"

    encrypted = cipher.encrypt(plaintext, key)

    assert encrypted == "1228 2339 1928 1215 3512 31"
    assert cipher.decrypt(encrypted, key) == plaintext


def test_ramsey_variants_file_passes_existing_validation_flow() -> None:
    variants = service.load_variants("ramsey")

    assert service.validate_variants_obj(variants) == []
