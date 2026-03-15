from __future__ import annotations

import json
from pathlib import Path

import pytest

from miskzi_ciphers.app import service
from miskzi_ciphers.common.paths import get_data_dir
from miskzi_ciphers.common.registry import REGISTRY, load_cipher


METHODICAL_KEY = {
    "keyword_table": "SUBWAY",
    "anagram": "ASINTOER",
    "group_size": 5,
}


CONTROL_PLAINTEXT = "PRACTICE MAKES PERFECT"
CONTROL_CIPHERTEXT = "85458 06180 39496 58830 94853 49238 06"
VARIANT_2_CIPHERTEXT = "73993 49495 19939 48285"
VARIANT_4_CIPHERTEXT = "93278 32794 10946 98394 80585 16593 94292 94958 7"


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

    parsed = cipher.parse_key({"keyword_table": "subway", "anagram": "asintoer", "group_size": "7"})

    assert parsed == {
        "keyword_table": "SUBWAY",
        "anagram": "ASINTOER",
        "group_size": 7,
    }


@pytest.mark.parametrize(
    ("raw_key", "message"),
    [
        ({"keyword_table": "SUBWAY1"}, "Latin letters A-Z"),
        ({"keyword_table": "ORBIT"}, "must be 'SUBWAY'"),
        ({"anagram": "SPARE"}, "must be 'ASINTOER'"),
        ({"group_size": 0}, "positive integer"),
        ({"extra": 1}, "Unknown key"),
    ],
)
def test_ramsey_parse_key_rejects_invalid_input(raw_key: dict[str, object], message: str) -> None:
    cipher = load_cipher("ramsey")

    with pytest.raises(ValueError, match=message):
        cipher.parse_key(raw_key)


def test_ramsey_encrypt_matches_control_vector() -> None:
    cipher = load_cipher("ramsey")
    key = cipher.parse_key(METHODICAL_KEY)

    assert cipher.encrypt(CONTROL_PLAINTEXT, key) == CONTROL_CIPHERTEXT


def test_ramsey_decrypt_matches_control_vector() -> None:
    cipher = load_cipher("ramsey")
    key = cipher.parse_key(METHODICAL_KEY)

    assert cipher.decrypt(CONTROL_CIPHERTEXT, key) == CONTROL_PLAINTEXT


def test_ramsey_decrypt_accepts_grouped_and_ungrouped_ciphertext() -> None:
    cipher = load_cipher("ramsey")
    key = cipher.parse_key({})
    grouped = CONTROL_CIPHERTEXT
    ungrouped = CONTROL_CIPHERTEXT.replace(" ", "")

    assert cipher.decrypt(grouped, key) == CONTROL_PLAINTEXT
    assert cipher.decrypt(ungrouped, key) == CONTROL_PLAINTEXT


def test_ramsey_decrypts_additional_methodics_variant() -> None:
    cipher = load_cipher("ramsey")
    key = cipher.parse_key({})

    assert cipher.decrypt(VARIANT_2_CIPHERTEXT, key) == "NEVER GIVE UP"
    assert cipher.decrypt(VARIANT_2_CIPHERTEXT.replace(" ", ""), key) == "NEVER GIVE UP"


def test_ramsey_roundtrip_with_methodical_defaults() -> None:
    cipher = load_cipher("ramsey")
    key = cipher.parse_key({})
    plaintext = "LONDON IS THE CAPITAL OF GB"

    encrypted = cipher.encrypt(plaintext, key)

    assert encrypted == VARIANT_4_CIPHERTEXT
    assert cipher.decrypt(encrypted, key) == plaintext


@pytest.mark.parametrize(
    ("ciphertext", "message"),
    [
        ("8", "incomplete 8x/9x"),
        ("78", "incomplete 8x/9x"),
        ("12A3", "digits and grouping spaces"),
    ],
)
def test_ramsey_decrypt_rejects_invalid_ciphertext(ciphertext: str, message: str) -> None:
    cipher = load_cipher("ramsey")
    key = cipher.parse_key({})

    with pytest.raises(ValueError, match=message):
        cipher.decrypt(ciphertext, key)


def test_ramsey_variants_file_passes_existing_validation_flow() -> None:
    variants = service.load_variants("ramsey")

    assert service.validate_variants_obj(variants) == []


def test_ramsey_variants_match_methodics_vectors() -> None:
    variants = _ramsey_variants()
    items = {entry["id"]: entry for entry in variants["items"] if isinstance(entry, dict) and "id" in entry}

    assert items[1]["expected"] == CONTROL_CIPHERTEXT
    assert items[2]["expected"] == CONTROL_PLAINTEXT
    assert items[3]["expected"] == "NEVER GIVE UP"
    assert items[4]["expected"] == "LONDON IS THE CAPITAL OF GB"
