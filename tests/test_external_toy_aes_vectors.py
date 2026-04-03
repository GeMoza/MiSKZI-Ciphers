from __future__ import annotations

import json
from pathlib import Path

import pytest

from miskzi_ciphers.app import service
from miskzi_ciphers.common.paths import get_data_dir
from miskzi_ciphers.common.registry import REGISTRY, load_cipher


def _variants(cipher_id: str) -> dict[str, object]:
    repo_root = Path(__file__).resolve().parents[1]
    data_dir = get_data_dir(cwd=repo_root)
    path = data_dir / cipher_id / "variants.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_toy_aes_is_discovered_by_registry() -> None:
    assert REGISTRY.has("toy_aes")
    assert "toy_aes" in REGISTRY.list_names()


def test_toy_aes_parse_key_expands_external_example_key() -> None:
    cipher = load_cipher("toy_aes")

    parsed = cipher.parse_key({"key_hex": "0B1F0C18"})

    assert parsed["key_hex"] == "0B1F0C18"
    assert parsed["round_keys"] == [
        [0x0B, 0x1F, 0x0C, 0x18],
        [0xA7, 0xB8, 0xCC, 0xD4],
        [0xED, 0x55, 0xA0, 0x74],
    ]


def test_toy_aes_matches_external_document_example() -> None:
    cipher = load_cipher("toy_aes")
    key = cipher.parse_key({"key_hex": "0B1F0C18"})

    encrypted = cipher.encrypt("00020A00", key)

    assert encrypted == "A70A4450"
    assert cipher.decrypt(encrypted, key) == "00020A00"


@pytest.mark.parametrize(
    ("key_hex", "plaintext", "expected_ciphertext"),
    [
        ("00112233", "44556677", "C3746808"),
        ("A1B2C3D4", "01020304", "479188D5"),
    ],
)
def test_toy_aes_project_control_vectors(key_hex: str, plaintext: str, expected_ciphertext: str) -> None:
    cipher = load_cipher("toy_aes")
    key = cipher.parse_key({"key_hex": key_hex})

    assert cipher.encrypt(plaintext, key) == expected_ciphertext
    assert cipher.decrypt(expected_ciphertext, key) == plaintext


@pytest.mark.parametrize(
    ("raw_key", "message"),
    [
        ({"key_hex": "1234"}, "8 hex"),
        ({"key_hex": "ZZZZZZZZ"}, "hexadecimal"),
    ],
)
def test_toy_aes_parse_key_rejects_invalid_input(raw_key: dict[str, object], message: str) -> None:
    cipher = load_cipher("toy_aes")

    with pytest.raises(ValueError, match=message):
        cipher.parse_key(raw_key)


@pytest.mark.parametrize(
    ("ciphertext", "message"),
    [
        ("1234567", "8 hex"),
        ("GGGGGGGG", "hexadecimal"),
    ],
)
def test_toy_aes_rejects_invalid_block_format(ciphertext: str, message: str) -> None:
    cipher = load_cipher("toy_aes")
    key = cipher.parse_key({"key_hex": "0B1F0C18"})

    with pytest.raises(ValueError, match=message):
        cipher.decrypt(ciphertext, key)


def test_toy_aes_variants_file_passes_existing_validation_flow() -> None:
    variants = service.load_variants("toy_aes")

    assert service.validate_variants_obj(variants) == []
    assert service.validate_variants_for_cipher("toy_aes", variants) == []


def test_toy_aes_variants_match_external_and_project_control_vectors() -> None:
    variants = _variants("toy_aes")
    items = {entry["id"]: entry for entry in variants["items"] if isinstance(entry, dict) and "id" in entry}

    assert items[1]["expected"] == "A70A4450"
    assert items[2]["expected"] == "00020A00"
    assert items[3]["expected"] == "C3746808"
    assert items[4]["expected"] == "44556677"
    assert items[5]["expected"] == "479188D5"
    assert items[6]["expected"] == "01020304"
