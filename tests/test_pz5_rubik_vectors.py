from __future__ import annotations

import json
from pathlib import Path

import pytest

from miskzi_ciphers.app import service
from miskzi_ciphers.common.paths import get_data_dir
from miskzi_ciphers.common.registry import REGISTRY, load_cipher


METHODICAL_KEY = {
    "moves": [
        {"face": 1, "direction": "right", "turns": 1},
        {"face": 3, "direction": "right", "turns": 1},
        {"face": 4, "direction": "right", "turns": 2},
    ]
}


def _rubik_variants() -> dict[str, object]:
    repo_root = Path(__file__).resolve().parents[1]
    data_dir = get_data_dir(cwd=repo_root)
    path = data_dir / "rubik_2x2" / "variants.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_rubik_is_discovered_by_registry() -> None:
    assert REGISTRY.has("rubik_2x2")
    assert "rubik_2x2" in REGISTRY.list_names()


def test_rubik_parse_key_canonicalizes_valid_input() -> None:
    cipher = load_cipher("rubik_2x2")

    parsed = cipher.parse_key(
        {
            "moves": [
                {"face": "1", "direction": "RIGHT", "turns": "1"},
                {"face": 4, "direction": "right", "turns": 4},
                {"face": 3, "direction": "right", "turns": 1},
                {"face": 4, "direction": "right", "turns": 2},
            ]
        }
    )

    assert parsed == METHODICAL_KEY


@pytest.mark.parametrize(
    ("raw_key", "message"),
    [
        ({"moves": {}}, "moves must be a list"),
        ({"moves": [{"face": 7, "direction": "right", "turns": 1}]}, "face must be in 1..6"),
        ({"moves": [{"face": 1, "direction": "clockwise", "turns": 1}]}, "direction must be 'right' or 'left'"),
        ({"moves": [{"face": 1, "direction": "right", "turns": 0}]}, "turns must be positive"),
        ({"moves": [{"face": 1, "direction": "right", "turns": 1, "extra": 1}]}, "Unknown key"),
    ],
)
def test_rubik_parse_key_rejects_invalid_input(raw_key: dict[str, object], message: str) -> None:
    cipher = load_cipher("rubik_2x2")

    with pytest.raises(ValueError, match=message):
        cipher.parse_key(raw_key)


def test_rubik_encrypt_matches_methodical_control_vector() -> None:
    cipher = load_cipher("rubik_2x2")
    key = cipher.parse_key(METHODICAL_KEY)

    assert cipher.encrypt("РТУ МИРЭА", key) == "ТМРРИАЭУ"


def test_rubik_decrypt_matches_methodical_control_vector() -> None:
    cipher = load_cipher("rubik_2x2")
    key = cipher.parse_key(METHODICAL_KEY)

    assert cipher.decrypt("ТМРРИАЭУ", key) == "РТУ МИРЭА"


def test_rubik_roundtrip_additional_example() -> None:
    cipher = load_cipher("rubik_2x2")
    key = cipher.parse_key({})
    plaintext = "АБВ ГДЕЁЖ"

    encrypted = cipher.encrypt(plaintext, key)

    assert encrypted == "БГЕАДЖЁВ"
    assert cipher.decrypt(encrypted, key) == plaintext


def test_rubik_variants_file_passes_existing_validation_flow() -> None:
    variants = service.load_variants("rubik_2x2")

    assert service.validate_variants_obj(variants) == []


def test_rubik_variants_contain_control_example() -> None:
    variants = _rubik_variants()
    items = {entry["id"]: entry for entry in variants["items"] if isinstance(entry, dict)}

    assert items[1]["expected"] == "ТМРРИАЭУ"
    assert items[2]["expected"] == "РТУ МИРЭА"
