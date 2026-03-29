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

LAYOUT_VARIANT_CURRENT_RESULTS = {
    1: "МАВ",
    2: "Е",
    3: "НОО",
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


def test_rubik_parse_layout_accepts_confirmed_variant_shape() -> None:
    cipher = load_cipher("rubik_2x2")

    parsed = cipher.parse_layout(
        {
            "1_tl": "М",
            "1_br": "О",
            "2_bl": "О",
            "2_br": "Р",
            "3_tl": "А",
            "3_br": "Т",
            "5_br": "В",
            "6_tl": "П",
        }
    )

    assert parsed["1_tl"] == "М"
    assert parsed["6_tl"] == "П"
    assert len(parsed) == 8


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


@pytest.mark.parametrize(
    ("raw_layout", "message"),
    [
        ({}, "exactly 8 occupied cells"),
        ({"7_tl": "А", "1_tl": "Б", "1_tr": "В", "1_bl": "Г", "1_br": "Д", "2_tl": "Е", "2_tr": "Ё", "2_bl": "Ж"}, "unknown"),
        ({"1_tl": "А", "1_tr": "Б", "1_bl": "В", "1_br": "Г", "2_tl": "Д", "2_tr": "Е", "2_bl": "Ё", "2_br": "ЖЖ"}, "must be one RU_33 letter"),
        ({"1_tl": "A", "1_tr": "Б", "1_bl": "В", "1_br": "Г", "2_tl": "Д", "2_tr": "Е", "2_bl": "Ё", "2_br": "Ж"}, "must be one RU_33 letter"),
    ],
)
def test_rubik_parse_layout_rejects_invalid_input(raw_layout: dict[str, object], message: str) -> None:
    cipher = load_cipher("rubik_2x2")

    with pytest.raises(ValueError, match=message):
        cipher.parse_layout(raw_layout)


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
    assert service.validate_variants_for_cipher("rubik_2x2", variants) == []


def test_rubik_variants_capture_confirmed_layout_methodics_vectors() -> None:
    variants = _rubik_variants()
    items = {entry["id"]: entry for entry in variants["items"] if isinstance(entry, dict)}

    assert items[1]["input_mode"] == "layout"
    assert items[1]["expected"] == "МОАОРТВП"
    assert items[2]["input_mode"] == "layout"
    assert items[2]["expected"] == "ВНОЕТИЕР"
    assert items[3]["input_mode"] == "layout"
    assert items[3]["expected"] == "БРОИНООД"


def test_rubik_layout_variants_current_results_are_still_diagnostic() -> None:
    variants = _rubik_variants()
    items = {entry["id"]: entry for entry in variants["items"] if isinstance(entry, dict)}

    for variant_id, actual in LAYOUT_VARIANT_CURRENT_RESULTS.items():
        result = service.run_variant("rubik_2x2", items[variant_id])
        assert result == actual
        assert result != items[variant_id]["expected"]
