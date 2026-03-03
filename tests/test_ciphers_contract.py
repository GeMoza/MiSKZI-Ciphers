from __future__ import annotations

from pathlib import Path

import pytest

from miskzi_ciphers.common.alphabet import RU_33
from miskzi_ciphers.common.paths import get_data_dir
from miskzi_ciphers.common.registry import REGISTRY


@pytest.mark.parametrize("name", REGISTRY.list_names())
def test_registry_load_and_describe(name: str) -> None:
    cipher = REGISTRY.load(name)
    info = cipher.describe()

    assert isinstance(info, dict)
    assert getattr(cipher, "name", "") == name


@pytest.mark.parametrize("name", REGISTRY.list_names())
def test_parse_key_empty_contract(name: str) -> None:
    cipher = REGISTRY.load(name)

    try:
        parsed = cipher.parse_key({})
    except (ValueError, TypeError):
        return

    assert isinstance(parsed, dict)


def _roundtrip_cases() -> dict[str, tuple[dict, str]]:
    repo_root = Path(__file__).resolve().parents[1]
    data_dir = get_data_dir(cwd=repo_root)
    key_path = data_dir / "book_cipher" / "key.txt"

    return {
        "atbash": ({}, "ПРИВЕТ, МИР!"),
        "caesar": ({"k": 3}, "ПРИВЕТ, МИР!"),
        "scytale": ({"r": 4}, "ПРИВЕТ, МИР!"),
        "polybius": ({"method": 1}, "ПРИВЕТ, МИР!"),
        "magic_square": ({}, "АБВГДЕЁЖЗИЙКЛМНО"),
        "book_cipher": ({"key_path": str(key_path)}, "ПРИВЕТМИР"),
        "affine": ({"a": 5, "b": 3}, "ПРИВЕТ, МИР!"),
        "binary_code": ({}, "МИРЭА"),
        "litorea": ({}, "МИРЭА"),
        "vigenere": ({"keyword": "ГДЕ ОН"}, "ПРИВЕТ, МИР!"),
        "alberti": (
            {
                "outer": RU_33,
                "inner": RU_33[::-1],
                "index_char": "А",
                "shift_every": 5,
                "shift_step": 1,
                "shift_dir": "left",
                "emit_prefix": True,
                "start_outer": "А",
            },
            "ПРИВЕТМИР",
        ),
        "gronsfeld": ({"digits": "15215"}, "ПРИВЕТ, МИР!"),
        "trisemus": ({"keyword": "КЛЮЧ", "cols": 6, "extras": "123"}, "ПРИВЕТ, МИР!"),
        "bacon": ({"group_len": 6, "separator": " "}, "МИРЭА"),
        "cardano_grille": (
            {"size": 6, "rotation": "ccw", "filler": "А", "mask_id": "fig12"},
            "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯАБВ",
        ),
        "richelieu": ({"permutations": [[4, 2, 1, 3]]}, "ТЕСТ"),
        "morse": ({}, "ТЕСТ МИР"),
        "vernam": ({"keyword": "...."}, "ТЕСТ"),
        "adfgvx": ({"keyword": "DRIVE"}, "TEST123"),
        "hill": ({"matrix": [[1, 2], [3, 5]]}, "ТЕСТ"),
    }


@pytest.mark.parametrize("name", REGISTRY.list_names())
def test_cipher_roundtrip_safe_cases(name: str) -> None:
    cipher = REGISTRY.load(name)
    raw_key, plaintext = _roundtrip_cases()[name]

    key_enc = cipher.parse_key(raw_key)
    ciphertext = cipher.encrypt(plaintext, key_enc)

    key_dec = cipher.parse_key(raw_key)
    roundtrip = cipher.decrypt(ciphertext, key_dec)

    assert roundtrip == plaintext
