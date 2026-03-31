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


def test_feistel_network_is_discovered_by_registry() -> None:
    assert REGISTRY.has("feistel_network")
    assert "feistel_network" in REGISTRY.list_names()


def test_magma_is_discovered_by_registry() -> None:
    assert REGISTRY.has("magma")
    assert "magma" in REGISTRY.list_names()


def test_feistel_network_matches_pz7_example() -> None:
    cipher = load_cipher("feistel_network")
    key = cipher.parse_key({"keyword": "ЛЕТО"})

    assert cipher.encrypt("КТСО", key) == "11 06 25 12"
    assert cipher.decrypt("11 06 25 12", key) == "КТСО"
    assert cipher.decrypt("КЕШЛ", key) == "КТСО"


@pytest.mark.parametrize(
    ("ciphertext", "keyword", "expected"),
    [
        ("13 00 45 26", "КТСО", "МАЯМ"),
        ("12 04 02 44", "ЗАРЯ", "ЛУНА"),
        ("13 01 28 19", "КИИБ", "МАРС"),
        ("17 20 29 13", "ЛИСА", "РОЛЬ"),
        ("08 17 05 08", "ЗИМА", "ЗФМШ"),
        ("25 28 06 25", "АВТО", "ШЛЮЗ"),
        ("01 00 18 10", "БЛОК", "АВТО"),
        ("01 06 20 07", "ЗВУК", "АРФА"),
        ("15 29 01 30", "ОКНО", "ОЧНЗ"),
    ],
)
def test_feistel_network_matches_pz7_variants(ciphertext: str, keyword: str, expected: str) -> None:
    cipher = load_cipher("feistel_network")
    key = cipher.parse_key({"keyword": keyword})

    assert cipher.decrypt(ciphertext, key) == expected


@pytest.mark.parametrize(
    ("raw_key", "message"),
    [
        ({"keyword": "ЛЁТО"}, "without 'Ё'"),
        ({"keyword": "ЛЕТ"}, "exactly 4"),
    ],
)
def test_feistel_network_parse_key_rejects_invalid_input(raw_key: dict[str, object], message: str) -> None:
    cipher = load_cipher("feistel_network")

    with pytest.raises(ValueError, match=message):
        cipher.parse_key(raw_key)


def test_feistel_network_variants_file_passes_existing_validation_flow() -> None:
    variants = service.load_variants("feistel_network")

    assert service.validate_variants_obj(variants) == []
    assert service.validate_variants_for_cipher("feistel_network", variants) == []


def test_magma_project_control_vector() -> None:
    cipher = load_cipher("magma")
    key = cipher.parse_key(
        {"key_hex": "FFEEDDCCBBAA99887766554433221100FEDCBA98765432100123456789ABCDEF"}
    )

    encrypted = cipher.encrypt("FEDCBA9876543210", key)

    assert encrypted == "949D6DA5C76B8DD2"
    assert cipher.decrypt(encrypted, key) == "FEDCBA9876543210"


@pytest.mark.parametrize(
    ("raw_key", "message"),
    [
        ({"key_hex": "1234"}, "64 hex"),
        ({"key_hex": "Z" * 64}, "hexadecimal"),
    ],
)
def test_magma_parse_key_rejects_invalid_input(raw_key: dict[str, object], message: str) -> None:
    cipher = load_cipher("magma")

    with pytest.raises(ValueError, match=message):
        cipher.parse_key(raw_key)


def test_magma_variants_file_passes_existing_validation_flow() -> None:
    variants = service.load_variants("magma")

    assert service.validate_variants_obj(variants) == []
    assert service.validate_variants_for_cipher("magma", variants) == []


def test_magma_variants_match_project_control_vectors() -> None:
    variants = _variants("magma")
    items = {entry["id"]: entry for entry in variants["items"] if isinstance(entry, dict) and "id" in entry}

    assert items[1]["expected"] == "949D6DA5C76B8DD2"
    assert items[2]["expected"] == "FEDCBA9876543210"
