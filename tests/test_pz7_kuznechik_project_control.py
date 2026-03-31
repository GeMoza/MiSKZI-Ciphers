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


def test_kuznechik_is_discovered_by_registry() -> None:
    assert REGISTRY.has("kuznechik")
    assert "kuznechik" in REGISTRY.list_names()


def test_kuznechik_parse_key_and_project_control_cycle() -> None:
    cipher = load_cipher("kuznechik")
    key = cipher.parse_key(
        {"key_hex": "8899AABBCCDDEEFF0011223344556677FEDCBA98765432100123456789ABCDEF"}
    )

    ciphertext = cipher.encrypt("1122334455667700FFEEDDCCBBAA9988", key)

    assert ciphertext == "EA50CC8040482AD5231BF987FDBBFF8A"
    assert cipher.decrypt(ciphertext, key) == "1122334455667700FFEEDDCCBBAA9988"


@pytest.mark.parametrize(
    ("raw_key", "message"),
    [
        ({"key_hex": "1234"}, "64 hex"),
        ({"key_hex": "Z" * 64}, "hexadecimal"),
    ],
)
def test_kuznechik_parse_key_rejects_invalid_input(raw_key: dict[str, object], message: str) -> None:
    cipher = load_cipher("kuznechik")

    with pytest.raises(ValueError, match=message):
        cipher.parse_key(raw_key)


def test_kuznechik_variants_file_passes_existing_validation_flow() -> None:
    variants = service.load_variants("kuznechik")

    assert service.validate_variants_obj(variants) == []
    assert service.validate_variants_for_cipher("kuznechik", variants) == []


def test_kuznechik_variants_match_project_control_vectors() -> None:
    variants = _variants("kuznechik")
    items = {entry["id"]: entry for entry in variants["items"] if isinstance(entry, dict) and "id" in entry}

    assert items[1]["expected"] == "EA50CC8040482AD5231BF987FDBBFF8A"
    assert items[2]["expected"] == "1122334455667700FFEEDDCCBBAA9988"
