from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from miskzi_ciphers.common.paths import get_data_dir
from miskzi_ciphers.common.registry import REGISTRY
from miskzi_ciphers.common.types import Cipher


def list_ciphers() -> list[str]:
    return REGISTRY.list_names()


def get_cipher(cipher_id: str) -> Cipher:
    return REGISTRY.load(cipher_id)


def get_cipher_description(cipher_id: str) -> dict[str, Any]:
    return get_cipher(cipher_id).describe()


def parse_key(cipher_id: str, raw: dict[str, Any]) -> dict[str, Any]:
    return get_cipher(cipher_id).parse_key(raw)


def encrypt(cipher_id: str, text: str, raw_key: dict[str, Any]) -> str:
    key = parse_key(cipher_id, raw_key)
    return get_cipher(cipher_id).encrypt(text, key)


def decrypt(cipher_id: str, text: str, raw_key: dict[str, Any]) -> str:
    key = parse_key(cipher_id, raw_key)
    return get_cipher(cipher_id).decrypt(text, key)


def data_dir() -> Path:
    return get_data_dir()


def variants_path(cipher_id: str) -> Path:
    return data_dir() / cipher_id / "variants.json"


def free_text_path(cipher_id: str) -> Path:
    return data_dir() / cipher_id / "free_text.txt"


def load_variants(cipher_id: str) -> dict[str, Any]:
    path = variants_path(cipher_id)
    if not path.exists():
        return {"items": []}
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        return {"items": []}
    return raw


def save_variants(cipher_id: str, obj: dict[str, Any]) -> None:
    path = variants_path(cipher_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def load_free_text(cipher_id: str) -> str:
    path = free_text_path(cipher_id)
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def save_free_text(cipher_id: str, text: str) -> None:
    path = free_text_path(cipher_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def validate_variants_obj(obj: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    if not isinstance(obj, dict):
        return ["root must be JSON object"]

    if "items" not in obj:
        return ["missing 'items'"]

    items = obj["items"]
    if not isinstance(items, list):
        return ["'items' must be list"]

    ids: set[int] = set()
    for i, item in enumerate(items):
        prefix = f"items[{i}]"

        if not isinstance(item, dict):
            errors.append(f"{prefix} must be object")
            continue

        item_id = item.get("id")
        if not isinstance(item_id, int):
            errors.append(f"{prefix}.id must be int")
        elif item_id in ids:
            errors.append(f"duplicate id={item_id}")
        else:
            ids.add(item_id)

        if item.get("mode") not in {"encrypt", "decrypt"}:
            errors.append(f"{prefix}.mode invalid")

        if not isinstance(item.get("text"), str):
            errors.append(f"{prefix}.text must be str")

        if not isinstance(item.get("key"), dict):
            errors.append(f"{prefix}.key must be dict")

        if "expected" in item and not isinstance(item["expected"], str):
            errors.append(f"{prefix}.expected must be str")

    return errors
