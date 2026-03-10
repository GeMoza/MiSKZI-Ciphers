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


def _normalize_variants_root(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {"meta": {}, "items": []}

    meta = raw.get("meta", {})
    if not isinstance(meta, dict):
        meta = {}

    items = raw.get("items", [])
    if not isinstance(items, list):
        items = []

    return {"meta": dict(meta), "items": items}


def _read_variants_root(cipher_id: str) -> dict[str, Any]:
    path = variants_path(cipher_id)
    if not path.exists():
        return {"meta": {}, "items": []}

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"meta": {}, "items": []}

    return _normalize_variants_root(raw)


def load_meta(cipher_id: str) -> dict[str, Any]:
    maybe_migrate_legacy_free_text(cipher_id)
    return dict(_read_variants_root(cipher_id).get("meta", {}))


def maybe_migrate_legacy_free_text(cipher_id: str) -> None:
    legacy_path = free_text_path(cipher_id)
    if not legacy_path.exists():
        return

    variants = _read_variants_root(cipher_id)
    meta = dict(variants.get("meta", {}))
    current_free_text = meta.get("free_text")
    if isinstance(current_free_text, str) and current_free_text.strip():
        return

    meta["free_text"] = legacy_path.read_text(encoding="utf-8")
    variants["meta"] = meta
    save_variants(cipher_id, variants)


def load_variants(cipher_id: str) -> dict[str, Any]:
    maybe_migrate_legacy_free_text(cipher_id)
    return _read_variants_root(cipher_id)


def save_variants(cipher_id: str, obj: dict[str, Any]) -> None:
    path = variants_path(cipher_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    normalized = _normalize_variants_root(obj)
    path.write_text(json.dumps(normalized, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def load_free_text(cipher_id: str) -> str:
    meta = load_meta(cipher_id)
    free_text = meta.get("free_text", "")
    return free_text if isinstance(free_text, str) else ""


def save_free_text(cipher_id: str, text: str) -> None:
    variants = load_variants(cipher_id)
    meta = dict(variants.get("meta", {}))
    meta["free_text"] = text
    variants["meta"] = meta
    save_variants(cipher_id, variants)


def validate_variants_obj(obj: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    if not isinstance(obj, dict):
        return ["root must be JSON object"]

    if "items" not in obj:
        return ["missing 'items'"]

    if "meta" in obj and not isinstance(obj["meta"], dict):
        errors.append("'meta' must be dict")
    else:
        meta = obj.get("meta", {})
        if isinstance(meta, dict):
            if "free_text" in meta and not isinstance(meta["free_text"], str):
                errors.append("meta.free_text must be str")
            if "notes" in meta and not isinstance(meta["notes"], str):
                errors.append("meta.notes must be str")
            if "raw_key_example" in meta and not isinstance(meta["raw_key_example"], dict):
                errors.append("meta.raw_key_example must be dict")

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
