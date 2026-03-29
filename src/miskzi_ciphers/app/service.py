from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from miskzi_ciphers.common.paths import get_data_dir
from miskzi_ciphers.common.registry import REGISTRY
from miskzi_ciphers.common.types import Cipher


TEXT_INPUT_MODE = "text"
LAYOUT_INPUT_MODE = "layout"
SUPPORTED_INPUT_MODES = {TEXT_INPUT_MODE, LAYOUT_INPUT_MODE}


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


def _item_input_mode(item: dict[str, Any]) -> str:
    raw_mode = item.get("input_mode", TEXT_INPUT_MODE)
    return str(raw_mode)


def run_variant(cipher_id: str, item: dict[str, Any]) -> str:
    if not isinstance(item, dict):
        raise ValueError("variant item must be object")

    mode = str(item.get("mode", ""))
    input_mode = _item_input_mode(item)
    if input_mode not in SUPPORTED_INPUT_MODES:
        raise ValueError(f"variant input_mode must be one of {sorted(SUPPORTED_INPUT_MODES)}")

    key_raw = item.get("key", {})
    if not isinstance(key_raw, dict):
        raise ValueError("variant key must be object")
    key = parse_key(cipher_id, key_raw)
    cipher = get_cipher(cipher_id)

    if cipher_id == "rubik_2x2" and input_mode == LAYOUT_INPUT_MODE:
        parse_layout = getattr(cipher, "parse_layout", None)
        encrypt_layout = getattr(cipher, "encrypt_layout", None)
        if not callable(parse_layout) or not callable(encrypt_layout):
            raise ValueError("rubik_2x2: layout variants are not supported by current cipher implementation")
        if mode != "encrypt":
            raise ValueError("rubik_2x2: layout variants currently support only encrypt mode")
        layout = parse_layout(item.get("layout", {}))
        return encrypt_layout(layout, key)

    text = item.get("text")
    if not isinstance(text, str):
        raise ValueError("variant text must be str")
    if mode == "encrypt":
        return cipher.encrypt(text, key)
    if mode == "decrypt":
        return cipher.decrypt(text, key)
    raise ValueError("variant mode invalid")


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

        input_mode = _item_input_mode(item)
        if input_mode not in SUPPORTED_INPUT_MODES:
            errors.append(f"{prefix}.input_mode invalid")
        elif input_mode == TEXT_INPUT_MODE:
            if not isinstance(item.get("text"), str):
                errors.append(f"{prefix}.text must be str")
            if "layout" in item and not isinstance(item["layout"], dict):
                errors.append(f"{prefix}.layout must be dict")
        else:
            if not isinstance(item.get("layout"), dict):
                errors.append(f"{prefix}.layout must be dict")
            if "text" in item and not isinstance(item["text"], str):
                errors.append(f"{prefix}.text must be str")

        if not isinstance(item.get("key"), dict):
            errors.append(f"{prefix}.key must be dict")

        if "expected" in item and not isinstance(item["expected"], str):
            errors.append(f"{prefix}.expected must be str")

    return errors


def validate_variants_for_cipher(cipher_id: str, obj: dict[str, Any]) -> list[str]:
    errors = validate_variants_obj(obj)
    items = obj.get("items", []) if isinstance(obj, dict) else []
    if not isinstance(items, list):
        return errors

    if cipher_id != "rubik_2x2":
        return errors

    cipher = get_cipher(cipher_id)
    parse_layout = getattr(cipher, "parse_layout", None)
    if not callable(parse_layout):
        return errors

    for i, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        if _item_input_mode(item) != LAYOUT_INPUT_MODE:
            continue
        try:
            parse_layout(item.get("layout", {}))
        except Exception as exc:
            errors.append(f"items[{i}].layout invalid: {exc}")

    return errors
