from __future__ import annotations

import json
from pathlib import Path

from miskzi_ciphers.common.paths import get_data_dir


def _variants_files() -> list[Path]:
    repo_root = Path(__file__).resolve().parents[1]
    data_dir = get_data_dir(cwd=repo_root)
    return sorted(data_dir.glob("*/variants.json"))


def test_variants_json_schema_and_ids_unique() -> None:
    files = _variants_files()
    assert files, "No variants.json files found under data/*/"

    for vf in files:
        raw = json.loads(vf.read_text(encoding="utf-8"))
        assert isinstance(raw, dict), f"{vf}: root must be JSON object"
        assert "items" in raw, f"{vf}: missing 'items'"
        assert isinstance(raw["items"], list), f"{vf}: 'items' must be list"

        if "meta" in raw:
            assert isinstance(raw["meta"], dict), f"{vf}: 'meta' must be dict"
            meta = raw["meta"]
            if "free_text" in meta:
                assert isinstance(meta["free_text"], str), f"{vf}: meta.free_text must be str"
            if "notes" in meta:
                assert isinstance(meta["notes"], str), f"{vf}: meta.notes must be str"
            if "raw_key_example" in meta:
                assert isinstance(meta["raw_key_example"], dict), f"{vf}: meta.raw_key_example must be dict"

        ids: set[int] = set()
        for i, item in enumerate(raw["items"]):
            assert isinstance(item, dict), f"{vf}: items[{i}] must be object"

            assert "id" in item and isinstance(item["id"], int), f"{vf}: items[{i}].id must be int"
            assert item["id"] not in ids, f"{vf}: duplicate id={item['id']}"
            ids.add(item["id"])

            assert item.get("mode") in {"encrypt", "decrypt"}, f"{vf}: items[{i}].mode invalid"
            assert isinstance(item.get("text"), str), f"{vf}: items[{i}].text must be str"
            assert isinstance(item.get("key"), dict), f"{vf}: items[{i}].key must be dict"

            if "expected" in item:
                assert isinstance(item["expected"], str), f"{vf}: items[{i}].expected must be str"
