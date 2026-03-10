from __future__ import annotations

import json

from miskzi_ciphers.app import service


def _item() -> dict[str, object]:
    return {"id": 1, "mode": "encrypt", "text": "abc", "key": {"k": 3}}


def test_load_variants_returns_meta_and_items_for_missing_file(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("MISKZI_DATA_DIR", str(tmp_path))

    assert service.load_variants("caesar") == {"meta": {}, "items": []}


def test_load_variants_normalizes_legacy_root(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("MISKZI_DATA_DIR", str(tmp_path))
    cipher_dir = tmp_path / "caesar"
    cipher_dir.mkdir(parents=True)
    (cipher_dir / "variants.json").write_text(json.dumps({"items": [_item()]}, ensure_ascii=False), encoding="utf-8")

    result = service.load_variants("caesar")

    assert result["meta"] == {}
    assert result["items"] == [_item()]


def test_maybe_migrate_legacy_free_text_into_meta(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("MISKZI_DATA_DIR", str(tmp_path))
    cipher_dir = tmp_path / "caesar"
    cipher_dir.mkdir(parents=True)
    (cipher_dir / "variants.json").write_text(json.dumps({"items": [_item()]}, ensure_ascii=False), encoding="utf-8")
    (cipher_dir / "free_text.txt").write_text("свободный текст", encoding="utf-8")

    service.maybe_migrate_legacy_free_text("caesar")
    migrated = json.loads((cipher_dir / "variants.json").read_text(encoding="utf-8"))

    assert migrated["meta"]["free_text"] == "свободный текст"
    assert migrated["items"] == [_item()]


def test_migration_does_not_override_existing_meta(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("MISKZI_DATA_DIR", str(tmp_path))
    cipher_dir = tmp_path / "caesar"
    cipher_dir.mkdir(parents=True)
    (cipher_dir / "variants.json").write_text(
        json.dumps({"meta": {"free_text": "из variants"}, "items": [_item()]}, ensure_ascii=False),
        encoding="utf-8",
    )
    (cipher_dir / "free_text.txt").write_text("legacy", encoding="utf-8")

    service.maybe_migrate_legacy_free_text("caesar")
    migrated = json.loads((cipher_dir / "variants.json").read_text(encoding="utf-8"))

    assert migrated["meta"]["free_text"] == "из variants"


def test_load_free_text_and_save_free_text_use_meta(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("MISKZI_DATA_DIR", str(tmp_path))

    service.save_free_text("caesar", "новый текст")

    variants = service.load_variants("caesar")
    assert variants["meta"]["free_text"] == "новый текст"
    assert service.load_free_text("caesar") == "новый текст"
