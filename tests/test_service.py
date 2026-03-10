from __future__ import annotations

from miskzi_ciphers.app.service import validate_variants_obj


def test_validate_variants_obj_basic_errors() -> None:
    obj = {
        "items": [
            {"id": 1, "mode": "encrypt", "text": "abc", "key": {"k": 3}},
            {"id": 1, "mode": "oops", "text": 10, "key": []},
        ]
    }

    errors = validate_variants_obj(obj)

    assert "duplicate id=1" in errors
    assert "items[1].mode invalid" in errors
    assert "items[1].text must be str" in errors
    assert "items[1].key must be dict" in errors


def test_validate_variants_obj_accepts_meta() -> None:
    obj = {
        "meta": {
            "free_text": "пример",
            "notes": "заметки",
            "raw_key_example": {"k": 3},
        },
        "items": [],
    }

    assert validate_variants_obj(obj) == []


def test_validate_variants_obj_rejects_bad_meta() -> None:
    obj = {
        "meta": {
            "free_text": 1,
            "notes": [],
            "raw_key_example": "{}",
        },
        "items": [],
    }

    errors = validate_variants_obj(obj)

    assert "meta.free_text must be str" in errors
    assert "meta.notes must be str" in errors
    assert "meta.raw_key_example must be dict" in errors
