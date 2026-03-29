from __future__ import annotations

from miskzi_ciphers.app.service import validate_variants_for_cipher, validate_variants_obj


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


def test_validate_variants_obj_accepts_layout_variants() -> None:
    obj = {
        "items": [
            {
                "id": 1,
                "input_mode": "layout",
                "mode": "encrypt",
                "layout": {
                    "1_tl": "М",
                    "1_br": "О",
                    "2_bl": "О",
                    "2_br": "Р",
                    "3_tl": "А",
                    "3_br": "Т",
                    "5_br": "В",
                    "6_tl": "П",
                },
                "key": {"moves": []},
            }
        ]
    }

    assert validate_variants_obj(obj) == []
    assert validate_variants_for_cipher("rubik_2x2", obj) == []


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


def test_validate_variants_for_cipher_rejects_invalid_rubik_layout() -> None:
    obj = {
        "items": [
            {
                "id": 1,
                "input_mode": "layout",
                "mode": "encrypt",
                "layout": {"1_tl": "М"},
                "key": {"moves": []},
            }
        ]
    }

    errors = validate_variants_for_cipher("rubik_2x2", obj)

    assert any("items[0].layout invalid" in err for err in errors)
