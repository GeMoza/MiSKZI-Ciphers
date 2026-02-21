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
