from __future__ import annotations

from miskzi_ciphers.app import service
from miskzi_ciphers.ui.app import _prepare_description_params


def test_prepare_description_params_serializes_complex_values() -> None:
    desc = service.get_cipher_description("hill")

    prepared = _prepare_description_params("hill", desc.get("params", []))

    matrix_row = next(row for row in prepared if row["Raw key"] == "matrix")
    assert matrix_row["Example"] == "[[1, 2], [3, 5]]"
    assert all(not isinstance(value, (list, dict, tuple)) for row in prepared for value in row.values())


def test_prepare_description_params_handles_other_cipher_descriptions() -> None:
    for cipher_id in ("ramsey", "rubik_2x2"):
        desc = service.get_cipher_description(cipher_id)
        prepared = _prepare_description_params(cipher_id, desc.get("params", []))

        assert prepared
        assert all(not isinstance(value, (list, dict, tuple)) for row in prepared for value in row.values())
