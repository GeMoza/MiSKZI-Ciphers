from __future__ import annotations

from miskzi_ciphers.ui.i18n import label_cipher, label_param, t


def test_i18n_ru_labels() -> None:
    assert t("Playground") == "Песочница"
    assert label_cipher("caesar") == "Шифр Цезаря"
    assert label_param("caesar", "k") == "Сдвиг (k)"
