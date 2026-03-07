from __future__ import annotations

from miskzi_ciphers.common.registry import REGISTRY
from miskzi_ciphers.ui.i18n import (
    label_cipher,
    label_family,
    label_param,
    label_param_help,
    label_param_value,
    t,
)


def test_i18n_ru_core_labels() -> None:
    assert t("Playground") == "Песочница"
    assert t("Key input") == "Ввод ключа"
    assert label_family("substitution") == "Подстановка"


def test_all_registered_ciphers_have_ru_ui_label() -> None:
    for cipher_id in REGISTRY.list_names():
        assert label_cipher(cipher_id) != cipher_id


def test_param_labels_and_values_are_localized() -> None:
    assert label_param("caesar", "k") == "Сдвиг"
    assert label_param("cardano_grille", "rotation") == "Направление поворота"
    assert label_param("hill", "matrix") == "Матрица ключа"

    assert label_param_value("cardano_grille", "rotation", "ccw") == "Против часовой (ccw)"
    assert label_param_value("alberti", "shift_dir", "left") == "Влево"
    assert label_param_value("polybius", "method", 2) == "Метод 2"


def test_param_help_fallback_and_override() -> None:
    assert "поворот" in (label_param_help("cardano_grille", "rotation") or "").lower()
    assert label_param_help("unknown_cipher", "unknown_param", "fallback") == "fallback"
