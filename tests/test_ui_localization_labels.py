from __future__ import annotations

from miskzi_ciphers.ui.i18n import label_param


def test_known_technical_param_keys_have_ru_form_labels() -> None:
    expected = {
        ("adfgvx", "keyword"): "Ключевое слово",
        ("gronsfeld", "digits"): "Цифровой ключ",
        ("cardano_grille", "rotation"): "Направление поворота",
        ("cardano_grille", "filler"): "Символ заполнения",
        ("cardano_grille", "mask_id"): "Идентификатор маски",
        ("vigenere", "one_based"): "Смещение от 1",
        ("bacon", "group_len"): "Длина группы",
        ("bacon", "separator"): "Разделитель",
        ("trisemus", "cols"): "Количество столбцов",
        ("trisemus", "extras"): "Дополнительные символы",
        ("richelieu", "permutations"): "Перестановки",
        ("hill", "matrix"): "Матрица ключа",
        ("hill", "pad_char"): "Символ дополнения",
        ("vernam", "keyword"): "Ключ",
    }

    for key, value in expected.items():
        cipher_id, param_name = key
        assert label_param(cipher_id, param_name) == value
