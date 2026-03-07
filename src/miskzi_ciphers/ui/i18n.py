from __future__ import annotations

from typing import Final

LANG_RU: Final[str] = "ru"
LANG_EN: Final[str] = "en"

UI_STRINGS: Final[dict[str, dict[str, str]]] = {
    "ru": {
        "Page": "Страница",
        "Playground": "Песочница",
        "Data Manager": "Менеджер данных",
        "Cipher": "Шифр",
        "Description": "Описание",
        "Technical description": "Техническое описание",
        "Cipher name": "Название шифра",
        "Family": "Семейство",
        "Notes": "Примечание",
        "Parameters": "Параметры",
        "Parameter": "Параметр",
        "Raw key": "Внутренний ключ",
        "Type": "Тип",
        "Required": "Обязательный",
        "Default": "По умолчанию",
        "Help": "Пояснение",
        "Example": "Пример",
        "Yes": "Да",
        "No": "Нет",
        "Key input mode": "Режим ввода ключа",
        "Form": "Форма",
        "Raw JSON": "Сырой JSON",
        "Raw key JSON": "JSON ключа",
        "Parse key": "Разобрать ключ",
        "Key parsed": "Ключ разобран",
        "Plaintext": "Открытый текст",
        "Ciphertext": "Шифротекст",
        "Decrypted": "Расшифрованный текст",
        "Encrypt": "Зашифровать",
        "Decrypt": "Расшифровать",
        "Roundtrip": "Раундтрип",
        "Roundtrip equals": "Раундтрип совпадает",
        "Load input": "Загрузка входных данных",
        "Source": "Источник",
        "None": "Нет",
        "Variant": "Вариант",
        "Free text": "Свободный текст",
        "Select variant": "Выберите вариант",
        "Load variant": "Загрузить вариант",
        "Load free_text": "Загрузить free_text",
        "Loaded variant": "Вариант загружен",
        "Loaded free_text": "free_text загружен",
        "Read-only: does not modify saved data": "Только чтение: сохранённые данные не изменяются",
        "Variants": "Варианты",
        "Edit variant": "Редактирование варианта",
        "Edit existing": "Редактировать существующий",
        "Add new": "Добавить новый",
        "Save": "Сохранить",
        "Delete": "Удалить",
        "Run variant": "Запустить вариант",
        "Save free_text": "Сохранить free_text",
        "Validation errors": "Ошибки валидации",
        "No params": "Нет параметров",
        "No variants": "Вариантов нет",
        "JSON error": "Ошибка JSON",
        "Raw JSON key must be an object": "Ключ в Raw JSON должен быть объектом",
        "Optional": "необязательный",
        "Encrypted": "Зашифровано",
        "Decrypted action": "Расшифровано",
        "Key JSON object": "key (JSON-объект)",
        "Expected optional": "expected (необязательно)",
        "key JSON must be object": "key JSON должен быть объектом",
        "key JSON error": "Ошибка key JSON",
        "Cannot save key JSON object": "Нельзя сохранить: key должен быть корректным JSON-объектом",
        "Cannot run key JSON object": "Нельзя запустить: key должен быть корректным JSON-объектом",
        "Saved variants": "variants.json сохранён",
        "Deleted variant": "Вариант удалён",
        "Result": "Результат",
        "expected match": "expected совпадает",
        "expected mismatch": "expected не совпадает",
        "free_text file": "free_text.txt",
        "Saved free_text": "free_text.txt сохранён",
        "Reset playground": "Сбросить песочницу",
        "Playground reset": "Песочница сброшена",
        "Data directory": "Каталог данных",
        "Cipher directory": "Каталог шифра",
        "Identifier": "Идентификатор",
        "Mode": "Режим",
        "Text": "Текст",
        "Key input": "Ввод ключа",
        "Apply JSON to Form": "Применить JSON к форме",
        "Sync to Raw JSON": "Синхронизировать с Raw JSON",
        "Reset form": "Сбросить форму",
        "Encrypt mode": "Шифрование",
        "Decrypt mode": "Расшифрование",
    },
    "en": {
        "Page": "Page",
        "Playground": "Playground",
        "Data Manager": "Data Manager",
        "Cipher": "Cipher",
        "Description": "Description",
        "Technical description": "Technical description",
        "Cipher name": "Cipher name",
        "Family": "Family",
        "Notes": "Notes",
        "Parameters": "Parameters",
        "Parameter": "Parameter",
        "Raw key": "Raw key",
        "Type": "Type",
        "Required": "Required",
        "Default": "Default",
        "Help": "Help",
        "Example": "Example",
        "Yes": "Yes",
        "No": "No",
        "Key input mode": "Key input mode",
        "Form": "Form",
        "Raw JSON": "Raw JSON",
        "Raw key JSON": "Raw key JSON",
        "Parse key": "Parse key",
        "Key parsed": "Key parsed",
        "Plaintext": "Plaintext",
        "Ciphertext": "Ciphertext",
        "Decrypted": "Decrypted",
        "Encrypt": "Encrypt",
        "Decrypt": "Decrypt",
        "Roundtrip": "Roundtrip",
        "Roundtrip equals": "Roundtrip equals",
        "Load input": "Load input",
        "Source": "Source",
        "None": "None",
        "Variant": "Variant",
        "Free text": "Free text",
        "Select variant": "Select variant",
        "Load variant": "Load variant",
        "Load free_text": "Load free_text",
        "Loaded variant": "Loaded variant",
        "Loaded free_text": "Loaded free_text",
        "Read-only: does not modify saved data": "Read-only: does not modify saved data",
        "Variants": "Variants",
        "Edit variant": "Edit variant",
        "Edit existing": "Edit existing",
        "Add new": "Add new",
        "Save": "Save",
        "Delete": "Delete",
        "Run variant": "Run variant",
        "Save free_text": "Save free_text",
        "Validation errors": "Validation errors",
        "No params": "No params",
        "No variants": "No variants",
    },
}

CIPHER_LABELS: Final[dict[str, dict[str, str]]] = {
    "ru": {
        "adfgvx": "Шифр ADFGVX",
        "affine": "Аффинный шифр",
        "alberti": "Шифр Альберти",
        "atbash": "Атбаш",
        "bacon": "Шифр Бэкона",
        "binary_code": "Двоичный код",
        "book_cipher": "Книжный шифр",
        "caesar": "Шифр Цезаря",
        "cardano_grille": "Решетка Кардано",
        "gronsfeld": "Шифр Гронсфельда",
        "hill": "Шифр Хилла",
        "litorea": "Русская литорея",
        "magic_square": "Магический квадрат",
        "morse": "Азбука Морзе",
        "polybius": "Квадрат Полибия",
        "richelieu": "Шифр Ришелье",
        "scytale": "Скитала",
        "trisemus": "Шифр Трисемуса",
        "vernam": "Шифр Вернама",
        "vigenere": "Шифр Виженера",
    },
    "en": {},
}

FAMILY_LABELS: Final[dict[str, dict[str, str]]] = {
    "ru": {
        "substitution": "Подстановка",
        "transposition": "Перестановка",
        "fractionating-transposition": "Дробление и перестановка",
        "substitution/fractionation": "Подстановка и дробление",
        "encoding": "Кодирование",
        "book": "Книжный шифр",
        "polyalphabetic": "Полиалфавитный",
        "polygraphic": "Полиграфический",
        "stream": "Потоковый",
    },
    "en": {},
}

PARAM_LABELS: Final[dict[str, dict[str, str]]] = {
    "ru": {
        "adfgvx.keyword": "Ключевое слово",
        "affine.a": "Коэффициент a",
        "affine.b": "Смещение b",
        "alberti.outer": "Внешний диск",
        "alberti.inner": "Внутренний диск",
        "alberti.index_char": "Индексная буква",
        "alberti.shift_every": "Сдвиг каждые N символов",
        "alberti.shift_step": "Шаг сдвига",
        "alberti.shift_dir": "Направление сдвига",
        "alberti.emit_prefix": "Добавлять префикс",
        "alberti.start_outer": "Начальный символ внешнего диска",
        "bacon.group_len": "Длина группы",
        "bacon.separator": "Разделитель",
        "book_cipher.key_text": "Текст ключа",
        "book_cipher.key_path": "Путь к ключевому файлу",
        "book_cipher.e_instead_of_ee": "Использовать Е вместо Э",
        "caesar.k": "Сдвиг",
        "cardano_grille.size": "Размер решетки",
        "cardano_grille.rotation": "Направление поворота",
        "cardano_grille.filler": "Символ заполнения",
        "cardano_grille.mask_id": "Идентификатор маски",
        "gronsfeld.digits": "Цифровой ключ",
        "hill.matrix": "Матрица ключа",
        "hill.pad_char": "Символ дополнения",
        "polybius.method": "Метод",
        "richelieu.key": "Ключ (строка перестановок)",
        "richelieu.permutations": "Перестановки",
        "scytale.r": "Число строк",
        "trisemus.keyword": "Ключевое слово",
        "trisemus.cols": "Количество столбцов",
        "trisemus.extras": "Дополнительные символы",
        "vernam.keyword": "Ключ",
        "vernam.apply_to": "Режим применения",
        "vigenere.keyword": "Ключевое слово",
        "vigenere.one_based": "Смещение от 1",
    },
    "en": {},
}

PARAM_HELPS: Final[dict[str, dict[str, str]]] = {
    "ru": {
        "adfgvx.keyword": "Ключевое слово на латинице A-Z.",
        "bacon.group_len": "Длина группы A/B. Для текущей таблицы RU_33 должна быть равна 6.",
        "bacon.separator": "Разделитель между группами в результате шифрования.",
        "book_cipher.e_instead_of_ee": "Если в ключевом тексте нет 'Э', при шифровании использовать 'Е'.",
        "cardano_grille.size": "Размер решетки (в текущей реализации поддерживается только 6).",
        "cardano_grille.rotation": "Поворот на 90 градусов: против часовой (ccw) или по часовой (cw).",
        "cardano_grille.filler": "Символ для заполнения пустых ячеек.",
        "cardano_grille.mask_id": "Идентификатор маски отверстий.",
        "gronsfeld.digits": "Ключ из цифр 0-9.",
        "hill.matrix": "Квадратная матрица n x n для преобразования блоков.",
        "hill.pad_char": "Символ из RU_33 для дополнения последнего блока.",
        "richelieu.key": "Нотация вида (4213)(51243).",
        "richelieu.permutations": "Список перестановок, например [[4,2,1,3],[5,1,2,4,3]].",
        "vernam.apply_to": "Режим совместимости: влияет на проверку параметров.",
        "vigenere.one_based": "Если включено, сдвиг считается как index+1 вместо index.",
    },
    "en": {},
}

PARAM_VALUE_LABELS: Final[dict[str, dict[str, dict[str, str]]]] = {
    "ru": {
        "alberti.shift_dir": {"left": "Влево", "right": "Вправо"},
        "cardano_grille.rotation": {"ccw": "Против часовой (ccw)", "cw": "По часовой (cw)"},
        "polybius.method": {"1": "Метод 1", "2": "Метод 2", "3": "Метод 3"},
        "vernam.apply_to": {"all": "Все символы", "letters_only": "Только буквы"},
    },
    "en": {},
}

DESC_OVERRIDES: Final[dict[str, dict[str, str]]] = {
    "ru": {},
    "en": {},
}


def get_lang() -> str:
    return LANG_RU


def t(key: str, default: str | None = None, lang: str | None = None) -> str:
    use_lang = lang or get_lang()
    return UI_STRINGS.get(use_lang, {}).get(key, default if default is not None else key)


def label_cipher(cipher_id: str, lang: str | None = None) -> str:
    use_lang = lang or get_lang()
    return CIPHER_LABELS.get(use_lang, {}).get(cipher_id, cipher_id)


def label_family(family_id: str, lang: str | None = None) -> str:
    use_lang = lang or get_lang()
    return FAMILY_LABELS.get(use_lang, {}).get(family_id, family_id)


def label_param(cipher_id: str, param_name: str, lang: str | None = None) -> str:
    use_lang = lang or get_lang()
    key = f"{cipher_id}.{param_name}"
    return PARAM_LABELS.get(use_lang, {}).get(key, param_name)


def label_param_help(cipher_id: str, param_name: str, default_help: str | None = None, lang: str | None = None) -> str | None:
    use_lang = lang or get_lang()
    key = f"{cipher_id}.{param_name}"
    return PARAM_HELPS.get(use_lang, {}).get(key, default_help)


def label_param_value(cipher_id: str, param_name: str, value: object, lang: str | None = None) -> str:
    use_lang = lang or get_lang()
    key = f"{cipher_id}.{param_name}"
    raw = str(value)
    return PARAM_VALUE_LABELS.get(use_lang, {}).get(key, {}).get(raw, raw)


def description_override(cipher_id: str, lang: str | None = None) -> str | None:
    use_lang = lang or get_lang()
    return DESC_OVERRIDES.get(use_lang, {}).get(cipher_id)
