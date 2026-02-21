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
        "Parameter": "Параметр",
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
    },
    "en": {
        "Page": "Page",
        "Playground": "Playground",
        "Data Manager": "Data Manager",
        "Cipher": "Cipher",
        "Description": "Description",
        "Technical description": "Technical description",
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
    },
}

CIPHER_LABELS: Final[dict[str, dict[str, str]]] = {
    "ru": {
        "atbash": "Атбаш",
        "caesar": "Шифр Цезаря",
        "scytale": "Скитала",
        "polybius": "Квадрат Полибия",
        "magic_square": "Магический квадрат 4×4",
        "book_cipher": "Книжный шифр",
        "affine": "Аффинный шифр",
        "binary_code": "Двоичный код (1..33 → 8 бит)",
        "litorea": "Русская литорея",
        "vigenere": "Шифр Виженера",
        "alberti": "Диск Альберти",
    },
    "en": {},
}

PARAM_LABELS: Final[dict[str, dict[str, str]]] = {
    "ru": {
        "caesar.k": "Сдвиг (k)",
        "scytale.r": "Число строк (r)",
        "polybius.method": "Метод",
        "book_cipher.key_path": "Путь к ключевому тексту",
        "affine.a": "Множитель (a)",
        "affine.b": "Смещение (b)",
        "vigenere.keyword": "Ключевая фраза",
        "alberti.outer": "Внешний диск (outer)",
        "alberti.inner": "Внутренний диск (inner)",
        "alberti.index_char": "Индексная буква (index_char)",
        "alberti.shift_every": "Сдвиг каждые N символов",
        "alberti.shift_step": "Шаг сдвига",
        "alberti.shift_dir": "Направление сдвига",
        "alberti.emit_prefix": "Добавлять префикс установки",
        "alberti.start_outer": "Стартовый символ outer",
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


def label_param(cipher_id: str, param_name: str, lang: str | None = None) -> str:
    use_lang = lang or get_lang()
    key = f"{cipher_id}.{param_name}"
    return PARAM_LABELS.get(use_lang, {}).get(key, param_name)


def description_override(cipher_id: str, lang: str | None = None) -> str | None:
    use_lang = lang or get_lang()
    return DESC_OVERRIDES.get(use_lang, {}).get(cipher_id)
