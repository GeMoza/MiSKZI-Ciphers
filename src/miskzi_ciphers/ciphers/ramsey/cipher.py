from __future__ import annotations

from string import ascii_uppercase

from miskzi_ciphers.common.keyparse import as_int, as_str, optional, reject_unknown_keys
from miskzi_ciphers.common.types import CipherInfo, Key

# Methodical constants from PZ-05:
# - table 29 uses the fixed keyword SUBWAY
# - table 30/31 use the fixed anagram ASINTOER
DEFAULT_KEYWORD_TABLE = "SUBWAY"
DEFAULT_ANAGRAM = "ASINTOER"
DEFAULT_GROUP_SIZE = 5

ALPHABET = ascii_uppercase
SEPARATOR_SYMBOL = "/"
EXTRA_SYMBOL = "."
PLAINTEXT_ALLOWED = set(ALPHABET + " " + SEPARATOR_SYMBOL + EXTRA_SYMBOL)

# Table 30: one-digit codes for the most probable symbols.
SINGLE_DIGIT_CODES: dict[str, str] = {
    "S": "0",
    "I": "1",
    "O": "2",
    "E": "3",
    "R": "4",
    "A": "5",
    "T": "6",
    "N": "7",
}

# Table 31: residual table encoded by 80..99.
DOUBLE_DIGIT_CODES: dict[str, str] = {
    "C": "80",
    "X": "81",
    "U": "82",
    "D": "83",
    "J": "84",
    "P": "85",
    "Z": "86",
    "B": "87",
    "K": "88",
    "Q": "89",
    ".": "90",
    "W": "91",
    "F": "92",
    "L": "93",
    "/": "94",
    "G": "95",
    "M": "96",
    "Y": "97",
    "H": "98",
    "V": "99",
}

ENCODE_MAP: dict[str, str] = {**SINGLE_DIGIT_CODES, **DOUBLE_DIGIT_CODES}
DECODE_MAP: dict[str, str] = {code: symbol for symbol, code in ENCODE_MAP.items()}


class RamseyCipher:
    name = "ramsey"

    def describe(self) -> CipherInfo:
        return {
            "name": self.name,
            "title": "Шифр Рамзая (ПЗ-05)",
            "family": "substitution/fractionation",
            "params": [
                {
                    "name": "keyword_table",
                    "type": "str",
                    "required": False,
                    "default": DEFAULT_KEYWORD_TABLE,
                    "help": "Фиксированное ключевое слово из методички ПЗ-05.",
                    "example": DEFAULT_KEYWORD_TABLE,
                },
                {
                    "name": "anagram",
                    "type": "str",
                    "required": False,
                    "default": DEFAULT_ANAGRAM,
                    "help": "Фиксированная анаграмма из таблиц 30-31 методички.",
                    "example": DEFAULT_ANAGRAM,
                },
                {
                    "name": "group_size",
                    "type": "int",
                    "required": False,
                    "default": DEFAULT_GROUP_SIZE,
                    "help": "Размер отображаемых групп цифр в шифртексте.",
                    "example": DEFAULT_GROUP_SIZE,
                },
            ],
            "notes": (
                "Реализация следует ПЗ-05: базовая таблица строится по слову SUBWAY, "
                "частотная строка кодов — по ASINTOER. Символы S/I/O/E/R/A/T/N кодируются "
                "одной цифрой 0..7, остальные символы таблицы — двузначными кодами 80..99. "
                "Пробелы во входном тексте нормализуются в '/', а при расшифровании '/' "
                "возвращается как пробел."
            ),
        }

    def parse_key(self, raw_key: Key) -> Key:
        reject_unknown_keys(raw_key, allowed=["keyword_table", "anagram", "group_size"], cipher=self.name)

        keyword_table = self._parse_fixed_keyword(
            optional(raw_key, "keyword_table", DEFAULT_KEYWORD_TABLE),
            field="keyword_table",
            expected=DEFAULT_KEYWORD_TABLE,
        )
        anagram = self._parse_fixed_keyword(
            optional(raw_key, "anagram", DEFAULT_ANAGRAM),
            field="anagram",
            expected=DEFAULT_ANAGRAM,
        )

        group_size = as_int(optional(raw_key, "group_size", DEFAULT_GROUP_SIZE), "group_size")
        if group_size <= 0:
            raise ValueError("ramsey: group_size must be a positive integer.")

        return {
            "keyword_table": keyword_table,
            "anagram": anagram,
            "group_size": group_size,
        }

    def encrypt(self, plaintext: str, key: Key) -> str:
        _ = key["keyword_table"]
        _ = key["anagram"]

        normalized = self._normalize_plaintext(plaintext)
        if normalized == "":
            return ""

        digits = "".join(ENCODE_MAP[symbol] for symbol in normalized)
        return self._group_digits(digits, int(key["group_size"]))

    def decrypt(self, ciphertext: str, key: Key) -> str:
        _ = key["keyword_table"]
        _ = key["anagram"]

        digits = self._normalize_ciphertext(ciphertext)
        if digits == "":
            return ""

        decoded_symbols: list[str] = []
        cursor = 0
        while cursor < len(digits):
            lead = digits[cursor]
            if lead in "01234567":
                code = lead
                cursor += 1
            elif lead in "89":
                if cursor + 1 >= len(digits):
                    raise ValueError("ramsey: ciphertext ends with incomplete 8x/9x code.")
                code = digits[cursor : cursor + 2]
                cursor += 2
            else:
                raise ValueError(f"ramsey: invalid ciphertext digit {lead!r}.")

            symbol = DECODE_MAP.get(code)
            if symbol is None:
                raise ValueError(f"ramsey: invalid ciphertext code {code!r}.")
            decoded_symbols.append(symbol)

        return "".join(" " if symbol == SEPARATOR_SYMBOL else symbol for symbol in decoded_symbols)

    @staticmethod
    def _parse_fixed_keyword(value: object, *, field: str, expected: str) -> str:
        raw = as_str(value, field).strip().upper()
        invalid = sorted({ch for ch in raw if ch not in ALPHABET})
        if invalid:
            joined = ", ".join(repr(ch) for ch in invalid)
            raise ValueError(f"ramsey: {field} must contain only Latin letters A-Z; invalid: {joined}.")
        if raw != expected:
            raise ValueError(f"ramsey: {field} is fixed by PZ-05 and must be {expected!r}.")
        return raw

    @staticmethod
    def _normalize_plaintext(value: str) -> str:
        normalized = value.upper().replace(" ", SEPARATOR_SYMBOL)
        invalid = sorted({ch for ch in normalized if ch not in PLAINTEXT_ALLOWED and ch != SEPARATOR_SYMBOL})
        if invalid:
            joined = ", ".join(repr(ch) for ch in invalid)
            raise ValueError(
                "ramsey: plaintext supports only Latin letters A-Z, spaces, '.' and '/'; "
                f"invalid: {joined}."
            )
        return normalized

    @staticmethod
    def _normalize_ciphertext(value: str) -> str:
        invalid = sorted({ch for ch in value if ch != " " and ch not in "0123456789"})
        if invalid:
            joined = ", ".join(repr(ch) for ch in invalid)
            raise ValueError(
                f"ramsey: ciphertext must contain only digits and grouping spaces; invalid: {joined}."
            )
        return value.replace(" ", "")

    @staticmethod
    def _group_digits(digits: str, group_size: int) -> str:
        return " ".join(digits[i : i + group_size] for i in range(0, len(digits), group_size))


def get_cipher() -> RamseyCipher:
    return RamseyCipher()
