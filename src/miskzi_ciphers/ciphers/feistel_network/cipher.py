from __future__ import annotations

import re

from miskzi_ciphers.common.keyparse import as_str, reject_unknown_keys, require
from miskzi_ciphers.common.types import CipherInfo, Key

ALPHABET = "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
ALPHABET_INDEX = {ch: index + 1 for index, ch in enumerate(ALPHABET)}
CODE_TO_CHAR = {index + 1: ch for index, ch in enumerate(ALPHABET)}
DECIMAL_TOKEN_RE = re.compile(r"[\s,;]+")


class FeistelNetworkCipher:
    name = "feistel_network"

    def describe(self) -> CipherInfo:
        return {
            "name": self.name,
            "title": "Учебная сеть Фейстеля",
            "family": "block",
            "params": [
                {"name": "keyword", "type": "str", "required": True, "help": "Ключ из 4 русских букв", "example": "ЛЕТО"},
            ],
            "notes": (
                "Учебная 4-раундовая схема из ПЗ-07: блок 32 бита (4 буквы), F = XOR с раундовым ключом, "
                "шифротекст выводится как 4 десятичных байта. В локальной ПЗ-07 есть методическая неоднозначность: "
                "таблица на странице выглядит как алфавит с 'Ё', но пример и варианты совпадают только с 32-буквенной "
                "нумерацией без 'Ё'; реализация следует примеру и вариантам."
            ),
        }

    def parse_key(self, raw_key: Key) -> Key:
        reject_unknown_keys(raw_key, allowed=["keyword"], cipher=self.name)
        keyword = _normalize_ru32_text(as_str(require(raw_key, "keyword"), "keyword"), field="keyword")
        if len(keyword) != 4:
            raise ValueError("feistel_network: keyword must contain exactly 4 RU32 letters without 'Ё'.")
        return {"keyword": keyword, "round_keys": [ALPHABET_INDEX[ch] for ch in keyword]}

    def encrypt(self, plaintext: str, key: Key) -> str:
        text = _normalize_ru32_text(plaintext, field="plaintext")
        if len(text) != 4:
            raise ValueError("feistel_network: plaintext must contain exactly 4 RU32 letters without 'Ё'.")

        left = _pair_to_word(text[:2])
        right = _pair_to_word(text[2:])
        k1, k2, k3, k4 = key["round_keys"]

        f1 = left ^ k1
        r1 = f1 ^ right

        f2 = r1 ^ k2
        l1 = f2 ^ left

        f3 = l1 ^ k3
        r2 = f3 ^ r1

        f4 = r2 ^ k4
        l2 = f4 ^ l1

        return _format_decimal_bytes(_word_to_bytes(r2) + _word_to_bytes(l2))

    def decrypt(self, ciphertext: str, key: Key) -> str:
        values = _parse_ciphertext(ciphertext)
        r2 = _bytes_to_word(values[:2])
        l2 = _bytes_to_word(values[2:])
        k1, k2, k3, k4 = key["round_keys"]

        f4 = r2 ^ k4
        l1 = f4 ^ l2

        f3 = l1 ^ k3
        r1 = f3 ^ r2

        f2 = r1 ^ k2
        l0 = f2 ^ l1

        f1 = l0 ^ k1
        r0 = f1 ^ r1

        return _word_to_pair(l0) + _word_to_pair(r0)


def _normalize_ru32_text(value: str, *, field: str) -> str:
    text = value.replace(" ", "").upper()
    invalid = sorted({ch for ch in text if ch not in ALPHABET_INDEX})
    if invalid:
        joined = ", ".join(repr(ch) for ch in invalid)
        raise ValueError(
            f"feistel_network: {field} supports only RU32 letters without 'Ё'; invalid: {joined}."
        )
    return text


def _pair_to_word(pair: str) -> int:
    return (ALPHABET_INDEX[pair[0]] << 8) | ALPHABET_INDEX[pair[1]]


def _word_to_pair(value: int) -> str:
    high, low = _word_to_bytes(value)
    return _decode_ru32_byte(high) + _decode_ru32_byte(low)


def _word_to_bytes(value: int) -> list[int]:
    return [(value >> 8) & 0xFF, value & 0xFF]


def _bytes_to_word(values: list[int]) -> int:
    return (values[0] << 8) | values[1]


def _decode_ru32_byte(value: int) -> str:
    char = CODE_TO_CHAR.get(value)
    if char is None:
        raise ValueError(f"feistel_network: byte value {value} has no RU32 letter mapping.")
    return char


def _format_decimal_bytes(values: list[int]) -> str:
    return " ".join(f"{value:02d}" for value in values)


def _parse_ciphertext(value: str) -> list[int]:
    stripped = value.strip()
    if not stripped:
        raise ValueError("feistel_network: ciphertext must contain 4 decimal bytes or 4 RU32 letters.")

    if all(ch in ALPHABET_INDEX for ch in stripped.upper().replace(" ", "")):
        letters = _normalize_ru32_text(stripped, field="ciphertext")
        if len(letters) != 4:
            raise ValueError("feistel_network: ciphertext letters must contain exactly 4 RU32 letters.")
        return [ALPHABET_INDEX[ch] for ch in letters]

    parts = [part for part in DECIMAL_TOKEN_RE.split(stripped) if part]
    if len(parts) != 4:
        raise ValueError("feistel_network: ciphertext must contain exactly 4 decimal byte values.")

    values: list[int] = []
    for part in parts:
        try:
            number = int(part, 10)
        except ValueError as exc:
            raise ValueError("feistel_network: ciphertext must contain decimal integers only.") from exc
        if not (0 <= number <= 255):
            raise ValueError("feistel_network: ciphertext byte values must be in range 0..255.")
        values.append(number)
    return values


def get_cipher() -> FeistelNetworkCipher:
    return FeistelNetworkCipher()
