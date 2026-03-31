from __future__ import annotations

import re

from miskzi_ciphers.common.keyparse import as_str, reject_unknown_keys, require
from miskzi_ciphers.common.types import CipherInfo, Key

ALPHABET = "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
ALPHABET_INDEX = {ch: index + 1 for index, ch in enumerate(ALPHABET)}
# Page 92 is internally inconsistent: the example table assigns 00000001 to 'Л'.
# Keep that methodical anomaly so the example reproduces exactly.
ALPHABET_INDEX["Л"] = 1
CODE_TO_CHAR = {index + 1: ch for index, ch in enumerate(ALPHABET)}
CODE_TO_CHAR[1] = "Л"
BYTE_SPLIT_RE = re.compile(r"[\s,;:-]+")
WORD_MASK = 0xFFFF


class RC5Cipher:
    name = "rc5"

    def describe(self) -> CipherInfo:
        return {
            "name": self.name,
            "title": "Учебный RC5",
            "family": "block",
            "params": [
                {"name": "keyword", "type": "str", "required": True, "help": "Ключ из 5 русских букв без 'Ё'.", "example": "КНИГА"},
            ],
            "notes": (
                "Упрощённая учебная схема RC5 из ПЗ-07, а не canonical RC5: один раунд, 2 слова по 16 бит, "
                "XOR вместо стандартной предобработки, циклический сдвиг по количеству значащих бит второго аргумента "
                "и обычное сложение без модульной арифметики. Методичка показывает буквенный шифротекст после обнуления "
                "старших 3 бит каждого байта; проектный API возвращает обратимый raw-формат из 4 hex-байтов. "
                "В локальной ПЗ-07 страница 92 противоречива: таблица примера почти полностью совпадает с 32-буквенной "
                "нумерацией без 'Ё', но при этом присваивает `00000001` и букве `А`, и букве `Л`. Проект сохраняет эту "
                "методическую аномалию ради точного воспроизведения примера `ЛЕТО -> БЙРО`; поэтому текущая реализация "
                "RC5 является узкой учебной реконструкцией, а не общим шифром для произвольного текста."
            ),
        }

    def parse_key(self, raw_key: Key) -> Key:
        reject_unknown_keys(raw_key, allowed=["keyword"], cipher=self.name)
        keyword = _normalize_text(as_str(require(raw_key, "keyword"), "keyword"), field="keyword")
        if len(keyword) != 5:
            raise ValueError("rc5: keyword must contain exactly 5 RU32 letters without 'Ё'.")
        values = [ALPHABET_INDEX[ch] for ch in keyword]
        return {"keyword": keyword, "s": values}

    def encrypt(self, plaintext: str, key: Key) -> str:
        text = _normalize_text(plaintext, field="plaintext")
        if len(text) != 4:
            raise ValueError("rc5: plaintext must contain exactly 4 RU32 letters without 'Ё'.")

        a = _pair_to_word(text[:2])
        b = _pair_to_word(text[2:])
        s0, s1, s2, s3, _ = key["s"]

        a_xor = a ^ s0
        b_xor = b ^ s1
        a_rot = _rol16(a_xor ^ b_xor, _significant_bits(b_xor))
        a1 = _checked_add(a_rot, s2, bits=16, field="A1")
        b_rot = _rol16(b_xor ^ a1, _significant_bits(a1))
        b1 = _checked_add(b_rot, s3, bits=16, field="B1")
        return _format_bytes(_word_to_bytes(a1) + _word_to_bytes(b1))

    def decrypt(self, ciphertext: str, key: Key) -> str:
        values = _parse_bytes(ciphertext)
        a1 = _bytes_to_word(values[:2])
        b1 = _bytes_to_word(values[2:])
        s0, s1, s2, s3, _ = key["s"]

        b_rot = _checked_sub(b1, s3, field="B1")
        b_xor = _ror16(b_rot, _significant_bits(a1)) ^ a1
        a_rot = _checked_sub(a1, s2, field="A1")
        a_xor = _ror16(a_rot, _significant_bits(b_xor)) ^ b_xor
        a = a_xor ^ s0
        b = b_xor ^ s1
        return _word_to_pair(a) + _word_to_pair(b)


def _normalize_text(value: str, *, field: str) -> str:
    text = value.replace(" ", "").upper()
    invalid = sorted({ch for ch in text if ch not in ALPHABET_INDEX})
    if invalid:
        joined = ", ".join(repr(ch) for ch in invalid)
        raise ValueError(f"rc5: {field} supports only RU32 letters without 'Ё'; invalid: {joined}.")
    return text


def _pair_to_word(pair: str) -> int:
    return (ALPHABET_INDEX[pair[0]] << 8) | ALPHABET_INDEX[pair[1]]


def _word_to_pair(value: int) -> str:
    high, low = _word_to_bytes(value)
    return _decode_byte(high) + _decode_byte(low)


def _decode_byte(value: int) -> str:
    char = CODE_TO_CHAR.get(value)
    if char is None:
        raise ValueError(f"rc5: byte value {value} has no RU32 letter mapping.")
    return char


def _word_to_bytes(value: int) -> list[int]:
    return [(value >> 8) & 0xFF, value & 0xFF]


def _bytes_to_word(values: list[int]) -> int:
    return (values[0] << 8) | values[1]


def _format_bytes(values: list[int]) -> str:
    return " ".join(f"{value:02X}" for value in values)


def _parse_bytes(value: str) -> list[int]:
    parts = [part for part in BYTE_SPLIT_RE.split(value.strip()) if part]
    if len(parts) != 4:
        raise ValueError("rc5: ciphertext must contain exactly 4 hex bytes.")
    out: list[int] = []
    for part in parts:
        if len(part) > 2:
            raise ValueError("rc5: ciphertext bytes must be 1-2 hex digits each.")
        try:
            number = int(part, 16)
        except ValueError as exc:
            raise ValueError("rc5: ciphertext must contain hexadecimal byte values.") from exc
        if not (0 <= number <= 0xFF):
            raise ValueError("rc5: ciphertext bytes must be in range 00..FF.")
        out.append(number)
    return out


def _significant_bits(value: int) -> int:
    return max(1, value.bit_length())


def _rol16(value: int, shift: int) -> int:
    shift %= 16
    value &= WORD_MASK
    return ((value << shift) & WORD_MASK) | (value >> (16 - shift if shift else 16))


def _ror16(value: int, shift: int) -> int:
    shift %= 16
    value &= WORD_MASK
    return (value >> shift) | ((value << (16 - shift if shift else 16)) & WORD_MASK)


def _checked_add(left: int, right: int, *, bits: int, field: str) -> int:
    limit = 1 << bits
    total = left + right
    if not (0 <= total < limit):
        raise ValueError(f"rc5: {field} leaves the {bits}-bit educational range.")
    return total


def _checked_sub(value: int, subtrahend: int, *, field: str) -> int:
    result = value - subtrahend
    if result < 0:
        raise ValueError(f"rc5: {field} cannot be reversed inside the educational range.")
    return result


def methodics_display(ciphertext: str) -> str:
    chars: list[str] = []
    for byte_value in _parse_bytes(ciphertext):
        masked = byte_value & 0x1F
        chars.append(CODE_TO_CHAR.get(masked, "."))
    return "".join(chars)


def get_cipher() -> RC5Cipher:
    return RC5Cipher()
