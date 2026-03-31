from __future__ import annotations

import re

from miskzi_ciphers.common.alphabet import RU_33
from miskzi_ciphers.common.keyparse import as_int, as_str, reject_unknown_keys, require
from miskzi_ciphers.common.types import CipherInfo, Key

ALPHABET = RU_33
ALPHABET_INDEX = {ch: index + 1 for index, ch in enumerate(ALPHABET)}
CODE_TO_CHAR = {index + 1: ch for index, ch in enumerate(ALPHABET)}
BYTE_SPLIT_RE = re.compile(r"[\s,;:-]+")
BYTE_MASK = 0xFF


class RC6Cipher:
    name = "rc6"

    def describe(self) -> CipherInfo:
        return {
            "name": self.name,
            "title": "Учебный RC6",
            "family": "block",
            "params": [
                {"name": "keyword", "type": "str", "required": True, "help": "Ключ из 5 русских букв.", "example": "КНИГА"},
                {"name": "shift", "type": "int", "required": False, "default": 1, "help": "Учебный циклический сдвиг.", "example": 1},
            ],
            "notes": (
                "Упрощённая учебная схема RC6 из ПЗ-07, а не canonical RC6: один раунд, 4 байта сообщения, "
                "функция f(x) = rol8(x XOR S[f], shift), затем XOR, циклический сдвиг по количеству значащих бит "
                "второго аргумента и обычное сложение. Методичка показывает буквенный шифротекст после обнуления "
                "старших 3 бит каждого байта; проектный API возвращает обратимый raw-формат из 4 hex-байтов."
            ),
        }

    def parse_key(self, raw_key: Key) -> Key:
        reject_unknown_keys(raw_key, allowed=["keyword", "shift"], cipher=self.name)
        keyword = _normalize_text(as_str(require(raw_key, "keyword"), "keyword"), field="keyword")
        if len(keyword) != 5:
            raise ValueError("rc6: keyword must contain exactly 5 RU_33 letters.")
        shift = as_int(raw_key.get("shift", 1), "shift")
        if shift < 0:
            raise ValueError("rc6: shift must be >= 0.")
        values = [ALPHABET_INDEX[ch] for ch in keyword]
        return {"keyword": keyword, "shift": shift, "s": values[:4], "sf": values[4]}

    def encrypt(self, plaintext: str, key: Key) -> str:
        text = _normalize_text(plaintext, field="plaintext")
        if len(text) != 4:
            raise ValueError("rc6: plaintext must contain exactly 4 RU_33 letters.")

        a0, b0, c0, d0 = [ALPHABET_INDEX[ch] for ch in text]
        s0, s1, s2, s3 = key["s"]
        sf = key["sf"]
        shift = int(key["shift"])

        a1 = _checked_add(b0, s0, field="A1")
        c1 = _checked_add(d0, s1, field="C1")
        t = _f(a1, sf, shift)
        u = _f(c1, sf, shift)
        d1 = _checked_add(_rol8(a0 ^ t, _significant_bits(u)), s2, field="D1")
        b1 = _checked_add(_rol8(c0 ^ u, _significant_bits(t)), s3, field="B1")
        return _format_bytes([a1, b1, c1, d1])

    def decrypt(self, ciphertext: str, key: Key) -> str:
        a1, b1, c1, d1 = _parse_bytes(ciphertext)
        s0, s1, s2, s3 = key["s"]
        sf = key["sf"]
        shift = int(key["shift"])

        a_prime = a1
        c_prime = c1
        t = _f(a_prime, sf, shift)
        u = _f(c_prime, sf, shift)
        c0 = _ror8(_checked_sub(b1, s3, field="B1"), _significant_bits(t)) ^ u
        a0 = _ror8(_checked_sub(d1, s2, field="D1"), _significant_bits(u)) ^ t
        b0 = _checked_sub(a_prime, s0, field="A1")
        d0 = _checked_sub(c_prime, s1, field="C1")
        return "".join(CODE_TO_CHAR[value] for value in (a0, b0, c0, d0))


def _normalize_text(value: str, *, field: str) -> str:
    text = value.replace(" ", "").upper()
    invalid = sorted({ch for ch in text if ch not in ALPHABET_INDEX})
    if invalid:
        joined = ", ".join(repr(ch) for ch in invalid)
        raise ValueError(f"rc6: {field} supports only RU_33 letters; invalid: {joined}.")
    return text


def _significant_bits(value: int) -> int:
    return max(1, value.bit_length())


def _rol8(value: int, shift: int) -> int:
    shift %= 8
    value &= BYTE_MASK
    return ((value << shift) & BYTE_MASK) | (value >> (8 - shift if shift else 8))


def _ror8(value: int, shift: int) -> int:
    shift %= 8
    value &= BYTE_MASK
    return (value >> shift) | ((value << (8 - shift if shift else 8)) & BYTE_MASK)


def _f(value: int, sf: int, shift: int) -> int:
    return _rol8(value ^ sf, shift)


def _checked_add(left: int, right: int, *, field: str) -> int:
    total = left + right
    if not (0 <= total <= BYTE_MASK):
        raise ValueError(f"rc6: {field} leaves the 8-bit educational range.")
    return total


def _checked_sub(value: int, subtrahend: int, *, field: str) -> int:
    result = value - subtrahend
    if result < 0:
        raise ValueError(f"rc6: {field} cannot be reversed inside the educational range.")
    return result


def _format_bytes(values: list[int]) -> str:
    return " ".join(f"{value:02X}" for value in values)


def _parse_bytes(value: str) -> list[int]:
    parts = [part for part in BYTE_SPLIT_RE.split(value.strip()) if part]
    if len(parts) != 4:
        raise ValueError("rc6: ciphertext must contain exactly 4 hex bytes.")
    out: list[int] = []
    for part in parts:
        if len(part) > 2:
            raise ValueError("rc6: ciphertext bytes must be 1-2 hex digits each.")
        try:
            number = int(part, 16)
        except ValueError as exc:
            raise ValueError("rc6: ciphertext must contain hexadecimal byte values.") from exc
        if not (0 <= number <= BYTE_MASK):
            raise ValueError("rc6: ciphertext bytes must be in range 00..FF.")
        out.append(number)
    return out


def methodics_display(ciphertext: str) -> str:
    chars: list[str] = []
    for byte_value in _parse_bytes(ciphertext):
        masked = byte_value & 0x1F
        chars.append(CODE_TO_CHAR.get(masked, "."))
    return "".join(chars)


def get_cipher() -> RC6Cipher:
    return RC6Cipher()
