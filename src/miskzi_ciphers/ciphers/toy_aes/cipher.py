from __future__ import annotations

from miskzi_ciphers.common.keyparse import as_str, reject_unknown_keys, require
from miskzi_ciphers.common.types import CipherInfo, Key

BLOCK_HEX_LEN = 8
KEY_HEX_LEN = 8
ROUND_COUNT = 2
AES_POLY = 0x11B
SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)
INV_SBOX = tuple(SBOX.index(value) for value in range(256))
INV_MIX_FACTOR = 0x52


class ToyAESCipher:
    name = "toy_aes"

    def describe(self) -> CipherInfo:
        return {
            "name": self.name,
            "title": "Учебный toy AES",
            "family": "block",
            "params": [
                {
                    "name": "key_hex",
                    "type": "str",
                    "required": True,
                    "help": "4-байтовый ключ в hex: ровно 8 шестнадцатеричных символов.",
                    "example": "0B1F0C18",
                }
            ],
            "notes": (
                "Внешний учебный материал `Практические занятия №8.docx` задаёт упрощённую AES-подобную схему "
                "для ручного счёта: блок 4 байта, ключ 4 байта, 2 раунда, стандартный AES S-box, "
                "ShiftRows, MixColumns только в первом раунде и учебное расширение ключа на 2-байтовых словах. "
                "Это не canonical AES и не production-реализация. В проекте поддерживается только итоговый "
                "контракт encrypt/decrypt для hex-блоков без публичного trace промежуточных состояний."
            ),
        }

    def parse_key(self, raw_key: Key) -> Key:
        reject_unknown_keys(raw_key, allowed=["key_hex"], cipher=self.name)
        key_hex = _normalize_hex(as_str(require(raw_key, "key_hex"), "key_hex"), expected_len=KEY_HEX_LEN, field="key_hex")
        key_bytes = _hex_to_bytes(key_hex)
        round_keys = _expand_round_keys(key_bytes)
        return {"key_hex": key_hex, "round_keys": round_keys}

    def encrypt(self, plaintext: str, key: Key) -> str:
        state = _hex_to_bytes(_normalize_hex(plaintext, expected_len=BLOCK_HEX_LEN, field="plaintext"))
        round_keys = key["round_keys"]

        state = _xor_state(state, round_keys[0])
        for round_index in range(1, ROUND_COUNT + 1):
            state = _sub_bytes(state)
            state = _shift_rows(state)
            if round_index != ROUND_COUNT:
                state = _mix_columns(state)
            state = _xor_state(state, round_keys[round_index])
        return _bytes_to_hex(state)

    def decrypt(self, ciphertext: str, key: Key) -> str:
        state = _hex_to_bytes(_normalize_hex(ciphertext, expected_len=BLOCK_HEX_LEN, field="ciphertext"))
        round_keys = key["round_keys"]

        for round_index in range(ROUND_COUNT, 0, -1):
            state = _xor_state(state, round_keys[round_index])
            if round_index != ROUND_COUNT:
                state = _inv_mix_columns(state)
            state = _inv_shift_rows(state)
            state = _inv_sub_bytes(state)
        state = _xor_state(state, round_keys[0])
        return _bytes_to_hex(state)


def _normalize_hex(value: str, *, expected_len: int, field: str) -> str:
    cleaned = value.strip().replace(" ", "").replace("_", "")
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) != expected_len:
        raise ValueError(f"toy_aes: {field} must contain exactly {expected_len} hex characters.")
    try:
        int(cleaned, 16)
    except ValueError as exc:
        raise ValueError(f"toy_aes: {field} must be a hexadecimal string.") from exc
    return cleaned.upper()


def _hex_to_bytes(value: str) -> list[int]:
    return [int(value[index : index + 2], 16) for index in range(0, len(value), 2)]


def _bytes_to_hex(values: list[int]) -> str:
    return "".join(f"{value:02X}" for value in values)


def _xor_state(left: list[int], right: list[int]) -> list[int]:
    return [a ^ b for a, b in zip(left, right)]


def _sub_bytes(state: list[int]) -> list[int]:
    return [SBOX[value] for value in state]


def _inv_sub_bytes(state: list[int]) -> list[int]:
    return [INV_SBOX[value] for value in state]


def _shift_rows(state: list[int]) -> list[int]:
    return [state[0], state[1], state[3], state[2]]


def _inv_shift_rows(state: list[int]) -> list[int]:
    return [state[0], state[1], state[3], state[2]]


def _mix_columns(state: list[int]) -> list[int]:
    left_top, right_top, left_bottom, right_bottom = state
    return [
        _gf_mul(left_top, 0x02) ^ left_bottom,
        _gf_mul(right_top, 0x02) ^ right_bottom,
        left_top ^ _gf_mul(left_bottom, 0x02),
        right_top ^ _gf_mul(right_bottom, 0x02),
    ]


def _inv_mix_columns(state: list[int]) -> list[int]:
    left_top, right_top, left_bottom, right_bottom = state
    return [
        _gf_mul(INV_MIX_FACTOR, left_bottom ^ _gf_mul(left_top, 0x02)),
        _gf_mul(INV_MIX_FACTOR, right_bottom ^ _gf_mul(right_top, 0x02)),
        _gf_mul(INV_MIX_FACTOR, left_top ^ _gf_mul(left_bottom, 0x02)),
        _gf_mul(INV_MIX_FACTOR, right_top ^ _gf_mul(right_bottom, 0x02)),
    ]


def _expand_round_keys(key_bytes: list[int]) -> list[list[int]]:
    if len(key_bytes) != 4:
        raise ValueError("toy_aes: internal error, 4 key bytes required.")

    words = [
        [key_bytes[0], key_bytes[2]],
        [key_bytes[1], key_bytes[3]],
    ]
    rc = 0x01

    while len(words) < 6:
        transformed = _g(words[-1], rc)
        next_even = _xor_word(words[-2], transformed)
        next_odd = _xor_word(next_even, words[-1])
        words.extend([next_even, next_odd])
        rc = _gf_mul(rc, 0x02)

    return [
        _words_to_state(words[0], words[1]),
        _words_to_state(words[2], words[3]),
        _words_to_state(words[4], words[5]),
    ]


def _g(word: list[int], rc: int) -> list[int]:
    rotated = [word[1], word[0]]
    substituted = [SBOX[rotated[0]], SBOX[rotated[1]]]
    return [substituted[0] ^ rc, substituted[1]]


def _xor_word(left: list[int], right: list[int]) -> list[int]:
    return [left[0] ^ right[0], left[1] ^ right[1]]


def _words_to_state(left: list[int], right: list[int]) -> list[int]:
    return [left[0], right[0], left[1], right[1]]


def _gf_mul(left: int, right: int) -> int:
    result = 0
    a = left
    b = right
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= AES_POLY
        a &= 0xFF
        b >>= 1
    return result


def get_cipher() -> ToyAESCipher:
    return ToyAESCipher()
