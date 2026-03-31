from __future__ import annotations

from miskzi_ciphers.common.keyparse import as_str, reject_unknown_keys, require
from miskzi_ciphers.common.types import CipherInfo, Key

MASK32 = 0xFFFFFFFF
BLOCK_HEX_LEN = 16
KEY_HEX_LEN = 64
SBOX = (
    (12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1),
    (6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15),
    (11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0),
    (12, 8, 2, 1, 13, 4, 10, 0, 7, 6, 15, 9, 3, 14, 5, 11),
    (7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12),
    (5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0),
    (8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7),
    (1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2),
)


class MagmaCipher:
    name = "magma"

    def describe(self) -> CipherInfo:
        return {
            "name": self.name,
            "title": "Блочный шифр Магма",
            "family": "block",
            "params": [
                {
                    "name": "key_hex",
                    "type": "str",
                    "required": True,
                    "help": "256-битный ключ в hex (64 hex-символа).",
                    "example": "FFEEDDCCBBAA99887766554433221100FEDCBA98765432100123456789ABCDEF",
                },
            ],
            "notes": (
                "Минимальная учебная реализация core-блока Магмы: один 64-битный блок в hex, "
                "режим простой замены, без внешних криптобиблиотек. Локальная ПЗ-07 даёт только теорию "
                "без готовой таблицы вариантов, поэтому data/tests используют project control set, а не "
                "восстановленные методические задания."
            ),
        }

    def parse_key(self, raw_key: Key) -> Key:
        reject_unknown_keys(raw_key, allowed=["key_hex"], cipher=self.name)
        key_hex = _normalize_hex(as_str(require(raw_key, "key_hex"), "key_hex"), expected_len=KEY_HEX_LEN, field="key_hex")
        words = [int(key_hex[offset : offset + 8], 16) for offset in range(0, KEY_HEX_LEN, 8)]
        return {"key_hex": key_hex, "round_keys_enc": _expand_encrypt_round_keys(words), "round_keys_dec": _expand_decrypt_round_keys(words)}

    def encrypt(self, plaintext: str, key: Key) -> str:
        block_hex = _normalize_hex(plaintext, expected_len=BLOCK_HEX_LEN, field="plaintext")
        left = int(block_hex[:8], 16)
        right = int(block_hex[8:], 16)
        out_left, out_right = _encrypt_block(left, right, key["round_keys_enc"])
        return f"{out_left:08X}{out_right:08X}"

    def decrypt(self, ciphertext: str, key: Key) -> str:
        block_hex = _normalize_hex(ciphertext, expected_len=BLOCK_HEX_LEN, field="ciphertext")
        left = int(block_hex[:8], 16)
        right = int(block_hex[8:], 16)
        out_left, out_right = _encrypt_block(left, right, key["round_keys_dec"])
        return f"{out_left:08X}{out_right:08X}"


def _normalize_hex(value: str, *, expected_len: int, field: str) -> str:
    cleaned = value.strip().replace(" ", "").replace("_", "")
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) != expected_len:
        raise ValueError(f"magma: {field} must contain exactly {expected_len} hex characters.")
    try:
        int(cleaned, 16)
    except ValueError as exc:
        raise ValueError(f"magma: {field} must be a hexadecimal string.") from exc
    return cleaned.upper()


def _expand_encrypt_round_keys(words: list[int]) -> list[int]:
    return words * 3 + list(reversed(words))


def _expand_decrypt_round_keys(words: list[int]) -> list[int]:
    return list(reversed(_expand_encrypt_round_keys(words)))


def _rotl32(value: int, shift: int) -> int:
    shift %= 32
    return ((value << shift) & MASK32) | ((value & MASK32) >> (32 - shift))


def _substitute_32(value: int) -> int:
    out = 0
    for index in range(8):
        nibble = (value >> (4 * index)) & 0xF
        out |= SBOX[index][nibble] << (4 * index)
    return out


def _g(value: int, round_key: int) -> int:
    total = (value + round_key) & MASK32
    substituted = _substitute_32(total)
    return _rotl32(substituted, 11)


def _encrypt_block(left: int, right: int, round_keys: list[int]) -> tuple[int, int]:
    if len(round_keys) != 32:
        raise ValueError("magma: internal error, 32 round keys required.")

    for round_key in round_keys[:-1]:
        left, right = right, (left ^ _g(right, round_key)) & MASK32
    return (left ^ _g(right, round_keys[-1])) & MASK32, right


def get_cipher() -> MagmaCipher:
    return MagmaCipher()
