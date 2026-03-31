from __future__ import annotations

from miskzi_ciphers.common.keyparse import as_str, reject_unknown_keys, require
from miskzi_ciphers.common.types import CipherInfo, Key

BLOCK_HEX_LEN = 32
KEY_HEX_LEN = 64
ROUND_COUNT = 4


class KuznechikCipher:
    name = "kuznechik"

    def describe(self) -> CipherInfo:
        return {
            "name": self.name,
            "title": "Учебный Кузнечик",
            "family": "block",
            "params": [
                {
                    "name": "key_hex",
                    "type": "str",
                    "required": True,
                    "help": "256-битный ключ в hex (64 hex-символа).",
                    "example": "8899AABBCCDDEEFF0011223344556677FEDCBA98765432100123456789ABCDEF",
                },
            ],
            "notes": (
                "Project-control реализация для темы 'Кузнечик': локальная ПЗ-07 только упоминает алгоритм как "
                "следующий шаг и не даёт полного описания, примеров или вариантов. Поэтому здесь реализован "
                "минимальный учебный SP-блок на одном 128-битном блоке и 4 раундах с обратимыми операциями "
                "XOR -> substitute -> permute. Это не полная спецификация ГОСТ Р 34.12-2015."
            ),
        }

    def parse_key(self, raw_key: Key) -> Key:
        reject_unknown_keys(raw_key, allowed=["key_hex"], cipher=self.name)
        key_hex = _normalize_hex(as_str(require(raw_key, "key_hex"), "key_hex"), expected_len=KEY_HEX_LEN, field="key_hex")
        key_bytes = bytes.fromhex(key_hex)
        return {"key_hex": key_hex, "round_keys": _derive_round_keys(key_bytes)}

    def encrypt(self, plaintext: str, key: Key) -> str:
        state = list(bytes.fromhex(_normalize_hex(plaintext, expected_len=BLOCK_HEX_LEN, field="plaintext")))
        for round_index, round_key in enumerate(key["round_keys"], start=1):
            state = _xor_bytes(state, round_key)
            state = [_s_box(value) for value in state]
            state = _permute(state, shift=round_index)
        return bytes(state).hex().upper()

    def decrypt(self, ciphertext: str, key: Key) -> str:
        state = list(bytes.fromhex(_normalize_hex(ciphertext, expected_len=BLOCK_HEX_LEN, field="ciphertext")))
        for round_index, round_key in reversed(list(enumerate(key["round_keys"], start=1))):
            state = _inverse_permute(state, shift=round_index)
            state = [_inverse_s_box(value) for value in state]
            state = _xor_bytes(state, round_key)
        return bytes(state).hex().upper()


def _normalize_hex(value: str, *, expected_len: int, field: str) -> str:
    cleaned = value.strip().replace(" ", "").replace("_", "")
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) != expected_len:
        raise ValueError(f"kuznechik: {field} must contain exactly {expected_len} hex characters.")
    try:
        int(cleaned, 16)
    except ValueError as exc:
        raise ValueError(f"kuznechik: {field} must be a hexadecimal string.") from exc
    return cleaned.upper()


def _derive_round_keys(key_bytes: bytes) -> list[list[int]]:
    left = list(key_bytes[:16])
    right = list(key_bytes[16:])
    round_1 = left
    round_2 = right
    round_3 = [left[(index + 1) % 16] ^ right[index] for index in range(16)]
    round_4 = [right[(index + 3) % 16] ^ left[index] for index in range(16)]
    return [round_1, round_2, round_3, round_4]


def _xor_bytes(left: list[int], right: list[int]) -> list[int]:
    return [a ^ b for a, b in zip(left, right, strict=True)]


def _s_box(value: int) -> int:
    return (197 * value + 123) % 256


def _inverse_s_box(value: int) -> int:
    return (13 * ((value - 123) % 256)) % 256


def _permute(state: list[int], *, shift: int) -> list[int]:
    use_shift = shift % len(state)
    return state[use_shift:] + state[:use_shift]


def _inverse_permute(state: list[int], *, shift: int) -> list[int]:
    use_shift = shift % len(state)
    if use_shift == 0:
        return list(state)
    return state[-use_shift:] + state[:-use_shift]


def get_cipher() -> KuznechikCipher:
    return KuznechikCipher()
