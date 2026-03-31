from __future__ import annotations

import re

from miskzi_ciphers.common.keyparse import as_int, reject_unknown_keys, require
from miskzi_ciphers.common.math_utils import gcd, modinv
from miskzi_ciphers.common.types import CipherInfo, Key


TOKEN_SPLIT_RE = re.compile(r"[\s,;]+")


class RSACipher:
    name = "rsa"

    def describe(self) -> CipherInfo:
        return {
            "name": self.name,
            "title": "Криптографический алгоритм RSA",
            "family": "public-key",
            "params": [
                {"name": "p", "type": "int", "required": True, "help": "Простое число p", "example": 3},
                {"name": "q", "type": "int", "required": True, "help": "Простое число q", "example": 11},
                {"name": "e", "type": "int", "required": True, "help": "Открытый показатель e", "example": 7},
            ],
            "notes": (
                "Учебная реализация RSA по ПЗ-06: parse_key() вычисляет n, phi(n) и d из p, q, e, "
                "encrypt/decrypt работают с одной или несколькими десятичными величинами, разделёнными пробелами. "
                "TODO: в локальной ПЗ-06 сейчас есть теория RSA, но не найдено явной таблицы нумерованных вариантов, "
                "поэтому в data/tests зафиксирован минимальный учебный набор малых чисел."
            ),
        }

    def parse_key(self, raw_key: Key) -> Key:
        reject_unknown_keys(raw_key, allowed=["p", "q", "e"], cipher=self.name)

        p = as_int(require(raw_key, "p"), "p")
        q = as_int(require(raw_key, "q"), "q")
        e = as_int(require(raw_key, "e"), "e")

        if p <= 1 or q <= 1:
            raise ValueError("rsa: p and q must be integers > 1.")
        if not _is_prime(p) or not _is_prime(q):
            raise ValueError("rsa: p and q must be prime numbers.")
        if p == q:
            raise ValueError("rsa: p and q must be different primes.")

        phi = (p - 1) * (q - 1)
        if not (1 < e < phi):
            raise ValueError("rsa: e must satisfy 1 < e < (p-1)*(q-1).")
        if gcd(e, phi) != 1:
            raise ValueError("rsa: e must be coprime with (p-1)*(q-1).")

        n = p * q
        d = modinv(e, phi)

        return {"p": p, "q": q, "e": e, "n": n, "phi": phi, "d": d}

    def encrypt(self, plaintext: str, key: Key) -> str:
        values = _parse_numeric_tokens(plaintext, field="plaintext")
        encrypted = [_rsa_transform(value, exponent=int(key["e"]), modulus=int(key["n"]), field="plaintext") for value in values]
        return " ".join(str(value) for value in encrypted)

    def decrypt(self, ciphertext: str, key: Key) -> str:
        values = _parse_numeric_tokens(ciphertext, field="ciphertext")
        decrypted = [_rsa_transform(value, exponent=int(key["d"]), modulus=int(key["n"]), field="ciphertext") for value in values]
        return " ".join(str(value) for value in decrypted)


def _parse_numeric_tokens(value: str, *, field: str) -> list[int]:
    parts = [part for part in TOKEN_SPLIT_RE.split(value.strip()) if part]
    if not parts:
        raise ValueError(f"rsa: {field} must contain at least one integer.")

    numbers: list[int] = []
    for part in parts:
        try:
            number = int(part)
        except ValueError as exc:
            raise ValueError(f"rsa: {field} must contain only decimal integers.") from exc
        if number < 0:
            raise ValueError(f"rsa: {field} values must be non-negative.")
        numbers.append(number)
    return numbers


def _rsa_transform(value: int, *, exponent: int, modulus: int, field: str) -> int:
    if value >= modulus:
        raise ValueError(f"rsa: {field} value {value} must be less than n={modulus}.")
    return pow(value, exponent, modulus)


def _is_prime(value: int) -> bool:
    if value <= 1:
        return False
    if value <= 3:
        return True
    if value % 2 == 0:
        return False

    divisor = 3
    while divisor * divisor <= value:
        if value % divisor == 0:
            return False
        divisor += 2
    return True


def get_cipher() -> RSACipher:
    return RSACipher()
