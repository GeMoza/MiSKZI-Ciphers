from __future__ import annotations

import re

from miskzi_ciphers.common.keyparse import as_int, reject_unknown_keys, require
from miskzi_ciphers.common.math_utils import gcd, modinv
from miskzi_ciphers.common.types import CipherInfo, Key


PAIR_RE = re.compile(r"^\(?\s*(\d+)\s*[, ]\s*(\d+)\s*\)?$")


class ElGamalCipher:
    name = "elgamal"

    def describe(self) -> CipherInfo:
        return {
            "name": self.name,
            "title": "Криптосистема Эль-Гамаля",
            "family": "public-key",
            "params": [
                {"name": "p", "type": "int", "required": True, "help": "Простое число p", "example": 11},
                {"name": "g", "type": "int", "required": True, "help": "Первообразный корень g", "example": 2},
                {"name": "x", "type": "int", "required": True, "help": "Закрытый ключ x", "example": 9},
                {"name": "k", "type": "int", "required": True, "help": "Сессионный ключ k", "example": 7},
            ],
            "notes": (
                "Учебная реализация шифрования Эль-Гамаля по ПЗ-06: parse_key() вычисляет y = g^x mod p, "
                "encrypt() возвращает пару 'a,b', decrypt() принимает 'a,b' или '(a,b)'. "
                "Сообщение M должно быть целым числом меньше p. "
                "Примечание: часть табличных наборов ПЗ-06 нарушает собственные предусловия схемы, "
                "поэтому в data/tests используются только корректные учебные варианты."
            ),
        }

    def parse_key(self, raw_key: Key) -> Key:
        reject_unknown_keys(raw_key, allowed=["p", "g", "x", "k"], cipher=self.name)

        p = as_int(require(raw_key, "p"), "p")
        g = as_int(require(raw_key, "g"), "g")
        x = as_int(require(raw_key, "x"), "x")
        k = as_int(require(raw_key, "k"), "k")

        if p <= 2 or not _is_prime(p):
            raise ValueError("elgamal: p must be a prime integer > 2.")
        if not (1 < g < p):
            raise ValueError("elgamal: g must satisfy 1 < g < p.")
        if not (1 < x < p):
            raise ValueError("elgamal: x must satisfy 1 < x < p.")
        if not (1 < k < p - 1):
            raise ValueError("elgamal: k must satisfy 1 < k < p-1.")
        if gcd(k, p - 1) != 1:
            raise ValueError("elgamal: k must be coprime with p-1.")

        y = pow(g, x, p)
        return {"p": p, "g": g, "x": x, "k": k, "y": y}

    def encrypt(self, plaintext: str, key: Key) -> str:
        p = int(key["p"])
        g = int(key["g"])
        y = int(key["y"])
        k = int(key["k"])
        message = _parse_single_integer(plaintext, field="plaintext")

        if not (0 <= message < p):
            raise ValueError(f"elgamal: plaintext message M must satisfy 0 <= M < p={p}.")

        a = pow(g, k, p)
        b = (pow(y, k, p) * message) % p
        return f"{a},{b}"

    def decrypt(self, ciphertext: str, key: Key) -> str:
        p = int(key["p"])
        x = int(key["x"])
        a, b = _parse_cipher_pair(ciphertext)
        if not (0 <= a < p and 0 <= b < p):
            raise ValueError(f"elgamal: ciphertext values must satisfy 0 <= a,b < p={p}.")

        shared = pow(a, x, p)
        message = (b * modinv(shared, p)) % p
        return str(message)


def _parse_single_integer(value: str, *, field: str) -> int:
    raw = value.strip()
    if raw == "":
        raise ValueError(f"elgamal: {field} must contain one decimal integer.")
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"elgamal: {field} must contain one decimal integer.") from exc


def _parse_cipher_pair(value: str) -> tuple[int, int]:
    match = PAIR_RE.match(value.strip())
    if match is None:
        raise ValueError("elgamal: ciphertext must be a pair 'a,b' or '(a,b)'.")
    return int(match.group(1)), int(match.group(2))


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


def get_cipher() -> ElGamalCipher:
    return ElGamalCipher()
