from __future__ import annotations

from string import ascii_uppercase

from miskzi_ciphers.common.alphabet import RU_33

LATIN_AZ = ascii_uppercase
RUSSIAN_ALPHABET = RU_33


def normalize_upper(text: str) -> str:
    return text.upper()


def keep_alphabet(text: str, alphabet: str) -> str:
    allowed = set(alphabet)
    return "".join(ch for ch in text if ch in allowed)


def normalize_latin(text: str) -> str:
    return keep_alphabet(normalize_upper(text), LATIN_AZ)


def normalize_russian(text: str) -> str:
    return keep_alphabet(normalize_upper(text), RUSSIAN_ALPHABET)
