from __future__ import annotations

from string import ascii_uppercase

from miskzi_ciphers.common.keyparse import as_int, as_str, optional, reject_unknown_keys, require
from miskzi_ciphers.common.types import CipherInfo, Key

ALPHABET = ascii_uppercase
SPACE_SYMBOL = " "
RAMSEY_SYMBOLS = ALPHABET + SPACE_SYMBOL
GRID_ROWS = 3
GRID_COLS = 9
DEFAULT_GROUP_SIZE = 5


class RamseyCipher:
    name = "ramsey"

    def describe(self) -> CipherInfo:
        return {
            "name": self.name,
            "title": "Ramsey cipher (PZ-05)",
            "family": "fractionating-transposition",
            "params": [
                {
                    "name": "keyword",
                    "type": "str",
                    "required": True,
                    "help": "Latin keyword used to build the 3x9 substitution table. Duplicate letters are removed in order.",
                    "example": "ORBIT",
                },
                {
                    "name": "anagram",
                    "type": "str",
                    "required": True,
                    "help": "Latin anagram key for the second-stage column permutation. Letters must be unique.",
                    "example": "SPARE",
                },
                {
                    "name": "group_size",
                    "type": "int",
                    "required": False,
                    "default": DEFAULT_GROUP_SIZE,
                    "help": "Display grouping for the numeric ciphertext. Grouping is applied to raw digits and may split 2-digit codes.",
                    "example": DEFAULT_GROUP_SIZE,
                },
            ],
            "notes": (
                "The Ramsey implementation uses a keyword-built 3x9 substitution table over A-Z plus a dedicated space symbol. "
                "Encryption uppercases plaintext, encodes each symbol as a 2-digit coordinate, applies an anagram-key columnar permutation "
                "over whole code pairs, and formats the final digit stream into readable groups. Decryption accepts grouped or ungrouped digits, "
                "strips only literal spaces, and then inverts the permutation. Grouping is display-only and does not define code-pair boundaries."
            ),
        }

    def parse_key(self, raw_key: Key) -> Key:
        reject_unknown_keys(raw_key, allowed=["keyword", "anagram", "group_size"], cipher=self.name)

        keyword = self._canonicalize_keyword(as_str(require(raw_key, "keyword"), "keyword"))
        anagram = self._canonicalize_anagram(as_str(require(raw_key, "anagram"), "anagram"))

        group_size_raw = optional(raw_key, "group_size", DEFAULT_GROUP_SIZE)
        group_size = as_int(group_size_raw, "group_size")
        if group_size <= 0:
            raise ValueError("ramsey: group_size must be a positive integer.")

        return {
            "keyword": keyword,
            "anagram": anagram,
            "group_size": group_size,
        }

    def encrypt(self, plaintext: str, key: Key) -> str:
        normalized = self._normalize_plaintext(plaintext)
        if normalized == "":
            return ""

        encoder, _ = self._build_substitution_maps(str(key["keyword"]))
        tokens = [encoder[ch] for ch in normalized]
        permuted = self._columnar_encrypt(tokens, str(key["anagram"]))
        digits = "".join(permuted)
        return self._group_digits(digits, int(key["group_size"]))

    def decrypt(self, ciphertext: str, key: Key) -> str:
        normalized = self._normalize_ciphertext(ciphertext)
        if normalized == "":
            return ""
        if len(normalized) % 2 != 0:
            raise ValueError("ramsey: ciphertext must contain an even number of digits.")

        _, decoder = self._build_substitution_maps(str(key["keyword"]))
        tokens = [normalized[i : i + 2] for i in range(0, len(normalized), 2)]
        restored = self._columnar_decrypt(tokens, str(key["anagram"]))

        try:
            return "".join(decoder[token] for token in restored)
        except KeyError as exc:
            raise ValueError(f"ramsey: invalid ciphertext code {exc.args[0]!r}.") from None

    @staticmethod
    def _canonicalize_keyword(value: str) -> str:
        cleaned = RamseyCipher._uppercase_letters_only(value, field="keyword")
        deduped: list[str] = []
        seen: set[str] = set()
        for ch in cleaned:
            if ch in seen:
                continue
            seen.add(ch)
            deduped.append(ch)
        keyword = "".join(deduped)
        if keyword == "":
            raise ValueError("ramsey: keyword must contain at least one Latin letter A-Z.")
        return keyword

    @staticmethod
    def _canonicalize_anagram(value: str) -> str:
        cleaned = RamseyCipher._uppercase_letters_only(value, field="anagram")
        if cleaned == "":
            raise ValueError("ramsey: anagram must contain at least one Latin letter A-Z.")
        if len(set(cleaned)) != len(cleaned):
            raise ValueError("ramsey: anagram must not contain duplicate letters.")
        return cleaned

    @staticmethod
    def _uppercase_letters_only(value: str, *, field: str) -> str:
        stripped = value.strip().upper()
        if stripped == "":
            return ""
        invalid = sorted({ch for ch in stripped if ch not in ALPHABET})
        if invalid:
            joined = ", ".join(repr(ch) for ch in invalid)
            raise ValueError(f"ramsey: {field} must contain only Latin letters A-Z; invalid: {joined}.")
        return stripped

    @staticmethod
    def _normalize_plaintext(value: str) -> str:
        normalized = value.upper()
        invalid = sorted({ch for ch in normalized if ch not in RAMSEY_SYMBOLS})
        if invalid:
            joined = ", ".join(repr(ch) for ch in invalid)
            raise ValueError(
                f"ramsey: plaintext supports only Latin letters A-Z and spaces; invalid: {joined}."
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
    def _build_substitution_maps(keyword: str) -> tuple[dict[str, str], dict[str, str]]:
        sequence = keyword + "".join(ch for ch in ALPHABET if ch not in keyword) + SPACE_SYMBOL
        encoder: dict[str, str] = {}
        decoder: dict[str, str] = {}
        index = 0
        for row in range(1, GRID_ROWS + 1):
            for col in range(1, GRID_COLS + 1):
                symbol = sequence[index]
                index += 1
                code = f"{row}{col}"
                encoder[symbol] = code
                decoder[code] = symbol
        return encoder, decoder

    @staticmethod
    def _column_order(anagram: str) -> list[int]:
        return sorted(range(len(anagram)), key=lambda index: (anagram[index], index))

    def _columnar_encrypt(self, tokens: list[str], anagram: str) -> list[str]:
        width = len(anagram)
        rows = [tokens[i : i + width] for i in range(0, len(tokens), width)]
        order = self._column_order(anagram)

        out: list[str] = []
        for col in order:
            for row in rows:
                if col < len(row):
                    out.append(row[col])
        return out

    def _columnar_decrypt(self, tokens: list[str], anagram: str) -> list[str]:
        width = len(anagram)
        count = len(tokens)
        full_rows, remainder = divmod(count, width)
        column_lengths = [full_rows + (1 if index < remainder else 0) for index in range(width)]

        columns: list[list[str]] = [[] for _ in range(width)]
        cursor = 0
        for original_col in self._column_order(anagram):
            length = column_lengths[original_col]
            columns[original_col] = tokens[cursor : cursor + length]
            cursor += length

        rows_count = full_rows + (1 if remainder else 0)
        restored: list[str] = []
        for row in range(rows_count):
            for col in range(width):
                if row < len(columns[col]):
                    restored.append(columns[col][row])
        return restored

    @staticmethod
    def _group_digits(digits: str, group_size: int) -> str:
        return " ".join(digits[i : i + group_size] for i in range(0, len(digits), group_size))


def get_cipher() -> RamseyCipher:
    return RamseyCipher()
