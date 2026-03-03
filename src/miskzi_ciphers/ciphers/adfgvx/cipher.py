from __future__ import annotations

from miskzi_ciphers.common.keyparse import as_str, reject_unknown_keys, require
from miskzi_ciphers.common.types import CipherInfo, Key

ADFGVX = "ADFGVX"
# Таблица 24 из методички (фиксированная 6x6).
GRID_ROWS = [
    "ABCDEF",
    "GHIJKL",
    "MNOPQR",
    "STUVWX",
    "YZ0123",
    "456789",
]

SYMBOL_TO_PAIR: dict[str, str] = {}
PAIR_TO_SYMBOL: dict[str, str] = {}
for r, row in enumerate(GRID_ROWS):
    for c, ch in enumerate(row):
        pair = ADFGVX[r] + ADFGVX[c]
        SYMBOL_TO_PAIR[ch] = pair
        PAIR_TO_SYMBOL[pair] = ch


class ADFGVXCipher:
    name = "adfgvx"

    def describe(self) -> CipherInfo:
        return {
            "name": self.name,
            "title": "Шифр ADFGVX",
            "family": "fractionating-transposition",
            "params": [
                {"name": "keyword", "type": "str", "required": True, "help": "Ключевое слово (латиница A-Z)", "example": "DRIVE"}
            ],
        }

    def parse_key(self, raw_key: Key) -> Key:
        reject_unknown_keys(raw_key, allowed=["keyword"], cipher=self.name)
        keyword = "".join(ch for ch in as_str(require(raw_key, "keyword"), "keyword").upper() if "A" <= ch <= "Z")
        if keyword == "":
            raise ValueError("adfgvx: keyword must contain at least one Latin letter A-Z.")
        return {"keyword": keyword}

    def encrypt(self, plaintext: str, key: Key) -> str:
        prepared = "".join(ch for ch in plaintext.upper() if ch != " ")
        for ch in prepared:
            if ch not in SYMBOL_TO_PAIR:
                raise ValueError(f"adfgvx: unsupported plaintext symbol {ch!r}; only A-Z, 0-9 and spaces are allowed.")

        stream = "".join(SYMBOL_TO_PAIR[ch] for ch in prepared)
        return self._columnar_encrypt(stream, key["keyword"])

    def decrypt(self, ciphertext: str, key: Key) -> str:
        for ch in ciphertext:
            if ch not in ADFGVX:
                raise ValueError("adfgvx: ciphertext must contain only letters A,D,F,G,V,X.")
        stream = self._columnar_decrypt(ciphertext, key["keyword"])
        if len(stream) % 2 != 0:
            raise ValueError("adfgvx: internal pair stream has odd length.")
        pairs = [stream[i : i + 2] for i in range(0, len(stream), 2)]
        return "".join(PAIR_TO_SYMBOL[p] for p in pairs)

    @staticmethod
    def _sort_order(keyword: str) -> list[int]:
        return sorted(range(len(keyword)), key=lambda i: (keyword[i], i))

    def _columnar_encrypt(self, stream: str, keyword: str) -> str:
        width = len(keyword)
        rows = [stream[i : i + width] for i in range(0, len(stream), width)]
        order = self._sort_order(keyword)

        out: list[str] = []
        for col in order:
            for row in rows:
                if col < len(row):
                    out.append(row[col])
        return "".join(out)

    def _columnar_decrypt(self, ciphertext: str, keyword: str) -> str:
        width = len(keyword)
        n = len(ciphertext)
        q, r = divmod(n, width)
        lengths = [q + (1 if i < r else 0) for i in range(width)]

        order = self._sort_order(keyword)
        cols = [""] * width
        pos = 0
        for original_col in order:
            ln = lengths[original_col]
            cols[original_col] = ciphertext[pos : pos + ln]
            pos += ln

        rows_count = q + (1 if r else 0)
        out: list[str] = []
        for row in range(rows_count):
            for col in range(width):
                if row < len(cols[col]):
                    out.append(cols[col][row])
        return "".join(out)


def get_cipher() -> ADFGVXCipher:
    return ADFGVXCipher()
