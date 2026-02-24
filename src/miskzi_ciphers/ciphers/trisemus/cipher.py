from __future__ import annotations

from math import ceil

from miskzi_ciphers.common.alphabet import RU_33
from miskzi_ciphers.common.keyparse import as_int, as_str, optional, reject_unknown_keys
from miskzi_ciphers.common.types import CipherInfo, Key


def _unique_in_order(text: str) -> str:
    seen: set[str] = set()
    out: list[str] = []
    for ch in text:
        if ch in seen:
            continue
        seen.add(ch)
        out.append(ch)
    return "".join(out)


class TrisemusCipher:
    name = "trisemus"

    def describe(self) -> CipherInfo:
        return {
            "name": self.name,
            "title": "Шифр Трисемуса",
            "family": "substitution",
            "params": [
                {
                    "name": "keyword",
                    "type": "str",
                    "required": True,
                    "help": "Ключевое слово, сначала его уникальные буквы, затем остаток алфавита",
                    "example": "КЛЮЧ",
                },
                {
                    "name": "cols",
                    "type": "int",
                    "required": False,
                    "default": 6,
                    "help": "Ширина таблицы",
                    "example": 6,
                },
                {
                    "name": "extras",
                    "type": "str",
                    "required": False,
                    "default": "123",
                    "help": "Дополнительные уникальные символы для заполнения прямоугольной таблицы",
                    "example": "123",
                },
            ],
        }

    def parse_key(self, raw_key: Key) -> Key:
        reject_unknown_keys(raw_key, allowed=["keyword", "cols", "extras"], cipher=self.name)
        keyword_raw = as_str(optional(raw_key, "keyword", ""), "keyword").upper()
        cols = as_int(optional(raw_key, "cols", 6), "cols")
        extras = _unique_in_order(as_str(optional(raw_key, "extras", "123"), "extras"))

        if cols < 2:
            raise ValueError("trisemus: cols must be >= 2.")

        symbolset = _unique_in_order(RU_33 + extras)
        keyword = _unique_in_order("".join(ch for ch in keyword_raw if ch in symbolset))
        if not keyword:
            raise ValueError("trisemus: keyword must contain at least one symbol from symbolset.")

        return {
            "keyword": keyword,
            "cols": cols,
            "extras": extras,
            "symbolset": symbolset,
        }

    def encrypt(self, plaintext: str, key: Key) -> str:
        return self._xform(plaintext, key=key, decrypt=False)

    def decrypt(self, ciphertext: str, key: Key) -> str:
        return self._xform(ciphertext, key=key, decrypt=True)

    def _xform(self, text: str, *, key: Key, decrypt: bool) -> str:
        cols = key["cols"]
        symbolset = key["symbolset"]
        keyword = key["keyword"]

        ordered = _unique_in_order(keyword + "".join(ch for ch in symbolset if ch not in keyword))
        rows = ceil(len(ordered) / cols)

        pos: dict[str, tuple[int, int]] = {}
        for i, ch in enumerate(ordered):
            pos[ch] = (i // cols, i % cols)

        out: list[str] = []
        for ch in text:
            up = ch.upper()
            found = pos.get(up)
            if found is None:
                out.append(ch)
                continue

            r, c = found
            r2 = (r - 1) % rows if decrypt else (r + 1) % rows
            i2 = r2 * cols + c
            if i2 >= len(ordered):
                i2 = c
            mapped = ordered[i2]

            if ch.islower() and mapped in RU_33:
                out.append(mapped.lower())
            else:
                out.append(mapped)
        return "".join(out)


def get_cipher() -> TrisemusCipher:
    return TrisemusCipher()
