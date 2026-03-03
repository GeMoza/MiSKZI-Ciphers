from __future__ import annotations

from miskzi_ciphers.common.alphabet import RU_33, build_index
from miskzi_ciphers.common.keyparse import as_enum_str, as_str, optional, reject_unknown_keys, require
from miskzi_ciphers.common.types import CipherInfo, Key

BYTE_DOT = 0
BYTE_OFFSET = 1
SUPPORTED = RU_33 + "."


class VernamCipher:
    name = "vernam"

    def describe(self) -> CipherInfo:
        return {
            "name": self.name,
            "title": "Шифр Вернама",
            "family": "stream",
            "params": [
                {"name": "keyword", "type": "str", "required": True, "help": "Ключевая строка", "example": "...."},
                {
                    "name": "apply_to",
                    "type": "enum",
                    "required": False,
                    "default": "all",
                    "choices": ["all", "letters_only"],
                    "help": "Режим совместимости; в текущей реализации влияет только на валидацию параметра.",
                },
            ],
            "notes": "Поддерживаются символы RU_33 и '.'; '.' кодируется байтом 00000000.",
        }

    def parse_key(self, raw_key: Key) -> Key:
        reject_unknown_keys(raw_key, allowed=["keyword", "apply_to"], cipher=self.name)
        keyword = as_str(require(raw_key, "keyword"), "keyword")
        apply_to = as_enum_str(optional(raw_key, "apply_to", "all"), "apply_to", {"all", "letters_only"})
        if keyword == "":
            raise ValueError("vernam: keyword must not be empty.")
        return {"keyword": keyword, "apply_to": apply_to}

    def encrypt(self, plaintext: str, key: Key) -> str:
        return self._xor_text(plaintext, key)

    def decrypt(self, ciphertext: str, key: Key) -> str:
        return self._xor_text(ciphertext, key)

    def _xor_text(self, text: str, key: Key) -> str:
        keyword: str = key["keyword"]
        out: list[str] = []
        k_pos = 0

        for ch in text:
            ch_up = ch.upper()
            if ch_up not in SUPPORTED:
                out.append(ch)
                continue

            key_char = keyword[k_pos % len(keyword)].upper()
            if key_char not in SUPPORTED:
                raise ValueError(f"vernam: unsupported keyword symbol {key_char!r} at position {k_pos}.")

            x = self.encode_char_to_byte(ch_up)
            y = self.encode_char_to_byte(key_char)
            z = x ^ y
            out.append(self.decode_byte_to_char(z))
            k_pos += 1

        return "".join(out)

    @staticmethod
    def encode_char_to_byte(ch: str) -> int:
        if ch == ".":
            return BYTE_DOT
        idx = build_index(RU_33).get(ch)
        if idx is None:
            raise ValueError(f"vernam: unsupported symbol {ch!r}.")
        return idx + BYTE_OFFSET

    @staticmethod
    def decode_byte_to_char(value: int) -> str:
        if value == BYTE_DOT:
            return "."
        if BYTE_OFFSET <= value <= len(RU_33):
            return RU_33[value - BYTE_OFFSET]
        raise ValueError(
            f"vernam: XOR result byte {value:08b} has no symbol mapping; "
            "use plaintext/keyword pairs that stay within RU_33+'.' table."
        )


def get_cipher() -> VernamCipher:
    return VernamCipher()
