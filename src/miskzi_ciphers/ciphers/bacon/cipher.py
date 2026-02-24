from __future__ import annotations

from miskzi_ciphers.common.alphabet import RU_33, build_index
from miskzi_ciphers.common.keyparse import as_int, as_str, optional, reject_unknown_keys
from miskzi_ciphers.common.types import CipherInfo, Key


class BaconCipher:
    name = "bacon"

    def describe(self) -> CipherInfo:
        return {
            "name": self.name,
            "title": "Шифр Бэкона (A/B кодирование)",
            "family": "encoding",
            "params": [
                {
                    "name": "group_len",
                    "type": "int",
                    "required": False,
                    "default": 6,
                    "help": "Длина группы A/B для RU_33",
                    "example": 6,
                },
                {
                    "name": "separator",
                    "type": "str",
                    "required": False,
                    "default": " ",
                    "help": "Разделитель групп в encrypt",
                    "example": " ",
                },
            ],
        }

    def parse_key(self, raw_key: Key) -> Key:
        reject_unknown_keys(raw_key, allowed=["group_len", "separator"], cipher=self.name)
        group_len = as_int(optional(raw_key, "group_len", 6), "group_len")
        separator = as_str(optional(raw_key, "separator", " "), "separator")
        if group_len != 6:
            raise ValueError("bacon: group_len must be 6 for RU_33 mapping.")
        return {"group_len": group_len, "separator": separator}

    def encrypt(self, plaintext: str, key: Key) -> str:
        idx = build_index(RU_33)
        groups: list[str] = []
        for ch in plaintext:
            up = ch.upper()
            pos = idx.get(up)
            if pos is None:
                continue
            bits = format(pos, f"0{key['group_len']}b")
            groups.append(bits.replace("0", "A").replace("1", "B"))
        return key["separator"].join(groups)

    def decrypt(self, ciphertext: str, key: Key) -> str:
        normalized = "".join(ch for ch in ciphertext.upper() if not ch.isspace())
        if any(ch not in {"A", "B"} for ch in normalized):
            raise ValueError("bacon: ciphertext must contain only A/B symbols and whitespace.")

        group_len = key["group_len"]
        if len(normalized) % group_len != 0:
            raise ValueError(
                f"bacon: count of A/B symbols must be divisible by {group_len}, got {len(normalized)}."
            )

        out: list[str] = []
        for i in range(0, len(normalized), group_len):
            grp = normalized[i : i + group_len]
            bits = grp.replace("A", "0").replace("B", "1")
            n = int(bits, 2)
            if not (0 <= n < len(RU_33)):
                raise ValueError(f"bacon: decoded value out of RU_33 range: {n}")
            out.append(RU_33[n])
        return "".join(out)


def get_cipher() -> BaconCipher:
    return BaconCipher()
