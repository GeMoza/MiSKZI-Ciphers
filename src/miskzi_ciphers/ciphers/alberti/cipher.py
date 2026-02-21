from __future__ import annotations

from miskzi_ciphers.common.keyparse import (
    as_bool,
    as_char,
    as_enum_str,
    as_int,
    as_str,
    optional,
    reject_unknown_keys,
    require,
)
from miskzi_ciphers.common.types import CipherInfo, Key


class AlbertiCipher:
    name = "alberti"

    def describe(self) -> CipherInfo:
        return {
            "name": self.name,
            "title": "Шифр Альберти (параметризуемый диск)",
            "family": "polyalphabetic",
            "params": [
                {"name": "outer", "type": "str", "required": True, "help": "Внешний диск"},
                {"name": "inner", "type": "str", "required": True, "help": "Внутренний диск"},
                {"name": "index_char", "type": "str", "required": True, "help": "Индексная буква"},
                {"name": "shift_every", "type": "int", "required": False, "default": 5},
                {"name": "shift_step", "type": "int", "required": False, "default": 1},
                {
                    "name": "shift_dir",
                    "type": "enum",
                    "required": False,
                    "default": "left",
                    "choices": ["left", "right"],
                },
                {"name": "emit_prefix", "type": "bool", "required": False, "default": True},
                {"name": "start_outer", "type": "str", "required": False, "help": "Установочный символ внешнего диска"},
            ],
        }

    def parse_key(self, raw_key: Key) -> Key:
        reject_unknown_keys(
            raw_key,
            allowed=[
                "outer",
                "inner",
                "index_char",
                "shift_every",
                "shift_step",
                "shift_dir",
                "emit_prefix",
                "start_outer",
            ],
            cipher=self.name,
        )

        outer = as_str(require(raw_key, "outer"), "outer")
        inner = as_str(require(raw_key, "inner"), "inner")
        index_char = as_char(require(raw_key, "index_char"), "index_char")
        shift_every = as_int(optional(raw_key, "shift_every", 5), "shift_every")
        shift_step = as_int(optional(raw_key, "shift_step", 1), "shift_step")
        shift_dir = as_enum_str(optional(raw_key, "shift_dir", "left"), "shift_dir", {"left", "right"})
        emit_prefix = as_bool(optional(raw_key, "emit_prefix", True), "emit_prefix")

        start_outer_raw = optional(raw_key, "start_outer", None)
        start_outer = None if start_outer_raw is None else as_char(start_outer_raw, "start_outer")
        if start_outer is None:
            start_outer = outer[0] if outer else ""

        if not outer or not inner:
            raise ValueError("alberti: outer and inner must be non-empty.")
        if len(outer) != len(inner):
            raise ValueError("alberti: outer and inner must have equal length.")
        if len(set(outer)) != len(outer):
            raise ValueError("alberti: outer alphabet must contain unique symbols.")
        if len(set(inner)) != len(inner):
            raise ValueError("alberti: inner alphabet must contain unique symbols.")
        if index_char not in inner:
            raise ValueError("alberti: index_char must be present in inner alphabet.")
        if start_outer not in outer:
            raise ValueError("alberti: start_outer must be present in outer alphabet.")
        if shift_every <= 0:
            raise ValueError("alberti: shift_every must be > 0.")

        return {
            "outer": outer,
            "inner": inner,
            "index_char": index_char,
            "shift_every": shift_every,
            "shift_step": shift_step % len(outer),
            "shift_dir": shift_dir,
            "emit_prefix": emit_prefix,
            "start_outer": start_outer,
        }

    def encrypt(self, plaintext: str, key: Key) -> str:
        outer = key["outer"]
        inner_aligned = self._align_inner(key=key, start_outer=key["start_outer"])

        out: list[str] = []
        if key["emit_prefix"]:
            out.append(key["start_outer"])

        processed = 0
        for ch in plaintext:
            pos = outer.find(ch)
            if pos == -1:
                out.append(ch)
                continue

            out.append(inner_aligned[pos])
            processed += 1
            if processed % key["shift_every"] == 0:
                inner_aligned = self._shift(inner_aligned, step=key["shift_step"], direction=key["shift_dir"])

        return "".join(out)

    def decrypt(self, ciphertext: str, key: Key) -> str:
        outer = key["outer"]
        emit_prefix = key["emit_prefix"]

        work = ciphertext
        start_outer = key["start_outer"]
        if emit_prefix:
            if work == "":
                raise ValueError("alberti: ciphertext is empty but emit_prefix=True expects setup symbol.")
            start_outer = work[0]
            if start_outer not in outer:
                raise ValueError("alberti: ciphertext prefix is not in outer alphabet.")
            work = work[1:]

        inner_aligned = self._align_inner(key=key, start_outer=start_outer)

        out: list[str] = []
        processed = 0
        for ch in work:
            pos = inner_aligned.find(ch)
            if pos == -1:
                out.append(ch)
                continue

            out.append(outer[pos])
            processed += 1
            if processed % key["shift_every"] == 0:
                inner_aligned = self._shift(inner_aligned, step=key["shift_step"], direction=key["shift_dir"])

        return "".join(out)

    def _align_inner(self, *, key: Key, start_outer: str) -> str:
        outer = key["outer"]
        inner = key["inner"]
        index_char = key["index_char"]

        start_pos = outer.index(start_outer)
        index_pos = inner.index(index_char)
        shift = start_pos - index_pos
        return self._rotate(inner, shift)

    @staticmethod
    def _rotate(s: str, shift: int) -> str:
        n = len(s)
        shift %= n
        return s[-shift:] + s[:-shift] if shift else s

    def _shift(self, s: str, *, step: int, direction: str) -> str:
        if step == 0:
            return s
        if direction == "left":
            return s[step:] + s[:step]
        return s[-step:] + s[:-step]


def get_cipher() -> AlbertiCipher:
    return AlbertiCipher()
