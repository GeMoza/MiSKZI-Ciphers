from __future__ import annotations

import re
from pathlib import Path
from common.keyparse import reject_unknown_keys, require, optional, as_str, as_bool
from common.types import CipherInfo, Key


_COORD_RE = re.compile(r"(\d+)\s*/\s*(\d+)")

RUS = set("АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ")

def is_rus_letter(ch: str) -> bool:
    return ch.upper() in RUS

def letters_only_upper(s: str) -> str:
    return "".join(ch.upper() for ch in s if is_rus_letter(ch))


def _split_lines(key_text: str) -> list[str]:
    # сохраняем строки как есть (включая пробелы), но убираем пустые строки по краям
    lines = [ln.rstrip("\n") for ln in key_text.splitlines()]
    # методичка даёт 4 строки; допускаем любое кол-во >0
    lines = [ln for ln in lines if ln.strip() != ""]
    if not lines:
        raise ValueError("book_cipher: key_text is empty")
    return lines


class BookCipher:
    name = "book_cipher"

    def describe(self) -> CipherInfo:
        return {
            "name": self.name,
            "title": "Книжный шифр (строка/столбец)",
            "family": "book",
            "params": [
                {
                    "name": "key_text",
                    "type": "str",
                    "required": False,
                    "help": "Текст-ключ (многострочный). Если не задан — используйте key_path.",
                },
                {
                    "name": "key_path",
                    "type": "path",
                    "required": False,
                    "help": "Путь к файлу с текстом-ключом (UTF-8).",
                },
                {
                    "name": "e_instead_of_ee",
                    "type": "bool",
                    "required": False,
                    "default": True,
                    "help": "Если в ключе нет 'Э', допускается использовать 'Е' вместо 'Э' при ШИФРОВАНИИ.",
                },
            ],
            "notes": (
                "Формат шифротекста: 'строка/столбец, строка/столбец, ...' "
                "(строка и столбец считаются с 1)."
            ),
        }

    def parse_key(self, raw_key: Key) -> Key:
        reject_unknown_keys(raw_key, allowed=["key_text", "key_path", "e_instead_of_ee"], cipher=self.name)
        key_text = raw_key.get("key_text")
        key_path = raw_key.get("key_path")
        e_rule = as_bool(optional(raw_key, "e_instead_of_ee", True), "e_instead_of_ee")

        if key_text is None:
            if key_path is None:
                raise ValueError("book_cipher: missing key_text or key_path")
            p = Path(as_str(key_path, "key_path"))
            if not p.exists() or not p.is_file():
                raise ValueError(f"book_cipher: key_path not found: {str(p)!r}")
            key_text = p.read_text(encoding="utf-8")

        raw_lines = _split_lines(as_str(key_text, "key_text"))

        # Нормализуем ключ: считаем столбцы только по русским буквам (без пробелов и знаков),
        # и работаем в верхнем регистре.
        lines = [letters_only_upper(ln) for ln in raw_lines]
        if any(len(ln) == 0 for ln in lines):
            raise ValueError("book_cipher: some key line has no russian letters after filtering.")

        # индекс: БУКВА -> список координат (line_idx, letter_col_idx), где letter_col_idx считается только по буквам
        index: dict[str, list[tuple[int, int]]] = {}
        for li, line in enumerate(lines, start=1):
            for ci, ch in enumerate(line, start=1):
                index.setdefault(ch, []).append((li, ci))

        has_EE = "Э" in index
        return {"lines": lines, "index": index, "e_rule": e_rule, "has_EE": has_EE}

    def encrypt(self, plaintext: str, key: Key) -> str:
        index: dict[str, list[tuple[int, int]]] = key["index"]
        e_rule: bool = key["e_rule"]
        has_EE: bool = key["has_EE"]

        coords: list[str] = []
        for ch in plaintext:
            if not is_rus_letter(ch):
                raise ValueError(f"book_cipher: plaintext contains non-russian-letter: {ch!r}")

            target = ch.upper()

            # по методичке: если нет Э, можно использовать Е вместо Э (при шифровании)
            if target == "Э" and (not has_EE) and e_rule:
                target = "Е"

            if target not in index:
                raise ValueError(f"book_cipher: char not found in key text: {ch!r}")
            li, ci = index[target][0]
            coords.append(f"{li}/{ci}")

        return ", ".join(coords)

    def decrypt(self, ciphertext: str, key: Key) -> str:
        lines: list[str] = key["lines"]

        pairs = _COORD_RE.findall(ciphertext)
        if not pairs:
            # допускаем пустую строку
            if ciphertext.strip() == "":
                return ""
            raise ValueError("book_cipher: no coordinates found (expected like '1/5, 4/2, ...')")

        out: list[str] = []
        for a, b in pairs:
            li = int(a)
            ci = int(b)
            if li < 1 or li > len(lines):
                raise ValueError(f"book_cipher: line out of range: {li}")
            line = lines[li - 1]
            if ci < 1 or ci > len(line):
                raise ValueError(f"book_cipher: column out of range: {li}/{ci}")
            out.append(line[ci - 1])
        return "".join(out)


def get_cipher() -> BookCipher:
    return BookCipher()
